"""
Veridrome — sertifika iptal-defteri ( append-only, hash-zincirli).

Revocation bir YENİ-YAZIM değildir — append-only deftere eklenen bir
giriştir ( Veridict-deseni). İptal edilmiş bir sertifika imzası hâlâ
geçerlidir ama geçerliliği defterdeki imzalı-iptal-girişiyle reddedilir.

Giriş formatı ( her satır):
  {
    "timestamp": <ISO8601-UTC>,
    "cert_id": <sha256>,
    "revoked_by": <did:key>,
    "reason": <dize>,
    "prev": <sha256 | 64x"0" genesis>,
    "h": <sha256(prev + canonical(json))>
  }

Bu, mevcut CT-log zinciriyle ( w3c_vc.py AT-177/183 desenleri) aynı
güvenlik-modelini taşır: tahriz edildiğinde bağımsız-tespit-edilir.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Set

from veridrome.certificate.didkey import is_did_key, sign, verify as didkey_verify

_GENESIS = "0" * 64


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RevocationLedger:
    """Append-only hash-zincirli iptal-defteri."""

    def __init__(self, path: str) -> None:
        self.path = path

    # -- okuma -------------------------------------------------------------

    def _read_lines(self) -> List[str]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return [ln for ln in f.read().splitlines() if ln.strip()]
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise RuntimeError(
                f"iptal-defteri-okunamadı: {self.path} — {exc} ( fail-closed)"
            ) from exc

    def read_entries(self) -> List[Dict[str, Any]]:
        """Defterdeki tüm girişleri JSON olarak döndürür ( boş-defter → [])."""
        entries: List[Dict[str, Any]] = []
        for ln in self._read_lines():
            try:
                entries.append(json.loads(ln))
            except ValueError as exc:
                # AT-183-deseni: bozuk-kuyruk → sessiz-genesis-YOK
                raise RuntimeError(
                    f"iptal-defteri-bozuk-satır — sessiz-zincir-kopması-YOK "
                    f"( fail-closed): {exc}"
                ) from exc
        return entries

    def verify_chain(self) -> bool:
        """Zincirin bütünlüğünü bağımsız olarak doğrular ( prev+h bağları)."""
        prev = _GENESIS
        for entry in self.read_entries():
            if entry.get("prev") != prev:
                return False
            body = {k: v for k, v in entry.items() if k != "h"}
            expected = hashlib.sha256(
                (prev + _canonical(body)).encode("utf-8")
            ).hexdigest()
            if entry.get("h") != expected:
                return False
            prev = entry["h"]
        return True

    def revoked_cert_ids(self) -> Set[str]:
        """İptal edilmiş cert_id kümesini döndürür ( zincir-bütünlüğü bilinmiyorsa
        çağıran tarafından doğrulanmalıdır)."""
        return {str(e.get("cert_id")) for e in self.read_entries()}

    # -- yazma -------------------------------------------------------------

    def revoke(
        self,
        cert_id: str,
        revoked_by_seed: bytes,
        revoked_by_did: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Yeni bir iptal-girişi ekler ( append-only; asla yeniden-yazım-YOK).

        Giriş, iptal edenin DID'i ile imzalanır — kim-iptal-ettiği kanıtlanır.
        """
        if len(cert_id) != 64:
            raise ValueError("cert_id 64-hex olmalı")
        if not is_did_key(revoked_by_did):
            raise ValueError(f"revoked_by geçerli bir did:key değil: {revoked_by_did!r}")

        lines = self._read_lines()
        if lines:
            try:
                prev = json.loads(lines[-1]).get("h", _GENESIS)
            except ValueError as exc:
                raise RuntimeError(
                    "iptal-defteri-bozuk-kuyruk — fail-closed ( AT-183-deseni)"
                ) from exc
        else:
            prev = _GENESIS

        now = _now_iso()
        body: Dict[str, Any] = {
            "timestamp": now,
            "cert_id": cert_id,
            "revoked_by": revoked_by_did,
            "reason": reason,
            "prev": prev,
        }
        # İmza, kanonik gövde üzerinden — kim-iptal-etti kanıtlanır
        body["signature"] = _b64(sign(revoked_by_seed, _canonical(body).encode("utf-8")))
        body["h"] = hashlib.sha256(
            (prev + _canonical(body)).encode("utf-8")
        ).hexdigest()

        # 0600-atomik-yazım ( AT-179-deseni: kanıt-gizliliği)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(body, ensure_ascii=False) + "\n")
        return body


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def verify_revocation_entry(entry: Dict[str, Any]) -> bool:
    """Bir iptal-girişinin imzasını bağımsız doğrular ( did:key-self-resolving)."""
    try:
        import base64

        sig_b64 = entry.get("signature")
        if not isinstance(sig_b64, str):
            return False
        revoked_by = entry.get("revoked_by")
        if not isinstance(revoked_by, str) or not is_did_key(revoked_by):
            return False
        body = {k: v for k, v in entry.items() if k not in ("signature", "h")}
        from veridrome.certificate.didkey import pubkey_from_did
        return didkey_verify(
            pubkey_from_did(revoked_by),
            _canonical(body).encode("utf-8"),
            base64.b64decode(sig_b64),
        )
    except Exception:
        return False


def check_revoked(
    cert_id: str,
    ledger: Optional[RevocationLedger],
) -> Dict[str, Any]:
    """Bir cert_id'nin iptal durumunu döndürür.

    Dönüş: {"revoked": bool, "reason": str, "entry": dict|None,
            "chain_valid": bool}
    """
    if ledger is None:
        return {"revoked": False, "reason": "", "entry": None, "chain_valid": True}
    chain_valid = ledger.verify_chain()
    for entry in ledger.read_entries():
        if entry.get("cert_id") == cert_id:
            return {
                "revoked": True,
                "reason": str(entry.get("reason", "")),
                "entry": entry,
                "chain_valid": chain_valid,
                "signature_valid": verify_revocation_entry(entry),
            }
    return {"revoked": False, "reason": "", "entry": None, "chain_valid": chain_valid}


__all__ = [
    "RevocationLedger",
    "verify_revocation_entry",
    "check_revoked",
]
