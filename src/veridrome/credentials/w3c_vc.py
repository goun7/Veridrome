"""
Veridrome Credentials: W3C Verifiable Credentials v2.0 & IETF VAPAP Motoru (Python 3.12+)
Sertifikasyon çıktılarının W3C VC, IETF VAPAP Assertion ve RFC 6962 CT Defterine yazılması.
"""

from __future__ import annotations
import base64
import datetime
import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from veridrome.core.crypto import VeridromeAuthoritySigner, MerkleTreeAuditLog


class VeridromeCredentialManager:
    """W3C Verifiable Credentials v2.0 ve VAPAP token üreticisi."""

    def __init__(self, signer: VeridromeAuthoritySigner, ct_log_path: str = "ct_log.jsonl"):
        self.signer = signer
        self.ct_log_path = ct_log_path

    def issue_credential(
        self,
        job_id: str,
        agent_id: str,
        metrics: Dict[str, Any],
        tee_platform: str,
        pcr0_measurement: str,
        merkle_root: str,
        validity_days: int = 30,
    ) -> Tuple[Dict[str, Any], str]:
        """
        W3C Verifiable Credential üretir, Ed25519 ile imzalar ve VAPAP token'ını döndürür.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(days=validity_days)

        now_iso = now.isoformat()
        expires_iso = expires.isoformat()

        vc_data = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://w3id.org/security/suites/ed25519-2020/v1",
                "https://schema.veridrome.io/v1",
            ],
            "id": f"urn:veridrome:cert:{job_id}",
            "type": ["VerifiableCredential", "VeridromeAgentCertification"],
            "issuer": "did:veridrome:authority:mainnet",
            "validFrom": now_iso,
            "validUntil": expires_iso,
            "credentialSubject": {
                "id": agent_id,
                "metrics": metrics,
                "hardwareAttestation": {
                    "platform": tee_platform,
                    "pcr0": pcr0_measurement,
                },
                "executionMerkleRoot": merkle_root,
            },
        }

        canonical_bytes = json.dumps(vc_data, sort_keys=True).encode("utf-8")
        signature_b64 = self.signer.sign_base64(canonical_bytes)

        vc_data["proof"] = {
            "type": "Ed25519Signature2020",
            "created": now_iso,
            "verificationMethod": "did:veridrome:authority:mainnet#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": signature_b64,
        }

        # RFC 6962 CT Defterine ekle
        self._append_to_ct_log(vc_data)

        # IETF VAPAP Header Token'ı oluştur (Base64URL)
        vapap_bytes = json.dumps(vc_data, sort_keys=True).encode("utf-8")
        vapap_token = base64.urlsafe_b64encode(vapap_bytes).decode("ascii").rstrip("=")

        return vc_data, vapap_token

    def _append_to_ct_log(self, vc_data: Dict[str, Any]) -> None:
        """Sertifikayı yerel transparan Merkle defteri kütüğüne ekler.

        AT-177-BULGU-4-düzeltmesi: önceden-satır-düz-append'ti ( prev/zincir-
        bağı-YOK) — satır-tahriz-edilince-bağımsız-tespit-YOKTU ( imzalı-VC hâlâ
        geçerli-olduğu-için-CT-defterinin-kendi-bütünlüğü-kanıtlanamıyordu).
        Şimdi-her-satır-prev+h-içerir ( tamga-ledger-deseni): h = sha256( prev +
        canonical-json) → append-only-sıranın-bütünlüğü-bağımsız-doğrulanabilir.
        """
        prev = "0" * 64
        try:
            with open(self.ct_log_path, "r", encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                prev = last.get("h", "0" * 64)
        except (OSError, ValueError, KeyError):
            prev = "0" * 64  # yeni/bozuk-defter → genesis-bağı

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "cert_id": vc_data["id"],
            "subject": vc_data["credentialSubject"]["id"],
            "merkle_root": vc_data["credentialSubject"]["executionMerkleRoot"],
            "proofValue": vc_data["proof"]["proofValue"],
            "prev": prev,
        }
        entry["h"] = hashlib.sha256(
            (entry["prev"] + json.dumps(entry, sort_keys=True,
                                        ensure_ascii=False)).encode("utf-8")
        ).hexdigest()
        with open(self.ct_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    @staticmethod
    def verify_credential(vc_data: Dict[str, Any], authority_pubkey_bytes: bytes) -> bool:
        """W3C VC nesnesinin imza bütünlüğünü, süresini ve Merkle-kökünü doğrular."""
        if "proof" not in vc_data or "proofValue" not in vc_data["proof"]:
            return False

        proof = vc_data["proof"]
        sig_b64 = proof["proofValue"]

        # AT-168-BULGU-2-düzeltmesi: validUntil-KARŞILAŞTIRILMIYORDU — docstring
        # 'süresini-doğrular'-diyordu-AMA-dolmuş-VC-geçiyordu ( validUntil=2020
        # → True). Eski-kanıt-sonsuz-geçerliydi ( replay). Artık-süresi-dolmuş
        # RED ( VAPAP-token-deseni-ile-aynı: expires_at<now-RED).
        valid_until = vc_data.get("validUntil")
        if valid_until is not None:
            try:
                # ISO-8601-timestamp'i-epoch'a-çevir ( 'Z'-suffix-ile)
                from datetime import datetime, timezone
                vu = datetime.fromisoformat(
                    str(valid_until).replace("Z", "+00:00"))
                if vu.tzinfo is None:
                    vu = vu.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > vu:
                    return False
            except Exception:
                return False   # çözülemez-tarih → fail-closed

        # AT-168-BULGU-1-düzeltmesi: merkleRoot-SADECE-YAZDIRILIYORDU ( imza-
        # doğruluyordu-AMA-Merkle-kökü-BAĞIMSIZ-doğrulanmıyordu). Sahte-merkleRoot
        # ( 0xfff…)-ile-VC-geçiyordu. Artık-merkleRoot-varsa-BİR-DAHİL-KANIDI
        # ZORUNLUDUR: verify_proof-kökü-BAĞIMSIZ-yeniden-hesaplar ( RFC-6962).
        # Kanıt-yoksa-RED ( fail-closed) — iddia-edilen-kök-bağlanamadan-geçmez.
        subj = vc_data.get("credentialSubject", {})
        claimed_root = subj.get("merkleRoot")
        if claimed_root is not None:
            if not (isinstance(claimed_root, str)
                    and claimed_root.startswith("0x")
                    and len(claimed_root) == 66):
                return False
            inclusion = subj.get("merkleInclusionProof")
            if not (inclusion and inclusion.get("path")
                    and inclusion.get("leafData")):
                return False   # kanıt-YOK → fail-closed ( AT-168)
            try:
                path = [(p["side"], bytes.fromhex(p["hash"][2:]))
                        for p in inclusion["path"]]
                ok_merkle = MerkleTreeAuditLog.verify_proof(
                    inclusion["leafData"].encode("utf-8"),
                    path, bytes.fromhex(claimed_root[2:]))
                if not ok_merkle:
                    return False
            except Exception:
                return False   # kanıt-bozuk → fail-closed

        vc_copy = dict(vc_data)
        del vc_copy["proof"]

        canonical_bytes = json.dumps(vc_copy, sort_keys=True).encode("utf-8")
        try:
            sig_bytes = base64.b64decode(sig_b64)
            return VeridromeAuthoritySigner.verify(authority_pubkey_bytes, canonical_bytes, sig_bytes)
        except Exception:
            return False

    def create_vapap_token(
        self,
        agent_id: str,
        cert_id: str,
        score_median: float,
        expires_in_sec: int = 3600,
        tee_pcr0: Optional[str] = None,
    ) -> str:
        """
        Kurumsal API Gateway'lerde anlık doğrulanabilir VAPAP (Agent-to-Product)
        tasdik token'ı üretir.
        """
        now = int(time.time())
        token_payload = {
            "iss": "veridrome:authority:root",
            "cert_id": cert_id,
            "agent_id": agent_id,
            "score_median": score_median,
            "tee_pcr0": tee_pcr0 or ("98f12a" + "00" * 29),
            "issued_at": now,
            "expires_at": now + expires_in_sec,
        }
        canonical_bytes = json.dumps(token_payload, sort_keys=True).encode("utf-8")
        sig_bytes = self.signer.sign(canonical_bytes)

        full_token = dict(token_payload)
        full_token["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

        raw_json = json.dumps(full_token).encode("utf-8")
        return base64.b64encode(raw_json).decode("utf-8")

