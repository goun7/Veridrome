"""
Veridrome MCP sunucusu — AI ajanları için test-geçişi sertifikasyon araçları.

MCP 2025-06 spesifikasyonuna uygun, stdlib-only ( ``json`` + ``sys.stdin``)
JSON-RPC taşıması. Hiçbir MCP-SDK'sına bağlı değil — bu, bir AI ajanının
test-sonuçlarını sertifika olarak yayınlayabilmesi için gereken TEK şeydir.

Sunulan araçlar:
  - ``certify``    : test sonuçlarından did:key-imzalı sertifika üret
  - ``verify``     : bir sertifikayı bağımsız olarak doğrula ( offline)
  - ``revoke``     : bir sertifikayı append-only deftere iptal-girişi ekle
  - ``provenance`` : bir sertifikanın köken-zincirini çıkar ( Sester-entegrasyonu)

Çalıştırma:
  python -m veridrome.mcp_server            # stdio-transportu
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from veridrome.certificate.core import (
    CertificateBuilder,
    verify_certificate,
    hash_files,
)
from veridrome.certificate.didkey import generate_keypair, keypair_from_seed, is_did_key
from veridrome.certificate.revocation import RevocationLedger, check_revoked

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "veridrome"
SERVER_VERSION = "0.2.0"

_DEFAULT_LEDGER = os.environ.get("VERIDROME_REVOCATION_LEDGER", "")
_DEFAULT_HOME = os.environ.get(
    "VERIDROME_HOME", os.path.join(os.path.expanduser("~"), ".veridrome")
)


# ---------------------------------------------------------------------------
# Anahtar-yönetimi — tohum ( seed) çevresel-değişkenden veya dosyadan
# ---------------------------------------------------------------------------

def _load_seed() -> bytes:
    """İmzalama tohumunu yükler; yoksa üretir ve kaydeder.

    Öncelik sırası:
      1. ``$VERIDROME_SEED_HEX`` ( hex-kodlanmış 32-bayt)
      2. ``$VERIDROME_HOME/seed.hex`` dosyası ( 0600-izin ile)
      3. üretilen-yeni-tohum → dosyaya yazılır

    PRIVATE_KEY asla loglanmaz, yazdırılmaz veya ağ'a çıkarılmaz.
    """
    hex_env = os.environ.get("VERIDROME_SEED_HEX", "").strip()
    if hex_env:
        try:
            seed = bytes.fromhex(hex_env)
            if len(seed) == 32:
                return seed
        except ValueError:
            pass

    home = _DEFAULT_HOME
    seed_path = os.path.join(home, "seed.hex")
    if os.path.exists(seed_path):
        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                seed = bytes.fromhex(f.read().strip())
            if len(seed) == 32:
                return seed
        except (OSError, ValueError):
            pass

    # Yeni-tohum üret → 0600-ile-yaz ( AT-179-deseni)
    seed = generate_keypair()[0]
    try:
        os.makedirs(home, exist_ok=True)
        fd = os.open(seed_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(seed.hex())
    except OSError:
        pass  # yazılamaz → bellek-te-tut; yine de çalışır
    return seed


def _ledger() -> Optional[RevocationLedger]:
    path = _DEFAULT_LEDGER or os.path.join(_DEFAULT_HOME, "revocations.jsonl")
    return RevocationLedger(path)


# ---------------------------------------------------------------------------
# Araç-girdi-şemaları
# ---------------------------------------------------------------------------

_CERTIFY_SCHEMA = {
    "type": "object",
    "required": ["test_results", "commit_sha"],
    "properties": {
        "test_results": {
            "type": "array",
            "description": (
                "Test-sonuçları listesi. Her öğe {name, outcome, duration_ms}. "
                "outcome ∈ passed|failed|skipped|error."
            ),
            "items": {
                "type": "object",
                "required": ["name", "outcome"],
                "properties": {
                    "name": {"type": "string"},
                    "outcome": {"type": "string"},
                    "duration_ms": {"type": "number"},
                },
            },
        },
        "commit_sha": {
            "type": "string",
            "description": "Doğrulanan kod-un tam-commit-hash'i ( hangi-sürüm cevabı).",
        },
        "repo_url": {"type": "string", "description": "Repo URL'i ( opsiyonel)."},
        "agent_did": {
            "type": "string",
            "description": "Ajan did:key'i ( opsiyonel; yoksa imzalayan-DID).",
        },
        "job_id": {"type": "string", "description": "CI job-kimliği ( opsiyonel)."},
        "test_files": {
            "type": "object",
            "description": "{dosya-yolu: sha256} haritası ( opsiyonel; güçlü-kanıt).",
        },
        "valid_days": {"type": "integer", "description": "Geçerlilik süresi ( gün)."},
    },
}

_VERIFY_SCHEMA = {
    "type": "object",
    "required": ["certificate"],
    "properties": {
        "certificate": {
            "type": "object",
            "description": "Doğrulanacak sertifika JSON'u.",
        },
        "check_revocation": {
            "type": "boolean",
            "description": "İptal-defteri de denetlensin mi ( varsayılan: true).",
        },
    },
}

_REVOKE_SCHEMA = {
    "type": "object",
    "required": ["cert_id", "reason"],
    "properties": {
        "cert_id": {"type": "string", "description": "İptal edilecek sertifika-kimliği."},
        "reason": {"type": "string", "description": "İptal-nedeni ( kanıt-iz)."},
    },
}

_PROVENANCE_SCHEMA = {
    "type": "object",
    "required": ["certificate"],
    "properties": {
        "certificate": {"type": "object", "description": "Kökeni çıkarılacak sertifika."},
        "payment_receipt": {
            "type": "object",
            "description": (
                "Sester ödeme-makbuzu ( opsiyonel). Verilirse, ödeme-kanıtı "
                "ile test-kanıtı köken-zincirinde bağlanır."
            ),
        },
    },
}

_TOOLS = [
    {
        "name": "certify",
        "description": (
            "Test-sonuçlarından did:key-imzalı, bağımsız-doğrulanabilir bir "
            "test-geçişi sertifikası üretir. Girdi: test sonuçları + commit-hash. "
            "Çıktı: sertifika JSON'u ( content-hash + Ed25519 imza + Merkle-kökü)."
        ),
        "inputSchema": _CERTIFY_SCHEMA,
    },
    {
        "name": "verify",
        "description": (
            "Bir test-geçişi sertifikasını BAĞIMSIZ olarak doğrular: imza, "
            "content-hash, Merkle-kökü, süre-geçerliliği ve iptal-durumu. "
            "Hiçbir ağ veya defter gerektirmez ( did:key self-resolving)."
        ),
        "inputSchema": _VERIFY_SCHEMA,
    },
    {
        "name": "revoke",
        "description": (
            "Bir sertifikayı append-only hash-zincirli iptal-defterine ekler. "
            "İptal bir yeniden-yazım değil, imzalı yeni bir giriştir."
        ),
        "inputSchema": _REVOKE_SCHEMA,
    },
    {
        "name": "provenance",
        "description": (
            "Bir sertifikanın köken-zincirini çıkarır: ne-zaman, hangi-commit, "
            "kim-imzaladı, hangi-testler. Sester ödeme-makbuzu verilirse "
            "ödeme-kanıtı ile test-kanıtı bağlanır ( mesh-sinerjisi)."
        ),
        "inputSchema": _PROVENANCE_SCHEMA,
    },
]


# ---------------------------------------------------------------------------
# Araç-uygulamaları
# ---------------------------------------------------------------------------

def _tool_certify(args: Dict[str, Any]) -> Dict[str, Any]:
    test_results = args.get("test_results")
    commit_sha = args.get("commit_sha")
    if not isinstance(test_results, list) or not test_results:
        return _error("test_results boş olmayan bir liste olmalı")
    if not isinstance(commit_sha, str) or not commit_sha.strip():
        return _error("commit_sha zorunlu — 'hangi-sürüm' cevapsız sertifika yok")

    seed = _load_seed()
    _, did, _ = keypair_from_seed(seed)
    builder = CertificateBuilder(seed, did)

    try:
        cert = builder.build(
            test_results=test_results,
            repo_url=args.get("repo_url"),
            commit_sha=commit_sha.strip(),
            test_files=args.get("test_files") if isinstance(args.get("test_files"), dict) else None,
            agent_did=args.get("agent_did"),
            job_id=args.get("job_id"),
            valid_days=int(args.get("valid_days", 365)) or 365,
        )
    except ValueError as exc:
        return _error(f"sertifika-üretilemedi ( fail-closed): {exc}")

    return {
        "certificate": cert,
        "cert_id": cert["cert_id"],
        "issuer_did": cert["issuer"],
        "summary": cert["credentialSubject"]["summary"],
        "merkle_root": cert["credentialSubject"]["merkle_root"],
        "note": (
            "Sertifika üretildi. Bağımsız doğrulama için 'verify' aracını "
            "kullanın — hiçbir ek-bilgi gerektirmez ( did:key self-resolving)."
        ),
    }


def _tool_verify(args: Dict[str, Any]) -> Dict[str, Any]:
    cert = args.get("certificate")
    if not isinstance(cert, dict):
        return _error("certificate bir JSON nesnesi olmalı")

    result = verify_certificate(cert)
    out: Dict[str, Any] = result.to_dict()
    out["cert_id"] = cert.get("cert_id")

    if args.get("check_revocation", True):
        rev = check_revoked(str(cert.get("cert_id", "")), _ledger())
        out["revocation"] = rev
        if rev.get("revoked"):
            out["valid"] = False
            out["errors"].append(
                f"sertifika iptal-edilmiş: {rev.get('reason') or 'neden-belirtilmemiş'}"
            )
    return out


def _tool_revoke(args: Dict[str, Any]) -> Dict[str, Any]:
    cert_id = args.get("cert_id")
    reason = args.get("reason")
    if not isinstance(cert_id, str) or len(cert_id) != 64:
        return _error("cert_id 64-hex olmalı")
    if not isinstance(reason, str) or not reason.strip():
        return _error("reason zorunlu — kanıt-izinde neden belirsiz olamaz")

    seed = _load_seed()
    _, did, _ = keypair_from_seed(seed)
    try:
        entry = _ledger().revoke(
            cert_id=cert_id,
            revoked_by_seed=seed,
            revoked_by_did=did,
            reason=reason.strip(),
        )
    except (ValueError, RuntimeError) as exc:
        return _error(f"iptal-edilemedi ( fail-closed): {exc}")

    return {
        "revoked": True,
        "cert_id": cert_id,
        "revoked_by": did,
        "timestamp": entry["timestamp"],
        "ledger_entry_hash": entry["h"],
    }


def _tool_provenance(args: Dict[str, Any]) -> Dict[str, Any]:
    cert = args.get("certificate")
    if not isinstance(cert, dict):
        return _error("certificate bir JSON nesnesi olmalı")

    subj = cert.get("credentialSubject", {})
    prov: Dict[str, Any] = {
        "cert_id": cert.get("cert_id"),
        "content_hash": cert.get("content_hash"),
        "signed_by": cert.get("issuer"),
        "signed_at": cert.get("proof", {}).get("created"),
        "valid_from": cert.get("validFrom"),
        "valid_until": cert.get("validUntil"),
        "repo": subj.get("repo"),
        "test_files": subj.get("test_files"),
        "merkle_root": subj.get("merkle_root"),
        "merkle_leaf_count": subj.get("merkle_leaf_count"),
        "hash_source": subj.get("hash_source"),
        "summary": subj.get("summary"),
        "proof_type": cert.get("proof", {}).get("type"),
        "verification_method": cert.get("proof", {}).get("verificationMethod"),
    }

    # Sester-sinerjisi: ödeme-makbuzu ile test-kanıtı köken-bağı
    payment = args.get("payment_receipt")
    if isinstance(payment, dict):
        prov["linked_payment"] = {
            "scheme": payment.get("scheme", "x402"),
            "receipt_id": payment.get("receipt_id") or payment.get("id"),
            "amount": payment.get("amount"),
            "currency": payment.get("currency"),
            "payer_did": payment.get("payer_did"),
            "signature": payment.get("signature"),
        }
        # BAĞLANTI-KANITI: ödeme-makbuzunun-hash'i → sertifika-hash'ine
        import hashlib
        pay_canon = json.dumps(payment, sort_keys=True, separators=(",", ":")).encode("utf-8")
        prov["link"] = {
            "payment_hash": hashlib.sha256(pay_canon).hexdigest(),
            "cert_content_hash": cert.get("content_hash"),
            "binding": (
                "sha256(receipt) + content_hash — ödeme-kanıtı ile test-kanıtı "
                "ayrılmaz şekilde bağlanır ( Sester × Veridrome)"
            ),
        }

    # İptal-durumu da kökenin bir parçasıdır
    rev = check_revoked(str(cert.get("cert_id", "")), _ledger())
    prov["revocation_status"] = rev.get("revoked", False)
    return prov


def _error(msg: str) -> Dict[str, Any]:
    return {"error": msg}


# ---------------------------------------------------------------------------
# JSON-RPC taşıması ( MCP 2025-06 stdio)
# ---------------------------------------------------------------------------

_DISPATCH = {
    "certify": _tool_certify,
    "verify": _tool_verify,
    "revoke": _tool_revoke,
    "provenance": _tool_provenance,
}


def _send(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _handle(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "capabilities": {
                    "tools": {"listChanged": False},
                },
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        handler = _DISPATCH.get(name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"bilinmeyen araç: {name}"},
            }
        try:
            result = handler(args)
        except Exception as exc:  # pragma: no cover — savunma
            result = {"error": f"araç-çalıştırma-hatası: {exc}"}
        # MCP 2025-06: sonuç content-bloklarında taşınır
        if isinstance(result, dict) and "error" in result and len(result) == 1:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                    "isError": True,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, default=str)}],
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if req_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"desteklenmeyen metod: {method}"},
    }


def serve_stdio() -> None:
    """MCP stdio-transportu üzerinden hizmet verir."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(request)
        if response is not None:
            _send(response)


if __name__ == "__main__":  # pragma: no cover
    serve_stdio()
