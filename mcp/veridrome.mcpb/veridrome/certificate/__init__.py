"""
veridrome.certificate — test-geçişi sertifikasyon çekirdeği.

Bir CI koşumunu did:key-imzalı, bağımsız-doğrulanabilir bir sertifikaya
dönüştürür. Kardeşlerle entegrasyon:
  - Kredent  → did:key ile imzalama ( self-resolving, offline-verify)
  - Veridict → aynı content-hash-binding felsefesi
  - TamgaProtocol → sertifika, Tamga hash-zincirli ledger'a sabitlenir
    ( tamga_anchor.publish/verify; Tamga'nın kendi ledger-verify'ında yeşil)
  - Sester   → ödeme-kanıtı ile test-kanıtı zincirlenebilir ( provenance)
"""

from veridrome.certificate.core import (
    CertificateBuilder,
    VerifyResult,
    verify_certificate,
    normalize_results,
    summarize,
    hash_file,
    hash_files,
    CERT_TYPE,
    SIGNATURE_SUITE,
)
from veridrome.certificate.didkey import (
    generate_keypair,
    keypair_from_seed,
    pubkey_from_did,
    is_did_key,
)
from veridrome.certificate.revocation import (
    RevocationLedger,
    check_revoked,
)
from veridrome.certificate.tamga_anchor import (
    TAMGA_ANCHOR_VERSION,
    TAMGA_OP,
    anchor_digest,
    bound_fields,
    publish as tamga_publish,
    verify as tamga_verify,
)

__all__ = [
    "CertificateBuilder",
    "verify_certificate",
    "VerifyResult",
    "normalize_results",
    "summarize",
    "hash_file",
    "hash_files",
    "generate_keypair",
    "keypair_from_seed",
    "pubkey_from_did",
    "is_did_key",
    "RevocationLedger",
    "check_revoked",
    "tamga_publish",
    "tamga_verify",
    "bound_fields",
    "anchor_digest",
    "TAMGA_ANCHOR_VERSION",
    "TAMGA_OP",
    "CERT_TYPE",
    "SIGNATURE_SUITE",
]
