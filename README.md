# Veridrome — W3C-VC + RFC-6962 Kanıt-Çekirdeği

Veridrome, TAMGA-MESH'in **kimlik-bilgisi** ve **şeffaflık-günlüğü**
protokolüdür: W3C Verifiable Credential üretimi + append-only CT-log.

## Rolü (mesh-içinde)

```
agent-çalışması → executionMerkleRoot → W3C-VC (Ed25519-imzalı)
                          ↓
              ct_log.jsonl ← prev+h-zinciri (RFC-6962-benzeri)
                          ↓
              §6-foreign_chain_proof → tamga D5-ledger (RFC-010 §6)
```

Veridrome **fon yönetmez** — **kanıt üretir**: bir işin gerçekten
çalıştığını, sırayla, bağımsız-doğrulanabilir şekilde kaydeder.

## Kurulum

```bash
cd veridrome/73-Veridrome
pip install -e .                        # pydantic + cryptography + nacl
python3 -m pytest tests/                # 39-passed
```

## Temel-API

```python
from veridrome.credentials.w3c_vc import VeridromeCredentialManager
from veridrome.core.crypto import VeridromeAuthoritySigner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

mgr = VeridromeCredentialManager(
    signer=VeridromeAuthoritySigner(Ed25519PrivateKey.generate()),
    ct_log_path="ct_log.jsonl",
)
vc = mgr.issue_credential(
    agent_id="agent-x", metrics={"k": 1},
    tee_platform="sev-snp", pcr0_measurement="98f12a…",
    merkle_root="0x…64hex…", validity_days=30)
```

## Güvenlik-modeli ( AT-165..183)

| Özellik | Uygulama |
|---|---|
| CT-log-zinciri | her-giriş `prev`+`h` (AT-177; tahriz-bağı- kırılır) |
| CT-log-gizlilik | `os.open(0o600)`-atomik (AT-179; 0644-YOK) |
| Bozuk-defter | `RuntimeError`-fail-closed (AT-183; sessiz-genesis-YOK) |
| Yeni-defter | genesis-dürüst-yolu ( boş-dosya ≠ bozuk-dosya) |
| Yazma-hatası | exception-yayılır ( kısmi-VC-YOK; fail-closed) |
| Merkle-agacı | yaprak-aggregate-root ile bağımsız-doğrulanır |

## Test

```bash
python3 -m pytest tests/ -q    # 39-passed
```

## Sınırlar ( dürüst)

- CT-log **RFC-6962-benzeri**, tam-specified-RFC-6962-değil ( bizim-özgün-
  zincir-modelimiz; AT-177-bağlamında-tasarlandı)
- `ct_log.jsonl` **lokal-dosya**; dağıtık-gossip-YOK ( dağıtık-tutarlılık
  kanıtı §6-üzerinden-tamga'ya-bırakılır)
