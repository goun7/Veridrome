<img src="docs/veridrome-logo.svg" alt="Veridrome" width="240" height="64"/>

# Veridrome — AI Ajan Test-Sertifikasyon Platformu

Bir AI ajan "testlerim geçti" dediğinde **kim doğruladı, ne zaman, hangi
sürüm?** Veridrome o sözü **bağımsız-doğrulanabilir bir kanıta** çevirir:
bir CI koşumunu `did:key`-imzalı, sıfır-ağ, stdlib-only sertifikaya dönüştürür.

> **Dürüst tek-cümle:** Veridrome testlerin *doğru* olduğunu kanıtlamaz —
> testlerin **hangi koşulda, hangi sürümde, ne zaman** geçtiğini
> kriptografik olarak bağlar. Testleriniz boşsa sertifikanız da boş bir
> bağlam taşır. Bu, "kanıtsız iddia"dan "bağlı kanıt"a bir adımdır;
> biçimsel doğrulamanın yerini almaz ( bkz. [SWE-Proof, 2026](docs/arastirma/README.md#2-test-sertifikası--biçimsel-doğrulama-2026)).

---

## 30 saniyede

```bash
cd veridrome/73-Veridrome
pip install -e .                     # cryptography + pydantic ( zincir-opsiyonel)
python3 -m pytest tests/ -q          # 103-passed

# 1) İmzalama anahtarı ( did:key — tohum ASLA yazdırılmaz, 0600-saklanır)
veridrome keygen

# 2) Test koşumundan sertifika üret ( pytest'i kendisi çalıştırır)
veridrome certify --commit $(git rev-parse HEAD) \
                  --repo https://github.com/org/repo \
                  --out cert.json

# 3) BAĞIMSIZ doğrula — hiçbir ağ, defter, hesap veya bizim-sunucumuz YOK
veridrome verify cert.json
```

`cert.json` içindeki her bayt **herkes tarafından yeniden hesaplanabilir**
— aşağıda [kanıtı](#bağımsız-yeniden-hesaplama-kanıtı) var.

---

## Ne üretir?

`veridrome certify` bir **W3C-VC uyumlu** sertifika üretir:

| Alan | İçerik | Bağ |
|---|---|---|
| `credentialSubject.summary` | `total/passed/failed/skipped` | Merkle-köküne `commitment` ile |
| `credentialSubject.merkle_root` | Geçen-testlerin sıralı-hash kökü | `merkle_leaves`'ten **bağımsız** yeniden-hesaplanır |
| `credentialSubject.merkle_leaves` | Her testin sha256(name+outcome+duration) | Doğrulayıcıya gömülü |
| `credentialSubject.repo.commit` | Testlerin koştuğu commit | Fail-closed: **commit-yok → sertifika-yok** |
| `credentialSubject.test_files` | `{yol: sha256}` | `hash_source: file` / `name-derived` |
| `proof.proofValue` | Ed25519 ( RFC-8032) imzası | `did:key`'den kurtarılan anahtarla |
| `content_hash` | `sha256(kanonik-gövde)` | Tek bayt değişiklik kırar |
| `cert_id` | `sha256(content_hash ‖ imza)` | Tek rakam değişiklik kırar |

### Fail-closed davranışları ( kasıtlı)

- ❌ **commit-hash yok** → sertifika üretilmez ( "hangi-sürüm" cevapsız)
- ❌ **test-sonucu yok** → sertifika üretilmez ( kanıtsız iddia-yok)
- ❌ **failing-test var** → sertifika üretilmez ( "geçti" iddiasıyla çelişir)
- ❌ **bozuk iptal-defteri** → `RuntimeError` ( sessiz-zincir-kopması-yok)

---

## Bağımsız yeniden-hesaplama kanıtı

`verify` bizim kodumuzun dışında da çalışır. Sadece stdlib:

```python
import json, hashlib, base64
from veridrome.certificate.didkey import pubkey_from_did, verify as did_verify
from veridrome.certificate.core import _canonical_bytes, _merkle_root

cert = json.load(open("cert.json"))
body = {k: v for k, v in cert.items() if k not in ("proof", "content_hash", "cert_id")}

# 1) content_hash — bizim-sunucumuz-YOK, yerel sha256
hashlib.sha256(_canonical_bytes(body)).hexdigest() == cert["content_hash"]   # True

# 2) merkle_root — sertifikadaki yapraklardan-bağımsız
_merkle_root(cert["credentialSubject"]["merkle_leaves"])                     # == merkle_root

# 3) imza — did:key'den kurtarılan anahtarla ( self-resolving, çözücü-YOK)
sig = base64.b64decode(cert["proof"]["proofValue"])
did_verify(pubkey_from_did(cert["issuer"]), _canonical_bytes(body), sig)     # True
```

**Sıfır-ağ. Sıfır-defter. Sıfır-hesap. Sıfır-ücret.** did:key
*self-resolving*'dir: doğrulama anahtarı tanımlayıcının kendisinden
kurtarılır ( `did:key:z6Mk…` = `base58btc(0xed01 ‖ Ed25519-pubkey)`).

---

## Kardeş entegrasyon ( TAMGA-MESH)

| Kardeş | Bağ | Nasıl |
|---|---|---|
| **Kredent** | Sertifika `did:key` ile imzalanır | **BİREBİR** aynı base58btc + `0xed01` multicodec + `did:key:z6Mk…` formatı; çapraz-imza-doğrulaması testlerle kanıtlanmıştır ( `test_certificate_didkey.py::test_kredent_*`) |
| **Veridict** | Aynı content-hash-binding felsefesi | "Verify-from-file-alone" deseni: yapraklar + kök + özet gövdeye gömülü |
| **Sester** | Ödeme-kanıtı ↔ test-kanıtı zinciri | MCP `provenance` aracı: `sha256(receipt) + content_hash` ile ayrılmaz bağ |

### MCP sunucusu ( MCP 2025-06-18)

```bash
veridrome mcp     # stdio-transportu; hiçbir MCP-SDK'sı yok ( json+sys.stdin)
```

Araçlar: `certify`, `verify`, `revoke`, `provenance` ( ödeme-makbuzu ile).
`initialize` → `tools/list` → `tools/call` ( JSON-RPC, content-blokları).

```jsonc
// tools/call { "name": "provenance", "arguments": {
//   "certificate": <cert.json>,
//   "payment_receipt": { "scheme": "x402", "receipt_id": "rcpt-771", "amount": "0.05" }
// }}
// → link: { "payment_hash": "68a12b…", "cert_content_hash": "<content_hash>",
//          "binding": "sha256(receipt) + content_hash — …" }
```

### API & CLI

```bash
veridrome serve --port 8000          # FastAPI: /v1/evaluations/submit, SSE-stream, /v1/certificates
veridrome run --agent-type honest    # 20-görevlü canlı-değerlendirme koşumu ( anti-gaming + TEE)
veridrome list-tasks
veridrome revoke cert.json --reason "key-compromise"   # append-only hash-zincirli defter
```

---

## Akademik gerekçe ( 2025–2026)

Üç odak-konu için 7 makale — **her link fetch ile HTTP-200 olarak doğrulanmış**,
tüm sayılar abstract'lardan birebir alınmıştır. Tam doküman:
[docs/arastirma/README.md](docs/arastirma/README.md)

- **Ajan değerlendirme:** "Unearned passes" — ajanlar istenen yeteneği
  göstermeden geçebiliyor; ihlal oranı %24→%73'a çıkıyor
  ([arXiv:2609.34262](https://arxiv.org/abs/2609.34262))
- **Benchmark güvenilirliği:** Tek bir pipeline seçimi puanı **80 puandan
  fazla** değiştirebiliyor; 10 modelden 9'u standart harness altında en az 3
  sıra kaybediyor ([arXiv:2609.08765](https://arxiv.org/abs/2609.08765))
- **Kirlenme/ezberleme:** Benchmark veri-setleri ön-eğitim-corpus'larına
  düşmüş durumda; test-geçen yamaların **dörtte biri** karşıt-örnek kabul
  ediyor ([arXiv:2605.19999](https://arxiv.org/abs/2605.19999),
  [arXiv:2609.21190](https://arxiv.org/abs/2609.21190))

---

## Güvenlik-modeli

| Özellik | Uygulama |
|---|---|
| did:key imzası | Ed25519 ( `cryptography` varsa constant-time; yoksa saf-Python RFC-8032) |
| Self-resolving doğrulama | Anahtar `issuer`'dan kurtarılır; çözücü/ağ YOK |
| Content-hash bağlama | `sha256(kanonik-gövde)`; issuer-değişimi dahi kırar |
| Merkle kanıtı | Yapraklar + kök gömülü; `summary.commitment` köke bağlı ( AT-187) |
| Backdating-red | `validFrom` ±60s skew toleransı ile denetlenir |
| Süre-dolumu | `validUntil` geçtiyse RED |
| İptal | Append-only `prev`+`h` zinciri; imzalı giriş; **yeniden-yazım DEĞİL** |
| Anahtar-gizliliği | Tohum `0600`-atomik yazılır; **asla** log/yazdır/ağ'a-çıkmaz |
| Bozuk-defter | Fail-closed `RuntimeError` ( sessiz-genesis-YOK, AT-183-deseni) |

RFC-8032 §7.1 **resmi test-vektörleri** ile çapraz-doğrulanmıştır
( `test_certificate_didkey.py::test_rfc8032_*`).

---

## Test

```bash
python3 -m pytest tests/ -q     # 103-passed
```

Son koşum: **103 passed** ( sertifika-çekirdek 30, did:key 29, sertifika-
ürütm-hattı 5, API/CLI/runner/diğer-modüller 39). Hızlı-geri-bildirim için
`-x` ve `--ff` desteklenir.

---

## Sınırlar ( dürüst)

- **Bu biçimsel doğrulama DEĞİLDİR.** Testlerin **eksik** olduğunu biliyoruz
  ( [SWE-Proof](https://arxiv.org/abs/2609.21190): test-geçen yamaların
  dörtte biri karşıt-örnek kabul ediyor). Veridrome bağlamı bağlar,
  doğruluğu **kanıtlamaz**.
- **Kirlenmeyi tespit etmez.** Bir test ezberlenmiş olabilir; sertifika
  bunu sadece *sürümden sorumlu tutar* ( commit + dosya-hash'i).
- `did:key` **static-key**'dir; anahtar-rotasyonu/iptal-için-defter
  gerektirir ( biz `revocations.jsonl` append-only-defteri kullanırız).
- İptal-defteri **lokal-dosya**dır; dağıtık-gossip YOK. Dağıtık-tutarlılık
  mesh'in §6-foreign_chain-proof katmanına bırakılır.
- CT-log **RFC-6962-benzeri**dir, tam-RFC-6962 değildir.
- **PRIVATE_KEY/mainnet YASAK** — bu kod para-transferi yapmaz, fon
  yönetmez; sadece kanıt üretir.

---

## Hızlı-erişim

- Araştırma: [docs/arastirma/README.md](docs/arastirma/README.md)
- Logo: [docs/veridrome-logo.svg](docs/veridrome-logo.svg)
- Sertifika-çekirdeği: [src/veridrome/certificate/core.py](src/veridrome/certificate/core.py)
- did:key: [src/veridrome/certificate/didkey.py](src/veridrome/certificate/didkey.py)
- MCP: [src/veridrome/mcp_server.py](src/veridrome/mcp_server.py)
- CLI: [src/veridrome/cli/main.py](src/veridrome/cli/main.py)

## Lisans

MIT.
