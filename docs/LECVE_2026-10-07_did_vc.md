# LEÇVE — Akademik zemin eki (2026-10-07): DID / doğrulanabilir kimlik bilgisi

> **README'ye eklenecek literatür ekidir.** Mevcut `README.md` içeriğine
> **dokunulmamıştır**; bu dosya `docs/` altında YENİ dosya olarak teslim
> edilmiştir (goal: doc bağlarını genişlet).
>
> **FP0:** aşağıdaki her alıntı `web_fetch` ile **HTTP-200 + tam başlık birebir
> eşleşmesi** ile doğrulanmıştır. Uydurma alıntı yoktur. Kanıt:
> [`orkestrasyon/docs/fp0_arxiv_manifest_2026-10-07.json`](../../00_TAMGA-MESH/orkestrasyon/docs/fp0_arxiv_manifest_2026-10-07.json).

---

## Akademik zemin — 2026-09-22..2026-10-07 penceresi (DID)

Veridrome, test-sertifikalarını W3C-VC biçiminde üretip Tamga ledger'ına
sabitleyerek "bir test sonucu, değişmez ve taşınamaz bir özne olmalı" der. Son
pencerenin VC literatürü bu iddiayı doğrular:

- **On the Usage of Verifiable Credentials in Privacy-Preserving Federated
  Analytics** ([arXiv:2609.33004](https://arxiv.org/abs/2609.33004),
  Drăgnoiu/Olimid, cs.CR, 26 Eyl 2026) — gizlilik-koruyan federatif analizde
  **doğrulanabilir kimlik bilgilerinin (VC)** nasıl kullanılacağını inceler:
  birden çok düğümün katkılarını, her katkıyı bir VC ile doğrulanabilir
  kılarak gizliliği bozmadan birleştirir. Veridrome'un W3C-VC → Tamga
  sabitleme modeli için doğrudan akademik karşılık: sertifika, hem
  **doğrulanabilir** (W3C-VC) hem **değişmez** (Tamga anchor) olmalı.
  **Fark:** makale VC'yi **federatif analiz** bağlamında, katkı
  doğrulama aracı olarak kullanır; Veridrome VC'yi bir **test-çıktısı
  sertifikası** olarak üretir ve onu bir kanıt-zincirine sabitler —
  böylece sertifika yalnızca doğrulanabilir değil, sonradan
  **değiştirilemez** de olur.

---

*Bu ek, `README.md`'nin akademik zemin bölümüne eklenmek üzere hazırlanmıştır.*
