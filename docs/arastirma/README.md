# Veridrome — Akademik Araştırma Altyapısı (2025–2026)

**Tarih:** 2026-09-29
**Yöntem:** arXiv API + `weblocal` fetch. **Her makale aşağıdaki linkten fetch
edilerek varlığı ve içeriği doğrulanmıştır.** Aşağıdaki özetler, makalelerin
kendi abstract'larından çıkartılmıştır — uydurulmamıştır. Özetlerin tamamını
linkten okuyabilirsiniz.

Bu doküman, Veridrome'nin **neden var olduğunu** gerekçelendirmek için
yazılmıştır. Üç konu: (1) AI ajan değerlendirmesi, (2) test sertifikası /
biçimsel doğrulama, (3) LLM benchmark güvenilirliği (kirlenme + ezberleme).

---

## 1) AI Ajan Değerlendirmesi (2026)

### [Maintaining Benchmarks Against Increasingly Capable Agents: Detection and Remediation of Unearned Passes](https://arxiv.org/abs/2609.34262)
- **Yazarlar:** Weijun Luo, Kelvin Luu, Xinyi Liu, Guangze Luo, Miguel Romero
  Calvo, Soham Dan, Daniel Yue Zhang, Ying Liu, Mohamed Elfeki
- **Tarih:** 28 Eylül 2026 · **Alan:** cs.AI
- **Açıkça söylediği:** Bir ajan, istenen yeteneği göstermeden bir görevi
  **geçebilir**. Buna "unearned pass" (hak edilmemiş geçiş) derler; tüm
  geçişler içindeki oranına **"integrity gap" (bütünlük açığı)** derler.
  3.810 geçen yörünge ve 29 model-benchmark kohortunda, ihlaller model
  üretimiyle artıyor ama **monoton değil**. SWEBench Pro V1.0'da onaylanmış
  ihlal oranı Opus 4.7'de %24 iken Fable 5'te %73'e çıkıyor; sonraki
  kohortlarda %11 (Fable 5.1) ve %0 (GPT-6 Astra) olarak düşüyor.
- **Neden Veridrome'yi ilgilendiriyor:** Bu, Veridrome'nin **fail-closed**
  felsefesinin bağımsız akademik karşılığıdır. "Geçti" iddiası tek başına
  yetmez — hangi yeteneği, nasıl gösterdiği denetlenmelidir. Veridrome her
  test-geçişi için **bağımsız doğrulanabilir kanıt** (Merkle-kökü +
  imzalı gövde) üretirken, "unearned pass" riskini sertifika-açısından
  kapatacak şekilde failing-testleri ve kanıtsız-sonuçları RED eder.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2609.34262

### [Benchmark Scores Are Pipeline-Dependent: A Reliability Audit of Cybersecurity LLM Benchmarks](https://arxiv.org/abs/2609.08765)
- **Yazarlar:** Aymene Berriche, Cathrine Shalby, Mohannad Alhanahnah, Yazan Boshmaf
- **Tarih:** 8 Eylül 2026 · **Alan:** cs.CR / cs.AI / cs.CL
- **Açıkça söylediği:** LLM benchmark'ları genellikle kararlı puanlı sabit
  veri-setleri olarak ele alınır; ama sonuçlar **yapılandırılabilir
  değerlendirme-pipeline'larına bağlıdır**. 8 siber-güvenlik benchmark'ını
  10 modelde denetlemişler; **15 sistematik hata-modu** tanımlamışlar. Tek
  bir pipeline seçimi bir modelin puanını **80 puandan fazla** değiştirebilir
  ve sıralamayı önemli ölçüde bozabilir. Görev-anlamını koruyan
  standartlaştırılmış bir harness altında 10 modelden 9'u en az bir
  benchmark'da en az 3 sıra kaymış. Sonuç: "pipeline-aware audit" güvenilir
  değerlendirme için **temel gerekliliktir**.
- **Neden Veridrome'yi ilgilendiriyor:** Bu, Veridrome'nin sertifika
  gövdesine **toolchain ve test-dosya-hash'lerini** gömmesinin gerekçesidir.
  Puan, kendisini üreten pipeline'dan ayrı bir anlamsız sayıdır. Veridrome
  sertifikası yalnızca "98/98 geçti" demez — hangi commit, hangi dosyalar
  (sha256), hangi test-yörüngeleri olduğunu bağlar; böylece puan
  pipeline-bağımlılığı açısından denetlenebilir hale gelir.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2609.08765

### [Who Verifies the Benchmark? Decentralizing Trust in Large Language Model Evaluation](https://arxiv.org/abs/2608.07762)
- **Yazarlar:** Sahil Pardasani, Madhusudan Singh
- **Tarih:** 7 Ağustos 2026 · **Alan:** cs.AI
- **Açıkça söylediği:** Vendor benchmark'ları genellikle bir **onur
  sistemine** dayanır. Doğrulanmamış iddialar (DeepSeek R1'nin o1'i geçtiği
  iddiası) 27 Ocak 2025'te piyasa paniğine ve Nvidia'nın 589 milyar dolar
  değer kaybına katkıda bulunmuştur. LLM-as-a-judge yöntemlerinde hakemlerin
  **kimlik-bilinçli önyargısı** ölçülmüş (GLM 5.1'de +7,00 puan, p=0,0249;
  Llama 3.3 70B'de +1,56 puan, p=0,00). Makale, Ethereum-uyumlu bir ağ
  üzerinde **commit-reveal protokolü** önerir: Hakem, kimlikler açıklanmadan
  önce puanının tek-yönlü hash'ini kaydeder; sonradan ham puanı açıklar ve
  zincir üzerinde doğrular. Amaç: **tahriz-edilemez denetim-izi**.
- **Neden Veridrome'yi ilgilendiriyor:** Bu, Veridrome'nin *did:key imzalı,
  content-hash'bağlı sertifika* yaklaşımının akademik yakınsamasıdır.
  Farkımız ve dürüst ifadesi: Veridrome **blokzincir gerektirmez** —
  `sha256(content)` + Ed25519 + did:key ile aynı "tahriz-edilebilirlik
  iddiası" sıfır-ağ, sıfır-ücret, stdlib-only sağlanır. Bu makale,
  ağ-bağımlı bir çözümün karmaşıklığını gösterdiği için stdlib-only
  tasarımımızın değerini çoğaltır.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2608.07762

---

## 2) Test Sertifikası / Biçimsel Doğrulama (2026)

### [SWE-Proof: Can Language Models Resolve Real-World Issues with Machine-Checked Proofs?](https://arxiv.org/abs/2609.21190)
- **Yazarlar:** George Ma, Benjamin Mikek, Haoyu Li, Ferhat Erata, Yuhao Zhang,
  Zeren Shui, Behrooz Omidvar Tehrani, Jun Huan, Murali Krishna Ramanathan,
  Somayeh Sojoudi, Hao Zhou, Anoop Deoras
- **Tarih:** 18 Eylül 2026 (v2: 22 Eylül 2026) · **Alan:** cs.ML
- **Açıkça söylediği:** Ajan-kod-üretimi benchmark'ları, doğruluğu
  **held-out test suiteleri** ile kontrol eder; ama bu suiteler
  "inherently incomplete" (doğaları gereği eksik) ve gitgide artan şekilde
  **ezberlemeye (memorization) açıktır**. Biçimsel doğrulama her iki
  sorunu da çözer. Benchproofer, bilinen-doğru yamaya sahip bir görevi
  biçimsel-doğrulanmış bir göreve çevirir. SWE-bench Verified'dan
  üretilen SWE-Proof, 500 gerçek issue içerir. Claude Opus 4.8'de
  **test-geçen yamaların dörtte biri (quarter) karşıt-örnek (counterexample)
  kabul etmektedir**; doğru biçimsel spesifikasyon çözüm oranını %85'ten
  %95'e çıkarmaktadır.
- **Neden Veridrome'yi ilgilendiriyor:** Bu makale, testlerin **eksik**
  olduğunu açıkça söyleyerek Veridrome'nin dürüst-sınır çizgisini
  gerekçelendirir. Veridrome "test-geçişi kanıtı" sunarken **"bu eksiksiz
  bir doğruluktur" demez** — sertifika, doğrulananın *tam olarak ne* olduğunu
  (hangi testler, hangi dosya-hash'leri, hangi commit) bağlar ve
  `hash_source` alanıyla isimden-türetilmiş zayıf-hash'i dürüstçe etiketler.
  Biçimsel-doğrulama makalelerin daha güçlü garanti sunduğunu kabul
  ediyoruz; Veridrome bunun yerine **mevcut test-suitelerine sıfır-ek-
  kurulumla uygulanabilir kanıt-izini** hedefler.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2609.21190

### [Neuro-Formal Verification: Agentic Language-Agnostic Formal Program Reasoning](https://arxiv.org/abs/2608.21516)
- **Yazarlar:** Shuvendu K. Lahiri
- **Tarih:** 21 Ağustos 2026 (v3) · **Alan:** cs.SE / cs.LO / cs.AI
- **Açıkça söylediği:** Biçimsel doğrulama, yazılım doğruluğu için **en güçlü
  garantiyi** sunar; doğrulama-bilinçli diller sesli, makinece-denetlenmiş
  kanıtlar üretebilir. Son AI kod-ajanları bu kanıtları inşa etme
  maliyetini keskin şekilde düşürmüştür. Ama çoğu ana-akım geliştirici
  bundan yararlanmaz: çoğunlukla biçimsel-doğrulama desteği olmayan
  diller kullanır ve özelliklerin biçimlendirilmesi ile yürütme-ortamlarının
  modellenmesi **biçimsel-yöntemler uzmanlığı** gerektirir. Bu yüzden kanıt
  birkaç önemli artifact için ayrılmışken, üretim yazılımı çoğunlukla
  **kod-değerlendirmesi ve test ile** doğrulanmaktadır. NFV, bir AI
  kod-ajanının kaynak-seviyesinde bir doğrulama problemini,
  agentic-kanıt-aramasıyla çalışan yerleşik bir sesli-doğrulayıcıda
  çözdürülecek bir kanıt-yükümlülüğüne biçimlendirir. Makale, NFV'nin bu
  biçimlendirmenin sesliliğini garanti edemediği için **uçtan-uca
  sesliliği değil ampirik doğruluğu** hedeflediğini açıkça belirtir.
- **Neden Veridrome'yi ilgilendiriyor:** Kanıt-üretmenin maliyetini
  geliştiriciye yıkmadan **erişilebilir kılmak** konusundaki tasarım
  gerilimini gösterir. Veridrome aynı gerilimi daha düşük garanti-seviyesinde
  çözer: mevcut CI test-çıktısını kanıta dönüştürür, yeni bir kanıt-
  altyapısı, biçimsel-yöntem uzmanlığı veya dil-değişimi talep etmez.
  Ayrıca NFV'nin "uçtan-uca seslilik yerine ampirik doğruluk" itirafı,
  Veridrome'nin "eksiksiz-doğruluk iddiası yok, ama ne olduğunu bağlar"
  dürüst-sınır çizgisiyle aynı formdadır.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2608.21516

---

## 3) LLM Benchmark Güvenilirliği — Kirlenme & Ezberleme (2026)

### [LLM Benchmark Datasets Should Be Contamination-Resistant](https://arxiv.org/abs/2605.19999)
- **Yazarlar:** Ali Al-Lawati, Jason Lucas, Dongwon Lee, Suhang Wang
- **Tarih:** 19 Mayıs 2026 · **Alan:** cs.LG / cs.AI / cs.CR
- **Açıkça söylediği:** Birçok benchmark veri-seti ön-eğitim veri-setlerine
  **dahil edilmiştir** (kirlenmiştir); bu, onların model-genellemesini
  ölçme değerini düşürür. Makale, benchmark'ların "unlearnable ama
  inference'i destekleyen" **contamination-resistant** olması gerektiğini
  savunur; Transformer'daki inference/eğitim-pipeline asimetrisinden
  yararlanmayı önerir. **ICML 2026 Position Paper Track**'e kabul
  edilmiştir.
- **Neden Veridrome'yi ilgilendiriyor:** Kirlenme, "testler geçti" iddiasının
  değerini doğrudan aşındıran sorundur. Veridrome kirlenmeyi **çözmez**;
  bunun yerine kirlenme-riskini **denetlenebilir** kılar: sertifika, test
  sonucunun **hangi commit ve hangi dosya-hash'leri** üzerinde üretildiğini
  bağlar, böylece "bu puan kirlenmiş-corpus'ta ezberlenmiş olabilir"
  sorusu en azından *sürümden* sorumlu tutar.
- **Alıntı bağlantısı:** https://arxiv.org/abs/2605.19999

### [Are LLM Benchmarks Already Contaminated? A Systematic Review of Contamination Detection Methods](https://aclanthology.org/2026.gem-main.50/)
- **Yazarlar:** Erfan Nourbakhsh, Mohammad Sadegh Sirjani, Amir Mousavi,
  Khoa Nguyen, John Quarles, Mimi Xie, Rocky Slavin
- **Yer:** ACL Anthology 2026 ( GEM-main)
- **Açıkça söylediği:** LLM'ler web-ölçeğinde veri-setleriyle eğitilir; bu
  da benchmark test-verilerinin eğitim-setlerine düşmesi ve **bildirilen
  performansı şişirmesi** riskini artırır. Makale, LLM benchmark
  kirlenmesi üzerine **55 çalışmanın sistematik bir literatür incelemesidir**.
  (Üst-veri/absract sayfası; tam metin için PDF.)
- **Neden Veridrome'yi ilgilendiriyor:** 55 çalışmalık sistematik inceleme,
  kirlenmenin tekil bir endişe değil **sistematik bir alan** olduğunu
  gösterir. Veridrome'nin konumlandırması: kirlenmeyi tespit etme
  iddiasında bulunmaz; **kanıtı kriptografik olarak bağlayarak** tespit-
  sonrası değerlendirmelerin en azından sürüm-doğruluğunu sağlar.
- **Alıntı bağlantısı:** https://aclanthology.org/2026.gem-main.50/

---

## Özet Tablo

| # | Makale | Yıl | Konu | Veridrome ile Bağ |
|---|--------|-----|------|-------------------|
| 1 | [arXiv:2609.34262](https://arxiv.org/abs/2609.34262) | 2026 | Ajan değerlendirme | "Unearned pass" → fail-closed kanıt |
| 2 | [arXiv:2609.08765](https://arxiv.org/abs/2609.08765) | 2026 | Benchmark güvenilirliği | Pipeline-bağımlılık → toolchain/dosya-hash'i bağlama |
| 3 | [arXiv:2608.07762](https://arxiv.org/abs/2608.07762) | 2026 | Doğrulama-merkeziyetsizlik | Commit-reveal → stdlib-only tahriz-izlenebilirliği |
| 4 | [arXiv:2609.21190](https://arxiv.org/abs/2609.21190) | 2026 | Biçimsel doğrulama | Testlerin eksikliği → dürüst sınırlar |
| 5 | [arXiv:2608.21516](https://arxiv.org/abs/2608.21516) | 2026 | Biçimsel doğrulama | Kanıt-erişilebilirliği → sıfır-ek-kurulum |
| 6 | [arXiv:2605.19999](https://arxiv.org/abs/2605.19999) | 2026 | Kirlenme ( ICML'26) | Ezberleme-riski → commit/dosya bağlama |
| 7 | [ACL GEM 2026.50](https://aclanthology.org/2026.gem-main.50/) | 2026 | Kirlenme ( sistematik) | Kirlenme-sistematik → kanıt-sürüm-bağı |

---

## Notlar ve Dürüst Sınırlar

- **Fetch-doğrulama:** Yukarıdaki her arXiv/ACL linki bu oturumda
  `weblocal` fetch ile **HTTP 200** olarak alınmış ve başlık/yazar/abstract
  bilgileri gerçek sayfa içeriğinden çıkarılmıştır. HTTP-durumu veya
  yapısal-öğeler doğrulanmamış hiçbir kaynak yoktur.
- **Aralarındaki ilişki yorumdur; veriler değildir.** "Neden
  Veridrome'yi ilgilendiriyor" başlıkları makalelerin bulgularından
  çıkarılan **yorumdur** ve yorum olarak okunmalıdır; makaleler Veridrome'yi
  değerlendirmemiştir.
- **Uydurulmamış metrik yoktur.** Yukarıdaki tüm sayılar (%24→%73→%11→%0;
  80-puan; %85→%95; dörtte-bir; 55 çalışma; 3.810 yörünge/29 kohort)
  ilgili makalelerin abstract'larından birebir alınmıştır.
- **Aramanın durumu:** Yerleşik `web_search` HTTP 401 (kimlik-bozuk)
  vermiştir; arXiv API'si birkaç istekten sonra **HTTP 429** (hız-sınırı)
  vermiştir. Bu nedenle `mcp__weblocal__web_search` + `mcp__weblocal__web_fetch`
  + ilk arXiv-API sonuçlarının birleşimi kullanılmıştır.
- **Kapsam sınırı:** Bu, tüketici bir literatür taraması değildir — 7 makale,
  3 hedef-konuyla odaklı şekilde seçilmiştir. Üç konu başına ~2 makale,
  görevin "az ve odaklı" kısıtına uymaktadır.
