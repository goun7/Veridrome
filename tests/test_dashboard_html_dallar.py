"""veridrome.server.dashboard_html dal-kesen testleri (Kural-1: YENI dosya — mevcut dosyalara DOKUNULMADI).

Modül anatomisi: dashboard_html.py tek bir modül-sabiti üretir — DASHBOARD_HTML
(787 satırlık statik HTML+CSS+JS arena sayfası). Fonksiyon YOK; bu yüzden
dal-kesim "yürütme-dalları" yerine YAPISAL-INVARIANT dallaridir: HTML'i
html.parser (standart-kütüphane, saf-bellek) ile çözümleyip regex ile
katman-katım (HTML/CSS/JS) bütünlüğünü keseriz.

Dal haritasi (D1..D19):
  D1  DASHBOARD_HTML temel kimlik: str, dolu, DOCTYPE ile başlar, </html>\n ile
      biter, CRLF yok (LF-sadece).
  D2  UTF-8 kodlama + Türkçe karaktervarlığı (round-trip).
  D3  HTMLParser etiket dengesi: void-dışı tüm etiketler (html/head/body/div/
      canvas/button/...) açılış==kapanış; void etiketlerin kapanışı yok.
  D4  Tek <script> bloğu; HTML yorumları açık-kalmamış.
  D5  <html><head></head><body></body></html> sıralama.
  D6  Erişilebilirlik/meta: lang="en", charset UTF-8, viewport, <title>.
  D7  Brand rozetleri (W1a/TEE/Base Sepolia) + footer versiyon sabiti.
  D8  JS TASKS kataloğu: 20 görev, id'ler T01..T20 benzersiz+sıralı.
  D9  Kategori sayıları ↔ filter-chip iddialari (E-Commerce (4) vb.) tutarlı.
  D10 Her görevin alanları dolu; havuz ∈ {PUBLIC_CANARY, DYNAMIC_HIDDEN}.
  D11 JS getElementById referansları ↔ HTML id attribute bütünlüğü.
  D12 HTML id'leri benzersiz; gizli paneller (cert-details/modal) display:none.
  D13 Modal innerText kullanımı (innerHTML yok — HTML-enjeksiyon kapalı).
  D14 onclick ile başvurulan her JS fonksiyonu tanımlı (function X(...)).
  D15 renderTasks şablon yuvaları (${t.id}...), bootstrap renderTasks('ALL').
  D16 CSS :root token'ları ↔ var(--x) kullanım bütünlüğü (tanımsız token yok).
  D17 API uç-nokta yuvaları: /v1/evaluations/submit, SSE EventSource,
      /v1/certificates/${certId}, method POST.
  D18 HTML entity kaçışları geçerli; ham-& sayısı sabitlenmiş (toleranslı).
  D19 Modül determinizmi: reload ile aynı değer; tek public sabit DASHBOARD_HTML.

Kural-4: saf-bellek — network/subprocess/socket/gerçek-HTTP YOK; yalnızca
standart-kütüphane çözümleme (html.parser/re) + importlib.reload.
"""
from __future__ import annotations

import html as _html
import importlib
import re
from collections import Counter
from html.parser import HTMLParser

import pytest

from veridrome.server import dashboard_html as _mod
from veridrome.server.dashboard_html import DASHBOARD_HTML

# ---------------------------------------------------------------------------
# Modül-seviyesi çözümleme (bir kez, saf-bellek) — testler bunu yeniden kullanır
# ---------------------------------------------------------------------------

# void (kapanışsız) HTML etiketleri — denge-dışı tutulur
_VOIDLER = {
    "meta", "link", "input", "br", "img", "hr",
    "area", "base", "col", "embed", "source", "track", "wbr",
}


class _EtiketSayac(HTMLParser):
    """Açılış/kapanış etiketlerini sayan minimal HTMLParser (CDATA-farkında)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.acilis: list[str] = []
        self.kapanis: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        self.acilis.append(tag)

    def handle_endtag(self, tag: str) -> None:
        self.kapanis.append(tag)

    def handle_startendtag(self, tag: str, attrs: object) -> None:
        pass  # self-closing — dengeye katkı yok


_SAYAC = _EtiketSayac()
_SAYAC.feed(DASHBOARD_HTML)
_ACILIS = Counter(_SAYAC.acilis)
_KAPANIS = Counter(_SAYAC.kapanis)

# JS TASKS kataloğu — her satır tek görev nesnesi
_TASKS_BLOGU = re.search(r"const TASKS = \[(.*?)\];", DASHBOARD_HTML, re.S)
_GOREVLER: list[tuple[str, str, str, str, str, str]] = []
if _TASKS_BLOGU is not None:
    for _satir in _TASKS_BLOGU.group(1).splitlines():
        _m = re.match(
            r'\s*\{id: "(T\d+)", cat: "(\w+)", pool: "(\w+)", '
            r'title: "([^"]*)", desc: "([^"]*)", rules: "([^"]*)"\},?\s*$',
            _satir,
        )
        if _m:
            _GOREVLER.append(_m.groups())  # type: ignore[arg-type]

# filter-chip etiketleri: (kategori, etiket, iddia-sayi)
_CIPLAR: list[tuple[str, str, int]] = [
    (k, e, int(s))
    for k, e, s in re.findall(
        r'onclick="filterTasks\(\'([^\']+)\'\)">\s*([^<]*?)\s*\((\d+)\)</div>',
        DASHBOARD_HTML,
    )
]
_CIP_KATEGORILERI = {c[0] for c in _CIPLAR}

# JS getElementById referansları ↔ HTML id attribute'leri
_JS_IDLER = sorted(set(re.findall(r"getElementById\('([^']+)'\)", DASHBOARD_HTML)))
_HTML_IDLER = re.findall(r'id="([^"]+)"', DASHBOARD_HTML)
_HTML_ID_KUMESI = set(_HTML_IDLER)

# CSS :root token'ları ↔ var(--x) kullanımları
_KOK_BLOK = re.search(r":root\s*\{([^}]*)\}", DASHBOARD_HTML)
_TANIMLI_TOKENLER = set(re.findall(r"--([\w-]+):", _KOK_BLOK.group(1))) if _KOK_BLOK else set()
_KULLANILAN_TOKENLER = set(re.findall(r"var\(--([\w-]+)\)", DASHBOARD_HTML))

# HTML entity'leri
_ENTITILER = sorted(set(re.findall(r"(&[a-zA-Z][a-zA-Z0-9]*;|&#\d+;|&#x[0-9a-fA-F]+;)", DASHBOARD_HTML)))

# onclick ile başvurulan fonksiyonlar ↔ tanımlı fonksiyonlar
_ONCLICK_FONKS = sorted(set(re.findall(r'onclick="(\w+)\(', DASHBOARD_HTML)))
_TANIMLI_FONKS = sorted(set(re.findall(r"function\s+(\w+)\s*\(", DASHBOARD_HTML)))


# ---------------------------------------------------------------------------
# D1 — temel kimlik
# ---------------------------------------------------------------------------
class TestModulKimligi:
    """D1: DASHBOARD_HTML'nin temel kimlik dallari."""

    def test_str_ve_dolu(self) -> None:
        assert isinstance(DASHBOARD_HTML, str)
        assert len(DASHBOARD_HTML) > 0

    def test_doctype_ile_baslar(self) -> None:
        assert DASHBOARD_HTML.startswith("<!DOCTYPE html>")

    def test_html_ile_biter_tek_satir_sonu(self) -> None:
        assert DASHBOARD_HTML.endswith("</html>\n")
        assert not DASHBOARD_HTML.endswith("\n\n")

    def test_crlf_yok_lf_sadece(self) -> None:
        assert "\r" not in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D2 — kodlama
# ---------------------------------------------------------------------------
class TestKodlama:
    """D2: UTF-8 kodlama dürüstlüğü ve Türkçe karakter varlığı."""

    def test_utf8_round_trip(self) -> None:
        donus = DASHBOARD_HTML.encode("utf-8").decode("utf-8")
        assert donus == DASHBOARD_HTML

    @pytest.mark.parametrize(
        "turkce",
        ["Doğrulama", "Değerlendirme", "Görev", "Başlat", "Kataloğu"],
        ids=["dogrulama", "degerlendirme", "gorev", "baslat", "katalog"],
    )
    def test_turkce_karakter_mevcut(self, turkce: str) -> None:
        assert turkce in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D3/D4/D5 — yapısal denge
# ---------------------------------------------------------------------------
class TestYapisalDenge:
    """D3/D4/D5: HTMLParser tabanlı etiket dengesi ve blok bütünlüğü."""

    def test_etiket_dengesi_genel(self) -> None:
        """Void-dışı tüm etiketlerde açılış sayısı == kapanış sayısı."""
        etiketler = set(_ACILIS) | set(_KAPANIS)
        sorunlu = {
            t: (_ACILIS[t], _KAPANIS[t])
            for t in etiketler
            if t not in _VOIDLER and _ACILIS[t] != _KAPANIS[t]
        }
        assert sorunlu == {}, f"dengesiz etiketler: {sorunlu}"

    @pytest.mark.parametrize(
        "etiket",
        ["html", "head", "body", "header", "main", "footer", "style",
         "script", "div", "canvas", "button", "h3", "p", "label", "span"],
        ids=["html", "head", "body", "header", "main", "footer", "style",
             "script", "div", "canvas", "button", "h3", "p", "label", "span"],
    )
    def test_etiket_dengesi_tek_tek(self, etiket: str) -> None:
        assert _ACILIS[etiket] == _KAPANIS[etiket], (
            f"<{etiket}>: {_ACILIS[etiket]} açılış ≠ {_KAPANIS[etiket]} kapanış"
        )

    @pytest.mark.parametrize("void", ["meta", "link", "input", "br", "img"],
                             ids=["meta", "link", "input", "br", "img"])
    def test_void_etiket_kapanis_yok(self, void: str) -> None:
        assert f"</{void}>" not in DASHBOARD_HTML

    def test_tek_script_bloku(self) -> None:
        assert DASHBOARD_HTML.count("<script") == 1
        assert DASHBOARD_HTML.count("</script>") == 1

    def test_yorum_acik_kalmamis(self) -> None:
        assert DASHBOARD_HTML.count("<!--") == DASHBOARD_HTML.count("-->")
        assert DASHBOARD_HTML.count("<!--") > 0  # HTML yorumları gerçekten mevcut

    def test_head_body_siralamasi(self) -> None:
        sira = [
            DASHBOARD_HTML.index("<html"),
            DASHBOARD_HTML.index("<head>"),
            DASHBOARD_HTML.index("</head>"),
            DASHBOARD_HTML.index("<body>"),
            DASHBOARD_HTML.index("</body>"),
            DASHBOARD_HTML.index("</html>"),
        ]
        assert sira == sorted(sira)


# ---------------------------------------------------------------------------
# D6 — meta/erişilebilirlik
# ---------------------------------------------------------------------------
class TestMetaVeErisilebilirlik:
    """D6: lang, charset, viewport, title meta dalları."""

    def test_html_lang_attr(self) -> None:
        assert '<html lang="en">' in DASHBOARD_HTML

    def test_charset_utf8(self) -> None:
        assert '<meta charset="UTF-8">' in DASHBOARD_HTML

    def test_viewport_var(self) -> None:
        assert 'name="viewport"' in DASHBOARD_HTML
        assert "width=device-width" in DASHBOARD_HTML

    def test_title_veridrome(self) -> None:
        assert "<title>" in DASHBOARD_HTML
        assert "</title>" in DASHBOARD_HTML
        baslik = re.search(r"<title>(.*?)</title>", DASHBOARD_HTML, re.S)
        assert baslik is not None and "Veridrome" in baslik.group(1)


# ---------------------------------------------------------------------------
# D7 — brand rozetleri
# ---------------------------------------------------------------------------
class TestBrandVeBadgeler:
    """D7: Status-rozetleri ve footer versiyon sabitleri."""

    @pytest.mark.parametrize(
        "roz",
        ["W1a Machine Proofs: ACTIVE", "SEV-SNP TEE: READY", "Base Sepolia: CONNECTED"],
        ids=["w1a-proofs", "tee-snp", "base-sepolia"],
    )
    def test_status_rozetleri(self, roz: str) -> None:
        assert roz in DASHBOARD_HTML

    @pytest.mark.parametrize(
        "teknoloji",
        ["AMD SEV-SNP", "AWS Nitro", "W3C VC v2.0", "Base Sepolia"],
        ids=["amd-snp", "aws-nitro", "w3c-vc", "sepolia"],
    )
    def test_footer_teknoloji_etiketleri(self, teknoloji: str) -> None:
        assert teknoloji in DASHBOARD_HTML

    def test_footer_versiyon_sabiti(self) -> None:
        assert "VERIDROME v1.3.0" in DASHBOARD_HTML

    def test_brand_logo_harfi(self) -> None:
        assert '<div class="brand-logo">V</div>' in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D8/D9/D10 — görev kataloğu
# ---------------------------------------------------------------------------
class TestGorevKatalogu:
    """D8/D9/D10: JS TASKS dizisinin yapısal bütünlüğü (regex çözümleme)."""

    def test_tasks_bloku_cozumlendi(self) -> None:
        assert _TASKS_BLOGU is not None, "const TASKS = [...] bloğu bulunamadı"

    def test_yirmi_gorev(self) -> None:
        assert len(_GOREVLER) == 20

    def test_id_benzersiz(self) -> None:
        idler = [g[0] for g in _GOREVLER]
        assert len(set(idler)) == len(idler) == 20

    def test_id_siralı_T01_T20(self) -> None:
        assert [g[0] for g in _GOREVLER] == [f"T{i:02d}" for i in range(1, 21)]

    @pytest.mark.parametrize(
        "gorev_id,kategori,havuz,baslik,aciklama,kurallar",
        _GOREVLER,
        ids=[g[0] for g in _GOREVLER],
    )
    def test_gorev_alanlari_dolu(
        self,
        gorev_id: str,
        kategori: str,
        havuz: str,
        baslik: str,
        aciklama: str,
        kurallar: str,
    ) -> None:
        """D10: her görevin tüm alanları dolu + kimlik/kategori/havuz biçimi."""
        assert re.fullmatch(r"T\d{2}", gorev_id)
        assert kategori, "kategori boş"
        assert kategori in {"e_commerce", "saas_admin", "finops", "modern_ui",
                            "data_extraction"}
        assert havuz in {"PUBLIC_CANARY", "DYNAMIC_HIDDEN"}
        assert baslik, "başlık boş"
        assert aciklama, "açıklama boş"
        assert kurallar and len(kurallar) >= 5, "kural metinsiz"

    @pytest.mark.parametrize(
        "kategori,etiket,iddia",
        [c for c in _CIPLAR if c[0] != "ALL"],
        ids=[c[0] for c in _CIPLAR if c[0] != "ALL"],
    )
    def test_kategori_sayisi_cip_iddiasina_uygun(
        self, kategori: str, etiket: str, iddia: int
    ) -> None:
        """D9: chip'in iddia ettiği sayı, TASKS'teki gerçek kategori sayısına eşit."""
        gercek = sum(1 for g in _GOREVLER if g[1] == kategori)
        assert gercek == iddia, f"{kategori}: chip {iddia} iddia ≠ gerçek {gercek}"

    def test_tumler_chip_toplami(self) -> None:
        """D9: 'Tümü (N)' chip'i tüm görevlerin toplamını iddia etmeli."""
        tum = [c for c in _CIPLAR if c[0] == "ALL"]
        assert len(tum) == 1
        assert tum[0][2] == len(_GOREVLER) == 20
        assert tum[0][1] == "Tümü"

    @pytest.mark.parametrize(
        "kategori,etiket,iddia",
        [c for c in _CIPLAR if c[0] != "ALL"],
        ids=[c[0] for c in _CIPLAR if c[0] != "ALL"],
    )
    def test_chip_etiket_dolu(self, kategori: str, etiket: str, iddia: int) -> None:
        assert etiket, f"{kategori} chip etiketi boş"
        assert iddia > 0

    def test_her_kategorinin_chip_i_var(self) -> None:
        kategoriler = {g[1] for g in _GOREVLER}
        assert kategoriler <= _CIP_KATEGORILERI

    def test_havuz_dagilim_sabiti(self) -> None:
        """Mevcut sabit dağılım: 12 PUBLIC_CANARY / 8 DYNAMIC_HIDDEN."""
        havuzlar = Counter(g[2] for g in _GOREVLER)
        assert havuzlar == {"PUBLIC_CANARY": 12, "DYNAMIC_HIDDEN": 8}


# ---------------------------------------------------------------------------
# D11/D12/D13 — DOM id bütünlüğü
# ---------------------------------------------------------------------------
class TestDomIdButunlugu:
    """D11/D12/D13: JS ↔ HTML id bütünlüğü ve gizli panel dalları."""

    @pytest.mark.parametrize("js_id", _JS_IDLER, ids=_JS_IDLER)
    def test_js_referans_id_html_de_var(self, js_id: str) -> None:
        """D11: JS'te getElementById ile başvurulan her id HTML'de tanımlı."""
        assert js_id in _HTML_ID_KUMESI, (
            f"JS 'getElementById('{js_id}') HTML'de id= olarak yok — kırık referans"
        )

    def test_html_idler_benzersiz(self) -> None:
        assert len(_HTML_IDLER) == len(_HTML_ID_KUMESI), "tekrarlı id attribute"

    def test_cert_details_gizli(self) -> None:
        assert 'id="cert-details"' in DASHBOARD_HTML
        assert 'display:none' in DASHBOARD_HTML

    def test_modal_overlay_gizli_css(self) -> None:
        assert ".modal-overlay {" in DASHBOARD_HTML
        assert "display: none;" in DASHBOARD_HTML

    @pytest.mark.parametrize(
        "modal_id",
        ["modal-title", "modal-desc", "modal-rules"],
        ids=["modal-title", "modal-desc", "modal-rules"],
    )
    def test_modal_ic_degistirici_innertext(self, modal_id: str) -> None:
        """D13: modal alanları innerText ile doldurulur (HTML-enjeksiyon kapalı)."""
        assert f"getElementById('{modal_id}').innerText" in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D14/D15 — JS fonksiyon slotları
# ---------------------------------------------------------------------------
class TestJsFonksiyonSlotlari:
    """D14/D15: onclick ↔ tanım bütünlüğü ve şablon yuvaları."""

    @pytest.mark.parametrize("fonk", _ONCLICK_FONKS, ids=_ONCLICK_FONKS)
    def test_onclick_fonksiyonu_tanimli(self, fonk: str) -> None:
        """D14: onclick ile başvurulan her fonksiyon <script> içinde tanımlı."""
        assert f"function {fonk}(" in DASHBOARD_HTML, (
            f"onclick='{fonk}' çağrılıyor ama 'function {fonk}(' tanımı yok"
        )

    @pytest.mark.parametrize("fonk", _TANIMLI_FONKS, ids=_TANIMLI_FONKS)
    def test_tanimli_fonksiyonlar_mevcut(self, fonk: str) -> None:
        assert f"function {fonk}(" in DASHBOARD_HTML

    def test_render_tasks_bootstrap_cagrisi(self) -> None:
        assert "renderTasks('ALL');" in DASHBOARD_HTML

    def test_filter_tasks_varyasyonlu_cagri(self) -> None:
        assert "filterTasks('ALL')" in DASHBOARD_HTML

    def test_render_tasks_sablon_yuvalari(self) -> None:
        """D15: görev-kartı şablonu dinamik alan yuvaları içerir."""
        for yuva in ("${t.id}", "${t.pool", "${t.title}", "${t.desc.substring(0, 48)}"):
            assert yuva in DASHBOARD_HTML, f"şablon yuvası yok: {yuva}"

    def test_show_modal_kural_slotu(self) -> None:
        assert "W1a Invariant Kuralları:" in DASHBOARD_HTML
        assert "Havuz Tipi: ${task.pool}" in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D16 — CSS token bütünlüğü
# ---------------------------------------------------------------------------
class TestCssTokenButunlugu:
    """D16: :root token tanımları ↔ var() kullanım bütünlüğü."""

    def test_kok_blok_var(self) -> None:
        assert _KOK_BLOK is not None, ":root { ... } bloğu yok"

    def test_var_kullanimlari_tanimli(self) -> None:
        """Kullanılan her var(--x) :root içinde tanımlı olmalı."""
        tanimsiz = _KULLANILAN_TOKENLER - _TANIMLI_TOKENLER
        assert tanimsiz == set(), f"tanımsız token kullanımı: {sorted(tanimsiz)}"

    @pytest.mark.parametrize(
        "token",
        ["bg-base", "bg-surface", "bg-card", "border-glow", "border-subtle",
         "text-main", "text-muted", "accent-cyan", "accent-indigo",
         "accent-emerald", "accent-rose", "accent-amber", "accent-violet",
         "font-sans", "font-mono"],
        ids=["bg-base", "bg-surface", "bg-card", "border-glow", "border-subtle",
             "text-main", "text-muted", "cyan", "indigo", "emerald",
             "rose", "amber", "violet", "font-sans", "font-mono"],
    )
    def test_ana_token_tanimli(self, token: str) -> None:
        assert token in _TANIMLI_TOKENLER

    def test_karanlik_tema_taban_rengi(self) -> None:
        assert "--bg-base: #07090e;" in DASHBOARD_HTML

    def test_var_donugu_kullaniliyor(self) -> None:
        assert "var(--accent-cyan)" in DASHBOARD_HTML
        assert "var(--font-mono)" in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D17 — API uç-nokta slotları
# ---------------------------------------------------------------------------
class TestApiSlotlari:
    """D17: arka-uc HTTP uç-nokta yuvaları (fetch/EventSource — sayfa içi)."""

    @pytest.mark.parametrize(
        "uc_nokta",
        ["/v1/evaluations/submit", "/v1/evaluations/", "/stream", "/v1/certificates/"],
        ids=["eval-submit", "eval-stream-root", "sse-stream", "cert-get"],
    )
    def test_api_uc_nokta_yuvasi(self, uc_nokta: str) -> None:
        assert uc_nokta in DASHBOARD_HTML

    def test_fetch_post_metodu(self) -> None:
        assert "method: 'POST'" in DASHBOARD_HTML

    def test_eventsource_sse_yuvasi(self) -> None:
        assert "new EventSource(" in DASHBOARD_HTML

    def test_fetch_cagrisi_mevcut(self) -> None:
        assert "fetch(" in DASHBOARD_HTML

    def test_json_govde_serileştirme(self) -> None:
        assert "JSON.stringify(payload)" in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D18 — kaçış/slot bütünlüğü (escape)
# ---------------------------------------------------------------------------
class TestKacisVeYuvaButunlugu:
    """D18: HTML entity kaçışları ve JS şablon yuvaları."""

    @pytest.mark.parametrize("entity", _ENTITILER, ids=[e.strip("&;") for e in _ENTITILER])
    def test_entity_geçerli(self, entity: str) -> None:
        """Her &x; entity'si html.unescape ile çözülebilmeli (geçerli entity)."""
        assert _html.unescape(entity) != entity, f"geçersiz entity: {entity}"

    def test_ham_ampersandlar_metinde(self) -> None:
        """Bilgi: 4 ham '& ' (tarayıcı-toleranslı), 4 '&bull;' entity, 2 href-sorgu '&'."""
        assert DASHBOARD_HTML.count("&") == 10
        assert len(re.findall(r"&\s", DASHBOARD_HTML)) == 4

    @pytest.mark.parametrize(
        "yuva",
        ["${data.job_id}", "${certId}", "${ev.certificate_id}", "${ev.step",
         "${ev.task_id", "${ev.status", "${subj.metrics", "${err.message}",
         "${icon}", "${msg}"],
        ids=["job-id", "cert-id", "cert-id-event", "ev-step", "ev-task",
             "ev-status", "subj-metrics", "err-msg", "toast-icon", "toast-msg"],
    )
    def test_js_interpolasyon_yuvasi(self, yuva: str) -> None:
        assert yuva in DASHBOARD_HTML

    def test_python_placeholder_kalintisi_yok(self) -> None:
        """Statik sabit: Python format/kalın-placeholder kalıntısı olmamalı."""
        assert "{{" not in DASHBOARD_HTML
        assert "%s" not in DASHBOARD_HTML
        assert "%(" not in DASHBOARD_HTML


# ---------------------------------------------------------------------------
# D19 — determinizm
# ---------------------------------------------------------------------------
class TestDeterminizm:
    """D19: modül-sabitinin determinizmi ve public yüzeyin sadeliği."""

    def test_reload_ile_ayni_deger(self) -> None:
        yeniden = importlib.reload(_mod)
        assert yeniden.DASHBOARD_HTML == DASHBOARD_HTML

    def test_tek_public_sabit(self) -> None:
        public = [n for n in vars(_mod) if not n.startswith("_")]
        assert sorted(public) == ["DASHBOARD_HTML"]
