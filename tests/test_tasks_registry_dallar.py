"""
test_tasks_registry_dallar.py — Dal-kesen (branch-coverage) testler: src/veridrome/tasks/registry.py

Hedeflenen public yüzey (TaskRegistry sınıfı):
  * TaskRegistry.__init__/_initialize_tasks — 20 kurumsal görevin kurulması
  * TaskRegistry.get                        — task_id ile görev bulma
  * TaskRegistry.list_all                   — tüm görevleri sıralı listeleme
  * TaskRegistry.filter_by_pool             — havuz-tipine (PUBLIC_CANARY /
                                               DYNAMIC_HIDDEN) göre süzme
  * TaskRegistry.filter_by_category         — kategoriye göre süzme

DAL HARİTASI (D1..D40):
  kurulum (__init__/_initialize_tasks):
    D1  tam 20 görev yüklenir
    D2  task_id kümesi T01..T20 — ardışık, tekrarsız, ekleme sırasında
    D3  iki bağımsız registry birbirini etkilemez
    D4  her görev en-az bir değişmezliğe (invariant) sahip
    D5  TaskSpec varsayılanları: timeout 180sn, 25 adım, 0.50 USD kap
    D6  EnvironmentSpec: https hedef + varsayılanlar (auth False, mutation
        True, aria True)
    D7  değişmezlik rule_type değerleri geçerli kümede
    D8  her görevin title/objective boş değil
  get:
    D9  varolan görev (T01) → TaskSpec döner, title eşleşir
    D10 bilinmeyen kimlik (T99) → None
    D11 sınır kimlikler: "" / "T0" / "T21" → None
    D12 büyük/küçük ve boşluk hassasiyeti: "t01"/"T001"/" T01"/"T01 " → None
        (BULGU R2: get case-sensitive'dir, belgelenmemiştir)
    D13 kimlik: get(T01) list_all()[0] ile AYNI nesne
    D14 T01..T20'nin tamamı bulunur (parametreli)
  list_all:
    D15 20 eleman
    D16 dönen liste kopya: mutasyon kayıt-defterini etkilemez; iki çağrı
        farklı liste nesneleri (BULGU R3: kapsülleme)
    D17 sıralama T01..T20 (ekleme sırası)
    D18 her eleman TaskSpec örneği
  filter_by_pool:
    D19 PUBLIC_CANARY 12 / DYNAMIC_HIDDEN 8
    D20 havuzların toplamı 20 (eksiksiz)
    D21 saf-dize değişken kabul edilir (str-Enum eşitliği)
        (BULGU R1: tip-güvensiz string kabulü)
    D22 bilinmeyen değerler boş liste ("FOO", None, 123)
    D23 dönenlerin tamamı istenen havuzda
    D24 PUBLIC_CANARY kimlik kümesi tam-eşleşme
        {T01,T03,T05,T06,T08,T09,T10,T12,T14,T16,T17,T19}
    D25 her çağrı yeni liste (durum-sızlık)
  filter_by_category:
    D26 dağılım: e_commerce 4, saas_admin 5, finops 4, modern_ui 3,
        data_extraction 4
    D27 beş kategori toplamı 20 ve aralarında kesişme yok
    D28 saf-dize kabul (BULGU R1)
    D29 bilinmeyen kategori boş
    D30 dönenlerin tamamı istenen kategoride
    D31 her kategori×havuz hücresi dağılımı (toplam 20)
  içerik (kayıt veri-dalları):
    D32 rule_type dağılımı: db_assert 11, dom_selector_text 8,
        network_assert 6, dom_element_state 3 (toplam 28)
    D33 her network_assert status_code taşır (int)
    D34 her dom_* değişmezliği selector taşır
    D35 her expected_regex derlenebilir (re.compile)
    D36 expected_db_value tür çeşitliliği: str/bool/float/int
        (BULGU R4: T08 tarihi "2027-09-15" dize — tarih-tipi yok)
    D37 havuz oranı %60/%40 (12/20, 8/20)
    D38 dom_element_state değişmezlikleri must_exist=True
    D39 get(T01) filter_by_pool(PUBLIC_CANARY) içinde
    D40 tek-değişmezlikli 13 görevin listesi ve kural-tipleri
        (T04..T20 dağılımı; BULGU R5)

BULGULAR (testlerle belle):
  R1  filter_by_pool/filter_by_category PoolType/TaskCategory işaretçisi yerine
      SAF-DİZE kabul eder (str-Enum == karşılaştırması) — yanlış-tür geçişi
      sessizce sonuç üretir (D21/D28).
  R2  get() BÜYÜK/küçük harfe duyarlıdır: "t01" → None; bu davranış kodda
      belgelenmemiştir (D12).
  R3  Kapsülleme iyi: _tasks dışarıdan erişilemez, list_all/filter_* her
      çağrıda YENİ liste döner — kayıt-defteri değişmez (D16/D25).
  R4  T08 license.valid_until değeri "2027-09-15" DİZE olarak saklanır —
      modelde tarih türü yok, karşılaştırma-temelli doğrulamalar çatışır (D36).
  R5  20 görev / 28 değişmezlik: ortalama 1.4 — 13/20 görev TEK değişmezlik
      taşır (8×db_assert, 3×dom_selector_text, 1×network_assert, 1×dom_element_state);
      tek-noktalı görevler minimum kapsamdadır (D40).

KURAL: SADECE YENİ DOSYA; production/conftest/mevcut-testlere DOKUNULMAZ.
Tüm koşumlar SAF-BELLEK'tir — ağ/RPC/subprocess/socket YOK; hiçbir yan-etki
içermeyen saf-okuma testleridir (VERIDROME_HOME izolasyonu gerektirmez).
"""

from __future__ import annotations

import re

import pytest

from veridrome.tasks.models import (
    EnvironmentSpec,
    InvariantSpec,
    PoolType,
    TaskCategory,
    TaskSpec,
)
from veridrome.tasks.registry import TaskRegistry

# Sabit beklenen değerler (kayıt-defteri icat-işveren verisi — 20 görev)
_GOREV_SAYISI = 20
_PUBLIC_SAYI = 12
_GIZLI_SAYI = 8
_TOPLAM_INVARYAN = 28

_PUBLIC_IDLER = {"T01", "T03", "T05", "T06", "T08", "T09", "T10", "T12",
                 "T14", "T16", "T17", "T19"}
_GIZLI_IDLER = {"T02", "T04", "T07", "T11", "T13", "T15", "T18", "T20"}
_BEKLENEN_IDLER = [f"T{i:02d}" for i in range(1, 21)]

_KATEGORI_DAGILIM = {
    TaskCategory.E_COMMERCE: 4,
    TaskCategory.SAAS_ADMIN: 5,
    TaskCategory.FINOPS: 4,
    TaskCategory.MODERN_UI: 3,
    TaskCategory.DATA_EXTRACTION: 4,
}

_KURAL_TIPLERI = {"dom_selector_text", "dom_element_state", "network_assert", "db_assert"}


# ---------------------------------------------------------------------------
# kurulum — __init__/_initialize_tasks (D1..D8)
# ---------------------------------------------------------------------------


class TestKurulum:
    def test_yirmi_gorev_yuklenir(self):
        assert len(TaskRegistry().list_all()) == _GOREV_SAYISI

    def test_task_id_kumesi_ardisik_ve_tekrarsiz(self):
        gorevler = TaskRegistry().list_all()
        idler = [g.task_id for g in gorevler]
        assert idler == _BEKLENEN_IDLER          # ekleme sırası
        assert len(set(idler)) == _GOREV_SAYISI  # tekrar yok

    def test_iki_registry_birbirinden_bagimsizdir(self):
        a = TaskRegistry()
        b = TaskRegistry()
        assert a is not b
        assert a.get("T01") is not b.get("T01")
        # a'nın dönen listesini bozma → b'yi (veya a'yı) etkilemez
        a.list_all().clear()
        assert len(a.list_all()) == _GOREV_SAYISI
        assert len(b.list_all()) == _GOREV_SAYISI

    def test_her_gorev_en_az_bir_degismezlige_sahip(self):
        for gorev in TaskRegistry().list_all():
            assert gorev.invariants, f"{gorev.task_id} değişmezliği yok"

    @pytest.mark.parametrize("alan,beklenen", [
        ("timeout_seconds", 180),
        ("max_browser_steps", 25),
        ("cost_cap_usd", 0.50),
    ])
    def test_taskspec_varsayilan_alanlari(self, alan, beklenen):
        for gorev in TaskRegistry().list_all():
            assert getattr(gorev, alan) == beklenen

    def test_environment_alanlari_ve_varsayilanlari(self):
        for gorev in TaskRegistry().list_all():
            ortam = gorev.environment
            assert isinstance(ortam, EnvironmentSpec)
            assert ortam.target_url.startswith("https://")
            assert ortam.auth_required is False
            assert ortam.synthetic_dom_mutation is True
            assert ortam.preserve_aria_semantics is True

    def test_invariant_rule_tipleri_gecerli_kumede(self):
        for gorev in TaskRegistry().list_all():
            for inv in gorev.invariants:
                assert inv.rule_type in _KURAL_TIPLERI, f"{gorev.task_id}: {inv.rule_type}"

    def test_her_gorevin_title_ve_objective_dolu(self):
        for gorev in TaskRegistry().list_all():
            assert gorev.title.strip() != ""
            assert gorev.objective.strip() != ""


# ---------------------------------------------------------------------------
# get (D9..D14)
# ---------------------------------------------------------------------------


class TestGetir:
    def test_varolan_gorev_donar(self):
        registry = TaskRegistry()
        gorev = registry.get("T01")
        assert gorev is not None
        assert isinstance(gorev, TaskSpec)
        assert gorev.task_id == "T01"
        assert gorev.title == "Kuponlu Sepet Onayı"

    def test_bilinmeyen_gorev_none(self):
        assert TaskRegistry().get("T99") is None

    @pytest.mark.parametrize("kimlik", ["", "T0", "T21", "T100"])
    def test_sinir_kimlikler_none(self, kimlik):
        assert TaskRegistry().get(kimlik) is None

    @pytest.mark.parametrize("kimlik", ["t01", "T001", " T01", "T01 ", "t-01"])
    def test_buyuk_kucuk_ve_bosluk_hassasiyeti(self, kimlik):
        # BULGU R2: get case-sensitive + boşluk-toleranssız.
        assert TaskRegistry().get(kimlik) is None

    def test_get_ve_list_all_ayni_nesne(self):
        registry = TaskRegistry()
        assert registry.get("T01") is registry.list_all()[0]

    @pytest.mark.parametrize("kimlik", _BEKLENEN_IDLER)
    def test_tum_yirmi_gorev_bulunur(self, kimlik):
        gorev = TaskRegistry().get(kimlik)
        assert gorev is not None
        assert gorev.task_id == kimlik


# ---------------------------------------------------------------------------
# list_all (D15..D18)
# ---------------------------------------------------------------------------


class TestListele:
    def test_yirmi_eleman(self):
        assert len(TaskRegistry().list_all()) == _GOREV_SAYISI

    def test_donulen_liste_kopyadir(self):
        # BULGU R3: kayıt-defteri değişmez — dönen liste mutasyona açıktır
        # ama iç kaynağı bozmaz.
        registry = TaskRegistry()
        ilk = registry.list_all()
        ilk.append("kirlilik")
        ikinci = registry.list_all()
        assert len(ikinci) == _GOREV_SAYISI
        assert ilk is not ikinci

    def test_ekleme_sirasi_korunur(self):
        assert [g.task_id for g in TaskRegistry().list_all()] == _BEKLENEN_IDLER

    def test_her_eleman_taskspec_ornegi(self):
        for gorev in TaskRegistry().list_all():
            assert isinstance(gorev, TaskSpec)


# ---------------------------------------------------------------------------
# filter_by_pool (D19..D25)
# ---------------------------------------------------------------------------


class TestHavuzSuzme:
    def test_havuz_dagilimi_oniki_sekiz(self):
        registry = TaskRegistry()
        assert len(registry.filter_by_pool(PoolType.PUBLIC_CANARY)) == _PUBLIC_SAYI
        assert len(registry.filter_by_pool(PoolType.DYNAMIC_HIDDEN)) == _GIZLI_SAYI

    def test_havuz_toplami_yirmi(self):
        registry = TaskRegistry()
        toplam = (len(registry.filter_by_pool(PoolType.PUBLIC_CANARY))
                  + len(registry.filter_by_pool(PoolType.DYNAMIC_HIDDEN)))
        assert toplam == _GOREV_SAYISI

    @pytest.mark.parametrize("dize_deger", ["PUBLIC_CANARY", "DYNAMIC_HIDDEN"])
    def test_saf_dize_deger_kabul_edilir(self, dize_deger):
        # BULGU R1: str-Enum olduğu için saf-dize de eşleşir — tip güvenliği yok.
        registry = TaskRegistry()
        sonuclar = registry.filter_by_pool(dize_deger)
        assert len(sonuclar) > 0
        assert sonuclar == registry.filter_by_pool(PoolType(dize_deger))

    @pytest.mark.parametrize("bilinmeyen", ["FOO", None, 123, PoolType.PUBLIC_CANARY.value + "x"])
    def test_bilinmeyen_havuz_degeri_bos_liste(self, bilinmeyen):
        assert TaskRegistry().filter_by_pool(bilinmeyen) == []

    def test_donulenlerin_tamami_istenen_havuzda(self):
        registry = TaskRegistry()
        for havuz in (PoolType.PUBLIC_CANARY, PoolType.DYNAMIC_HIDDEN):
            for gorev in registry.filter_by_pool(havuz):
                assert gorev.pool_type == havuz

    def test_public_havuz_kimlik_kumesi_tam_eslesme(self):
        registry = TaskRegistry()
        public_idler = {g.task_id for g in registry.filter_by_pool(PoolType.PUBLIC_CANARY)}
        gizli_idler = {g.task_id for g in registry.filter_by_pool(PoolType.DYNAMIC_HIDDEN)}
        assert public_idler == _PUBLIC_IDLER
        assert gizli_idler == _GIZLI_IDLER
        assert public_idler.isdisjoint(gizli_idler)

    def test_her_cagri_yeni_liste(self):
        registry = TaskRegistry()
        a = registry.filter_by_pool(PoolType.PUBLIC_CANARY)
        b = registry.filter_by_pool(PoolType.PUBLIC_CANARY)
        assert a == b
        assert a is not b
        a.clear()
        assert len(registry.filter_by_pool(PoolType.PUBLIC_CANARY)) == _PUBLIC_SAYI


# ---------------------------------------------------------------------------
# filter_by_category (D26..D31)
# ---------------------------------------------------------------------------


class TestKategoriSuzme:
    @pytest.mark.parametrize("kategori,beklenen", list(_KATEGORI_DAGILIM.items()))
    def test_kategori_dagilimi(self, kategori, beklenen):
        assert len(TaskRegistry().filter_by_category(kategori)) == beklenen

    def test_kategoriler_toplami_yirmi_ve_kesisimsiz(self):
        registry = TaskRegistry()
        kumeler = []
        toplam = 0
        for kategori in _KATEGORI_DAGILIM:
            sonuclar = registry.filter_by_category(kategori)
            idler = {g.task_id for g in sonuclar}
            kumeler.append(idler)
            toplam += len(idler)
        assert toplam == _GOREV_SAYISI
        for i, a in enumerate(kumeler):
            for b in kumeler[i + 1:]:
                assert a.isdisjoint(b)

    @pytest.mark.parametrize("kategori_dizesi", ["e_commerce", "saas_admin", "finops", "modern_ui", "data_extraction"])
    def test_saf_dize_kategori_kabul_edilir(self, kategori_dizesi):
        # BULGU R1: kategori süzmesi de saf-dize kabul eder.
        registry = TaskRegistry()
        assert (registry.filter_by_category(kategori_dizesi)
                == registry.filter_by_category(TaskCategory(kategori_dizesi)))

    @pytest.mark.parametrize("bilinmeyen", ["unknown", "E_COMMERCE", None, 42])
    def test_bilinmeyen_kategori_bos_liste(self, bilinmeyen):
        # Not: "E_COMMERCE" (enum ADI) kabul etmez — enum DEĞERİ "e_commerce" gerekir.
        assert TaskRegistry().filter_by_category(bilinmeyen) == []

    def test_donulenlerin_tamami_istenen_kategoride(self):
        registry = TaskRegistry()
        for kategori in _KATEGORI_DAGILIM:
            for gorev in registry.filter_by_category(kategori):
                assert gorev.category == kategori

    @pytest.mark.parametrize("kategori", list(_KATEGORI_DAGILIM))
    def test_kategori_havuz_matrisi_toplami_yirmi(self, kategori):
        registry = TaskRegistry()
        public = registry.filter_by_category(kategori)
        gizli = [g for g in public if g.pool_type == PoolType.DYNAMIC_HIDDEN]
        acik = [g for g in public if g.pool_type == PoolType.PUBLIC_CANARY]
        assert len(acik) + len(gizli) == len(public)

    def test_kategori_havuz_hucreleri_tam_hesaplar(self):
        # 5 kategori × 2 havuz hücrelerinin toplamı 20'e eşit olmalı.
        registry = TaskRegistry()
        toplam = 0
        for kategori in _KATEGORI_DAGILIM:
            for havuz in (PoolType.PUBLIC_CANARY, PoolType.DYNAMIC_HIDDEN):
                toplam += len([g for g in registry.filter_by_category(kategori)
                               if g.pool_type == havuz])
        assert toplam == _GOREV_SAYISI


# ---------------------------------------------------------------------------
# içerik — kayıt veri-dalları (D32..D40)
# ---------------------------------------------------------------------------


class TestIcerikDogrulama:
    @pytest.mark.parametrize("kural_tipi,beklenen", [
        ("db_assert", 11),
        ("dom_selector_text", 8),
        ("network_assert", 6),
        ("dom_element_state", 3),
    ])
    def test_rule_type_dagilimi(self, kural_tipi, beklenen):
        tumu = [inv for g in TaskRegistry().list_all() for inv in g.invariants]
        sayi = sum(1 for inv in tumu if inv.rule_type == kural_tipi)
        assert sayi == beklenen

    def test_toplam_invaryan_sayisi(self):
        tumu = [inv for g in TaskRegistry().list_all() for inv in g.invariants]
        assert len(tumu) == _TOPLAM_INVARYAN
        assert len(tumu) == sum(1 for inv in tumu if inv.rule_type in _KURAL_TIPLERI)

    def test_network_assert_status_code_tasir(self):
        for g in TaskRegistry().list_all():
            for inv in g.invariants:
                if inv.rule_type == "network_assert":
                    assert isinstance(inv.status_code, int)
                    assert 100 <= inv.status_code <= 599

    def test_dom_kurallari_selector_tasir(self):
        for g in TaskRegistry().list_all():
            for inv in g.invariants:
                if inv.rule_type.startswith("dom_"):
                    assert inv.selector is not None and inv.selector != ""

    def test_expected_regex_derlenebilir(self):
        derlenen = 0
        for g in TaskRegistry().list_all():
            for inv in g.invariants:
                if inv.expected_regex is not None:
                    assert re.compile(inv.expected_regex) is not None
                    derlenen += 1
        assert derlenen > 0  # en-az bir regex kuralı var (8 dom_selector_text)

    @pytest.mark.parametrize("kimlik,degisken,beklenen_tip", [
        ("T02", "cart.items[0].sku", str),       # "ALT-92"
        ("T07", "webhook.active", bool),         # True
        ("T10", "invoice.tax_total", float),     # 184.20
        ("T11", "reconciliation.flagged_count", int),  # 3
    ])
    def test_expected_db_value_tur_cesitliligi(self, kimlik, degisken, beklenen_tip):
        gorev = TaskRegistry().get(kimlik)
        bul = [inv for inv in gorev.invariants
               if inv.rule_type == "db_assert" and inv.selector == degisken]
        assert len(bul) == 1
        assert isinstance(bul[0].expected_db_value, beklenen_tip)

    def test_t08_tarihi_dizedir(self):
        # BULGU R4: T08 license.valid_until → "2027-09-15" DİZE (tarih tipi yok).
        gorev = TaskRegistry().get("T08")
        bul = [inv for inv in gorev.invariants if inv.selector == "license.valid_until"]
        assert bul[0].expected_db_value == "2027-09-15"
        assert isinstance(bul[0].expected_db_value, str)

    def test_havuz_orani_yuzde_altmis_kirk(self):
        registry = TaskRegistry()
        public = len(registry.filter_by_pool(PoolType.PUBLIC_CANARY))
        gizli = len(registry.filter_by_pool(PoolType.DYNAMIC_HIDDEN))
        assert public / _GOREV_SAYISI == pytest.approx(0.60)
        assert gizli / _GOREV_SAYISI == pytest.approx(0.40)

    def test_dom_element_state_must_exist_true(self):
        for g in TaskRegistry().list_all():
            for inv in g.invariants:
                if inv.rule_type == "dom_element_state":
                    assert inv.must_exist is True

    def test_get_filter_by_pool_uyelugu(self):
        registry = TaskRegistry()
        assert registry.get("T01") in registry.filter_by_pool(PoolType.PUBLIC_CANARY)
        assert registry.get("T02") not in registry.filter_by_pool(PoolType.PUBLIC_CANARY)

    @pytest.mark.parametrize("kimlik,beklenen_kural", [
        ("T04", "db_assert"), ("T07", "db_assert"), ("T08", "db_assert"),
        ("T09", "dom_selector_text"), ("T11", "db_assert"), ("T13", "db_assert"),
        ("T14", "dom_selector_text"), ("T15", "dom_element_state"),
        ("T16", "network_assert"), ("T17", "db_assert"), ("T18", "db_assert"),
        ("T19", "dom_selector_text"), ("T20", "db_assert"),
    ])
    def test_tek_invaryantli_gorevler_minimum_kapsam(self, kimlik, beklenen_kural):
        # BULGU R5: 13/20 görev TEK değişmezlik taşır — tek-noktalı görevler
        # minimum kapsamdadır (başarısızlık gizlenmesinin tek kanıtı).
        gorev = TaskRegistry().get(kimlik)
        assert len(gorev.invariants) == 1
        assert gorev.invariants[0].rule_type == beklenen_kural

    def test_tek_invaryantli_gorev_sayisi_onuc(self):
        tekler = [g.task_id for g in TaskRegistry().list_all() if len(g.invariants) == 1]
        assert len(tekler) == 13
        # kalan 7 görevde 2+ değişmezlik → toplam 28
        assert sum(len(g.invariants) for g in TaskRegistry().list_all()) == _TOPLAM_INVARYAN
