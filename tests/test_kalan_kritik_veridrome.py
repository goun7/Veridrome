"""Veridrome — kalan EN KRİTİK test açıkları (sadece YENI dosya).

Kapsam (mevcut testleri DEĞİŞTİRMEZ):

  1. core.anti_gaming.AntiGamingEngine'in istatistiksel ilkel fonksiyonları
     (test_anti_gaming.py sadece yüksek-seviye evaluate() kararlarını
     test ediyordu; spearman/shannon/JSD/welch formülleri doğrudan
     test-dışı): spearman_rank_correlation, compute_shannon_entropy,
     jensen_shannon_divergence, welch_ttest_sandbagging.
  2. certificate.tamga_anchor.es_number (31L tam test-dışı) — RFC 8785
     §3.2.2.2 ECMAScript Number.prototype.toString serileştirme.
  3. certificate.revocation: check_revoked / verify_revocation_entry /
     read_entries — append-only iptal-defteri bütünlüğü ve imza doğrulaması.

Tüm testler saf fonksiyon/yerel-kripto mantığını test eder; dış ağ veya
disk-üretim dosyası YOK. Geçici defterler tmp_path altındadır.
"""
from __future__ import annotations

import hashlib

import pytest

from veridrome.certificate.didkey import generate_keypair
from veridrome.certificate.revocation import (
    RevocationLedger,
    check_revoked,
    verify_revocation_entry,
)
from veridrome.certificate.tamga_anchor import es_number
from veridrome.core.anti_gaming import AntiGamingEngine


# =====================================================================
# 1) anti_gaming istatistiksel ilkeller
# =====================================================================

# ---- Spearman sıra korelasyonu ----

def test_spearman_kisa_girdi_guvenli_sekilde_bir_donar() -> None:
    """<3 örnek → korelasyon tanımsız; güvenli varsayılan (1.0, 0.0)."""
    assert AntiGamingEngine.spearman_rank_correlation([1.0, 2.0], [3.0, 4.0]) == (1.0, 0.0)
    assert AntiGamingEngine.spearman_rank_correlation([], []) == (1.0, 0.0)


def test_spearman_mukemmel_pozitif_korelasyon() -> None:
    """Doğru-orantılı diziler → rho = +1.0."""
    rho, p = AntiGamingEngine.spearman_rank_correlation(
        [1.0, 2.0, 3.0, 4.0], [2.0, 4.0, 6.0, 8.0])
    assert rho == pytest.approx(1.0)
    assert 0.0 <= p <= 1.0


def test_spearman_tam_negatif_korelasyon() -> None:
    """Ters-orantılı diziler → rho = -1.0 (açık/gizli davranış ayrışması)."""
    rho, _ = AntiGamingEngine.spearman_rank_correlation(
        [1.0, 2.0, 3.0], [6.0, 4.0, 2.0])
    assert rho == pytest.approx(-1.0)


def test_spearman_sabit_dizi_tanimsiz_doner() -> None:
    """Sabit girdi → korelasyon tanımsız → güvenli (1.0, 0.0)."""
    assert AntiGamingEngine.spearman_rank_correlation(
        [5.0, 5.0, 5.0], [1.0, 2.0, 3.0]) == (1.0, 0.0)
    assert AntiGamingEngine.spearman_rank_correlation(
        [1.0, 2.0, 3.0], [7.0, 7.0, 7.0]) == (1.0, 0.0)


def test_spearman_farkli_uzunluk_kirpilarak_esitlenir() -> None:
    """Farklı uzunluk → kısa olana göre kırpılır (min_len)."""
    rho, _ = AntiGamingEngine.spearman_rank_correlation(
        [1.0, 2.0, 3.0, 9.0, 9.0], [2.0, 4.0, 6.0])
    assert rho == pytest.approx(1.0)


# ---- Shannon entropi ----

def test_shannon_bos_dizi_sifir() -> None:
    assert AntiGamingEngine.compute_shannon_entropy([]) == 0.0


def test_shannon_tek_tekrar_eylem_sifir() -> None:
    """Hep aynı eylem → sıfır belirsizlik (deterministik ajan)."""
    assert AntiGamingEngine.compute_shannon_entropy(["a", "a", "a"]) == 0.0


def test_shannon_serbest_dagitim_log2() -> None:
    """n farklı eşit eylem → log2(n) bit."""
    assert AntiGamingEngine.compute_shannon_entropy(["a", "b"]) == pytest.approx(1.0)
    assert AntiGamingEngine.compute_shannon_entropy(["a", "b", "c", "d"]) == pytest.approx(2.0)


def test_shannon_karisik_dagitim_formul() -> None:
    """["a","a","b"] → -(2/3 log2 2/3 + 1/3 log2 1/3)."""
    import math
    expected = -(2 / 3 * math.log2(2 / 3) + 1 / 3 * math.log2(1 / 3))
    assert AntiGamingEngine.compute_shannon_entropy(["a", "a", "b"]) == pytest.approx(expected)


def test_shannon_aralik_sifir_log2n() -> None:
    """Entropi her zaman [0, log2(n)] aralığında (n = farklı eylem sayısı)."""
    import math

    actions = ["click", "type", "submit", "scroll", "click", "type"]
    h = AntiGamingEngine.compute_shannon_entropy(actions)
    assert 0.0 <= h <= math.log2(4) + 1e-12


# ---- Jensen-Shannon divergence ----

def test_jsd_iki_bos_dizi_sifir() -> None:
    assert AntiGamingEngine.jensen_shannon_divergence([], []) == 0.0


def test_jsd_ayni_dagitim_sifir() -> None:
    """Aynı dağılım → JSD 0 (davranış tutarlı)."""
    assert AntiGamingEngine.jensen_shannon_divergence(
        ["a", "b", "c"], ["a", "b", "c"]) == pytest.approx(0.0)


def test_jsd_ayri_dagitim_maksimum_bir() -> None:
    """Tam ayrık dağılımlar → JSD 1.0 (tamamen farklı davranış)."""
    assert AntiGamingEngine.jensen_shannon_divergence(
        ["a", "a"], ["b", "b"]) == pytest.approx(1.0)


def test_jsd_kismi_paylasim_sifir_bir_arasinda() -> None:
    """Kısmi örtüşme → (0, 1) arasında; tekillik hassasiyeti."""
    jsd = AntiGamingEngine.jensen_shannon_divergence(
        ["a", "a", "b", "b"], ["a", "a", "a", "b"])
    assert 0.0 < jsd < 1.0
    assert jsd == pytest.approx(0.0487949, abs=1e-5)


def test_jsd_simetrik() -> None:
    """JSD simetriktir: JSD(P,Q) == JSD(Q,P)."""
    p = ["click", "type", "submit", "click"]
    q = ["type", "type", "scroll", "click"]
    a = AntiGamingEngine.jensen_shannon_divergence(p, q)
    b = AntiGamingEngine.jensen_shannon_divergence(q, p)
    assert a == pytest.approx(b)


def test_jsd_negatif_deger_donmez() -> None:
    """max(0.0, jsd) — sayısal sapmada negatif üretmez."""
    jsd = AntiGamingEngine.jensen_shannon_divergence(["a"], ["a", "a", "a"])
    assert jsd >= 0.0


# ---- Welch t-test (sandbagging) ----

def test_welch_kisa_girdi_guvenli_doner() -> None:
    """<2 örnek → (0.0, 1.0) (karar verilemez)."""
    assert AntiGamingEngine.welch_ttest_sandbagging([1.0], [2.0]) == (0.0, 1.0)


def test_welch_yakin_gecikmeler_p_yuksek() -> None:
    """Benzer gecikmeler → istatistik küçük, p değeri büyük (sandbagging YOK)."""
    stat, p = AntiGamingEngine.welch_ttest_sandbagging(
        [10.0, 12.0, 11.0], [10.5, 12.5, 11.5])
    assert abs(stat) < 1.0
    assert p > 0.05


def test_welch_gizli_havuz_yavas_p_dusuk() -> None:
    """Gizli havuzda belirgin yavaşlama → negatif istatistik, p < 0.05."""
    stat, p = AntiGamingEngine.welch_ttest_sandbagging(
        [10.0, 11.0, 12.0], [50.0, 55.0, 60.0])
    assert stat < 0.0
    assert p < 0.05


def test_welch_her_iki_sabit_esit_p_bir() -> None:
    """İki sabit-dizili küme, aynı değer → (0.0, 1.0)."""
    assert AntiGamingEngine.welch_ttest_sandbagging(
        [5.0, 5.0], [5.0, 5.0]) == (0.0, 1.0)


def test_welch_her_iki_sabit_farkli_buyuk_statistik() -> None:
    """Sabit kümeler, farklı ortalamalar → ±1e6 ile p=0 (kararlı çözüm)."""
    stat, p = AntiGamingEngine.welch_ttest_sandbagging([5.0, 5.0], [8.0, 8.0])
    assert stat == pytest.approx(-1e6)
    assert p == pytest.approx(0.0)
    # özel havuz daha hızlıysa pozitif
    stat2, _ = AntiGamingEngine.welch_ttest_sandbagging([8.0, 8.0], [5.0, 5.0])
    assert stat2 == pytest.approx(1e6)


# =====================================================================
# 2) es_number — RFC 8785 ECMAScript Number.toString
# =====================================================================

@pytest.mark.parametrize("deger, beklenen", [
    (0.0, "0"),
    (-0.0, "0"),                     # -0 → ECMAScript "0" basar
    (1.0, "1"),                      # tamsayı sondaki sıfırlar atılır
    (-1.0, "-1"),
    (2.5, "2.5"),
    (100.0, "100"),
    (0.1, "0.1"),
    (123456.789, "123456.789"),
    (1e16, "10000000000000000"),     # k <= n <= 21 → sıfırlarla uzat
    (1e21, "1e+21"),                 # n > 21 → üslü gösterim
    (1e22, "1e+22"),
    (2.93e-07, "2.93e-7"),           # n <= -6 → üslü, kısa üs
    (1e-7, "1e-7"),
    (1e-6, "0.000001"),              # -6 < n <= 0 → önde sıfırlar
    (1.5e-6, "0.0000015"),
])
def test_es_number_ecmascript_spesifikasyonu(deger, beklenen) -> None:
    """RFC 8785 §3.2.2.2 — her sınıf ECMAScript ile birebir."""
    assert es_number(deger) == beklenen


@pytest.mark.parametrize("deger", [float("nan"), float("inf"), float("-inf")])
def test_es_number_sonlu_olmayan_reddedilir(deger) -> None:
    """NaN/Infinity I-JSON altkümesinde değil (RFC 7493) → ValueError."""
    with pytest.raises(ValueError, match="ijson_number_not_finite"):
        es_number(deger)


def test_es_number_json_parse_ile_geri_donuser() -> None:
    """Üretilen her gösterim JSON'a gömülüp aynı değerle ayrıştırılır."""
    import json

    for v in (0.0, 1.0, -2.5, 1e16, 1e21, 2.93e-07, 1e-7, 123456.789, 0.1):
        assert json.loads(es_number(v)) == v


def test_es_number_pozitif_ve_negatif_simetri() -> None:
    """İşaret dışında gösterim aynıdır."""
    for v in (1.0, 2.5, 1e21, 2.93e-07):
        assert es_number(-v) == "-" + es_number(v)


# =====================================================================
# 3) revocation — iptal-defteri bütünlüğü
# =====================================================================

def _cert_id(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


@pytest.fixture()
def keypair():
    return generate_keypair()


@pytest.fixture()
def ledger(tmp_path) -> RevocationLedger:
    return RevocationLedger(str(tmp_path / "revocations.jsonl"))


def test_revocation_bos_defter_okuma_ve_dogrulama(ledger) -> None:
    """Boş defter → read_entries [] ve verify_chain True (genesis kabul)."""
    assert ledger.read_entries() == []
    assert ledger.verify_chain() is True


def test_check_revoked_ledger_none_iptal_degil() -> None:
    """ledger=None → iptal edilmemiş, zincir geçerli (defter yok)."""
    r = check_revoked(_cert_id(b"x"), None)
    assert r == {"revoked": False, "reason": "", "entry": None, "chain_valid": True}


def test_check_revoked_bos_defter_iptal_degildir(ledger) -> None:
    """Boş defter → herhangi cert_id iptal edilmemiş."""
    r = check_revoked(_cert_id(b"y"), ledger)
    assert r["revoked"] is False
    assert r["entry"] is None
    assert r["chain_valid"] is True


def test_revocation_revoke_gecerli_giris_olusturur(ledger, keypair) -> None:
    """revoke → prev=genesis, h ve imza içeren geçerli giriş."""
    seed, did, _ = keypair
    cid = _cert_id(b"cert-1")
    entry = ledger.revoke(cid, seed, did, reason="güvenlik ihlali")
    assert entry["cert_id"] == cid
    assert entry["prev"] == "0" * 64
    assert entry["revoked_by"] == did
    assert entry["reason"] == "güvenlik ihlali"
    assert "h" in entry and len(entry["h"]) == 64
    assert "signature" in entry
    assert ledger.verify_chain() is True


def test_revocation_check_revoked_iptal_edilmis_bulur(ledger, keypair) -> None:
    """İptal edilmiş cert_id → revoked=True + reason + imza geçerli."""
    seed, did, _ = keypair
    cid = _cert_id(b"cert-2")
    ledger.revoke(cid, seed, did, reason="kandırma tespit edildi")
    r = check_revoked(cid, ledger)
    assert r["revoked"] is True
    assert r["reason"] == "kandırma tespit edildi"
    assert r["entry"]["cert_id"] == cid
    assert r["chain_valid"] is True
    assert r["signature_valid"] is True


def test_revocation_check_revoked_baska_cert_degildir(ledger, keypair) -> None:
    """Sadece kayıtlı cert_id iptaldir; başkası değil."""
    seed, did, _ = keypair
    ledger.revoke(_cert_id(b"a"), seed, did)
    r = check_revoked(_cert_id(b"b"), ledger)
    assert r["revoked"] is False
    assert r["entry"] is None


def test_revocation_coklu_giris_zincir_baglanti(ledger, keypair) -> None:
    """İkinci giriş prev ile birincinin h'sine bağlanır; zincir geçerli."""
    seed, did, _ = keypair
    e1 = ledger.revoke(_cert_id(b"1"), seed, did)
    e2 = ledger.revoke(_cert_id(b"2"), seed, did, reason="ikinci")
    assert e2["prev"] == e1["h"]
    assert ledger.verify_chain() is True
    assert len(ledger.read_entries()) == 2


def test_revocation_verify_revocation_entry_gecerli_imza(ledger, keypair) -> None:
    """Did:key ile imzalanmış giriş bağımsız olarak doğrulanır."""
    seed, did, _ = keypair
    entry = ledger.revoke(_cert_id(b"signed"), seed, did)
    assert verify_revocation_entry(entry) is True


@pytest.mark.parametrize("bozma", [
    "body", "signature", "yok_sig", "bad_did",
])
def test_revocation_verify_revocation_entry_bozuklar_reddedilir(ledger, keypair, bozma) -> None:
    """Bozuk giriş → False (fail-closed)."""
    seed, did, _ = keypair
    entry = ledger.revoke(_cert_id(b"tamper"), seed, did)
    if bozma == "body":
        entry["reason"] = "değiştirildi"
    elif bozma == "signature":
        entry["signature"] = "!!!not-base64!!!"
    elif bozma == "yok_sig":
        entry.pop("signature", None)
    else:
        entry["revoked_by"] = "did:BOGUS:değil"
    assert verify_revocation_entry(entry) is False


def test_revocation_kisa_cert_id_reddedilir(ledger, keypair) -> None:
    """cert_id 64-hex değil → ValueError (fail-closed)."""
    seed, did, _ = keypair
    with pytest.raises(ValueError, match="64-hex"):
        ledger.revoke("kısa", seed, did)


def test_revocation_gecersiz_did_reddedilir(ledger, keypair) -> None:
    """revoked_by geçerli did:key değil → ValueError."""
    seed, _, _ = keypair
    with pytest.raises(ValueError, match="did:key"):
        ledger.revoke("a" * 64, seed, "did:BOGUS:değil")


def test_revocation_kirik_zincir_tespit_edilir(ledger, keypair) -> None:
    """prev bağı kırık → verify_chain False (bağımsız tespit)."""
    seed, did, _ = keypair
    ledger.revoke(_cert_id(b"chain"), seed, did)
    with open(ledger.path, "a", encoding="utf-8") as f:
        f.write('{"cert_id":"x","prev":"KIRIK","h":"y","revoked_by":"z"}\n')
    assert ledger.verify_chain() is False


def test_revocation_bozuk_json_satiri_runtime_error(tmp_path) -> None:
    """Bozuk JSONL satırı → RuntimeError (sessiz zincir-kopması YOK)."""
    path = tmp_path / "bad.jsonl"
    path.write_text('{"ok": 1}\nBU JSON DEĞİL\n', encoding="utf-8")
    with pytest.raises(RuntimeError):
        RevocationLedger(str(path)).read_entries()


def test_revocation_olmayan_dosya_bos_defter_gibi_okunur(tmp_path) -> None:
    """Olmayan dosya → FileNotFoundError sessizce [] döner (fail-open değil,

    bilinen-boş-defter anlamında; check_revoked güvenli varsayım yapar)."""
    ledger = RevocationLedger(str(tmp_path / "yok.jsonl"))
    assert ledger.read_entries() == []
    assert ledger.verify_chain() is True
