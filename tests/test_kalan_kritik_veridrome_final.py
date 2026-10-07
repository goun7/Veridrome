"""Kalan EN KRITIK test-disi fonksiyonlar icin dal-kesen testler (final batch).

Hedefler (AST taramasi + manukal dogrulama; mevcut testlerde cagrilmiyor):
  1. parse_pytest_json                        (certificate/pytest_parser.py:22)
     — pytest-json-report okuyucu, fail-closed hata dallari
  2. MerkleTreeAuditLog.hash_leaf / hash_children (core/crypto.py:64/69)
     — RFC 6962 Merkle oncelikleri (capraz-capa / kurcalama teshisi)
  3. AntiGamingEngine.compute_entropy_delta   (core/anti_gaming.py:82)
     — anti-gaming istatistiksel ilkeli (sandbagging teshisi)

KURALLAR: sadece fonksiyonun kendi mantigi; dis cagri/mock yok; mevcut
testleri/kodu degistirmez.
"""

import hashlib
import json

import pytest

from veridrome.certificate.pytest_parser import parse_pytest_json
from veridrome.core.anti_gaming import AntiGamingEngine
from veridrome.core.crypto import MerkleTreeAuditLog


# ---------------------------------------------------------------------------
# 1) parse_pytest_json
# ---------------------------------------------------------------------------
class TestParsePytestJson:
    def _zarf(self):
        return {
            "created": 1.0,
            "duration": 0.5,
            # zarf icindeki "iddia edilen" ozet — GERI DONULERECEK (asla guvenilmez)
            "summary": {"passed": 99, "failed": 0, "total": 3},
            "tests": [
                {
                    "nodeid": "tests/test_a.py::test_one",
                    "outcome": "passed",
                    "duration": 0.1,
                    "call": {"duration": 0.09, "outcome": "passed"},
                },
                {
                    "nodeid": "tests/test_a.py::test_two",
                    "outcome": "failed",
                    "duration": 0.2,
                    "call": {"duration": 0.19, "outcome": "failed"},
                },
                {
                    "nodeid": "tests/test_b.py::test_three",
                    "outcome": "skipped",
                    "duration": 0.0,
                },
            ],
        }

    def test_gecerli_zarf_normalize_ve_ozet_donar(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps(self._zarf()), encoding="utf-8")
        out = parse_pytest_json(str(p))

        assert out["source"] == str(p)
        assert len(out["entries"]) == 3
        assert out["summary"]["total"] == 3
        assert out["summary"]["passed"] == 1
        assert out["summary"]["failed"] == 1
        assert out["summary"]["skipped"] == 1

    def test_ozet_zarftan_bagimsiz_yeniden_hesaplanir(self, tmp_path):
        """Dürüstluk: ozet entries'ten YENIDEN hesaplanir, zarfın iddiasina
        GUVENILMEZ (burada zarf 99 passed iddia ediyor ama gercek 1)."""
        p = tmp_path / "report.json"
        p.write_text(json.dumps(self._zarf()), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["raw_summary"]["passed"] == 99  # iddia
        assert out["summary"]["passed"] == 1       # hesaplanan gercek
        assert out["raw_summary"]["failed"] == 0   # iddia
        assert out["summary"]["failed"] == 1       # hesaplanan gercek

    def test_raw_summary_zarf_icinden_gecirilir(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps(self._zarf()), encoding="utf-8")
        out = parse_pytest_json(str(p))
        # raw_summary zarfin KENDI iddiasi (oldugu gibi gecer; dogrulanmaz)
        assert out["raw_summary"] == {"passed": 99, "failed": 0, "total": 3}

    def test_nodeid_name_olarak_alinir(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps(self._zarf()), encoding="utf-8")
        isimler = {e["name"] for e in parse_pytest_json(str(p))["entries"]}
        assert "tests/test_a.py::test_one" in isimler
        assert "tests/test_b.py::test_three" in isimler

    def test_sure_saniyeden_milisaniyeye_cevrilir(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps(self._zarf()), encoding="utf-8")
        sureler = {e["name"]: e["duration_ms"] for e in parse_pytest_json(str(p))["entries"]}
        # 0.1 saniye -> 100.0 ms; 0.2 saniye -> 200.0 ms
        assert sureler["tests/test_a.py::test_one"] == pytest.approx(100.0)
        assert sureler["tests/test_a.py::test_two"] == pytest.approx(200.0)

    def test_bos_test_listesi_bos_ozet(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({"summary": {}, "tests": []}), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["entries"] == []
        assert out["summary"]["total"] == 0
        assert out["summary"]["passed"] == 0

    def test_olmayan_dosya_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="bulunamad"):
            parse_pytest_json(str(tmp_path / "yok.json"))

    def test_gecersiz_json_value_error(self, tmp_path):
        p = tmp_path / "bozuk.json"
        p.write_text("{ bu json degil ", encoding="utf-8")
        with pytest.raises(ValueError, match="geçersiz JSON"):
            parse_pytest_json(str(p))

    def test_json_listesi_raw_summary_none(self, tmp_path):
        """data bir dict degilse raw_summary None olur (dürüst düşürme)."""
        p = tmp_path / "liste.json"
        p.write_text(json.dumps([{"name": "x", "outcome": "passed"}]), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["raw_summary"] is None
        assert out["summary"]["passed"] == 1

    def test_call_outcome_yedek_olarak_kullanilir(self, tmp_path):
        """pytest-json-report bazen ust-duzey 'outcome'u bos birakir."""
        p = tmp_path / "report.json"
        p.write_text(json.dumps({
            "tests": [{"nodeid": "t::x", "call": {"outcome": "passed"}}],
        }), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["entries"][0]["outcome"] == "passed"

    def test_call_crash_failed_olarak_algilanir(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({
            "tests": [{"nodeid": "t::x", "call": {"crash": {"message": "boom"}}}],
        }), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["entries"][0]["outcome"] == "failed"

    def test_taninmayan_sonuc_other_da_sayilir(self, tmp_path):
        """Taninmayan sonuc 'other' olarak dürüstce raporlanir (gizlenmez)."""
        p = tmp_path / "report.json"
        p.write_text(json.dumps({
            "tests": [{"nodeid": "t::a", "outcome": "passed"},
                      {"nodeid": "t::b", "outcome": "bilinmeyen"}],
        }), encoding="utf-8")
        ozet = parse_pytest_json(str(p))["summary"]
        assert ozet["total"] == 2
        assert ozet["passed"] == 1
        assert ozet["other"] == 1

    def test_utf8_nodeid_korunur(self, tmp_path):
        p = tmp_path / "report.json"
        p.write_text(json.dumps({
            "tests": [{"nodeid": "tests/t.py::test_türkçe", "outcome": "passed"}],
        }), encoding="utf-8")
        out = parse_pytest_json(str(p))
        assert out["entries"][0]["name"] == "tests/t.py::test_türkçe"


# ---------------------------------------------------------------------------
# 2) MerkleTreeAuditLog.hash_leaf / hash_children (RFC 6962)
# ---------------------------------------------------------------------------
class TestMerkleHashPrimitives:
    def test_hash_leaf_prefix_0x00(self):
        """RFC 6962: SHA256(0x00 || data) — bagimsiz yeniden-hesap."""
        assert MerkleTreeAuditLog.hash_leaf(b"abc") == hashlib.sha256(b"\x00" + b"abc").digest()

    def test_hash_children_prefix_0x01(self):
        """RFC 6962: SHA256(0x01 || left || right)."""
        left = hashlib.sha256(b"\x00a").digest()
        right = hashlib.sha256(b"\x00b").digest()
        assert MerkleTreeAuditLog.hash_children(left, right) == \
            hashlib.sha256(b"\x01" + left + right).digest()

    def test_hash_leaf_32_bayt_donar(self):
        assert len(MerkleTreeAuditLog.hash_leaf(b"x")) == 32
        assert len(MerkleTreeAuditLog.hash_children(b"\x01" * 32, b"\x02" * 32)) == 32

    def test_yaprak_ve_ic_dugum_prefixleri_farklidir(self):
        """Ayni baytlar icin bile 0x00 ve 0x01 prefixleri farkli ozet uretir."""
        a, b = b"aaaa", b"bbbb"
        assert MerkleTreeAuditLog.hash_leaf(a) != MerkleTreeAuditLog.hash_children(a, b)

    def test_deterministik_tekrar_uretilir(self):
        assert MerkleTreeAuditLog.hash_leaf(b"veri") == MerkleTreeAuditLog.hash_leaf(b"veri")
        assert MerkleTreeAuditLog.hash_children(b"l", b"r") == \
            MerkleTreeAuditLog.hash_children(b"l", b"r")

    def test_farkli_veri_farkli_ozet(self):
        assert MerkleTreeAuditLog.hash_leaf(b"veri") != MerkleTreeAuditLog.hash_leaf(b"veri2")
        assert MerkleTreeAuditLog.hash_children(b"l", b"r") != \
            MerkleTreeAuditLog.hash_children(b"l", b"R")

    def test_cocuk_sirasi_onemlidir(self):
        """Merkle agaci siraya-duyarlidir: (l,r) != (r,l)."""
        assert MerkleTreeAuditLog.hash_children(b"l", b"r") != \
            MerkleTreeAuditLog.hash_children(b"r", b"l")

    def test_bos_veri_de_calisir(self):
        """Bos yaprak da gecerli bir 32-bayt ozet uretir (fail-closed degil)."""
        h = MerkleTreeAuditLog.hash_leaf(b"")
        assert h == hashlib.sha256(b"\x00").digest()
        assert len(h) == 32

    def test_tek_yaprak_kok_hash_leafe_esittir(self):
        """get_root() tutarligi: tek yaprakli agacin koku o yapragin ozetidir."""
        log = MerkleTreeAuditLog()
        log.add_leaf(b"tek")
        assert log.get_root() == MerkleTreeAuditLog.hash_leaf(b"tek")

    def test_iki_yaprak_kok_hash_children_ile_ayni(self):
        log = MerkleTreeAuditLog()
        l = log.add_leaf(b"bir")
        r = log.add_leaf(b"iki")
        assert log.get_root() == MerkleTreeAuditLog.hash_children(l, r)

    def test_add_leaf_ham_veriyi_degil_ozeti_saklar(self):
        """Defterde ham veri degil, oncelikli olarak ozet tutulur (RFC 6962)."""
        log = MerkleTreeAuditLog()
        log.add_leaf(b"gizli")
        assert b"gizli" not in b"".join(log.leaves)
        assert log.leaves[0] == MerkleTreeAuditLog.hash_leaf(b"gizli")

    def test_bos_agacin_koku_bos_ozet(self):
        assert MerkleTreeAuditLog().get_root() == hashlib.sha256(b"").digest()


# ---------------------------------------------------------------------------
# 3) AntiGamingEngine.compute_entropy_delta
# ---------------------------------------------------------------------------
class TestComputeEntropyDelta:
    def test_ayni_dagilim_sifir_sapma(self):
        delta = AntiGamingEngine.compute_entropy_delta(
            ["a", "b", "c", "a"], ["a", "b", "c", "a"]
        )
        assert delta == pytest.approx(0.0)

    def test_iki_bosluk_sifir(self):
        assert AntiGamingEngine.compute_entropy_delta([], []) == pytest.approx(0.0)

    def test_duzgun_vs_tekilli_bilinen_deger(self):
        """Duzgun 4-eylem = 2.0 bit; tek-eylem = 0.0 bit -> delta = 2.0."""
        delta = AntiGamingEngine.compute_entropy_delta(
            ["a", "a", "a", "a"], ["a", "b", "c", "d"]
        )
        assert delta == pytest.approx(2.0)

    def test_bilinen_shannon_degerleri(self):
        """Iki-eylem dizilişi 1.0 bit; dort-eylem 2.0 bit."""
        assert AntiGamingEngine.compute_entropy_delta(
            ["a", "b"], ["a", "b", "c", "d"]
        ) == pytest.approx(1.0)

    def test_mutlak_deger_simetriktir(self):
        """abs(h_priv - h_pub) oldugu icin arguman sirasi sonucu degistirmez."""
        pub = ["a", "b", "c", "a", "b"]
        priv = ["a", "a", "a", "a", "b"]
        d1 = AntiGamingEngine.compute_entropy_delta(pub, priv)
        d2 = AntiGamingEngine.compute_entropy_delta(priv, pub)
        assert d1 == pytest.approx(d2)
        assert d1 > 0.0

    def test_bir_bosluk_digeri_duzgun(self):
        """Bir havuz bos (0.0 bit), digeri duzgun 2-eylem (1.0 bit) -> 1.0."""
        assert AntiGamingEngine.compute_entropy_delta(
            [], ["a", "b"]
        ) == pytest.approx(1.0)

    def test_sapma_eşigi_uzerinde(self):
        """Sandbagging sinyali: gizli havuz cok daha az cesitli (yuksek delta)."""
        pub = ["a", "b", "c", "d", "a", "b", "c", "d"]
        priv = ["a", "a", "a", "a", "a", "a", "a", "a"]
        delta = AntiGamingEngine.compute_entropy_delta(pub, priv)
        assert delta > AntiGamingEngine.ENTROPY_DELTA_THRESHOLD

    def test_sapma_esigi_altinda(self):
        """Benzer cesitlilik: kucuk delta, anti-gaming alarmi yok."""
        pub = ["a", "b", "c", "a", "b", "c"]
        priv = ["a", "b", "c", "a", "b", "c"]
        assert AntiGamingEngine.compute_entropy_delta(pub, priv) < \
            AntiGamingEngine.ENTROPY_DELTA_THRESHOLD

    def test_hic_negatif_donmez(self):
        """abs() garantisi: her zaman >= 0."""
        for pub, priv in [
            (["a"], ["b", "c", "d"]),
            (["a", "b", "c"], ["a"]),
            ([], ["a", "a", "b"]),
        ]:
            assert AntiGamingEngine.compute_entropy_delta(pub, priv) >= 0.0

    def test_kismi_paylasim_arasi_delta(self):
        """Tamamen farkli ama ayni boyutlu dagilimlar -> cesitlilik esitse
        eylem etiketleri onemli degil, dagilim onemli (delta 0 olabilir)."""
        # Iki dagilim da 2'ser oranli farkli eylemler -> entropi esit -> delta 0
        d = AntiGamingEngine.compute_entropy_delta(
            ["a", "a", "b", "b"], ["x", "x", "y", "y"]
        )
        assert d == pytest.approx(0.0)
