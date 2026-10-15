"""veridrome.certificate.pytest_parser dal-kesen testleri (Kural-1: YENI dosya — mevcut dosyalara DOKUNULMADI).

Modül anatomisi:
  parse_pytest_json(path)  — pytest-json-report dosyasını okur/normalize eder.
  run_pytest_json(args, pytest_cmd) — pytest KOŞAR (subprocess) + JSON üretir;
    eklenti yoksa -v stdout'undan toparlar. subprocess KURAL-4 gereği
    monkeypatch'lenir (gerçek süreç AÇILMAZ).
  _parse_verbose_stdout(stdout) — pytest -v satırlarını girdiye çevirir.

Dal haritasi (D1..D18):
  D1  parse_pytest_json — geçerli zarf: entries/summary/source/raw_summary.
  D2  parse_pytest_json — nodeid boşluk (AT-189) + Türkçe unicode taşınımı.
  D3  parse_pytest_json — outcome çözümleme: doğrudan outcome / call.outcome
      fallback / call.crash → failed.
  D4  parse_pytest_json — duration saniye→milisaniye dönüşümü (<1000 çarpar,
      ≥1000 olduğu gibi; eksik → duration_ms yok).
  D5  parse_pytest_json — dosya yok → FileNotFoundError (mesajında yol).
  D6  parse_pytest_json — geçersiz JSON / boş dosya → ValueError.
  D7  parse_pytest_json — dizin yolu → yakalanmamış IsADirectoryError (uç-dağılım).
  D8  parse_pytest_json — skalar/liste girdilerde boş-entries toleransı.
  D9  parse_pytest_json — raw_summary passthrough (dict/str/None).
  D10 run_pytest_json — eklenti yolu: rapor geçerli → report_format
      "pytest-json-report" + exit_code.
  D11 run_pytest_json — son-çare yolu: bozuk/boş rapor → verbose-stdout.
  D12 run_pytest_json — pytest_cmd/args iletimi + default cmd (`or` fallthrough).
  D13 run_pytest_json — exit_code yayılımı (crash kodu / ikinci süreç rc).
  D14 run_pytest_json — finally temizliği: report dosyası unlink; OSError yutulur.
  D15 run_pytest_json — stdout_tail son-2000-budama.
  D16 _parse_verbose_stdout — outcome anahtar kelimeleri + çok-boşluk + EOL dalı.
  D17 _parse_verbose_stdout — gürültü/özet satırları düşürülür.
  D18 _parse_verbose_stdout — XPASS düşme gap'i: pytest 'XPASS' yazar ama regex
      'XPASSED' bekler → giriş sessizce düşürülür (BULGU — dokunulmadı).

Kural-4: saf-bellek — network/subprocess/socket/gerçek-HTTP YOK; subprocess.run
monkeypatch'li sahte nesneyle, girdiler tmp_path/INLINE-string fixture.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional

import pytest

import veridrome.certificate.core as _core
import veridrome.certificate.pytest_parser as _parser_mod

# ---------------------------------------------------------------------------
# INLINE fixture'lar — örnek pytest çıktıları (subprocess ile pytest KOŞULMAZ)
# ---------------------------------------------------------------------------

PYTEST_JSON_RAPORU: dict[str, Any] = {
    "created": 1_800_000_000.0,
    "duration": 0.5,
    "summary": {"passed": 2, "failed": 1, "skipped": 1, "error": 0, "total": 4},
    "tests": [
        {
            "nodeid": "tests/test_a.py::test_one",
            "outcome": "passed",
            "duration": 0.11,
            "call": {"duration": 0.10, "outcome": "passed"},
        },
        {
            "nodeid": "tests/test_a.py::test_two",
            "outcome": "failed",
            "duration": 0.22,
            "call": {"duration": 0.21, "outcome": "failed"},
        },
        {"nodeid": "tests/test_b.py::test_uc", "outcome": "skipped"},
        {
            "nodeid": "tests/test_b.py::test_kritik[hello world]",
            "outcome": "passed",
            "call": {"outcome": "passed"},
        },
    ],
}

# normalize_results'in ürettiği beklenen girdiler
BEKLENEN_GIRDILER = [
    {"name": "tests/test_a.py::test_one", "outcome": "passed", "duration_ms": 110.0},
    {"name": "tests/test_a.py::test_two", "outcome": "failed", "duration_ms": 220.0},
    {"name": "tests/test_b.py::test_uc", "outcome": "skipped"},
    {"name": "tests/test_b.py::test_kritik[hello world]", "outcome": "passed"},
]

BEKLENEN_OZET = {"total": 4, "passed": 2, "failed": 1, "skipped": 1, "other": 0}

# pytest -v çıktısı (INLINE string — koşulmaz, yalnızca çözümlenir)
VERBOSE_STDOUT = (
    "============================= test session starts ==============================\n"
    "platform linux -- Python 3.14.8\n"
    "rootdir: /home/gokun/veridrome\n"
    "collected 3 items\n"
    "tests/test_a.py::test_one PASSED [ 33%]\n"
    "tests/test_a.py::test_two FAILED [ 66%]\n"
    "tests/test_b.py::test_param[hello world] PASSED [100%]\n"
    "========================= 1 failed, 2 passed in 0.10s =========================\n"
)


def _rapor_yaz(dizin: str, icerik: Any, ad: str = "rapor.json") -> str:
    """INLINE JSON'u tmp dizine yazar; parse_pytest_json'e verilecek yolu döndürür."""
    yol = os.path.join(dizin, ad)
    if isinstance(icerik, str):
        with open(yol, "w", encoding="utf-8") as f:
            f.write(icerik)
    else:
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(icerik, f, ensure_ascii=False)
    return yol


# ---------------------------------------------------------------------------
# subprocess.run sahtesi — gerçek süreç AÇILMAZ (Kural-4)
# ---------------------------------------------------------------------------


class _SahteProc:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


class _SahteSubprocess:
    """subprocess.run yerine: rapor dosyasına yazar/bozuk bırakır, stdout döner.

    mod:
      gecerli     — --report-json yoluna geçerli JSON yazar (eklenti yolu)
      cop         — yola bozuk JSON yazar (parse ValueError)
      bos         — hiç dokunmaz (NamedTemporaryFile zaten boş)
      yaz_ve_sil  — yazar sonra siler (finally unlink'in OSError dalı)
    """

    def __init__(
        self,
        mod: str = "gecerli",
        returncode: int = 0,
        stdout: str = "",
        ikinci_returncode: Optional[int] = None,
    ) -> None:
        self.mod = mod
        self.returncode = returncode
        self.stdout = stdout
        self.ikinci_returncode = ikinci_returncode
        self.cagrilar: list[list[str]] = []
        self._cagri_no = 0
        self.report_yollari: list[str] = []

    def run(self, cmd: list[str], capture_output: bool = False, text: bool = False) -> _SahteProc:
        self.cagrilar.append(list(cmd))
        ilk = self._cagri_no == 0
        self._cagri_no += 1

        if "--report-json" in cmd:
            yol = cmd[cmd.index("--report-json") + 1]
            self.report_yollari.append(yol)
            if self.mod == "gecerli":
                with open(yol, "w", encoding="utf-8") as f:
                    json.dump(PYTEST_JSON_RAPORU, f)
            elif self.mod == "cop":
                with open(yol, "w", encoding="utf-8") as f:
                    f.write("{bu-geçerli-bir-json-değil")
            elif self.mod == "yaz_ve_sil":
                with open(yol, "w", encoding="utf-8") as f:
                    json.dump(PYTEST_JSON_RAPORU, f)
                os.unlink(yol)

        rc = self.returncode
        if not ilk and self.ikinci_returncode is not None:
            rc = self.ikinci_returncode
        return _SahteProc(rc, self.stdout)


@pytest.fixture
def sahte_subprocess(monkeypatch: pytest.MonkeyPatch) -> Any:
    """parser_mod.subprocess'u sahteyle değiştirir; sahteyi döndürür (kurucu)."""

    def kur(
        mod: str = "gecerli",
        returncode: int = 0,
        stdout: str = "",
        ikinci_returncode: Optional[int] = None,
    ) -> _SahteSubprocess:
        sahte = _SahteSubprocess(mod, returncode, stdout, ikinci_returncode)
        monkeypatch.setattr(_parser_mod, "subprocess", sahte)
        return sahte

    return kur


# ===========================================================================
# Modül yüzeyi
# ===========================================================================
class TestModulYuzu:
    def test_all_ihracat_listesi(self) -> None:
        assert _parser_mod.__all__ == ["parse_pytest_json", "run_pytest_json"]

    @pytest.mark.parametrize("fonk", ["parse_pytest_json", "run_pytest_json"],
                             ids=["parse", "run"])
    def test_ihrac_edilen_fonksiyon_cagrilabilir(self, fonk: str) -> None:
        assert callable(getattr(_parser_mod, fonk))

    def test_core_fonksiyonlari_reexport_baglaminda(self) -> None:
        """normalize_results/summarize core'dan aynı nesne olarak bağlanır."""
        assert _parser_mod.normalize_results is _core.normalize_results
        assert _parser_mod.summarize is _core.summarize

    def test_verbose_regex_module_seviyesinde_derlenmis(self) -> None:
        assert hasattr(_parser_mod, "_VERBOSE_RE")
        assert _parser_mod._VERBOSE_RE.pattern.startswith("^(?P<nodeid>.+?)")
        assert "(?P<outcome>PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASSED)" in _parser_mod._VERBOSE_RE.pattern


# ===========================================================================
# parse_pytest_json — başarı yolları (D1..D4)
# ===========================================================================
class TestParsePytestJsonBasari:
    def test_gecerli_rapor_tam(self, tmp_path: str) -> None:
        """D1: geçerli zarf → entries/summary/source/raw_summary birlikte."""
        yol = _rapor_yaz(str(tmp_path), PYTEST_JSON_RAPORU)
        sonuc = _parser_mod.parse_pytest_json(yol)
        assert sonuc["entries"] == BEKLENEN_GIRDILER
        assert sonuc["summary"] == BEKLENEN_OZET
        assert sonuc["source"] == yol
        assert sonuc["raw_summary"] == PYTEST_JSON_RAPORU["summary"]

    def test_nodeid_bosluk_parametrize_korunur(self, tmp_path: str) -> None:
        """D2 (AT-189): '[hello world]' nodeid'i bütünüyle taşınır."""
        yol = _rapor_yaz(str(tmp_path), PYTEST_JSON_RAPORU)
        sonuc = _parser_mod.parse_pytest_json(yol)
        isimler = [e["name"] for e in sonuc["entries"]]
        assert "tests/test_b.py::test_kritik[hello world]" in isimler

    def test_turkce_unicode_nodeid(self, tmp_path: str) -> None:
        """D2: Türkçe karakter içeren nodeid bozulmadan taşınır."""
        rapor = [{"name": "tests/test_türkçe.py::test_ğüış", "outcome": "passed"}]
        yol = _rapor_yaz(str(tmp_path), {"tests": rapor, "summary": {"passed": 1}})
        sonuc = _parser_mod.parse_pytest_json(yol)
        assert sonuc["entries"][0]["name"] == "tests/test_türkçe.py::test_ğüış"
        assert sonuc["summary"]["passed"] == 1

    @pytest.mark.parametrize(
        "outcome,beklenen",
        [("passed", "passed"), ("FAILED", "failed"), ("Skipped", "skipped"),
         ("error", "error"), ("xfail", "xfail")],
        ids=["passed", "failed-buyuk", "skipped-karisik", "error", "xfail"],
    )
    def test_outcome_kucuk_harfe_normallesir(self, tmp_path: str, outcome: str, beklenen: str) -> None:
        """D3: outcome değerleri küçük-harfe normalize edilir."""
        rapor = {"tests": [{"name": "t", "outcome": outcome}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"][0]["outcome"] == beklenen

    def test_call_outcome_fallback(self, tmp_path: str) -> None:
        """D3: doğrudan outcome yoksa call.outcome kullanılır (pytest-json-report)."""
        rapor = {"tests": [{"nodeid": "t::x", "call": {"outcome": "passed"}}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"] == [{"name": "t::x", "outcome": "passed"}]

    def test_call_crash_failed_sayilir(self, tmp_path: str) -> None:
        """D3: call.crash varsa outcome 'failed' olur (fail-closed)."""
        rapor = {"tests": [{"nodeid": "t::y", "call": {"crash": {"exitcode": 1}}}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"][0]["outcome"] == "failed"

    @pytest.mark.parametrize(
        "duration,beklenen",
        [(0.11, 110.0), (0.5, 500.0), (1.5, 1500.0), (2.0, 2000.0), (0.0005, 0.5)],
        ids=["110ms", "500ms", "1500ms", "2000ms-direkt", "yarim-ms"],
    )
    def test_duration_saniyeden_millisaniyeye(self, tmp_path: str, duration: float, beklenen: float) -> None:
        """D4: <1000 saniye → ×1000; ≥1000 → olduğu gibi (yuvarlatılmış)."""
        rapor = {"tests": [{"name": "t::d", "outcome": "passed", "duration": duration}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"][0]["duration_ms"] == beklenen

    def test_duration_yoksa_anahtar_yok(self, tmp_path: str) -> None:
        """D4: duration alanı yoksa duration_ms anahtarı da yoktur."""
        rapor = {"tests": [{"name": "t::n", "outcome": "passed"}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert "duration_ms" not in sonuc["entries"][0]

    def test_duz_liste_girdi(self, tmp_path: str) -> None:
        """D8: zarf olmadan düz JSON listesi de normalize edilir; raw_summary None."""
        rapor = [{"name": "t::a", "outcome": "passed"}, {"name": "t::b", "outcome": "failed"}]
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert len(sonuc["entries"]) == 2
        assert sonuc["summary"]["total"] == 2
        assert sonuc["raw_summary"] is None

    def test_junit_benzeri_tekil_kayit(self, tmp_path: str) -> None:
        """D8: JUnit-benzeri DÜZ tekil kayıt (name/classname/result) normalize edilir."""
        rapor = {"name": "TestX", "classname": "mod", "result": "passed"}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"] == [{"name": "TestX", "outcome": "passed"}]

    def test_icice_testcase_zarfi_acilmaz(self, tmp_path: str) -> None:
        """D8 (uç-dağılım, gözlem): {'testcase': {...}} iç-içe biçim açılmaz.

        normalize_results'in 'testcase' dalı zarfın KENDİSİNİ girdi alır; içteki
        name/outcome alanlarına bakılmaz → boş entries (core.py davranışı).
        """
        rapor = {"testcase": {"name": "TestX", "classname": "mod", "result": "passed"}}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["entries"] == []
        assert sonuc["summary"]["total"] == 0


# ===========================================================================
# parse_pytest_json — başarısız/sınır yolları (D5..D9)
# ===========================================================================
class TestParsePytestJsonBasarisiz:
    def test_dosya_yok(self, tmp_path: str) -> None:
        """D5: bulunamayan dosya → FileNotFoundError, mesajında yol."""
        yol = os.path.join(str(tmp_path), "yok.json")
        with pytest.raises(FileNotFoundError) as exc:
            _parser_mod.parse_pytest_json(yol)
        assert yol in str(exc.value)

    def test_gecersiz_json(self, tmp_path: str) -> None:
        """D6: bozuk JSON → ValueError, mesajında yol."""
        yol = _rapor_yaz(str(tmp_path), "{bu: json-degil")
        with pytest.raises(ValueError) as exc:
            _parser_mod.parse_pytest_json(yol)
        assert yol in str(exc.value)

    def test_bos_dosya(self, tmp_path: str) -> None:
        """D6: boş dosya → ValueError (JSONDecodeError sarmalanmış)."""
        yol = _rapor_yaz(str(tmp_path), "")
        with pytest.raises(ValueError):
            _parser_mod.parse_pytest_json(yol)

    def test_dizin_yolu_isadirectoryerror(self, tmp_path: str) -> None:
        """D7 (uç-dağılım, BULGU): dizin yolu yakalanmamış IsADirectoryError fırlatır.

        except FileNotFoundError / json.JSONDecodeError — IsADirectoryError
        kardeş sınıf olduğu için yakalanmaz; sarmalanmadan doğrudan yayılır.
        """
        with pytest.raises(IsADirectoryError):
            _parser_mod.parse_pytest_json(str(tmp_path))

    @pytest.mark.parametrize(
        "skalar",
        ["42", '"metin"', "true", "null"],
        ids=["int", "str", "bool", "null"],
    )
    def test_skalar_girdi_bos_entries(self, tmp_path: str, skalar: str) -> None:
        """D8: yapısal olmayan JSON → boş entries, raw_summary None, hata YOK."""
        yol = _rapor_yaz(str(tmp_path), skalar)
        sonuc = _parser_mod.parse_pytest_json(yol)
        assert sonuc["entries"] == []
        assert sonuc["summary"]["total"] == 0
        assert sonuc["raw_summary"] is None

    def test_bos_json_listesi(self, tmp_path: str) -> None:
        """D8: boş test listesi → boş entries (kabul, hata yok)."""
        yol = _rapor_yaz(str(tmp_path), {"tests": [], "summary": {}})
        sonuc = _parser_mod.parse_pytest_json(yol)
        assert sonuc["entries"] == []
        assert sonuc["summary"]["total"] == 0
        assert sonuc["raw_summary"] == {}

    def test_raw_summary_string_passthrough(self, tmp_path: str) -> None:
        """D9: raw_summary olduğu gibi (string dahi olsa) taşınır."""
        rapor = {"tests": [{"name": "t::s", "outcome": "passed"}], "summary": "3 passed"}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["raw_summary"] == "3 passed"

    def test_ozet_olmayan_zarf(self, tmp_path: str) -> None:
        """D9: 'summary' anahtarı yoksa raw_summary None olur."""
        rapor = {"tests": [{"name": "t::s", "outcome": "passed"}]}
        sonuc = _parser_mod.parse_pytest_json(_rapor_yaz(str(tmp_path), rapor))
        assert sonuc["raw_summary"] is None
        assert sonuc["summary"]["passed"] == 1

    def test_ayni_girdi_deterministik(self, tmp_path: str) -> None:
        """Aynı dosya iki kez çözümlenir → özdeş sonuç (determinizm)."""
        yol = _rapor_yaz(str(tmp_path), PYTEST_JSON_RAPORU)
        assert _parser_mod.parse_pytest_json(yol) == _parser_mod.parse_pytest_json(yol)


# ===========================================================================
# run_pytest_json — tamamen monkeypatch'li (D10..D15)
# ===========================================================================
class TestRunPytestJsonEklentiYolu:
    def test_eklenti_yolu_basarili(self, sahte_subprocess: Any) -> None:
        """D10: --report-json geçerli → pytest-json-report formatı + entries."""
        sahte = sahte_subprocess(mod="gecerli", returncode=0)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["report_format"] == "pytest-json-report"
        assert sonuc["entries"] == BEKLENEN_GIRDILER
        assert sonuc["summary"] == BEKLENEN_OZET
        assert sonuc["exit_code"] == 0
        assert sonuc["source"].endswith(".json")
        assert sonuc["raw_summary"] == PYTEST_JSON_RAPORU["summary"]

    def test_crash_exit_code_programa_yansir(self, sahte_subprocess: Any) -> None:
        """D13: süreç rc=1 ile çökse de rapor geçerliyse ayrıştırılır (uç-dağılım)."""
        sahte_subprocess(mod="gecerli", returncode=1)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["exit_code"] == 1
        assert sonuc["report_format"] == "pytest-json-report"

    def test_gecerli_rapor_sonrasi_stdout_kullanilmaz(self, sahte_subprocess: Any) -> None:
        """D10: eklenti yolu başarılıysa stdout toplayıcı yola gidilmez."""
        sahte = sahte_subprocess(mod="gecerli", stdout="tests/a.py::test_q PASSED [ 10%]")
        sonuc = _parser_mod.run_pytest_json()
        assert len(sahte.cagrilar) == 1, "ikinci (stdout) süreç açılmamalı"
        assert sonuc["entries"] == BEKLENEN_GIRDILER


class TestRunPytestJsonSonCareYolu:
    def test_bos_rapor_stdout_toparlar(self, sahte_subprocess: Any) -> None:
        """D11: rapor boşsa -v stdout'undan toplanır → verbose-stdout."""
        sahte = sahte_subprocess(mod="bos", stdout=VERBOSE_STDOUT)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["report_format"] == "verbose-stdout"
        assert sonuc["source"] == "stdout"
        assert sonuc["exit_code"] == 0
        assert [e["name"] for e in sonuc["entries"]] == [
            "tests/test_a.py::test_one",
            "tests/test_a.py::test_two",
            "tests/test_b.py::test_param[hello world]",
        ]
        assert [e["outcome"] for e in sonuc["entries"]] == ["passed", "failed", "passed"]
        assert sonuc["summary"]["total"] == 3

    def test_bozuk_rapor_stdout_toparlar(self, sahte_subprocess: Any) -> None:
        """D11: rapor bozuk JSON'sa da son-çare yoluna düşülür."""
        sahte_subprocess(mod="cop", stdout=VERBOSE_STDOUT)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["report_format"] == "verbose-stdout"
        assert len(sonuc["entries"]) == 3

    def test_her_iki_yol_basarisiz_bos_sonuc(self, sahte_subprocess: Any) -> None:
        """D11+D13: rapor bozuk + stdout sessiz → entries boş, exit_code yayılır."""
        sahte_subprocess(mod="cop", stdout="", returncode=3)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["entries"] == []
        assert sonuc["summary"] == {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "other": 0}
        assert sonuc["exit_code"] == 3

    def test_ikinci_surecin_returncode_kullanilir(self, sahte_subprocess: Any) -> None:
        """D13: son-çare yolunda exit_code ikinci süreçten (ikinci_returncode=5)."""
        sahte_subprocess(mod="bos", stdout=VERBOSE_STDOUT, returncode=0, ikinci_returncode=5)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["exit_code"] == 5

    def test_stdout_tail_iki_bin_budama(self, sahte_subprocess: Any) -> None:
        """D15: stdout_tail stdout'un son 2000 karakterine eşittir."""
        uzun = "a" * 3000
        sahte_subprocess(mod="bos", stdout=uzun)
        sonuc = _parser_mod.run_pytest_json()
        assert len(sonuc["stdout_tail"]) == 2000
        assert sonuc["stdout_tail"] == uzun[-2000:]

    def test_stdout_tail_kisa_girdi_oldugu_gibi(self, sahte_subprocess: Any) -> None:
        """D15: 2000'den kısa stdout budanmaz."""
        kisa = "tests/a.py::test_q PASSED [ 10%]\n"
        sahte_subprocess(mod="bos", stdout=kisa)
        sonuc = _parser_mod.run_pytest_json()
        assert sonuc["stdout_tail"] == kisa


class TestRunPytestJsonKomuta:
    def test_default_pytest_cmd(self, sahte_subprocess: Any) -> None:
        """D12: cmd verilmezse [sys.executable, '-m', 'pytest'] kullanılır."""
        sahte = sahte_subprocess(mod="gecerli")
        _parser_mod.run_pytest_json()
        beklenen = [sys.executable, "-m", "pytest", "--report-json"]
        assert sahte.cagrilar[0][:4] == beklenen
        assert sahte.cagrilar[0][-1] == "-q"

    def test_bos_liste_cmd_defaulta_duser(self, sahte_subprocess: Any) -> None:
        """D12 (uç-dağılım): pytest_cmd=[] falsy → default cmd (`or` fallthrough)."""
        sahte = sahte_subprocess(mod="gecerli")
        _parser_mod.run_pytest_json(pytest_cmd=[])
        assert sahte.cagrilar[0][0] == sys.executable

    def test_custom_pytest_cmd_kullanilir(self, sahte_subprocess: Any) -> None:
        """D12: özel pytest_cmd aynen iletilir."""
        sahte = sahte_subprocess(mod="gecerli")
        _parser_mod.run_pytest_json(pytest_cmd=["docker", "exec", "pytest"])
        assert sahte.cagrilar[0][:3] == ["docker", "exec", "pytest"]

    def test_args_her_iki_cagriya_eklenir(self, sahte_subprocess: Any) -> None:
        """D12: args hem eklenti hem son-çare komutuna eklenir."""
        sahte = sahte_subprocess(mod="bos", stdout=VERBOSE_STDOUT)
        _parser_mod.run_pytest_json(args=["tests/test_x.py", "-k", "foo"])
        for cagri in sahte.cagrilar:
            assert cagri[3:6] == ["tests/test_x.py", "-k", "foo"]

    def test_toplama_komutu_flag_dizilimi(self, sahte_subprocess: Any) -> None:
        """D12: son-çare komutu -v/--tb=no/-o addopts= bayraklarını taşır."""
        sahte = sahte_subprocess(mod="bos", stdout=VERBOSE_STDOUT)
        _parser_mod.run_pytest_json()
        toplama = sahte.cagrilar[1]
        for bayrak in ("-v", "--tb=no", "-o", "addopts="):
            assert bayrak in toplama, f"bayrak yok: {bayrak}"


class TestRunPytestJsonTemizlik:
    def test_report_dosyasi_silinir(self, sahte_subprocess: Any) -> None:
        """D14: başarı sonrası geçici report dosyası finally'de unlink edilir."""
        sahte = sahte_subprocess(mod="gecerli")
        _parser_mod.run_pytest_json()
        for yol in sahte.report_yollari:
            assert not os.path.exists(yol), f"geçici dosya silinmemiş: {yol}"

    def test_son_care_sonrasi_da_silinir(self, sahte_subprocess: Any) -> None:
        """D14: son-çare yolunda da report dosyası temizlenir."""
        sahte = sahte_subprocess(mod="bos", stdout=VERBOSE_STDOUT)
        _parser_mod.run_pytest_json()
        for yol in sahte.report_yollari:
            assert not os.path.exists(yol)

    def test_unlink_hatasina_dayanikli(self, sahte_subprocess: Any) -> None:
        """D14: finally unlink dosya çoktan silinmişse OSError yutulur, hata yok."""
        sahte_subprocess(mod="yaz_ve_sil", stdout=VERBOSE_STDOUT)
        sonuc = _parser_mod.run_pytest_json()
        # dosya fake tarafından silindi → parse FileNotFoundError → son-çare yolu
        assert sonuc["report_format"] == "verbose-stdout"
        assert len(sonuc["entries"]) == 3


# ===========================================================================
# _parse_verbose_stdout — INLINE pytest çıktısından çözümleme (D16..D18)
# ===========================================================================
class TestParseVerboseStdout:
    @pytest.mark.parametrize(
        "satir,ad,sonuc",
        [
            ("tests/test_a.py::test_one PASSED [ 12%]", "tests/test_a.py::test_one", "passed"),
            ("tests/test_a.py::test_two FAILED [ 34%]", "tests/test_a.py::test_two", "failed"),
            ("tests/a.py::test_s SKIPPED [ 45%]", "tests/a.py::test_s", "skipped"),
            ("tests/a.py::test_e ERROR [ 55%]", "tests/a.py::test_e", "error"),
            ("tests/a.py::test_xf XFAIL [ 60%]", "tests/a.py::test_xf", "xfail"),
            ("tests/a.py::test_c PASSED", "tests/a.py::test_c", "passed"),
            ("tests/a.py::test_d   FAILED   [ 56%]", "tests/a.py::test_d", "failed"),
            ("tests/a.py::test_passed PASSED [ 50%]", "tests/a.py::test_passed", "passed"),
        ],
        ids=["passed", "failed", "skipped", "error", "xfail", "eol-dali",
             "coklu-bosluk", "nodeid-icinde-gecen"],
    )
    def test_sonuc_satiri_ayristirilir(self, satir: str, ad: str, sonuc: str) -> None:
        """D16: her outcome anahtar kelimesi doğru (ad, outcome) çiftini üretir."""
        girdiler = _parser_mod._parse_verbose_stdout(satir)
        assert girdiler == [{"name": ad, "outcome": sonuc}]

    @pytest.mark.parametrize(
        "satir,ad",
        [
            ("tests/test_a.py::test_param[hello world] PASSED [ 34%]",
             "tests/test_a.py::test_param[hello world]"),
            ("tests/test_a.py::test_param[the quick brown fox] FAILED [ 34%]",
             "tests/test_a.py::test_param[the quick brown fox]"),
        ],
        ids=["hello-world", "the-quick-brown-fox"],
    )
    def test_nodeid_bosluk_iceren_parametrize(self, satir: str, ad: str) -> None:
        """D16 (AT-189): boşluk içeren parametrize kimliği düşürülmez."""
        girdiler = _parser_mod._parse_verbose_stdout(satir)
        assert girdiler[0]["name"] == ad

    def test_crlf_satir_sonu(self) -> None:
        """D16: Windows-tarzı CRLF satır sonları da işlenir."""
        girdiler = _parser_mod._parse_verbose_stdout("tests/a.py::test_n PASSED [ 10%]\r\n")
        assert girdiler == [{"name": "tests/a.py::test_n", "outcome": "passed"}]

    def test_xpass_dusulur_bulgu(self) -> None:
        """D18 (BULGU — dokunulmadı): pytest 'XPASS' yazar, regex 'XPASSED' bekler.

        Sonuç: xpass eden testler son-çare (verbose-stdout) yolunda SESSİZCE
        düşürülür — özet sayısı gerçekten azalır. Üretim kaynağı:
        pytest_parser.py:118-120 (_VERBOSE_RE alternasyonu).
        """
        girdiler = _parser_mod._parse_verbose_stdout("tests/a.py::test_xp XPASS [ 50%]")
        assert girdiler == []

    def test_xpassed_ayristirilir_kaynak_disi(self) -> None:
        """D18: 'XPASSED' (pytest'in hiç yayınlamadığı kelime) eşleşir — gap kanıtı."""
        girdiler = _parser_mod._parse_verbose_stdout("tests/a.py::test_xp XPASSED [ 50%]")
        assert girdiler == [{"name": "tests/a.py::test_xp", "outcome": "xpassed"}]

    @pytest.mark.parametrize(
        "gurultu",
        [
            "========================= 3 passed, 1 failed in 0.50s =========================",
            "========================= 2 failed, 3 passed, 1 skipped in 1.23s =========================",
            "collected 5 items",
            "platform linux -- Python 3.14.8",
            "rootdir: /home/gokun/veridrome",
            "plugins: cov-4.1.0, asyncio-0.23.0",
            "",
            "   ",
            "warning: summary line",
            "==================== short test summary info ====================",
        ],
        ids=["ozet-failed", "ozet-skipped", "collected", "platform", "rootdir",
             "plugins", "bos", "bosluk", "warning", "short-summary"],
    )
    def test_gurultu_satirlari_dusurulur(self, gurultu: str) -> None:
        """D17: özet/bilgi satırları girdi olarak kabul edilmez."""
        assert _parser_mod._parse_verbose_stdout(gurultu) == []

    def test_bos_girdi(self) -> None:
        """D17: boş string → boş liste."""
        assert _parser_mod._parse_verbose_stdout("") == []

    def test_karisik_akis_sirayla(self) -> None:
        """D16/D17: çok satırlı çıktıda sadece sonuç satırları, akış sırasıyla."""
        girdiler = _parser_mod._parse_verbose_stdout(VERBOSE_STDOUT)
        assert [e["name"] for e in girdiler] == [
            "tests/test_a.py::test_one",
            "tests/test_a.py::test_two",
            "tests/test_b.py::test_param[hello world]",
        ]
        assert [e["outcome"] for e in girdiler] == ["passed", "failed", "passed"]

    def test_outcome_sonrasi_yuzde_parantezi(self) -> None:
        """D16: outcome'dan sonra yüzdeparens gelse de eşleşir (' [ 90%]')."""
        girdiler = _parser_mod._parse_verbose_stdout("tests/a.py::test_p SKIPPED [ 90%]")
        assert girdiler == [{"name": "tests/a.py::test_p", "outcome": "skipped"}]
