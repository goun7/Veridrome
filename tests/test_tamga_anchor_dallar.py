"""
Dal-kesen testler: ``veridrome.certificate.tamga_anchor`` — TAMGA zincir-
bağlama/anker modülü ( DALGA-2, EN YÜKSEK ÖNCELİK — mesh-merkezi).

KURAL: bu dosya YALNIZCA yeni test dosyasıdır — üretim modüllerine,
``conftest.py``'ye veya mevcut testlere DOKUNMAZ. Tamamen pure in-memory
( gerçek ağ/RPC/subprocess YOK — ``TestPureInMemory`` kanıtlar); dosya
yazmaları ``tmp_path`` üzerindedir. Sıra-bağımsızdır: modül-globali kirleten
hiçbir test yoktur ( modül sabitleri ``str``/``frozenset`` — değiştirilemez).

Modül anatomisi ( 612 satır): RFC 8785 (JCS) stdlib-only gömülü canonicalizer
( ``es_number``/``jcs``/``jcs_str``), sertifika-bağlama (
``bound_fields``/``anchor_digest``), Tamga zincir-çekirdeği (
``record_hash``/``verify_node_sig``/``read_ledger``/``verify_chain``) ve
pub/sub apisi ( ``publish``/``verify``). ``__all__``'deki 14 ismin TAMAMI
( artı çekirdek özel-fonksiyon ``_append_record``) aşağıda test edilir.

Belgelenen bulgular ( üretime DOKUNULMADI — Kural-1; gerçek burada belgelendi):
  * BULGU-B1: ``verify`` non-dict ``sidecar``'da ( None/str/list/int) veya
    non-dict ``tamga`` alanında ``AttributeError`` FIRLATIR. Docstring'in
    "kötü-veride asla hata fırlatmaz" sözleşmesini ihlal eder — hata-bloğu
    f-string'i güçsüz-nesne üzerinde ``.get`` çağırır. ( ``TestVerifySozlesmeGaci``)
  * BULGU-B2: ``read_ledger``'in UTF-8 decode'u ``for line in f`` yinelemesindedir
    ( try bloğunun DIŞINDA) → 1 MiB altında geçersiz-UTF-8 bayt içeren ledger
    ``UnicodeDecodeError`` fırlatır; ``verify`` yalnız ``OSError`` yakaladığı
    için bu SIZAR. Yine "asla hata fırlatmaz" ihlali. ( ``TestVerifySozlesmeGaci``)
  * BULGU-B3: ``bound_fields`` zorunlu-alan denetimini ``is None`` ile yapar —
    falsy-ama-None-olmayan değerler ( ``""``, ``0``) GEÇER; substance'ı
    olmayan "boş bağ" üretilir. ( ``TestBoundFieldsGecisBoslugu``)
  * BULGU-B4: ``_encode``'in savunma dalı ``isinstance(o, bool)`` ölü-koddur —
    ``bool`` alt-sınıflanamaz, ``True``/``False`` zaten ``is`` ile yakalanır.
  * BULGU-B5: ``verify_chain`` ``node_sig`` denetimini yalnızca anahtar VARSA
    yapar — ``node_id`` içeren ama ``node_sig`` içermeyen kayıt yeşil geçer.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess

import pytest

from veridrome.certificate.didkey import derive_public_key
from veridrome.certificate.didkey import sign as _ed25519_sign
from veridrome.certificate.tamga_anchor import (
    TAMGA_ANCHOR_VERSION,
    TAMGA_OP,
    GENESIS_PREV,
    BozukTamgaZinciriError,
    _append_record,
    anchor_digest,
    bound_fields,
    es_number,
    jcs,
    jcs_str,
    publish,
    read_ledger,
    record_hash,
    verify,
    verify_chain,
    verify_node_sig,
)

# ---------------------------------------------------------------------------
# Ortak yardımcılar — sıra-bağımsız, stateless, dış-bağımlılık YOK
# ---------------------------------------------------------------------------

# Deterministik Ed25519 test-anahtarı ( ağ YOK — pure in-memory).
_NODE_SEED = bytes(range(32))
_NODE_PUB_HEX = derive_public_key(_NODE_SEED).hex()

# 1 MiB satır-bombası sınırı ( __all__'de değil ama normatif davranışın temeli).
_MAX_LINE_OVERHEAD = len('{"pad": ""}')   # 11 bayt ( prefix 9 + suffix 2)


def _cert(cert_id: str = "CID1", content_hash: str = "CH1",
          issuer: str = "did:key:z6Mktest", merkle_root: str = "MR1",
          leaf_count: int = 5, commit: str = "COMMIT1",
          repo=None) -> dict:
    """Başarılı bir ``bound_fields`` için eksiksiz test-geçişi sertifikası."""
    return {
        "cert_id": cert_id,
        "content_hash": content_hash,
        "issuer": issuer,
        "credentialSubject": {
            "merkle_root": merkle_root,
            "merkle_leaf_count": leaf_count,
            "repo": {"commit": commit, "url": "https://example.invalid/repo"}
            if repo is None else repo,
        },
    }


def _bound(**over) -> dict:
    """Tam bir anchor-bağı ( anahtar-kümesi ``bound_fields`` çıktısıyla aynı)."""
    b = {
        "cert_id": "CID1",
        "content_hash": "CH1",
        "merkle_root": "MR1",
        "leaf_count": 5,
        "issuer": "did:key:z6Mktest",
        "commit": "COMMIT1",
    }
    b.update(over)
    return b


def _write_ledger(path, lines) -> None:
    """Ledger'a ham satırlar yazar ( herbirine '\n' ekler)."""
    with open(path, "w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


def _valid_rec(seq: int, prev: str, payload: dict | None = None,
               node_key: bytes | None = None) -> dict:
    """``verify_chain``'den geçen tek bir Tamga grameri kaydı üretir."""
    rec: dict = {"op": TAMGA_OP, "ts": "t", **(payload or {})}
    rec["seq"] = seq
    rec["prev"] = prev
    if node_key is not None:
        rec["node_id"] = derive_public_key(node_key).hex()
    rec["h"] = record_hash(prev, rec)
    if node_key is not None:
        rec["node_sig"] = _ed25519_sign(node_key, rec["h"].encode("utf-8")).hex()
    return rec


def _chain(n: int) -> list:
    """n kayıtlık geçerli bir zincir üretir ( genesis'den başlar)."""
    recs = []
    prev = GENESIS_PREV
    for i in range(1, n + 1):
        rec = _valid_rec(i, prev, {"index": i})
        recs.append(rec)
        prev = rec["h"]
    return recs


# ===========================================================================
# 1. Sabitler + istisna sınıfı
# ===========================================================================

class TestSabitler:
    """TAMGA_ANCHOR_VERSION / TAMGA_OP / GENESIS_PREV — modülün normatif sabitleri.

    Dallar:
      D1: TAMGA_ANCHOR_VERSION == "veridrome-anchor-tamga-1" ( str)
      D2: TAMGA_OP == "veridrome.cert.anchor" ( str)
      D3: GENESIS_PREV == 64×'0' ( sha256 hex-uzunluğu)
      D4: GENESIS_PREV tamamı '0' karakteri
      D5: _HASH_DISI_ALANLAR frozenset {"h","node_sig"} ( değiştirilemez)
    """

    def test_anchor_version_degeri(self):
        # D1
        assert TAMGA_ANCHOR_VERSION == "veridrome-anchor-tamga-1"
        assert isinstance(TAMGA_ANCHOR_VERSION, str)

    def test_tamga_op_degeri(self):
        # D2
        assert TAMGA_OP == "veridrome.cert.anchor"
        assert isinstance(TAMGA_OP, str)

    def test_genesis_prev_degeri(self):
        # D3 + D4
        assert GENESIS_PREV == "0" * 64
        assert len(GENESIS_PREV) == 64
        assert set(GENESIS_PREV) == {"0"}

    def test_hash_disi_alanlar_frozenset(self):
        # D5 — __all__'de değil ama normatif hash-kuralının temeli
        from veridrome.certificate.tamga_anchor import _HASH_DISI_ALANLAR
        assert isinstance(_HASH_DISI_ALANLAR, frozenset)
        assert set(_HASH_DISI_ALANLAR) == {"h", "node_sig"}


class TestBozukTamgaZinciriError:
    """BozukTamgaZinciriError — RuntimeError alt-sınıfı ( fail-closed sinyali).

    Dallar:
      D1: RuntimeError'dan kalıtımlı ( except RuntimeError yakalar)
      D2: mesaj ``str()``'de korunur
      D3: iki örnek bağımsız referanslardır
    """

    def test_runtime_error_alt_sinifi(self):
        # D1
        exc = BozukTamgaZinciriError("test")
        assert isinstance(exc, RuntimeError)
        assert isinstance(exc, Exception)

    def test_mesaj_tasinir(self):
        # D2
        assert "kırık zincir" in str(BozukTamgaZinciriError("kırık zincir"))

    def test_iki_ornek_bagimsizdir(self):
        # D3
        assert BozukTamgaZinciriError("a") is not BozukTamgaZinciriError("a")


# ===========================================================================
# 2. RFC 8785 (JCS) — es_number
# ===========================================================================

class TestEsNumber:
    """es_number — ECMAScript ``Number.prototype.toString`` ( RFC 8785 §3.2.2.2).

    Dallar:
      D1:  NaN → ValueError ( I-JSON altkümesi reddi)
      D2:  +Infinity → ValueError
      D3:  -Infinity → ValueError
      D4:  0.0 → "0"
      D5:  -0.0 → "0" ( ECMAScript eksi-sıfır basmaz — işaret kaybolur)
      D6:  tam-sayı float ( 1.0 → "1" — sondaki-sıfır atma)
      D7:  negatif ( "-" öneki)
      D8:  k <= n <= 21 → sabit-nokta, sıfırlarla uzama ( 1e16 → 17 hane)
      D9:  0 < n <= 21 → ondalık noktalı ( 123.456)
      D10: n == 0 → "0." + s ( 0.293)
      D11: -6 < n < 0 → "0.000ddd" önde-sıfırlı ( 1e-6)
      D12: n <= -6 → üslü, NEGATIF üs ( 1e-7 → "1e-7")
      D13: n > 21 → üslü, POZITIF üs ( 1e21 → "1e+21")
      D14: üslüde k == 1 → mantis tek-hane ( "1e+21", asla "1.e+21")
      D15: üslüde k > 1 → "d.ddde±xx" ( 2.93e-07 → "2.93e-7")
      D16: int girdi ( 5 → "5" — float-tipli olmasa da çalışır)
      D17: ±2^53 sınır-int'leri ( I-JSON güvenli-aralık)
      D18: 256 farklı değer → 256 farklı çıktı ( en-kısa-gösterim çığ-etkisi)
    """

    @pytest.mark.parametrize("deger,beklenen", [
        (0.0, "0"),                        # D4
        (-0.0, "0"),                       # D5
        (1.0, "1"),                        # D6
        (10.0, "10"),                      # D6
        (100.0, "100"),                    # D6
        (-1.0, "-1"),                      # D7
        (-123.456, "-123.456"),            # D7
        (1e16, "10000000000000000"),       # D8 — 17 hane, noktasız
        (1e17, "100000000000000000"),      # D8
        (1e20, "100000000000000000000"),   # D8 — n=21 ( sınır-dahil)
        (123.456, "123.456"),              # D9
        (1000000.5, "1000000.5"),          # D9
        (0.293, "0.293"),                  # D10 — n == 0
        (0.1, "0.1"),                      # D10
        (1e-5, "0.00001"),                 # D11
        (1e-6, "0.000001"),                # D11 — n == -5 ( sınır-dahil)
        (1e-7, "1e-7"),                    # D12 — n == -6 sınırı ( üslü)
        (2.93e-07, "2.93e-7"),             # D15 — docstring vektörü
        (1.2345e-10, "1.2345e-10"),        # D15
        (-2.93e-07, "-2.93e-7"),           # D7 + D15
        (1e21, "1e+21"),                   # D13 + D14
        (1e22, "1e+22"),                   # D13
        (1.5e21, "1.5e+21"),               # D13 + k > 1
        (1.23e22, "1.23e+22"),             # D15'in pozitif-üs hali
    ], ids=lambda v: f"{v!r}" if not isinstance(v, str) else v)
    def test_basari_ciktilari(self, deger, beklenen):
        """ECMAScript Number.prototype.toString referans çıktıları ( D4-D15)."""
        assert es_number(deger) == beklenen

    @pytest.mark.parametrize("deger", [float("nan"), float("inf"), float("-inf")],
                             ids=["nan", "pozitif-inf", "negatif-inf"])
    def test_nan_inf_reddedilir(self, deger):
        # D1 + D2 + D3 — I-JSON ( RFC 7493) altkümesinde değiller
        with pytest.raises(ValueError, match="ijson_number_not_finite"):
            es_number(deger)

    @pytest.mark.parametrize("deger,beklenen", [
        (5, "5"), (-7, "-7"), (0, "0"),
        (2 ** 53, str(2 ** 53)),           # D17 — güvenli-aralık sınırı ( dahil)
        (-(2 ** 53), str(-(2 ** 53))),     # D17
    ], ids=["5", "-7", "0", "2^53", "-2^53"])
    def test_int_girdi_calisir(self, deger, beklenen):
        # D16 + D17
        assert es_number(deger) == beklenen

    @pytest.mark.parametrize("deger", [2 ** 53 + 1, -(2 ** 53 + 1)],
                             ids=["2^53+1", "-(2^53+1)"])
    def test_guvenli_aralik_disi_int_kabul_edilir(self, deger):
        """D16 sınır-davranışı: ``es_number`` int'leri ``str()`` ile yazar —
        I-JSON sınır-denetimi ( "ijson_number_out_of_range") ``jcs``'in
        sorumluluğundadır, ``es_number``'ın değil. Bu test MEVCUT ayrımı
        belgeler: es_number( 2**53+1) → str( 2**53+1), hata YOK."""
        assert es_number(deger) == str(deger)

    def test_benzersiz_degerler_benzersiz_cikti(self):
        # D18 — 256 farklı tamsayı → 256 farklı çıktı
        assert len({es_number(float(i)) for i in range(256)}) == 256


# ===========================================================================
# 3. RFC 8785 (JCS) — jcs / jcs_str
# ===========================================================================

class TestJcs:
    """jcs — RFC 8785 canonical serialization ( UTF-8 bayt-çıkışı).

    Dallar:
      D1:  None → b"null"
      D2:  True → b"true" ( identity-check dalı)
      D3:  False → b"false" ( identity-check dalı)
      D4:  int ∈ [−2^53, 2^53] → ondalıksız ASCII ( ±2^53 sınır-dahil)
      D5:  int ∉ [−2^53, 2^53] → ValueError ( sessiz-yuvarlama YOK)
      D6:  float → es_number ( 1.0 → "1")
      D7:  float NaN/inf → ValueError ( es_number'dan yayılır)
      D8:  str → çift-tırnak + kaçışlar
      D9:  < 0x20 kontrol-karakteri → \\uXXXX küçük-hex
      D10: 0x7f ( DEL) ve 0x20 ( boşluk) → HAM ( < 0x20 DEĞİL — sınır)
      D11: non-ASCII → HAM UTF-8 ( \\uXXXX kaçışı YOK — RFC 8785)
      D12: kaçış tekrarı yok ( literal '\\n' → '\\\\n')
      D13: dict — üye-adları UTF-16-BE sıralı ( §3.2.3)
      D14: dict — BMP-dışı karakter UTF-16 surrogate-birimiyle ÖNCE sıralanır
             ( codepoint sıralamasından FARKLI — RFC 8785'in gerçek dalı)
      D15: dict — boş nesne {}
      D16: dict — non-str anahtar ( int → str(key) ile serileşir)
      D17: list → köşeli-parantez, sıra korunur
      D18: tuple → list ile AYNI çıkış
      D19: boş list/tuple → []
      D20: iç-içe yapılar ( özyineleme)
      D21: desteklenmeyen tip ( object/set/bytes/complex) → TypeError
      D22: kaçış tablosu ( " \\ \\b \\f \\n \\r \\t — 7 giriş)
    """

    @pytest.mark.parametrize("deger,beklenen", [
        (None, b"null"),                                # D1
        (True, b"true"),                                # D2
        (False, b"false"),                              # D3
        (42, b"42"),                                    # D4
        (-7, b"-7"),                                    # D4
        (0, b"0"),                                      # D4
        (2 ** 53, str(2 ** 53).encode()),               # D4 — sınır
        (-(2 ** 53), str(-(2 ** 53)).encode()),         # D4 — sınır
        (1.0, b"1"),                                    # D6
        (123.456, b"123.456"),                          # D6
        ("", b'""'),                                    # D8
        ("a", b'"a"'),                                  # D8
        ('a"b', b'"a\\"b"'),                            # D8 — tırnak kaçışı
        ("\\", b'"\\\\"'),                              # D8 — ters-eğik kaçışı
    ], ids=["None", "True", "False", "42", "-7", "0", "2^53", "-2^53",
            "1.0", "123.456", "bos-str", "a", "tirnak", "ters-eğik"])
    def test_primitif_basarilar(self, deger, beklenen):
        # D1-D8, D22
        assert jcs(deger) == beklenen

    @pytest.mark.parametrize("karakter,cikti", [
        ("\b", b'"\\b"'),          # D22 — backspace ( 0x08)
        ("\f", b'"\\f"'),          # D22 — form-feed ( 0x0c)
        ("\n", b'"\\n"'),          # D22 — LF
        ("\r", b'"\\r"'),          # D22 — CR
        ("\t", b'"\\t"'),          # D22 — tab
        ("\x00", b'"\\u0000"'),    # D9  — NUL
        ("\x01", b'"\\u0001"'),    # D9  — kontrol-karakter, küçük-hex
        ("\x1f", b'"\\u001f"'),    # D9  — en-yüksek < 0x20
        ("\x7f", b'"\x7f"'),       # D10 — DEL HAM ( 0x7f ≮ 0x20)
        (" ", b'" "'),             # D10 — boşluk HAM ( 0x20 ≮ 0x20)
    ], ids=["backspace", "formfeed", "LF", "CR", "tab",
            "NUL", "u0001", "u001f", "DEL-ham", "bosluk-ham"])
    def test_kacis_tablosu(self, karakter, cikti):
        # D9 + D10 + D22 — gerçek kontrol-karakterler ve paycheck sınırları
        assert jcs(karakter) == cikti

    def test_non_ascii_ham_utf8(self):
        # D11 — non-ASCII kaçışlanMAZ, doğrudan UTF-8 baytları
        assert jcs("café") == '"café"'.encode("utf-8")
        # astral emoji — 4-bayt UTF-8; \\uXXXX veya surrogate-pair YOK
        assert jcs("😀") == '"😀"'.encode("utf-8")

    def test_kacis_tekrari_yok(self):
        # D12 — mevcut ters-eğik TEKRAR kaçışlanmaz ( literal '\\n' → '\\\\n')
        assert jcs("\\n") == b'"\\\\n"'        # backslash + n ( literal)
        assert jcs("a\\nb") == b'"a\\\\nb"'

    def test_dict_utf16be_siralama(self):
        # D13 — ASCII anahtarlar UTF-16-BE ( = codepoint) sıralı
        assert jcs({"b": 1, "a": 2, "c": 3}) == b'{"a":2,"b":1,"c":3}'

    def test_dict_utf16be_siralama_codepointten_farkli(self):
        # D14 — BMP-dışı ( astral) karakterin UTF-16 yüksek-surrogate birimi
        # 0xD800-0xDBFF aralığında → U+E000( 0xE000)'dan ÖNCE sıralanır.
        # Python codepoint sıralaması TERS sonuç verir — RFC 8785 §3.2.3'ün
        # UTF-16 kod-birim sıralamasının GERÇEK dalı:
        sonuc = jcs({chr(0xE000): "pu", "\U0001F600": "emoji"})
        assert sonuc.index(b"\xf0\x9f\x98\x80") < sonuc.index(b"\xee\x80\x80")
        assert sorted([chr(0xE000), "\U0001F600"]) == [chr(0xE000), "\U0001F600"]

    def test_dict_bos_ve_ic_ice(self):
        # D15 + D20
        assert jcs({}) == b"{}"
        assert jcs({"a": {"z": 1, "y": [1, 2, 3]}}) == b'{"a":{"y":[1,2,3],"z":1}}'

    def test_dict_non_str_anahtar(self):
        # D16 — int anahtar str()'e çevrilir, UTF-16-BE'ye göre sıralanır:
        # "1" < "10" < "2" ( sayısal DEĞİL — kod-birim leksikografik)
        assert jcs({2: "b", 1: "a", 10: "c"}) == b'{"1":"a","10":"c","2":"b"}'

    def test_list_tuple_esit_cikti(self):
        # D17 + D18
        assert jcs([1, "x", None, True]) == b'[1,"x",null,true]'
        assert jcs((1, "x", None, True)) == b'[1,"x",null,true]'
        assert jcs((1, 2)) == jcs([1, 2])

    def test_bos_list_tuple(self):
        # D19
        assert jcs([]) == b"[]"
        assert jcs(()) == b"[]"

    def test_desteklenmeyen_tip_red(self):
        # D21 — set/bytes/object/complex → TypeError
        for kotu in [{1, 2}, b"bytes", object(), complex(1, 2)]:
            with pytest.raises(TypeError, match="jcs-desteklenmeyen-tip"):
                jcs(kotu)

    @pytest.mark.parametrize("deger", [2 ** 53 + 1, -(2 ** 53 + 1)],
                             ids=["2^53+1", "-(2^53+1)"])
    def test_int_aralik_disi_red(self, deger):
        # D5 — sessiz-yuvarlama ( ECMAScript-double bozulması) yerine RED
        with pytest.raises(ValueError, match="ijson_number_out_of_range"):
            jcs(deger)

    @pytest.mark.parametrize("deger", [float("nan"), float("inf"), float("-inf")],
                             ids=["nan", "inf", "-inf"])
    def test_float_nan_inf_red(self, deger):
        # D7 — es_number'dan yayılan ValueError
        with pytest.raises(ValueError, match="ijson_number_not_finite"):
            jcs(deger)


class TestJcsStr:
    """jcs_str — aynı canonicalization, ``str`` olarak.

    Dallar:
      D1: jcs_str( obj) == jcs( obj).decode("utf-8")
      D2: dönüş-tipi ``str`` ( bytes DEĞIL)
      D3: boş nesne → "{}"
      D4: determinizm — aynı girdi iki çağrıda aynı çıkış
    """

    @pytest.mark.parametrize("deger", [
        None, True, 42, 1.0, "café", [1, 2], {"b": 1, "a": {"y": [1, 2]}},
        {"😀": 1, chr(0xE000): 2},
    ], ids=["None", "True", "42", "1.0", "kafe", "list", "nested", "astral"])
    def test_jcs_str_jcs_bytes_esitlik(self, deger):
        # D1
        assert jcs_str(deger) == jcs(deger).decode("utf-8")

    def test_str_donuyor(self):
        # D2
        assert isinstance(jcs_str({"a": 1}), str)

    def test_bos_nesne(self):
        # D3
        assert jcs_str({}) == "{}"

    def test_determinizm(self):
        # D4 — canonicalization kararı ( sıra-bağımsızlık)
        girdi = {"z": [3, {"b": 1, "a": 0}], "a": "x", "n": None}
        assert jcs(girdi) == jcs(girdi)
        assert jcs_str(girdi) == jcs_str(girdi)


# ===========================================================================
# 4. Sertifika-bağlama — bound_fields / anchor_digest
# ===========================================================================

class TestBoundFields:
    """bound_fields — sertifikadan anchor-bağını çıkarır ( ZORUNLU-alan denetimi).

    Dallar:
      D1:  tam sertifika → 6 alanlı bağ ( başarı)
      D2:  cert non-dict ( str/None/list/int/tuple) → ValueError
      D3:  credentialSubject eksik → ValueError
      D4:  credentialSubject non-dict ( str/None/list) → ValueError
      D5:  cert_id eksik → ValueError ( missing-listesinde)
      D6:  content_hash eksik → ValueError
      D7:  issuer eksik → ValueError
      D8:  merkle_root eksik → ValueError
      D9:  merkle_leaf_count eksik → ValueError
      D10: repo.commit eksik ( repo yok) → ValueError
      D11: repo None → {} fallback → commit None → ValueError
      D12: sertifikadaki ekstra alanlar BAĞA TAŞINMAZ
      D13: birden fazla eksik → hepsi missing-listesinde
    """

    def test_tam_sertifika_basari(self):
        # D1
        bound = bound_fields(_cert())
        assert bound == {
            "cert_id": "CID1", "content_hash": "CH1", "merkle_root": "MR1",
            "leaf_count": 5, "issuer": "did:key:z6Mktest", "commit": "COMMIT1",
        }
        assert set(bound) == {"cert_id", "content_hash", "merkle_root",
                              "leaf_count", "issuer", "commit"}

    @pytest.mark.parametrize("kotu", ["str", None, ["x"], 42, ("t",)],
                             ids=["str", "None", "list", "int", "tuple"])
    def test_non_dict_cert_red(self, kotu):
        # D2
        with pytest.raises(ValueError, match="bir JSON nesnesi değil"):
            bound_fields(kotu)

    @pytest.mark.parametrize("cert", [
        {},                                    # D3 — subject yok
        {"credentialSubject": "str"},          # D4
        {"credentialSubject": None},           # D4
        {"credentialSubject": ["x"]},          # D4
    ], ids=["subject-yok", "subject-str", "subject-None", "subject-list"])
    def test_subject_eksik_veya_non_dict(self, cert):
        # D3 + D4
        with pytest.raises(ValueError, match="credentialSubject eksik"):
            bound_fields(cert)

    @pytest.mark.parametrize("silinen", ["cert_id", "content_hash", "issuer"])
    def test_ust_duzey_alan_eksik(self, silinen):
        # D5 + D6 + D7
        cert = _cert()
        del cert[silinen]
        with pytest.raises(ValueError, match="gerekli alanlar eksik:") as exc:
            bound_fields(cert)
        assert silinen in str(exc.value)

    @pytest.mark.parametrize("silinen", ["merkle_root", "merkle_leaf_count"])
    def test_subject_alani_eksik(self, silinen):
        # D8 + D9 — missing-listesi BAĞ adlarını taşır: sertifika alanı
        # ``merkle_leaf_count`` → bağ alanı ``leaf_count`` ( isim-eşlemesi)
        beklenen_bag_adi = {"merkle_root": "merkle_root",
                            "merkle_leaf_count": "leaf_count"}[silinen]
        cert = _cert()
        del cert["credentialSubject"][silinen]
        with pytest.raises(ValueError, match="gerekli alanlar eksik:") as exc:
            bound_fields(cert)
        assert beklenen_bag_adi in str(exc.value)

    def test_commit_eksik_repo_yok(self):
        # D10 — repo anahtarı hiç yok
        cert = _cert()
        del cert["credentialSubject"]["repo"]
        with pytest.raises(ValueError) as exc:
            bound_fields(cert)
        assert "commit" in str(exc.value)

    def test_repo_none_ise_bos_dict_fallback(self):
        # D11 — subject["repo"]=None → `or {}` fallback → commit None → RED
        cert = _cert()
        cert["credentialSubject"]["repo"] = None
        with pytest.raises(ValueError) as exc:
            bound_fields(cert)
        assert "commit" in str(exc.value)

    def test_ekstra_alanlar_baga_tasinmaz(self):
        # D12 — bağ yalnızca 6 normatif alanı taşır
        cert = _cert()
        cert["extra_top"] = "yok"
        cert["credentialSubject"]["extra_sub"] = "yok"
        cert["credentialSubject"]["repo"]["url"] = "https://example.invalid"
        bound = bound_fields(cert)
        assert "extra_top" not in bound
        assert "extra_sub" not in bound
        assert "url" not in bound
        assert len(bound) == 6

    def test_tum_eksik_birden_fazla_listelenir(self):
        # D13
        with pytest.raises(ValueError) as exc:
            bound_fields({"credentialSubject": {}})
        for alan in ("cert_id", "content_hash", "merkle_root", "leaf_count",
                     "issuer", "commit"):
            assert alan in str(exc.value)


class TestBoundFieldsGecisBoslugu:
    """BULGU-B3 — ``bound_fields`` zorunlu-alan denetimini ``is None`` ile yapar;
    falsy-ama-None-olmayan değerler ( ``""``, ``0``) GEÇER. "Bağlamı-olmayan-çapa"
    üretimini engellemeyen bir geçiş-boşluğu — üretime DOKUNULMADI ( Kural-1),
    gerçek burada belgelendi. Aşağıdaki testler MEVCUT davranışı belgeler.

    Dallar:
      D1: commit="" ( boş commit) → GEÇER ( bağlam yok ama çapa var)
      D2: leaf_count=0 → GEÇER
      D3: tüm alanlar "" / 0 → tamamen-boş bağ GEÇER
      D4: None değerler → RED ( denetimin çalıştığı dal — karşıtlık)
    """

    def test_bos_commit_gecer(self):
        # D1
        assert bound_fields(_cert(commit=""))["commit"] == ""

    def test_sifir_leaf_count_gecer(self):
        # D2
        assert bound_fields(_cert(leaf_count=0))["leaf_count"] == 0

    def test_tamami_bos_bag_gecer(self):
        # D3 — hiçbir substance'ı olmayan bağ üretilir
        cert = _cert(cert_id="", content_hash="", issuer="",
                     merkle_root="", leaf_count=0, commit="")
        assert bound_fields(cert) == {
            "cert_id": "", "content_hash": "", "merkle_root": "",
            "leaf_count": 0, "issuer": "", "commit": "",
        }

    @pytest.mark.parametrize("alan", ["cert_id", "content_hash", "issuer",
                                      "merkle_root", "leaf_count", "commit"])
    def test_none_deger_red(self, alan):
        # D4 — None denetimi çalışır ( falsy-geçiş-boşluğunun tersi).
        # Konum-eşlemesi: bağ alanı → sertifika içindeki yeri.
        cert = _cert()
        if alan in ("merkle_root", "leaf_count"):
            kaynak = "merkle_leaf_count" if alan == "leaf_count" else alan
            cert["credentialSubject"][kaynak] = None
        elif alan == "commit":
            cert["credentialSubject"]["repo"][alan] = None
        else:
            cert[alan] = None
        with pytest.raises(ValueError, match="gerekli alanlar eksik"):
            bound_fields(cert)


class TestAnchorDigest:
    """anchor_digest — sha256( jcs( bound)) ( 64 hex).

    Dallar:
      D1: sha256/jcs ile birebir ( bağımsız-yeniden-hesap)
      D2: 64-hane küçük-hex
      D3: tek-alan değişikliği digest'ı KIRAR
      D4: anahtar-sırası değişse digest AYNI ( JCS sıralar)
      D5: boş-dict → sha256("{}") bilinen değeri
      D6: iki farklı bağ → iki farklı digest
    """

    def test_sha256_jcs_birebir(self):
        # D1
        bound = _bound()
        assert anchor_digest(bound) == hashlib.sha256(jcs(bound)).hexdigest()

    def test_64_kucuk_hex(self):
        # D2
        d = anchor_digest(_bound())
        assert len(d) == 64
        assert all(c in "0123456789abcdef" for c in d)

    @pytest.mark.parametrize("alan,deger", [
        ("cert_id", "CID2"), ("content_hash", "CH2"), ("merkle_root", "MR2"),
        ("leaf_count", 6), ("issuer", "did:key:other"), ("commit", "COMMIT2"),
    ], ids=["cert_id", "content_hash", "merkle_root", "leaf_count", "issuer", "commit"])
    def test_tek_alan_degisikligi_kirar(self, alan, deger):
        # D3 — tek-rakam/tek-bayt değişikliği çapayı kırar
        once = anchor_digest(_bound())
        sonra = anchor_digest(_bound(**{alan: deger}))
        assert once != sonra

    def test_anahtar_sirasi_bagimsiz(self):
        # D4 — dict insertion-sırası digest'ı ETKİLEMEZ
        b1 = _bound()
        b2 = {k: b1[k] for k in reversed(sorted(b1))}
        assert anchor_digest(b1) == anchor_digest(b2)

    def test_bos_dict_bilinen_deger(self):
        # D5
        assert anchor_digest({}) == hashlib.sha256(b"{}").hexdigest()

    def test_iki_farkli_bag_iki_farkli_digest(self):
        # D6
        assert anchor_digest(_bound()) != anchor_digest(_bound(cert_id="BASKA"))


# ===========================================================================
# 5. Zincir-çekirdek — record_hash / verify_node_sig / read_ledger / verify_chain
# ===========================================================================

class TestRecordHash:
    """record_hash — D5 kuralı: h = sha256( prev ‖ jcs( kayıt − {h, node_sig})).

    Dallar:
      D1: prev dize-prefix + jcs gövdesi ( bağımsız-yeniden-hesap)
      D2: ``h`` DIŞARIDA ( kendini hash'leyemez) — h var/yok aynı digest
      D3: ``node_sig`` DIŞARIDA — değeri digest'ı ETKİLEMEZ
      D4: ``node_id`` İÇERİDE — değişince digest kırılır
      D5: prev farklı → digest farklı ( zincir-bağı)
      D6: kayıt anahtar-sırası bağımsız ( JCS sıralar)
      D7: 64-hane hex
      D8:  herhangi bir prev-DEXESI kabul edilir ( format denetimi YOK);
           non-str prev → TypeError ( örtük-tip-denetimi)
    """

    def test_birebir_yeniden_hesap(self):
        # D1
        rec = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV, "ts": "t"}
        beklenen = hashlib.sha256(
            (GENESIS_PREV + jcs_str(rec)).encode("utf-8")).hexdigest()
        assert record_hash(GENESIS_PREV, rec) == beklenen

    def test_h_alani_disarida(self):
        # D2 — h eklemek/çıkarmak digest'ı değiştirmez
        rec = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV, "ts": "t"}
        rec_h = dict(rec, h="ff" * 32)
        assert record_hash(GENESIS_PREV, rec) == record_hash(GENESIS_PREV, rec_h)

    def test_node_sig_disarida(self):
        # D3 — imza-katmanı hash'e girmez
        rec = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV, "ts": "t"}
        rec2 = dict(rec, node_sig="aa" * 64)
        assert record_hash(GENESIS_PREV, rec) == record_hash(GENESIS_PREV, rec2)

    def test_node_id_iceride(self):
        # D4 — node_id hash-girdisine DAHİL ( kimlik bağlanır)
        rec1 = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV, "ts": "t"}
        rec2 = dict(rec1, node_id="ab" * 32)
        assert record_hash(GENESIS_PREV, rec1) != record_hash(GENESIS_PREV, rec2)

    def test_prev_degisince_digest_kirar(self):
        # D5
        rec = {"op": TAMGA_OP, "seq": 1, "ts": "t"}
        assert record_hash(GENESIS_PREV, rec) != record_hash("a" * 64, rec)

    def test_anahtar_sirasi_bagimsiz(self):
        # D6
        rec1 = {"op": TAMGA_OP, "seq": 1, "prev": GENESIS_PREV, "ts": "t"}
        rec2 = {k: rec1[k] for k in reversed(sorted(rec1))}
        assert record_hash(GENESIS_PREV, rec1) == record_hash(GENESIS_PREV, rec2)

    def test_64_hex(self):
        # D7
        h = record_hash(GENESIS_PREV, {"op": "x"})
        assert len(h) == 64
        int(h, 16)   # geçerli hex

    def test_prev_dize_format_denetimi_yok(self):
        # D8 — herhangi DIZE prev kabul edilir ( boş/kısa/uzun/geçersiz-karakter)
        for prev in ["", "kisa", "g" * 64, "!" * 64, "\x00\xff"*32]:
            assert len(record_hash(prev, {"op": "x"})) == 64

    @pytest.mark.parametrize("prev", [None, 42, b"bayt", ["l"]],
                             ids=["None", "int", "bytes", "list"])
    def test_prev_non_str_type_error(self, prev):
        # D8'nin sınırı — prev dize-prefix olarak kullanıldığından non-str
        # tipler TypeError fırlatır ( örtük-tip-denetimi; coerce YOK)
        with pytest.raises(TypeError):
            record_hash(prev, {"op": "x"})


class TestVerifyNodeSig:
    """verify_node_sig — L1 düğüm-ortak-imzası ( Ed25519, didkey katmanı).

    Dallar:
      D1:  geçerli imza → True
      D2:  hatalı imza-bytes → False
      D3:  farklı-mesaj imzası → False
      D4:  node_id eksik → False
      D5:  node_sig eksik → False
      D6:  h eksik → False
      D7:  boş kayıt {} → False
      D8:  non-str değerler ( None/int) → False
      D9:  node_id geçersiz-hex → False
      D10: node_sig geçersiz-hex → False
      D11: node_sig uzunluğu yanlış ( 4 bayt) → False
      D12: node_id uzunluğu yanlış ( 2 bayt) → False
      D13: başka-düğüm-anahtarı pubkey ile → False
      D14: hatalı girişte ASLA hata fırlatmaz ( Exception yönetimi)
    """

    @staticmethod
    def _signed(h="aa" * 32, seed=_NODE_SEED, msg=None) -> dict:
        mesaj = (h if msg is None else msg).encode("utf-8")
        return {
            "node_id": derive_public_key(seed).hex(),
            "node_sig": _ed25519_sign(seed, mesaj).hex(),
            "h": h,
        }

    def test_gecerli_imza_true(self):
        # D1
        assert verify_node_sig(self._signed()) is True

    def test_hatali_imza_false(self):
        # D2
        rec = self._signed()
        rec["node_sig"] = "ff" * 64
        assert verify_node_sig(rec) is False

    def test_farkli_mesaj_imzasi_false(self):
        # D3 — imza başka bir mesaj üzerinden
        assert verify_node_sig(self._signed(msg="baska-mesaj")) is False

    @pytest.mark.parametrize("rec", [
        {},                                                    # D7
        ({"node_sig": "aa" * 64, "h": "aa" * 32}),             # D4
        ({"node_id": _NODE_PUB_HEX, "h": "aa" * 32}),          # D5
        ({"node_id": _NODE_PUB_HEX, "node_sig": "aa" * 64}),   # D6
        ({"node_id": None, "node_sig": None, "h": None}),      # D8
        ({"node_id": 42, "node_sig": 42, "h": 42}),            # D8
        ({"node_id": "zz", "node_sig": "aa" * 64, "h": "aa" * 32}),      # D9
        ({"node_id": _NODE_PUB_HEX, "node_sig": "zz", "h": "aa" * 32}),  # D10
        ({"node_id": _NODE_PUB_HEX, "node_sig": "abcd", "h": "aa" * 32}),  # D11
        ({"node_id": "abcd", "node_sig": "aa" * 64, "h": "aa" * 32}),      # D12
    ], ids=["bos", "node_id-yok", "node_sig-yok", "h-yok", "none-degerler",
            "int-degerler", "kotu-hex-node_id", "kotu-hex-sig",
            "kisa-sig", "kisa-key"])
    def test_basarisizlik_dallari(self, rec):
        # D4-D12 — hepsi False, ASLA hata fırlatmaz
        assert verify_node_sig(rec) is False

    def test_baska_dugum_pubkey_false(self):
        # D13 — doğru imza, ama doğrulama ANOTHER düğümün pubkey'ı ile
        baska = self._signed(seed=bytes(range(1, 33)))
        assert verify_node_sig(baska) is True              # kendi pub'ıyla
        assert verify_node_sig({**baska, "node_id": _NODE_PUB_HEX}) is False

    def test_asla_hata_firlatmaz(self):
        # D14 — Exception yönetimi ( try/except Exception → False)
        assert verify_node_sig({"node_id": object(), "node_sig": object(),
                                "h": object()}) is False


class TestReadLedger:
    """read_ledger — JSONL ledger'ı kayıt-listesine okur ( fail-closed sentinel).

    Dallar:
      D1:  tek geçerli satır → [rec]
      D2:  çok-satır → her satır bir kayıt
      D3:  boş dosya → []
      D4:  boş-boşluk satırları atlanır ( strip)
      D5:  bozuk-JSON satırı → {} sentinel
      D6:  geçerli "{}" satırı → {} ( ayrıştırılabilir boş nesne)
      D7:  1 MiB TAM sınırı ( 1048576 bayt) → HALA ayrıştırılır
      D8:  1 MiB + 1 bayt → {} sentinel ( satır-bombası panzehiri)
      D9:  1 MiB - 1 bayt → ayrıştırılır ( sınır-altı)
      D10: geçersiz-UTF-8 ( < 1 MiB) → UnicodeDecodeError FIRLATIR
           ( BULGU-B2 — decode try'ın DIŞINDA, verify'den sizar)
      D11: olmayan dosya → OSError ( FileNotFoundError)
      D12: baş/son boşluk → strip sonra ayrıştırma başarılı
      D13: son satırda newline YOK → yine okunur
    """

    def test_tek_gecerli_satir(self, tmp_path):
        # D1
        p = tmp_path / "lg.jsonl"
        _write_ledger(p, [json.dumps({"op": "x", "seq": 1})])
        assert read_ledger(str(p)) == [{"op": "x", "seq": 1}]

    def test_cok_satir_karisik(self, tmp_path):
        # D2 + D4 + D5 + D6 — geçerli/boş/bozuk/boş-nesne karışımı
        p = tmp_path / "lg.jsonl"
        _write_ledger(p, [
            json.dumps({"h": "aa"}),      # geçerli
            "",                            # D4 — tamamen boş
            "   ",                         # D4 — boşluk
            "not-json{",                   # D5 — bozuk JSON
            "{}",                          # D6 — geçerli boş nesne
        ])
        assert read_ledger(str(p)) == [{"h": "aa"}, {}, {}]

    def test_bos_dosya(self, tmp_path):
        # D3
        p = tmp_path / "bos.jsonl"
        p.write_text("", encoding="utf-8")
        assert read_ledger(str(p)) == []

    def test_max_line_bytes_tam_sinir_gecerli(self, tmp_path):
        # D7 — tam 1048576 bayt ( stripped) hala ayrıştırılır
        from veridrome.certificate.tamga_anchor import MAX_LINE_BYTES
        satir = '{"pad": "' + "A" * (MAX_LINE_BYTES - _MAX_LINE_OVERHEAD) + '"}'
        assert len(satir.encode("utf-8")) == MAX_LINE_BYTES
        p = tmp_path / "sinir.jsonl"
        _write_ledger(p, [satir])
        recs = read_ledger(str(p))
        assert len(recs) == 1 and "pad" in recs[0]

    def test_max_line_bytes_bir_ust_sentinel(self, tmp_path):
        # D8 — 1048577 bayt → {} sentinel ( RAM sınırlı, fail-closed)
        from veridrome.certificate.tamga_anchor import MAX_LINE_BYTES
        satir = '{"pad": "' + "A" * (MAX_LINE_BYTES - _MAX_LINE_OVERHEAD + 1) + '"}'
        assert len(satir.encode("utf-8")) == MAX_LINE_BYTES + 1
        p = tmp_path / "bomb.jsonl"
        _write_ledger(p, [satir])
        assert read_ledger(str(p)) == [{}]

    def test_bir_alt_gecerli(self, tmp_path):
        # D9 — 1048575 bayt geçerli
        from veridrome.certificate.tamga_anchor import MAX_LINE_BYTES
        satir = '{"pad": "' + "A" * (MAX_LINE_BYTES - _MAX_LINE_OVERHEAD - 1) + '"}'
        p = tmp_path / "alt.jsonl"
        _write_ledger(p, [satir])
        recs = read_ledger(str(p))
        assert len(recs) == 1 and "pad" in recs[0]

    def test_gecersiz_utf8_sentinel_olarak_yutulur_ancank_b2(self, tmp_path):
        # D10 — ANCANK-B2 (DUZELTILDI): artik-ikili-modda-acilir-ve-gecersiz-
        # UTF-8-satiri-bozuk-satir-sentineline-donuser ( okuyucu-cokmez).
        p = tmp_path / "kotu.jsonl"
        p.write_bytes(b'{"h":"aa"}\n\xff\xfe\x00\n{"h":"bb"}\n')
        recs = read_ledger(str(p))
        assert recs[1] == {} and len(recs) == 3

    def test_olmayan_dosya_oserror(self, tmp_path):
        # D11
        with pytest.raises(OSError):
            read_ledger(str(tmp_path / "yok.jsonl"))

    def test_bas_son_bosluk_strip(self, tmp_path):
        # D12
        p = tmp_path / "lg.jsonl"
        _write_ledger(p, ['   {"op": "x"}   '])
        assert read_ledger(str(p)) == [{"op": "x"}]

    def test_son_satir_newlinesiz(self, tmp_path):
        # D13
        p = tmp_path / "lg.jsonl"
        p.write_text('{"a":1}\n{"b":2}', encoding="utf-8")
        assert read_ledger(str(p)) == [{"a": 1}, {"b": 2}]


class TestVerifyChain:
    """verify_chain — Tamga'nın ``_verify_chain`` birebir taklidi ( genesisten).

    Dönen ``(tip, errors)``. Her kırılma TÜM zinciri reddeder ( ilk-hata).

    Dallar:
      D1:  boş kayıt-listesi → ( GENESIS_PREV, [])
      D2:  tek geçerli kayıt → ( rec.h, [])
      D3:  n-geçerli zincir → ( son h, [])
      D4:  kayıt non-dict ( str) → ( None, ["h alanı yok"])
      D5:  kayıtta h yok / {} sentinel → ( None, ["h alanı yok"])
      D6:  prev uyuşmuyor → ( None, ["prev uyuşmuyor"])
      D7:  seq uyuşmuyor → ( None, ["seq ... beklenen ..."])
      D8:  seq float ( 1.0) → GEÇER ( == int 1 — verify'de ayrı dal)
      D9:  h yeniden-hesaplanmıyor → ( None, [h hatası])
      D10: node_sig var ama GEÇERSİZ → ( None, ["node_sig geçersiz"])
      D11: node_sig var ve GEÇERLİ → zincir yeşil
      D12: node_id var, node_sig YOK → yeşil ( BULGU-B5 — denetim anahtara bağlı)
      D13: 2. kayıtta kırılma → ( None, [tek hata])
      D14: seq dize ( "1") → RED ( type-coercion YOK)
      D15: çoklu kırıkta SADECE ilk hata ( kısa-devre)
    """

    def test_bos_zincir_genesis_donuyor(self):
        # D1
        tip, errors = verify_chain([])
        assert tip == GENESIS_PREV
        assert errors == []

    def test_tek_gecerli_kayit(self):
        # D2
        rec = _valid_rec(1, GENESIS_PREV)
        tip, errors = verify_chain([rec])
        assert tip == rec["h"]
        assert errors == []

    def test_n_gecerli_zincir(self):
        # D3 — 5 kayıtlık zincir, tip son kaydın h'si
        recs = _chain(5)
        tip, errors = verify_chain(recs)
        assert tip == recs[-1]["h"]
        assert errors == []

    def test_non_dict_kayit_red(self):
        # D4
        tip, errors = verify_chain(["kayit-degil"])
        assert tip is None
        assert len(errors) == 1 and "h alanı yok" in errors[0]

    @pytest.mark.parametrize("rec", [{}, {"seq": 1, "prev": GENESIS_PREV}],
                             ids=["bos-sentinel", "h-siz"])
    def test_h_alani_yok(self, rec):
        # D5 — {} sentinel ( read_ledger bombası) ve h-siz kayıt aynı yol
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "h alanı yok" in errors[0]

    def test_prev_uyusmuyor(self):
        # D6 — ilk kaydın prev'i genesis DEĞİL
        rec = _valid_rec(1, GENESIS_PREV)
        rec["prev"] = "ff" * 32
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "prev uyuşmuyor" in errors[0]

    def test_seq_uyusmuyor(self):
        # D7 — beklenen 1, kayıt 5
        rec = _valid_rec(1, GENESIS_PREV)
        rec["seq"] = 5
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "seq" in errors[0] and "beklenen 1" in errors[0]

    def test_seq_dize_red(self):
        # D14 — "1" ( str) != 1 ( int) — type-coercion YOK
        rec = _valid_rec(1, GENESIS_PREV)
        rec["seq"] = "1"
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "seq" in errors[0]

    def test_seq_float_gecerli(self):
        # D8 — 1.0 == 1 ( jcs'de aynı çıkış) → zincir YEŞIL; verify'de yakalanır
        rec = _valid_rec(1, GENESIS_PREV)
        rec["seq"] = 1.0
        tip, errors = verify_chain([rec])
        assert errors == []
        assert tip == rec["h"]

    def test_h_yeniden_hesaplanmiyor(self):
        # D9 — kurcalanmış h
        rec = _valid_rec(1, GENESIS_PREV)
        rec["h"] = "de" * 32
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "h yeniden-hesaplanmıyor" in errors[0]

    def test_node_sig_gecersiz(self):
        # D10 — node_sig var, geçersiz → zincir RED
        rec = _valid_rec(1, GENESIS_PREV, node_key=_NODE_SEED)
        rec["node_sig"] = "ff" * 64
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "node_sig geçersiz" in errors[0]

    def test_node_sig_gecerli_yesil(self):
        # D11 — gerçek L1 imza ile zincir yeşil
        rec = _valid_rec(1, GENESIS_PREV, node_key=_NODE_SEED)
        assert verify_node_sig(rec) is True
        tip, errors = verify_chain([rec])
        assert tip == rec["h"] and errors == []

    def test_node_id_var_node_sig_yok_yesil(self):
        # D12 — BULGU-B5: node_sig ANAHTARI yok → imza denetimi YAPILMAZ
        rec = _valid_rec(1, GENESIS_PREV, node_key=_NODE_SEED)
        del rec["node_sig"]
        tip, errors = verify_chain([rec])
        assert errors == [] and tip == rec["h"]

    def test_ikinci_kayitta_kirilma(self):
        # D13 — 2 kayıtlık zincir, 2.'nin prev'i yanlış
        r1, r2 = _chain(2)
        r2["prev"] = "ff" * 32
        tip, errors = verify_chain([r1, r2])
        assert tip is None
        assert len(errors) == 1
        assert errors[0].startswith("zincir kırıldı, seq 2")

    def test_ilk_hata_kisa_devre(self):
        # D15 — 3 kırık kayıttan yalnızca BİRİNCİSÜ raporlanır
        recs = _chain(3)
        for r in recs:
            r["h"] = "00" * 32
        tip, errors = verify_chain(recs)
        assert tip is None
        assert len(errors) == 1
        assert "seq 1" in errors[0]


class TestVerifyChainHataSirasi:
    """verify_chain hata-öncelik sırası: h-alanı → prev → seq → h-yeniden → node_sig.

    Dallar:
      D1: h yok + prev yanlış → "h alanı yok" ( önce)
      D2: prev yanlış + seq yanlış → "prev uyuşmuyor" ( önce)
      D3: seq yanlış + h yanlış → seq hatası ( önce)
      D4: h yanlış + node_sig yanlış → h hatası ( önce)
    """

    def test_h_once_prev_once(self):
        # D1
        tip, errors = verify_chain([{"prev": "yanlis"}])
        assert tip is None
        assert "h alanı yok" in errors[0]

    def test_prev_once_seq_once(self):
        # D2 — sarmalayıcı "zincir kırıldı, seq 1: <neden>" içerdiğinden
        # neden-kısmini denetleriz: prev-uyuşmazlığı, seq-karşılaştırması YOK
        tip, errors = verify_chain([{"h": "aa", "prev": "yanlis", "seq": 9}])
        assert tip is None
        assert errors[0] == "zincir kırıldı, seq 1: prev uyuşmuyor"
        assert "beklenen" not in errors[0]

    def test_seq_once_h_once(self):
        # D3
        rec = _valid_rec(1, GENESIS_PREV)
        rec["seq"] = 9
        rec["h"] = "ee" * 32
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "beklenen 1" in errors[0]

    def test_h_once_nodesig_once(self):
        # D4
        rec = _valid_rec(1, GENESIS_PREV, node_key=_NODE_SEED)
        rec["h"] = "ee" * 32
        tip, errors = verify_chain([rec])
        assert tip is None
        assert "h yeniden-hesaplanmıyor" in errors[0]


# ===========================================================================
# 6. _append_record — akışkan append ( kırık-zinciri uzatmaz)
# ===========================================================================

class TestAppendRecord:
    """_append_record — Tamga gramerinde kayıt ekle ( publish'in çekirdeği).

    Dallar:
      D1:  yeni dosya → seq=1, prev=GENESIS, ts=now
      D2:  mevcut geçerli ledger → seq=n+1, prev=son-h ( zincir akışkan)
      D3:  now=None → varsayılan _now_iso() ( UTC ISO-8601, geçerli zaman)
      D4:  node_key verilirse → node_id + node_sig + h ( node_id İÇERİDE)
      D5:  node_key yok → node_id/node_sig YOK, sadece h
      D6:  node_key'li kaydın imzası verify_node_sig'den GEÇER
      D7:  kırık ledger ( satırlar var, h yok) → BozukTamgaZinciriError
      D8:  sadece-boş-satır dosyası → n=0 → seq=1 ( akıcı başlangıç)
      D9:  chmod 0600 ( Tamga'nın kendi ledger izin-modeli)
      D10: kayıt JSONL olarak yazılır ( tek satır + newline)
      D11: dosyaya append EDILIR ( önceki içerik korunur)
      D12: node_key'li kayıt verify_chain'den geçer
      D13: h, node_id'yi içeren gövdenin hash'idir ( node_sig hariç)
    """

    def test_yeni_dosya_genesis(self, tmp_path):
        # D1
        p = str(tmp_path / "yeni.jsonl")
        rec = _append_record(p, {"op": "x"}, now="2020-01-01T00:00:00+00:00")
        assert rec["seq"] == 1
        assert rec["prev"] == GENESIS_PREV
        assert rec["ts"] == "2020-01-01T00:00:00+00:00"
        assert rec["h"] == record_hash(GENESIS_PREV, rec)

    def test_mevcut_ledger_devam(self, tmp_path):
        # D2 + D11 — ikinci kayıt birincinin h'sine bağlanır
        p = str(tmp_path / "devam.jsonl")
        ilk = _append_record(p, {"op": "x"}, now="2020-01-01T00:00:00+00:00")
        iki = _append_record(p, {"op": "y"}, now="2020-01-02T00:00:00+00:00")
        assert iki["seq"] == 2
        assert iki["prev"] == ilk["h"]
        with open(p, encoding="utf-8") as f:
            satirlar = [ln for ln in f.read().splitlines() if ln.strip()]
        assert len(satirlar) == 2

    def test_now_none_varsayilan_iso(self, tmp_path):
        # D3 — varsayılan ts geçerli ISO-8601, UTC, bu an içinde
        from datetime import datetime, timezone
        once = datetime.now(timezone.utc)
        rec = _append_record(str(tmp_path / "t.jsonl"), {"op": "x"})
        sonra = datetime.now(timezone.utc)
        ts = datetime.fromisoformat(rec["ts"])
        assert ts.tzinfo is not None
        assert once <= ts <= sonra

    def test_node_key_dugum_imzasi(self, tmp_path):
        # D4 + D6 + D12
        p = str(tmp_path / "imzali.jsonl")
        rec = _append_record(p, {"op": "x"}, node_key=_NODE_SEED,
                             now="2020-01-01T00:00:00+00:00")
        assert "node_id" in rec and "node_sig" in rec
        assert rec["node_id"] == _NODE_PUB_HEX
        assert verify_node_sig(rec) is True
        tip, errors = verify_chain(read_ledger(p))
        assert errors == [] and tip == rec["h"]

    def test_node_key_yok_imza_yok(self, tmp_path):
        # D5
        rec = _append_record(str(tmp_path / "plain.jsonl"), {"op": "x"},
                             now="2020-01-01T00:00:00+00:00")
        assert "node_id" not in rec
        assert "node_sig" not in rec
        assert "h" in rec

    def test_kirik_ledger_uzatilmaz(self, tmp_path):
        # D7 — satırlar var ama geçerli head-h yok → fail-closed
        p = str(tmp_path / "kirik.jsonl")
        _write_ledger(p, ["not-json", "alsobad"])
        with pytest.raises(BozukTamgaZinciriError, match="geçerli head-kayıtı yok"):
            _append_record(p, {"op": "x"})

    def test_sadece_bos_satirlar_seq_bir(self, tmp_path):
        # D8 — n=0 ( boş satırlar sayılmaz) → genesis'ten başlanır
        p = str(tmp_path / "bos.jsonl")
        _write_ledger(p, ["", "   "])
        rec = _append_record(p, {"op": "x"}, now="2020-01-01T00:00:00+00:00")
        assert rec["seq"] == 1
        assert rec["prev"] == GENESIS_PREV

    def test_chmod_0600(self, tmp_path):
        # D9 — posix izin-modeli
        if os.name == "nt":
            pytest.skip("posix izin-modeli Windows'da yok")
        p = str(tmp_path / "mod.jsonl")
        _append_record(p, {"op": "x"})
        assert (os.stat(p).st_mode & 0o777) == 0o600

    def test_jsonl_satir_yazilir(self, tmp_path):
        # D10 — her kayıt tek satır + newline
        p = str(tmp_path / "jsonl.jsonl")
        _append_record(p, {"op": "x"}, now="t")
        with open(p, encoding="utf-8") as f:
            ham = f.read()
        assert ham.endswith("\n")
        assert ham.count("\n") == 1
        assert json.loads(ham.strip())["op"] == "x"

    def test_node_id_h_den_once_atanir(self, tmp_path):
        # D13 — node_id h'den ÖNCE atanır: h, node_id'yi KAPSAR
        p = str(tmp_path / "sira.jsonl")
        rec = _append_record(p, {"op": "x"}, node_key=_NODE_SEED,
                             now="2020-01-01T00:00:00+00:00")
        govde = {k: v for k, v in rec.items() if k not in ("h", "node_sig")}
        assert rec["h"] == record_hash(GENESIS_PREV, govde)


# ===========================================================================
# 7. publish — sertifikayı Tamga zincirine sabitle
# ===========================================================================

class TestPublish:
    """publish — sertifikanın bağını Tamga gramerli ledger'a sabitler.

    Dallar:
      D1:  başarılı sidecar {anchor_version, tamga{ledger,seq,h,node_signed},
           bound, digest}
      D2:  node_key'siz → node_signed False
      D3:  node_key'li → node_signed True
      D4:  varsayılan op = TAMGA_OP
      D5:  özel op ledger'a yazılır
      D6:  now verilirse ts olarak yazılır
      D7:  ledger kaydı {op, anchor_version, bound, digest, seq, prev, ts, h}
      D8:  sidecar.digest == anchor_digest( bound) == rec.digest
      D9:  geçersiz sertifika → ValueError YAYILIR ( fail-closed)
      D10: non-dict sertifika → ValueError
      D11: kırık ledger → BozukTamgaZinciriError YAYILIR
      D12: aynı ledger'a 2. publish → seq=2 ( akıcı zincir)
      D13: sidecar tamga.h == ledger kaydının h'si
      D14: farklı bağ → farklı digest
    """

    @staticmethod
    def _roundtrip_cep(tmp_path, **kw):
        p = str(tmp_path / "a.jsonl")
        return publish(_cert(), p, **kw), p

    def test_sidecar_yapisi(self, tmp_path):
        # D1 + D2
        p = str(tmp_path / "a.jsonl")
        sc = publish(_cert(), p)
        assert sc["anchor_version"] == TAMGA_ANCHOR_VERSION
        assert set(sc) == {"anchor_version", "tamga", "bound", "digest"}
        assert set(sc["tamga"]) == {"ledger", "seq", "h", "node_signed"}
        assert sc["tamga"]["ledger"] == p
        assert sc["tamga"]["seq"] == 1
        assert sc["tamga"]["node_signed"] is False
        assert sc["bound"] == _bound()

    def test_node_keyli_node_signed_true(self, tmp_path):
        # D3
        sc = publish(_cert(), str(tmp_path / "s.jsonl"), node_key=_NODE_SEED)
        assert sc["tamga"]["node_signed"] is True

    def test_varsayilan_op_tamga_op(self, tmp_path):
        # D4 + D7
        p = str(tmp_path / "o.jsonl")
        publish(_cert(), p)
        rec = read_ledger(p)[0]
        assert rec["op"] == TAMGA_OP
        assert rec["anchor_version"] == TAMGA_ANCHOR_VERSION
        assert set(rec) == {"op", "anchor_version", "bound", "digest",
                            "seq", "prev", "ts", "h"}

    def test_ozel_op_ve_now(self, tmp_path):
        # D5 + D6
        p = str(tmp_path / "oz.jsonl")
        publish(_cert(), p, op="test.ozel-op", now="2021-05-05T05:05:05+00:00")
        rec = read_ledger(p)[0]
        assert rec["op"] == "test.ozel-op"
        assert rec["ts"] == "2021-05-05T05:05:05+00:00"

    def test_digest_tutarliligi(self, tmp_path):
        # D8 + D13
        p = str(tmp_path / "d.jsonl")
        sc = publish(_cert(), p)
        rec = read_ledger(p)[0]
        assert sc["digest"] == anchor_digest(_bound())
        assert sc["digest"] == rec["digest"]
        assert sc["tamga"]["h"] == rec["h"]

    def test_gecersiz_sertifika_value_error(self, tmp_path):
        # D9 + D10
        with pytest.raises(ValueError, match="credentialSubject eksik"):
            publish({"credentialSubject": "x"}, str(tmp_path / "e.jsonl"))
        with pytest.raises(ValueError, match="bir JSON nesnesi değil"):
            publish("sertifika-degil", str(tmp_path / "e2.jsonl"))

    def test_kirik_ledger_bozuk_hata(self, tmp_path):
        # D11 — kırık kuyruk uzatılmaz
        p = str(tmp_path / "k.jsonl")
        _write_ledger(p, ["not-json"])
        with pytest.raises(BozukTamgaZinciriError):
            publish(_cert(), p)

    def test_iki_publish_seq_iki(self, tmp_path):
        # D12 — zincir akışkan: ikinci çapa birincinin üstüne
        p = str(tmp_path / "iki.jsonl")
        sc1 = publish(_cert(), p, now="2020-01-01T00:00:00+00:00")
        sc2 = publish(_cert(cert_id="CID2"), p, now="2020-01-02T00:00:00+00:00")
        assert sc1["tamga"]["seq"] == 1
        assert sc2["tamga"]["seq"] == 2
        assert sc2["tamga"]["h"] != sc1["tamga"]["h"]
        tip, errors = verify_chain(read_ledger(p))
        assert errors == []
        assert tip == sc2["tamga"]["h"]

    def test_farkli_sertifika_farkli_digest(self, tmp_path):
        # D14
        s1 = publish(_cert(), str(tmp_path / "f1.jsonl"))
        s2 = publish(_cert(cert_id="BASKA"), str(tmp_path / "f2.jsonl"))
        assert s1["digest"] != s2["digest"]


# ===========================================================================
# 8. verify — offline; yalnızca ledger'ın kendi zincir-matematiğine güvenilir
# ===========================================================================

class TestVerify:
    """verify — anchor sidecar'ı adını verdiği ledger'a karşı doğrular.

    Dallar ( başarı):
      D1:  tam roundtrip ( cert ile) → valid, errors []
      D2:  node-imzalı roundtrip → valid, summary node_signed True
      D3:  cert=None → cert-denetimleri atlanır, yine valid
      D4:  summary {cert_id, content_hash, merkle_root, leaf_count, issuer,
                    commit, digest, ledger, seq, h, tip, records, node_signed,
                    anchor_op}
      D5:  çok-kayıtlı ledger'da 2. çapa valid ( records=2)

    Dallar ( başarısızlık — fail-closed):
      D6:  anchor_version yanlış → "bir tamga anchor sidecar'ı değil"
      D7:  sidecar {} → invalid ( anchor_version None)
      D8:  tamga yok / ledger-yok → "sidecar bir ledger belirtmiyor"
      D9:  ledger dosyası mevcut-değil → "ledger-okunamadı"
      D10: cert başka sertifika → "anchor-bağı sertifikayla uyuşmuyor"
      D11: cert geçersiz → errors[0] bound_fields mesajı, summary {}
      D12: sidecar digest ≠ bağ-digest → "anchor digest ... yeniden-hesaplanmıyor"
      D13: seq ledger'da yok → "seq N bir kayıt yok"
      D14: sidecar h ≠ kayıt h → "kayıt h'si sidecar ile uyuşmuyor"
      D15: sidecar bound ≠ kayıt bound → "ledger kaydı bu sertifikanın bağını taşımıyor"
      D16: ledger zinciri kırık → zincir hataları ( TÜM zincir reddi)
      D17: seq float ( 1.0) → "sidecar seq pozitif bir tamsayı olmalı"
      D18: sidecar digest ≠ kayıt digest → "ledger kaydının digest'ı ... uyuşmuyor"
      D19: errors her zaman ``list`` döner ( yapı sözleşmesi)
    """

    @staticmethod
    def _roundtrip(tmp_path, cert=None, **kw):
        cert = _cert() if cert is None else cert
        p = str(tmp_path / "anchor.jsonl")
        sc = publish(cert, p, **kw)
        return sc, verify(sc, cert)

    def test_tam_roundtrip_gecerli(self, tmp_path):
        # D1
        _, rapor = self._roundtrip(tmp_path)
        assert rapor["valid"] is True
        assert rapor["errors"] == []

    def test_node_imzali_roundtrip(self, tmp_path):
        # D2
        _, rapor = self._roundtrip(tmp_path, node_key=_NODE_SEED)
        assert rapor["valid"] is True
        assert rapor["summary"]["node_signed"] is True

    def test_cert_none_gecerli(self, tmp_path):
        # D3 — sertifikasız doğrulama ( yalnız ledger matematiği)
        sc, _ = self._roundtrip(tmp_path)
        assert verify(sc)["valid"] is True

    def test_summary_icerigi(self, tmp_path):
        # D4 — summary'nin beklenen alanları
        sc, rapor = self._roundtrip(tmp_path)
        s = rapor["summary"]
        assert set(s) == {"cert_id", "content_hash", "merkle_root", "leaf_count",
                          "issuer", "commit", "digest", "ledger", "seq", "h",
                          "tip", "records", "node_signed", "anchor_op"}
        assert s["cert_id"] == "CID1"
        assert s["seq"] == 1
        assert s["records"] == 1
        assert s["digest"] == sc["digest"]
        assert s["h"] == sc["tamga"]["h"]
        assert s["anchor_op"] == TAMGA_OP
        assert s["node_signed"] is False
        assert s["tip"] == sc["tamga"]["h"]

    def test_ikinci_cap_gecerli(self, tmp_path):
        # D5 — çok-kayıtlı ledger'da 2. çapa valid
        p = str(tmp_path / "c.jsonl")
        publish(_cert(), p, now="2020-01-01T00:00:00+00:00")
        sc2 = publish(_cert(cert_id="CID2"), p, now="2020-01-02T00:00:00+00:00")
        rapor = verify(sc2, _cert(cert_id="CID2"))
        assert rapor["valid"] is True
        assert rapor["summary"]["records"] == 2
        assert rapor["summary"]["seq"] == 2

    def test_anchor_version_yanlis(self, tmp_path):
        # D6 + D7
        sc, _ = self._roundtrip(tmp_path)
        rapor = verify(dict(sc, anchor_version="YANLIS"))
        assert rapor["valid"] is False
        assert "bir tamga anchor sidecar'ı değil" in rapor["errors"][0]
        rapor2 = verify({})
        assert rapor2["valid"] is False
        assert rapor2["summary"] == {}

    def test_ledger_yok(self, tmp_path):
        # D8 — tamga {} veya ledger anahtarsız
        sc, _ = self._roundtrip(tmp_path)
        kotu = dict(sc)
        kotu["tamga"] = {"h": sc["tamga"]["h"], "seq": 1}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("bir ledger belirtmiyor" in e for e in rapor["errors"])

    def test_ledger_dosyasi_yok(self, tmp_path):
        # D9
        sc, _ = self._roundtrip(tmp_path)
        kotu = dict(sc)
        kotu["tamga"] = {"ledger": str(tmp_path / "YOK.jsonl"),
                         "seq": 1, "h": sc["tamga"]["h"]}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("ledger-okunamadı" in e for e in rapor["errors"])

    def test_cert_baska_sertifika(self, tmp_path):
        # D10 — sidecar CID1'i, eldeki sertifika BASKA'yı söylüyor
        sc, _ = self._roundtrip(tmp_path)
        rapor = verify(sc, _cert(cert_id="BASKA", content_hash="CH9"))
        assert rapor["valid"] is False
        assert any("anchor-bağı sertifikayla uyuşmuyor" in e
                   for e in rapor["errors"])

    def test_cert_gecersiz(self, tmp_path):
        # D11 — bound_fields ValueError → errors[0], summary {}
        sc, _ = self._roundtrip(tmp_path)
        rapor = verify(sc, {"credentialSubject": "x"})
        assert rapor["valid"] is False
        assert "credentialSubject eksik" in rapor["errors"][0]
        assert rapor["summary"] == {}

    def test_sidecar_digest_yanlis(self, tmp_path):
        # D12 + D18 — sidecar digest'ı kurcalanmış
        sc, _ = self._roundtrip(tmp_path)
        rapor = verify(dict(sc, digest="00" * 32), _cert())
        assert rapor["valid"] is False
        assert any("anchor digest, bağdan yeniden-hesaplanmıyor" in e
                   for e in rapor["errors"])
        assert any("ledger kaydının digest'ı sidecar ile uyuşmuyor" in e
                   for e in rapor["errors"])

    def test_seq_yok(self, tmp_path):
        # D13 — iddia edilen seq ledger'da değil
        sc, _ = self._roundtrip(tmp_path)
        kotu = dict(sc)
        kotu["tamga"] = {"ledger": sc["tamga"]["ledger"], "seq": 99,
                         "h": sc["tamga"]["h"]}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("seq 99 bir kayıt yok" in e for e in rapor["errors"])

    def test_sidecar_h_yanlis(self, tmp_path):
        # D14 — sidecar'ın iddia ettiği h kaydın h'si değil
        sc, _ = self._roundtrip(tmp_path)
        kotu = dict(sc)
        kotu["tamga"] = {"ledger": sc["tamga"]["ledger"], "seq": 1,
                         "h": "ff" * 32}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("kayıt h'si sidecar ile uyuşmuyor" in e
                   for e in rapor["errors"])

    def test_ledger_bound_yanlis(self, tmp_path):
        # D15 — sidecar'ın bound'u kaydın bound'ünden farklı ( cert yok)
        sc, _ = self._roundtrip(tmp_path)
        kotu = dict(sc)
        kotu["bound"] = _bound(cert_id="BASKA")
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("ledger kaydı bu sertifikanın bağını taşımıyor" in e
                   for e in rapor["errors"])

    def test_kirik_zincir_red(self, tmp_path):
        # D16 — ledger'ın seq'si kurcalanmış → TÜM zincir reddi
        p = str(tmp_path / "kirik.jsonl")
        publish(_cert(), p, now="2020-01-01T00:00:00+00:00")
        recs = read_ledger(p)
        recs[0]["seq"] = 7
        _write_ledger(p, [json.dumps(r) for r in recs])
        sc = publish(_cert(), str(tmp_path / "baska.jsonl"))
        kotu = dict(sc)
        kotu["tamga"] = {"ledger": p, "seq": 1, "h": read_ledger(p)[0]["h"]}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("zincir kırıldı" in e for e in rapor["errors"])

    def test_seq_float_red(self, tmp_path):
        # D17 — ledger'da seq 1.0 ( verify_chain geçer) ama sidecar'da 1.0
        # int-değil → "pozitif bir tamsayı olmalı"
        p = str(tmp_path / "f.jsonl")
        sc = publish(_cert(), p, now="2020-01-01T00:00:00+00:00")
        rec = read_ledger(p)[0]
        govde = {k: v for k, v in rec.items() if k != "h"}
        govde["seq"] = 1.0
        govde["h"] = record_hash(GENESIS_PREV, govde)
        _write_ledger(p, [json.dumps(govde)])
        kotu = dict(sc)
        kotu["tamga"] = {"ledger": p, "seq": 1.0, "h": govde["h"]}
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert any("seq pozitif bir tamsayı olmalı" in e for e in rapor["errors"])

    @pytest.mark.parametrize("kotu", [
        {"anchor_version": "YANLIS"},
        {},
    ], ids=["version-yok", "bos-sidecar"])
    def test_errors_her_zaman_liste(self, kotu):
        # D19 — hata durumunda errors ``list`` ( yapı sözleşmesi)
        rapor = verify(kotu)
        assert rapor["valid"] is False
        assert isinstance(rapor["errors"], list)


class TestVerifySozlesmeGaci:
    """BULGU-B1 + B2 — ``verify``'in "kötü-veride ASLA hata fırlatmaz" sözleşmesi
    İHLAL EDİLİR. Üretim koduna DOKUNULMADI ( Kural-1); bu testler MEVCUT
    davranışı ( karakterizasyon-testi) belgeler ve raporda açıklanır.

    BULGU-B1: non-dict ``sidecar`` ( None/str/list/int) veya non-dict ``tamga``
      alanı → hata-bloğunun f-string'i güçsüz-nesne üzerinde ``.get`` çağırır →
      ``AttributeError``. ("kötü-veride asla hata fırlatmaz" ihlali.)
    BULGU-B2: ``read_ledger``'in UTF-8 decode'u ``for line in f`` içindedir
      ( try'ın DIŞINDA) → geçersiz-UTF-8 ledger ``UnicodeDecodeError`` fırlatır;
      ``verify`` yalnızca ``OSError`` yakaladığı için bu SIZAR.

    Dallar:
      D1: sidecar None → AttributeError ( B1)
      D2: sidecar str → AttributeError ( B1)
      D3: sidecar list → AttributeError ( B1)
      D4: sidecar int → AttributeError ( B1)
      D5: tamga non-dict ( str) → AttributeError ( B1)
      D6: geçersiz-UTF-8 ledger → UnicodeDecodeError ( B2)
    """

    @pytest.mark.parametrize("kotu", [None, "str", ["x"], 42],
                             ids=["None", "str", "list", "int"])
    def test_non_dict_sidecar_attribute_error(self, kotu):
        # D1-D4 — MEVCUT davranış: AttributeError ( docstring ihlali)
        with pytest.raises(AttributeError):
            verify(kotu)

    def test_non_dict_tamga_attribute_error(self):
        # D5 — anchor_version doğru ama tamga=str → t.get → AttributeError
        sc = {"anchor_version": TAMGA_ANCHOR_VERSION,
              "tamga": "str-degil-dict", "bound": {}, "digest": ""}
        with pytest.raises(AttributeError):
            verify(sc)

    def test_gecersiz_utf8_ledger_reddeder_ancank_b2(self, tmp_path):
        # D6 — ANCANK-B2 (DUZELTILDI): gecersiz-UTF-8-ledger-artik-
        # UnicodeDecodeError-sizmaz-verify-zincir-kirikligi-ile-reddeder.
        p = tmp_path / "kotu.jsonl"
        p.write_bytes(b'{"h":"aa"}\n\xff\xfe\x00\n')
        sc = {"anchor_version": TAMGA_ANCHOR_VERSION,
              "tamga": {"ledger": str(p), "seq": 1, "h": "aa"},
              "bound": {"cert_id": "c"}, "digest": ""}
        sonuc = verify(sc)
        assert sonuc["valid"] is False and sonuc["errors"]


# ===========================================================================
# 9. Uçtan-uca — çapraz-çapa bütünlüğü senaryoları + pure-in-memory kanıtı
# ===========================================================================

class TestUctanUcaCapaButunlugu:
    """Uçtan-uca — publish → verify senaryoları ( kurcalama tespiti).

    Dallar:
      D1: 3 farklı sertifika aynı ledger'da sırayla → hepsi valid
      D2: sertifikanın içeriği geriye-dönük değişirse eski çapa RED
          ( anchor-bağı sertifikayla uyuşmaz — cross-anchor bütünlüğü)
      D3: ledger'daki kaydın bound'u kurcalanırsa → h yeniden-hesaplanmaz → RED
      D4: publish/verify sırasında RPC/ağ/subprocess çağrısı YAPILMAZ
    """

    def test_uc_sertifika_sirayla_gecerli(self, tmp_path):
        # D1
        p = str(tmp_path / "uclu.jsonl")
        scarlar = []
        for i in range(3):
            cert = _cert(cert_id=f"C{i}", content_hash=f"CH{i}",
                         merkle_root=f"MR{i}", leaf_count=i + 1,
                         commit=f"COMMIT{i}")
            scarlar.append((publish(cert, p,
                                    now=f"2020-01-0{i + 1}T00:00:00+00:00"), cert))
        for sc, cert in scarlar:
            rapor = verify(sc, cert)
            assert rapor["valid"] is True, rapor["errors"]

    def test_sertifika_degisince_capa_red(self, tmp_path):
        # D2 — cross-anchor: sertifika geriye-dönük değişti → çapa yakalar
        p = str(tmp_path / "x.jsonl")
        cert = _cert()
        sc = publish(cert, p, now="2020-01-01T00:00:00+00:00")
        assert verify(sc, cert)["valid"] is True
        kurcali = _cert(leaf_count=999)
        rapor = verify(sc, kurcali)
        assert rapor["valid"] is False
        assert any("anchor-bağı sertifikayla uyuşmuyor" in e
                   for e in rapor["errors"])

    def test_ledger_bound_kurcalaninca_red(self, tmp_path):
        # D3 — kaydın bound'u değiştirilirse h yeniden-hesaplanmaz → RED
        p = str(tmp_path / "y.jsonl")
        sc = publish(_cert(), p, now="2020-01-01T00:00:00+00:00")
        assert verify(sc)["valid"] is True
        recs = read_ledger(p)
        recs[0]["bound"] = _bound(cert_id="KURCALANMIS")
        _write_ledger(p, [json.dumps(r) for r in recs])
        rapor = verify(sc)
        assert rapor["valid"] is False
        assert any("h yeniden-hesaplanmıyor" in e for e in rapor["errors"])

    def test_pure_in_memory_dag_yok(self, tmp_path, monkeypatch):
        # D4 — publish/verify sırasında subprocess/socket ASLA çağrılmaz
        def _yasakli(*args, **kwargs):
            raise AssertionError("yasakli dis-cagri ( subprocess/socket)")

        monkeypatch.setattr(subprocess, "Popen", _yasakli)
        monkeypatch.setattr(subprocess, "run", _yasakli)
        monkeypatch.setattr(subprocess, "call", _yasakli)
        monkeypatch.setattr(socket, "socket", _yasakli)
        p = str(tmp_path / "pure.jsonl")
        sc = publish(_cert(), p, node_key=_NODE_SEED,
                     now="2020-01-01T00:00:00+00:00")
        rapor = verify(sc, _cert())
        assert rapor["valid"] is True
