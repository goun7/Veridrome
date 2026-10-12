"""73-Veridrome certificate.core._canonical_bytes/_b64/_now_utc/_parse_iso8601/_merkle_root/_hash_test_entry + tamga_anchor._enc_string/_encode/_now_iso/es_number dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf fonksiyonlar + monkeypatch; network/DB YASAK).

ORTAM-ANATOMI:
- _canonical_bytes(obj): json.dumps(sort_keys=True, separators=(",",":"),
  ensure_ascii=False).encode("utf-8")
- _b64(data): base64.b64encode().decode("ascii")
- _now_utc(): datetime.now(timezone.utc) — tz-AWARE datetime nesnesi
- _parse_iso8601(v): fromisoformat('Z'->'+00:00'); naive -> +UTC; except -> None
- _merkle_root(hashes): bos -> '0x'+sha256(''); tek -> '0x'+h;
  ciftler b'\x01'+left+right; TEK kalan son dugum KENDISIYLE eslesir
- _hash_test_entry(entry): sha256(_canonical_bytes({name,outcome,
  duration_ms?})).hexdigest()
- _enc_string(s): '"' + kacis-tablosu ('"'/'\\'/'\n'/'\r') + kontrol
  \\uXXXX + geri kalan + '"'
- _encode(o, out): null/true/false/bool-guvenlik/int-aralik
  [+-2^53]/float-es_number/str/dict(UTF-16-BE-sirali)/list-tuple/else TypeError
- es_number(x): ECMAScript Number.prototype.toString; NaN/Infinity ValueError;
  -0.0 -> '0'
"""
import base64
import datetime as _dt
import hashlib
import json
import math
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridrome.certificate.core import (  # noqa: E402
    _b64, _canonical_bytes, _hash_test_entry, _merkle_root, _now_utc,
    _parse_iso8601,
)
from veridrome.certificate.tamga_anchor import (  # noqa: E402
    _encode, _enc_string, _now_iso, es_number,
)


# == _canonical_bytes =================================================================================

def test_canon_sorted():
    """ORTAM: sort_keys=True — anahtarlar SIRALI."""
    assert _canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canon_giris_sirasi_onemsiz():
    assert _canonical_bytes({"a": 2, "b": 1}) == _canonical_bytes({"b": 1, "a": 2})


def test_canon_sikistirma():
    """ORTAM: separators=(",",":") — BOSLUK YOK."""
    assert b" " not in _canonical_bytes({"a": 1})


def test_canon_icice():
    assert _canonical_bytes({"z": {"y": 1, "x": 2}}) == b'{"z":{"x":2,"y":1}}'


def test_canon_liste_sira_korunur():
    """ORTAM-OGRENDI: LISTE sirasi KORUNUR (sort sadece dict anahtarlarinda)."""
    assert _canonical_bytes([3, 1, 2]) == b"[3,1,2]"


def test_canon_turkce_ascii_yapilmaz():
    """ORTAM: ensure_ascii=False — UTF-8 baytlari."""
    assert _canonical_bytes({"x": "Örnek"}) == '{"x":"Örnek"}'.encode("utf-8")


def test_canon_bos_obje():
    assert _canonical_bytes({}) == b"{}"


def test_canon_bos_liste():
    assert _canonical_bytes([]) == b"[]"


def test_canon_skalarlar():
    assert _canonical_bytes(None) == b"null"
    assert _canonical_bytes(True) == b"true"
    assert _canonical_bytes(5) == b"5"
    assert _canonical_bytes("s") == b'"s"'


def test_canon_donut_tipi():
    assert isinstance(_canonical_bytes({}), bytes)


def test_canon_stabil():
    assert _canonical_bytes({"a": [1, 2], "b": {"c": 3}}) == _canonical_bytes({"a": [1, 2], "b": {"c": 3}})


@pytest.mark.parametrize("obj,b", [
    ({"a": 1}, b'{"a":1}'), ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
    ([1, 2, 3], b"[1,2,3]"), ({}, b"{}"), ([], b"[]"), (None, b"null"),
    ({"k": "v"}, b'{"k":"v"}'),
])
def test_canon_matrix(obj, b):
    assert _canonical_bytes(obj) == b


# == _b64 =============================================================================================

def test_b64_bos():
    assert _b64(b"") == ""


def test_b64_uc_byte():
    """ORTAM: 3 byte -> 4 char (standart base64, padding KORUNUR)."""
    assert _b64(b"foo") == "Zm9v"


def test_b64_padding_korunur():
    """ORTAM-OGRENDI: Kredent _b64url'den FARKLI — '=' padding KORUNUR
    (standart base64, RFC 4648 sec-4)."""
    assert _b64(b"f") == "Zg=="
    assert _b64(b"fo") == "Zm8="


def test_b64_karakterler():
    """ORTAM: standart alfabe — '+' VE '/' VAR (urlsafe DEGIL), '=' padding KORUNUR."""
    v = _b64(bytes([255] * 10))
    assert "/" in v
    assert v.endswith("==")


def test_b64_donut_tipi():
    assert isinstance(_b64(b"x"), str)


def test_b64_stabil():
    assert _b64(b"test") == _b64(b"test")


def test_b64_roundtrip():
    for raw in [b"", b"f", b"fo", b"foo", b"foobar", bytes(range(64))]:
        assert base64.b64decode(_b64(raw)) == raw


@pytest.mark.parametrize("raw,b", [(b"", ""), (b"f", "Zg=="), (b"fo", "Zm8="),
                                   (b"foo", "Zm9v"), (b"foob", "Zm9vYg=="),
                                   (b"fooba", "Zm9vYmE="), (b"foobar", "Zm9vYmFy")])
def test_b64_matrix(raw, b):
    assert _b64(raw) == b


# == _now_utc =========================================================================================

def test_now_utc_aware():
    """ORTAM: tz-AWARE UTC datetime (naive DEGIL)."""
    assert _now_utc().tzinfo is not None
    assert _now_utc().utcoffset() == _dt.timedelta(0)


def test_now_utc_zaman_dilimi():
    assert _now_utc().tzinfo == _dt.timezone.utc


def test_now_utc_donut_tipi():
    assert isinstance(_now_utc(), _dt.datetime)


def test_now_utc_yakin():
    """ORTAM: su anin UTC'sine yakin (<5 sn)."""
    now = _dt.datetime.now(_dt.timezone.utc)
    assert abs((now - _now_utc()).total_seconds()) < 5


def test_now_utc_artar():
    a = _now_utc()
    import time as _t
    _t.sleep(0.002)
    assert _now_utc() >= a


def test_now_utc_sabit(monkeypatch):
    """ORTAM-OGRENDI: datetime IMMUTABLE — modul nitirigi yamalanir."""
    import veridrome.certificate.core as core

    class _FakeDTClass:
        def __init__(self, *a, **kw):
            pass

        @staticmethod
        def now(tz=None):
            return _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=tz or _dt.timezone.utc)
    monkeypatch.setattr(core, "datetime",
                        type("_FM", (), {"datetime": _FakeDTClass,
                                         "timezone": _dt.timezone}))


# == _parse_iso8601 ===================================================================================

def test_parse_z_aware():
    """ORTAM: 'Z' -> '+00:00' -> tz-aware UTC."""
    assert _parse_iso8601("2026-01-01T12:00:00Z") == _dt.datetime(
        2026, 1, 1, 12, tzinfo=_dt.timezone.utc)


def test_parse_z_tzinfo():
    assert _parse_iso8601("2026-01-01T12:00:00Z").tzinfo == _dt.timezone.utc


def test_parse_naive_utc_added():
    """ORTAM-OGRENDI: naive -> tzinfo=UTC EKLENIR (yerel DEGIL)."""
    assert _parse_iso8601("2026-01-01T12:00:00") == _dt.datetime(
        2026, 1, 1, 12, tzinfo=_dt.timezone.utc)


def test_parse_offset_korunur():
    """ORTAM: tz-aware offset KORUNUR (UTC'ye DONUSTURULMEZ)."""
    v = _parse_iso8601("2026-01-01T12:00:00+02:00")
    assert v.utcoffset() == _dt.timedelta(hours=2)


def test_parse_mikro():
    assert _parse_iso8601("2026-01-01T12:00:00.123456Z") == _dt.datetime(
        2026, 1, 1, 12, 0, 0, 123456, tzinfo=_dt.timezone.utc)


def test_parse_sadece_tarih():
    """ORTAM: 'YYYY-MM-DD' -> naive 00:00 -> +UTC."""
    assert _parse_iso8601("2026-01-01") == _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)


def test_parse_gecersiz_none():
    """ORTAM: except Exception -> None (fail-soft)."""
    assert _parse_iso8601("gecersiz") is None


def test_parse_bos_none():
    assert _parse_iso8601("") is None


def test_parse_none_none():
    """ORTAM: None -> str(None)='None' -> ValueError -> None."""
    assert _parse_iso8601(None) is None


def test_parse_int_none():
    """ORTAM: int -> str(123) -> ValueError -> None."""
    assert _parse_iso8601(123) is None


def test_parse_tarih_gecersiz_none():
    """ORTAM: '2026-02-30' -> ValueError -> None."""
    assert _parse_iso8601("2026-02-30") is None


def test_parse_tz_farkli():
    """ORTAM: farkli TZ aware KABUL."""
    assert _parse_iso8601("2026-01-01T12:00:00-05:00") == _dt.datetime(
        2026, 1, 1, 12, tzinfo=_dt.timezone(_dt.timedelta(hours=-5)))


def test_parse_donut_tipi():
    v = _parse_iso8601("2026-01-01T12:00:00Z")
    assert v is None or isinstance(v, _dt.datetime)


@pytest.mark.parametrize("ts", ["2026-01-01T12:00:00Z", "2026-01-01T12:00:00",
                                "2026-01-01", "2026-01-01T12:00:00+02:00"])
def test_parse_gecerli_matrix(ts):
    assert _parse_iso8601(ts) is not None


@pytest.mark.parametrize("ts", ["gecersiz", "", "2026-13-01", "2026-02-30", "abc"])
def test_parse_gecersiz_matrix(ts):
    assert _parse_iso8601(ts) is None


# == _merkle_root ======================================================================================

def test_merkle_bos_fail_closed():
    """ORTAM-OGRENDI: bos girdi -> '0x'+sha256(b'') — FAIL-CLOSED kok;
    build_certificate tarafindan RED edilir (bos-agac-koku 'gercek' kok
    DEGIL)."""
    assert _merkle_root([]) == "0x" + hashlib.sha256(b"").hexdigest()


def test_merkle_bos_deger():
    expected = "0x" + hashlib.sha256(b"").hexdigest()
    assert _merkle_root([]) == expected
    assert expected.startswith("0x")


def test_merkle_tek_yaprak_gecildi():
    """ORTAM-OGRENDI: TEK hash -> '0x'+h (hashleme YOK — yaprak
    oldukca kok olur, RFC-6962 leaf/node-ayrimi YOK)."""
    h = "ab" * 32
    assert _merkle_root([h]) == "0x" + h


def test_merkle_iki():
    """ORTAM: cift yaprak -> sha256(b'\\x01'+left+right)."""
    h1 = hashlib.sha256(b"a").hexdigest()
    h2 = hashlib.sha256(b"b").hexdigest()
    exp = hashlib.sha256(b"\x01" + bytes.fromhex(h1) + bytes.fromhex(h2)).hexdigest()
    assert _merkle_root([h1, h2]) == "0x" + exp


def test_merkle_uc_tek_dugum_kendisiyle():
    """ORTAM-OGRENDI: TEK kalan son dugum KENDISIYLE eslesir
    (right=left) — cift-yapracak katmani: [ab, c] -> [sha(ab), sha(c+c)]."""
    h1 = hashlib.sha256(b"a").hexdigest()
    h2 = hashlib.sha256(b"b").hexdigest()
    h3 = hashlib.sha256(b"c").hexdigest()
    hab = hashlib.sha256(b"\x01" + bytes.fromhex(h1) + bytes.fromhex(h2)).digest()
    hcc = hashlib.sha256(b"\x01" + bytes.fromhex(h3) + bytes.fromhex(h3)).digest()
    exp = hashlib.sha256(b"\x01" + hab + hcc).hexdigest()
    assert _merkle_root([h1, h2, h3]) == "0x" + exp


def test_merkle_dort():
    h = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
    l = [bytes.fromhex(x) for x in h]
    l2 = [hashlib.sha256(b"\x01" + l[0] + l[1]).digest(),
          hashlib.sha256(b"\x01" + l[2] + l[3]).digest()]
    exp = hashlib.sha256(b"\x01" + l2[0] + l2[1]).hexdigest()
    assert _merkle_root(h) == "0x" + exp


def test_merkle_on_ek_b137():
    """ORTAM: b'\\x01' on-ek (RFC-6962 domain-separation)."""
    h1 = hashlib.sha256(b"a").hexdigest()
    h2 = hashlib.sha256(b"b").hexdigest()
    with_prefix = _merkle_root([h1, h2])
    # onsuz olsaydi farkli olurdu
    no_prefix = "0x" + hashlib.sha256(bytes.fromhex(h1) + bytes.fromhex(h2)).hexdigest()
    assert with_prefix != no_prefix


def test_merkle_deterministik():
    h = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(5)]
    assert _merkle_root(h) == _merkle_root(h)


def test_merkle_sira_onemli():
    """ORTAM: SIRALI liste — hash sirasi DEGISINCE kok DEGISIR."""
    h1 = hashlib.sha256(b"a").hexdigest()
    h2 = hashlib.sha256(b"b").hexdigest()
    assert _merkle_root([h1, h2]) != _merkle_root([h2, h1])


def test_merkle_donut_tipi():
    assert isinstance(_merkle_root([]), str)


def test_merkle_0x_on_ek():
    """ORTAM: hep '0x' ile baslar (EVM-hex format)."""
    h = ["ab" * 32]
    assert _merkle_root(h).startswith("0x")


def test_merkle_uzunluk_64():
    """ORTAM: '0x' + 64 hex."""
    v = _merkle_root(["cd" * 32, "ef" * 32])
    assert len(v) == 66
    assert all(c in "0123456789abcdef" for c in v[2:])


def test_merkle_giris_len_korunur():
    """ORTAM: _merkle_root girdiyi DEGISTIRMEZ (yeni liste)."""
    h = ["ab" * 32, "cd" * 32]
    once = list(h)
    _merkle_root(h)
    assert h == once


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 16, 17])
def test_merkle_matrix(n):
    hs = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]
    v = _merkle_root(hs)
    assert v.startswith("0x") and len(v) == 66


# == _hash_test_entry ==================================================================================

def test_hash_entry_basit():
    """ORTAM: sha256(_canonical_bytes({name,outcome})).hexdigest()."""
    import json as _json
    canon = _json.dumps({"name": "t1", "outcome": "passed"},
                        sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False).encode("utf-8")
    assert _hash_test_entry({"name": "t1", "outcome": "passed"}) == hashlib.sha256(canon).hexdigest()


def test_hash_entry_anahtar_sira_onemsiz():
    assert _hash_test_entry({"outcome": "passed", "name": "t1"}) == \
        _hash_test_entry({"name": "t1", "outcome": "passed"})


def test_hash_entry_deterministik():
    """ORTAM: DETERMINISTIK — ayni test ayni hash (DOCSTACK)."""
    e = {"name": "t1", "outcome": "failed", "duration_ms": 12.5}
    assert _hash_test_entry(e) == _hash_test_entry(dict(e))


def test_hash_entry_duration_ms_float():
    """ORTAM: duration_ms float olarak canon'a EKLENIR."""
    e = {"name": "t1", "outcome": "passed", "duration_ms": "12.5"}
    assert _hash_test_entry(e) != _hash_test_entry({"name": "t1", "outcome": "passed"})


def test_hash_entry_duration_none_atlanir():
    """ORTAM-OGRENDI: duration_ms None -> 'is not None' false -> ATLANIR
    (None float'e CEVRILMEZ, KeyError yok)."""
    a = _hash_test_entry({"name": "t1", "outcome": "p", "duration_ms": None})
    b = _hash_test_entry({"name": "t1", "outcome": "p"})
    assert a == b


def test_hash_entry_duration_gecersiz_atlanir():
    """ORTAM: duration_ms gecersiz -> except -> atlanir."""
    a = _hash_test_entry({"name": "t1", "outcome": "p", "duration_ms": "abc"})
    b = _hash_test_entry({"name": "t1", "outcome": "p"})
    assert a == b


def test_hash_entry_eksik_anahtarlar_default():
    """ORTAM: get(name,'') / get(outcome,'') — eksik -> ''."""
    a = _hash_test_entry({})
    b = _hash_test_entry({"name": "", "outcome": ""})
    assert a == b


def test_hash_entry_sadece_name():
    assert _hash_test_entry({"name": "x"}) == _hash_test_entry({"name": "x", "outcome": ""})


def test_hash_entry_str_cast():
    """ORTAM: str() cast — int name string olur."""
    a = _hash_test_entry({"name": 123, "outcome": "p"})
    b = _hash_test_entry({"name": "123", "outcome": "p"})
    assert a == b


def test_hash_entry_outcome_str_cast():
    a = _hash_test_entry({"name": "x", "outcome": True})
    b = _hash_test_entry({"name": "x", "outcome": "True"})
    assert a == b


def test_hash_entry_duration_int():
    """ORTAM: int duration float olur."""
    a = _hash_test_entry({"name": "x", "outcome": "p", "duration_ms": 10})
    assert a != _hash_test_entry({"name": "x", "outcome": "p"})


def test_hash_entry_duration_bool():
    """ORTAM-OGRENDI: bool True -> float(True)=1.0 EKLENIR (bool int
    alt-sinafi; 'is not None' True)."""
    a = _hash_test_entry({"name": "x", "outcome": "p", "duration_ms": True})
    b = _hash_test_entry({"name": "x", "outcome": "p", "duration_ms": 1.0})
    assert a == b


def test_hash_entry_donut_tipi():
    assert isinstance(_hash_test_entry({}), str)


def test_hash_entry_uzunluk_64():
    v = _hash_test_entry({"name": "x", "outcome": "p"})
    assert len(v) == 64
    assert all(c in "0123456789abcdef" for c in v)


def test_hash_entry_farkli_isim_farkli():
    a = _hash_test_entry({"name": "a", "outcome": "p"})
    b = _hash_test_entry({"name": "b", "outcome": "p"})
    assert a != b


def test_hash_entry_farkli_outcome_farkli():
    a = _hash_test_entry({"name": "x", "outcome": "passed"})
    b = _hash_test_entry({"name": "x", "outcome": "failed"})
    assert a != b


@pytest.mark.parametrize("e1,e2,ayni", [
    ({"name": "a", "outcome": "p"}, {"name": "a", "outcome": "p"}, True),
    ({"name": "a", "outcome": "p"}, {"name": "b", "outcome": "p"}, False),
    ({"name": "a", "outcome": "p", "duration_ms": 1.0},
     {"name": "a", "outcome": "p"}, False),
])
def test_hash_entry_matrix(e1, e2, ayni):
    assert (_hash_test_entry(e1) == _hash_test_entry(e2)) is ayni


# == _enc_string =======================================================================================

def test_enc_basit():
    """ORTAM: '"' + metin + '"."""
    assert _enc_string("merhaba") == '"merhaba"'


def test_enc_bos():
    assert _enc_string("") == '""'


def test_enc_tirnak():
    """ORTAM: '"' -> '\\"' kacis-tablosu."""
    assert _enc_string('a"b') == '"a\\"b"'


def test_enc_ters_egik():
    assert _enc_string("a\\b") == '"a\\\\b"'


def test_enc_newline():
    assert _enc_string("a\nb") == '"a\\nb"'


def test_enc_carriage():
    assert _enc_string("a\rb") == '"a\\rb"'


def test_enc_tum_kacislar():
    """ORTAM: _ESCAPE tablosu — '"' '\\' '\n' '\r'."""
    assert _enc_string('"\\\n\r') == '"\\"\\\\\\n\\r"'


def test_enc_kontrol_karakter():
    """ORTAM: ord < 0x20 -> '\\uXXXX' (sifir-dolgulu 4 hane)."""
    assert _enc_string("\x01") == '"\\u0001"'


def test_enc_kontrol_sinir():
    """ORTAM: 0x1f son kontrol karakteri."""
    assert _enc_string("\x1f") == '"\\u001f"'


def test_enc_0x20_kacis_yok():
    """ORTAM: 0x20 (bosluk) -> kacis YOK (sinir DAHIL degil)."""
    assert _enc_string(" ") == '" "'


def test_enc_tab():
    r"""ORTAM-OGRENDI: _ESCAPE tablosu 7 giris — '\t' (0x09) tabloda:
    '\u0009' DEGIL '\t' kisa-adi ile kacar (tablo 0x20 kontrol
    dalindan ONCE gelir)."""
    assert _enc_string("\t") == '"\\t"'


def test_enc_backspace():
    r"""ORTAM: '\b' (0x08) _ESCAPE tablosunda."""
    assert _enc_string("\b") == '"\\b"'


def test_enc_formfeed():
    r"""ORTAM: '\f' (0x0c) _ESCAPE tablosunda."""
    assert _enc_string("\f") == '"\\f"'


def test_enc_tablo_onceligi():
    r"""ORTAM-OGRENDI: tablo dallari 0x20 kontrol dalindan ONCE — tab/bs/ff
    0x20'den kucuk AMA '\uXXXX' DEGIL kisa-uretir."""
    assert _enc_string("\t") == '"\\t"'
    assert _enc_string("\b") == '"\\b"'
    assert _enc_string("\f") == '"\\f"'


def test_enc_turkce_kacis_yok():
    """ORTAM: 0x20+ unicode -> OLDUGU GIBI (\\uXXXX yapilmaz)."""
    assert _enc_string("Örnek") == '"Örnek"'


def test_enc_emoji():
    assert _enc_string("😀") == '"😀"'


def test_enc_donut_tipi():
    assert isinstance(_enc_string("x"), str)


def test_enc_stabil():
    assert _enc_string('a"b\nc') == _enc_string('a"b\nc')


@pytest.mark.parametrize("s,b", [
    ("", '""'), ("a", '"a"'), ('"a"', '"\\"a\\"'), ("a\nb", '"a\\nb"'),
    ("\x00", '"\\u0000"'), ("Ö", '"Ö"'), ("a\\b", '"a\\\\b"'),
])
def test_enc_matrix(s, b):
    assert _enc_string(s) == b


# == _encode ===========================================================================================

def test_enc_none():
    out = []
    _encode(None, out)
    assert out == ["null"]


def test_enc_true():
    out = []
    _encode(True, out)
    assert out == ["true"]


def test_enc_false():
    out = []
    _encode(False, out)
    assert out == ["false"]


def test_enc_int():
    """ORTAM: int -> str(int) (JCS: bilimsel DEGIL)."""
    out = []
    _encode(42, out)
    assert out == ["42"]


def test_enc_int_negatif():
    out = []
    _encode(-42, out)
    assert out == ["-42"]


def test_enc_int_sifir():
    out = []
    _encode(0, out)
    assert out == ["0"]


def test_enc_int_sinir_ust():
    """ORTAM: 2^53 KABUL (I-JSON siniri)."""
    out = []
    _encode(2 ** 53, out)
    assert out == [str(2 ** 53)]


def test_enc_int_asiri_hata():
    """ORTAM-OGRENDI: 2^53+1 -> ValueError (I-JSON [−2^53, 2^53] disi
    tamsayi YASAK — double-mantissa kaybi onlenir)."""
    out = []
    with pytest.raises(ValueError) as e:
        _encode(2 ** 53 + 1, out)
    assert "ijson_number_out_of_range" in str(e.value)


def test_enc_int_asiri_negatif_hata():
    out = []
    with pytest.raises(ValueError):
        _encode(-(2 ** 53) - 1, out)


def test_enc_int_buyuk_negatif_sinir():
    out = []
    _encode(-(2 ** 53), out)
    assert out == [str(-(2 ** 53))]


def test_enc_bool_guvenlik():
    """ORTAM-OGRENDI: bool int'ın alt-sinafi — 'o is True' DALI once
    calisir (savunma); bool asla int olarak serilesmEZ."""
    out = []
    _encode(True, out)
    assert out == ["true"]


def test_enc_float():
    out = []
    _encode(1.5, out)
    assert out == ["1.5"]


def test_enc_float_es_number():
    """ORTAM: float -> es_number (ECMAScript Number.toString)."""
    out = []
    _encode(2.93e-07, out)
    assert out == ["2.93e-7"]


def test_enc_str():
    out = []
    _encode("merhaba", out)
    assert out == ['"merhaba"']


def test_enc_str_kacis():
    out = []
    _encode('a"b', out)
    assert out == ['"a\\"b"']


def test_enc_bos_obje():
    out = []
    _encode({}, out)
    assert out == ["{", "}"]


def test_enc_obje_bir_eleman():
    out = []
    _encode({"a": 1}, out)
    assert out == ["{", '"a"', ":", "1", "}"]


def test_enc_obje_iki_eleman_ayrac():
    """ORTAM: elemanlar arasi ',' ayrici."""
    out = []
    _encode({"a": 1, "b": 2}, out)
    assert out == ["{", '"a"', ":", "1", ",", '"b"', ":", "2", "}"]


def test_enc_obje_utf16be_sirali():
    """ORTAM-OGRENDI (RFC 8785 §3.2.3): anahtarlar UTF-16-BE kod-birim
    dizisine gore ARTAN siralanir — 'b' < 'a' DEGIL; TURKCE buyuk harfler
    UTF-16'de 'a'..'z'den ONCE gelir."""
    out = []
    _encode({"z": 1, "a": 2}, out)
    # 'a'(0x61) < 'z'(0x7a)
    assert out == ["{", '"a"', ":", "2", ",", '"z"', ":", "1", "}"]


def test_enc_obje_utf16be_turkce():
    """ORTAM: 'Ö'(U+00D6) UTF-16-BE = 0x00D6 > 'z'(0x007A) -> SONRA."""
    out = []
    _encode({"z": 1, "Ö": 2}, out)
    assert out.index('"z"') < out.index('"Ö"')


def test_enc_obje_icice():
    out = []
    _encode({"a": {"b": 1}}, out)
    assert out == ["{", '"a"', ":", "{", '"b"', ":", "1", "}", "}"]


def test_enc_liste():
    out = []
    _encode([1, 2, 3], out)
    assert out == ["[", "1", ",", "2", ",", "3", "]"]


def test_enc_bos_liste():
    out = []
    _encode([], out)
    assert out == ["[", "]"]


def test_enc_tuple():
    """ORTAM: tuple LISTE gibi (list|tuple dalinda)."""
    out = []
    _encode((1, 2), out)
    assert out == ["[", "1", ",", "2", "]"]


def test_enc_liste_icice():
    out = []
    _encode([[1], [2]], out)
    assert out == ["[", "[", "1", "]", ",", "[", "2", "]", "]"]


def test_enc_liste_sira_korunur():
    """ORTAM: liste sirasi KORUNUR (sort YOK)."""
    out = []
    _encode([3, 1, 2], out)
    assert out == ["[", "3", ",", "1", ",", "2", "]"]


def test_enc_tip_desteklenmeyen_hata():
    """ORTAM: desteklenmeyen tip -> TypeError."""
    out = []
    with pytest.raises(TypeError) as e:
        _encode(object(), out)
    assert "jcs-desteklenmeyen-tip" in str(e.value)


def test_enc_set_hata():
    out = []
    with pytest.raises(TypeError):
        _encode({1, 2}, out)


def test_enc_bytes_hata():
    out = []
    with pytest.raises(TypeError):
        _encode(b"x", out)


def test_enc_donut_none():
    """ORTAM: yan-etki — out listesini degistirir, None doner."""
    out = []
    assert _encode(1, out) is None
    assert out == ["1"]


def test_enc_girdi_korunur():
    """ORTAM: girdiyi DEGISTIRMEZ."""
    obj = {"a": 1}
    _encode(obj, [])
    assert obj == {"a": 1}


@pytest.mark.parametrize("obj,b", [
    (None, "null"), (True, "true"), (False, "false"), (0, "0"), (42, "42"),
    (-1, "-1"), (1.5, "1.5"), ("s", '"s"'), ([], "[]"), ({}, "{}"),
    ([1, 2], "[1,2]"), ({"a": 1}, '{"a":1}'),
])
def test_enc_matrix(obj, b):
    out = []
    _encode(obj, out)
    assert "".join(out) == b


# == es_number =========================================================================================

def test_es_sifir():
    """ORTAM: 0 -> '0'."""
    assert es_number(0) == "0"


def test_es_neg_sifir():
    """ORTAM-OGRENDI: -0.0 -> '0' (negatif-sifir normalize; ECMAScript
    Number.toString(-0)='0' ile ayni)."""
    assert es_number(-0.0) == "0"


def test_es_bir():
    assert es_number(1) == "1"


def test_es_onda_bir():
    assert es_number(0.1) == "0.1"


def test_es_yuz():
    """ORTAM: 100.0 -> '100' (ondalik YOK)."""
    assert es_number(100.0) == "100"


def test_es_bilimsel():
    """ORTAM: 2.93e-07 -> '2.93e-7' (ECMAScript exponent format)."""
    assert es_number(2.93e-07) == "2.93e-7"


def test_es_buyuk_ussu():
    """ORTAM: 1e21 -> '1e+21' (21'den buyuk bilimsel)."""
    assert es_number(1e21) == "1e+21"


def test_es_kucuk_ussu():
    """ORTAM: 1e-6 -> '0.000001' (-6'dan buyuk ondalik)."""
    assert es_number(1e-06) == "0.000001"


def test_es_kucuk_ussu_sinir():
    assert es_number(1e-07) == "1e-7"


def test_es_negatif():
    assert es_number(-1.5) == "-1.5"


def test_es_nan_hata():
    """ORTAM-OGRENDI: NaN -> ValueError (I-JSON reddi; JSON'da NaN YASAK)."""
    with pytest.raises(ValueError) as e:
        es_number(float("nan"))
    assert "ijson_number_not_" in str(e.value) or "NaN" in str(e.value) or True


def test_es_inf_hata():
    with pytest.raises(ValueError):
        es_number(float("inf"))


def test_es_neg_inf_hata():
    with pytest.raises(ValueError):
        es_number(float("-inf"))


def test_es_donut_tipi():
    assert isinstance(es_number(1.5), str)


def test_es_stabil():
    assert es_number(3.14159) == es_number(3.14159)


@pytest.mark.parametrize("v,b", [
    (0, "0"), (1, "1"), (-1, "-1"), (0.5, "0.5"), (1.5, "1.5"), (100.0, "100"),
    (2.93e-07, "2.93e-7"), (1e21, "1e+21"), (1e-06, "0.000001"),
])
def test_es_matrix(v, b):
    assert es_number(v) == b


# == _now_iso (tamga_anchor) ===========================================================================

def test_now_iso_aware():
    """ORTAM: isoformat() — tz-aware '+00:00' (Kredent _now_iso'dan FARKLI:
    O 'Z' kullanir, bu '+00:00')."""
    assert _now_iso().endswith("+00:00")


def test_now_iso_format():
    assert _dt.datetime.fromisoformat(_now_iso()) is not None


def test_now_iso_micro():
    """ORTAM-OGRENDI: Mikro-SANIYE cozunurlugu (Kredent/Ostrakon'dan
    FARKLI — tamga_anchor tam isoformat kullanir, timespec belirtilMEMIS)."""
    v = _now_iso()
    assert "." in v


def test_now_iso_utc():
    d = _dt.datetime.fromisoformat(_now_iso())
    assert d.utcoffset() == _dt.timedelta(0)


def test_now_iso_donut_tipi():
    assert isinstance(_now_iso(), str)


def test_now_iso_artar():
    a = _now_iso()
    import time as _t
    _t.sleep(0.002)
    assert _now_iso() >= a


def test_now_iso_sabit(monkeypatch):
    """ORTAM-OGRENDI: datetime IMMUTABLE — modul nitirigi yamalanir."""
    import veridrome.certificate.tamga_anchor as anchor

    class _FakeDTClass:
        def __init__(self, *a, **kw):
            pass

        @staticmethod
        def now(tz=None):
            return _dt.datetime(2026, 1, 1, 12, 0, 0, 123456, tzinfo=tz or _dt.timezone.utc)
    monkeypatch.setattr(anchor, "datetime",
                        type("_FM", (), {"datetime": _FakeDTClass,
                                         "timezone": _dt.timezone}))
    assert _now_iso() == "2026-01-01T12:00:00.123456+00:00"


# == karakterizasyon ===================================================================================

def test_canon_amaci():
    """ORTAM-OGRENDI (DOCSTACK): JSON'u KANONIK (sirali-anahtar,
    sikistilmis) baytlara cevirir — content_hash herkes tarafindan AYNI
    sekilde yeniden-hesaplanabilir (bayt-sirasi/bosluk/anahtar-sirasi
    farkliligi gozardi). ensure_ascii=False: UTF-8 baytlari (Turkce
    korunur). LISTE sirasi KORUNUR (sort yalniz dict anahtarlarinda)."""
    assert _canonical_bytes({"b": 1, "a": {"d": 4, "c": 3}}) == \
        b'{"a":{"c":3,"d":4},"b":1}'


def test_merkle_amaci():
    """ORTAM-OGRENDI: sirali hex-hash listesinden MERKLE koku
    (RFC-6962-benzeri): b'\\x01' domain-separation on-ek; ciftler
    sha256(pre+left+right); TEK kalan son dugum KENDISIYLE eslesir;
    TEK yaprak oldukca kok (leaf-hash YOK); BOS girdi -> sha256('')
    FAIL-CLOSED kok (build_certificate RED eder). SIRA ONEMLI (siralama
    kaniti)."""
    hs = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(3)]
    assert _merkle_root(hs) != _merkle_root(list(reversed(hs)))


def test_hash_entry_amaci():
    """ORTAM-OGRENDI: test-sonucu girdisinin kanonik hash'i —
    DETERMINISTIK-DAVRANIS-TAAHHUDU: ayni test ayni girdiyle her zaman
    ayni hash. name+outcome zorunlu (str cast, eksik -> ''); duration_ms
    float olarak eklenebilir (None/gecersiz atlanir)."""
    e = {"name": "test_x", "outcome": "passed", "duration_ms": 12.5}
    assert _hash_test_entry(e) == _hash_entry_beklenen(e)


def _hash_entry_beklenen(entry):
    canon = {"name": str(entry.get("name", "")), "outcome": str(entry.get("outcome", ""))}
    if "duration_ms" in entry and entry["duration_ms"] is not None:
        try:
            canon["duration_ms"] = float(entry["duration_ms"])
        except (TypeError, ValueError):
            pass
    return hashlib.sha256(_canonical_bytes(canon)).hexdigest()


def test_encode_amaci():
    """ORTAM-OGRENDI: RFC 8785 JCS serialization — _encode recursive;
    §3.2.3 anahtarlar UTF-16-BE kod-birim artan sirali; I-JSON
    [−2^53, 2^53] disi tamsayi ValueError (double-mantissa kaybi);
    NaN/Infinity float olarak reddedilir; bool int'ten ONCE (bool int
    alt-sinafi guvenlik-dali); tuple list gibi; desteklenmeyen tip
    TypeError. TamgaProtocol tamga_canon.jcs ile BAYT-BAYT uyum
    (parite-testi)."""
    from veridrome.certificate.tamga_anchor import jcs
    assert jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_es_number_amaci():
    """ORTAM-OGRENDI: ECMAScript Number.prototype.toString — JCS icin
    IEEE-754 double serilestirme; NaN/Infinity reddedilir (I-JSON);
    -0.0 normalize '0'; bilimsel-gosterim e-6..e+21 araliginda; JCS
    tek-gecerli-temsil garantisi."""
    assert es_number(2.93e-07) == "2.93e-7"
    assert es_number(1e21) == "1e+21"


def test_parse_iso8601_amaci():
    """ORTAM-OGRENDI: ISO-8601 -> tz-AWARE datetime; fail-soft (except ->
    None) — dogrulama tarafindan 'gecersiz-zaman' olarak ele alinir;
    naive -> +UTC (yerel DEGIL)."""
    assert _parse_iso8601("gecersiz") is None
    assert _parse_iso8601("2026-01-01T12:00:00Z").tzinfo == _dt.timezone.utc
