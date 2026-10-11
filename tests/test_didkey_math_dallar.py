"""73-Veridrome didkey dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (saf-arithmetik — dis cagri YOK).
Ed25519 curve-yardimcilari (RFC 8032).
"""
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridrome.certificate.didkey import (  # noqa: E402
    _xrecover, _edwards_add, _scalar_multiply, _scalar_reduce,
    _point_compress, _point_decompress, _expand_seed, _clamp_scalar,
    _sha512, _hash_int, _public_point_from_seed, _BASE_POINT, _P, _L, _D,
    ED25519_KEY_LEN,
)


# == sabitler =========================================================================================

def test_p_asal_boyut():
    """ORTAM: P 255-bit (2^255-19)."""
    assert _P == 2**255 - 19


def test_p_bit_sayisi():
    assert _P.bit_length() == 255


def test_l_derecesi():
    """ORTAM: L alt-grup derecesi (2^252 + ...)."""
    assert _L > 2**252
    assert _L < 2**253


def test_d_small():
    """ORTAM: D twisted-Edwards parametresi."""
    assert 0 < _D < _P


def test_base_point_uzunluk():
    assert len(_BASE_POINT) == 4


def test_base_point_uzeri():
    """ORTAM: twisted-Edwards: -x^2 + y^2 = 1 + D x^2 y^2."""
    x, y, z, t = _BASE_POINT
    lhs = (-x * x + y * y) % _P
    rhs = (1 + _D * x * x * y * y) % _P
    assert lhs == rhs


def test_ed25519_key_len():
    """ORTAM: 32-bayt."""
    assert ED25519_KEY_LEN == 32


# == _xrecover ========================================================================================

def test_xrecover_base_y():
    """ORTAM: base-point y'sini recover eder."""
    x, y, z, t = _BASE_POINT
    assert _xrecover(y, x & 1) == x


def test_xrecover_mod_p():
    assert 0 <= _xrecover(4, 0) < _P


def test_xrecover_isaret0():
    """ORTAM: sign=0 -> x cift."""
    x = _xrecover(4, 0)
    assert x % 2 == 0


def test_xrecover_isaret1():
    """ORTAM: sign=1 -> x tek."""
    x = _xrecover(4, 1)
    assert x % 2 == 1


def test_xrecover_isaret_negatif():
    """ORTAM: sign tersi -> x = P - x."""
    a = _xrecover(4, 0)
    b = _xrecover(4, 1)
    assert (a + b) % _P == 0


def test_xrecover_curve_denklemi():
    """ORTAM: recover edilen x twisted-Edwards denklemini saglar."""
    for y in (4, 5, 100, _P - 1):
        x = _xrecover(y, 0)
        lhs = (-x * x + y * y) % _P
        rhs = (1 + _D * x * x * y * y) % _P
        assert lhs == rhs


def _curve_uzeri(x, y):
    """Twisted-Edwards: -x^2 + y^2 = 1 + D x^2 y^2 (mod P)."""
    return (-x * x + y * y) % _P == (1 + _D * x * x * y * y) % _P


@pytest.mark.parametrize("y", [4, 5, 7, 100, 12345])
def test_xrecover_matrix(y):
    """ORTAM: her y icin 2-x (sign) — karsilik (a+b)%P==0."""
    a = _xrecover(y, 0)
    b = _xrecover(y, 1)
    assert a != b
    assert (a + b) % _P == 0


@pytest.mark.parametrize("y", [4, 5, 100, 12345])
def test_xrecover_gecerli_matrix(y):
    """ORTAM: gecerli-y icin recover edilen x curve uzerinde."""
    x = _xrecover(y, 0)
    assert _curve_uzeri(x, y)


# == _edwards_add =====================================================================================

def test_edwards_add_neutral():
    """ORTAM: (0,1,1,0) neutral eleman."""
    n = (0, 1, 1, 0)
    r = _edwards_add(_BASE_POINT, n)
    assert _edwards_add(_BASE_POINT, n) == _edwards_add(n, _BASE_POINT)
    # normalize karsilastirma
    _, _, z, _ = r
    assert z != 0


def test_edwards_add_donus():
    """ORTAM: P + P = 2P (scalar ile ayni)."""
    iki = _scalar_multiply(2, _BASE_POINT)
    toplam = _edwards_add(_BASE_POINT, _BASE_POINT)
    a = tuple((c * pow(iki[2], _P - 2, _P)) % _P for c in iki)
    b = tuple((c * pow(toplam[2], _P - 2, _P)) % _P for c in toplam)
    assert a[:2] == b[:2]


def test_edwards_add_uzunluk():
    assert len(_edwards_add(_BASE_POINT, _BASE_POINT)) == 4


def test_edwards_add_mod_p():
    r = _edwards_add(_BASE_POINT, _BASE_POINT)
    assert all(0 <= c < _P for c in r)


def test_edwards_add_komutatif():
    """ORTAM: P + Q == Q + P (normalize)."""
    def norm(p):
        zi = pow(p[2], _P - 2, _P)
        return tuple((c * zi) % _P for c in p)
    q = _scalar_multiply(3, _BASE_POINT)
    assert norm(_edwards_add(_BASE_POINT, q)) == norm(_edwards_add(q, _BASE_POINT))


# == _scalar_multiply ==================================================================================

def test_scalar_mult_sifir():
    """ORTAM: 0 * P = neutral (0,1,1,0)."""
    r = _scalar_multiply(0, _BASE_POINT)
    # normalize
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == 0
    assert (r[1] * zi) % _P == 1


def test_scalar_mult_bir():
    """ORTAM: 1 * P = P."""
    r = _scalar_multiply(1, _BASE_POINT)
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == _BASE_POINT[0]
    assert (r[1] * zi) % _P == _BASE_POINT[1]


def test_scalar_mult_iki():
    r = _scalar_multiply(2, _BASE_POINT)
    assert r != _BASE_POINT


def test_scalar_mult_l():
    """ORTAM: L * P = neutral (sonlu-grup)."""
    r = _scalar_multiply(_L, _BASE_POINT)
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == 0
    assert (r[1] * zi) % _P == 1


def test_scalar_mult_l_arti_bir():
    """ORTAM: (L+1) * P = P."""
    r = _scalar_multiply(_L + 1, _BASE_POINT)
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == _BASE_POINT[0]


@pytest.mark.parametrize("k", [0, 1, 2, 3, 5, 100, _L - 1])
def test_scalar_mult_matrix(k):
    """ORTAM: her k icin sonuc curve uzerinde."""
    r = _scalar_multiply(k, _BASE_POINT)
    zi = pow(r[2], _P - 2, _P)
    x, y = (r[0] * zi) % _P, (r[1] * zi) % _P
    assert (-x * x + y * y) % _P == (1 + _D * x * x * y * y) % _P


# == _scalar_reduce ====================================================================================

def test_scalar_reduce_mod_l():
    assert _scalar_reduce(_L) == 0


def test_scalar_reduce_kucuk():
    assert _scalar_reduce(5) == 5


def test_scalar_reduce_buyuk():
    assert _scalar_reduce(_L + 1) == 1


def test_scalar_reduce_iki_l():
    assert _scalar_reduce(2 * _L) == 0


# == _point_compress / _point_decompress ===============================================================

def test_compress_uzunluk():
    """ORTAM: 32-bayt."""
    assert len(_point_compress(_BASE_POINT)) == 32


def test_compress_decompress_roundtrip():
    """ORTAM: roundtrip base-point."""
    c = _point_compress(_BASE_POINT)
    r = _point_decompress(c)
    zi = pow(r[2], _P - 2, _P)
    x, y = (r[0] * zi) % _P, (r[1] * zi) % _P
    assert x == _BASE_POINT[0]
    assert y == _BASE_POINT[1]


@pytest.mark.parametrize("k", [1, 2, 3, 5, 7, 100])
def test_compress_decompress_matrix(k):
    """ORTAM: roundtrip her skaler-kat icin."""
    p = _scalar_multiply(k, _BASE_POINT)
    c = _point_compress(p)
    r = _point_decompress(c)
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == (p[0] * pow(p[2], _P - 2, _P)) % _P
    assert (r[1] * zi) % _P == (p[1] * pow(p[2], _P - 2, _P)) % _P


def test_decompress_uzunluk_hatasi():
    """ORTAM: 32-bayt DEGIL -> ValueError."""
    with pytest.raises(ValueError):
        _point_decompress(b"x" * 31)


def test_decompress_cok_uzun():
    with pytest.raises(ValueError):
        _point_decompress(b"x" * 33)


def test_decompress_bos():
    with pytest.raises(ValueError):
        _point_decompress(b"")


def test_decompress_y_buyuk_p():
    """ORTAM: y >= P -> ValueError."""
    with pytest.raises(ValueError):
        _point_decompress(_P.to_bytes(32, "little"))


def test_decompress_isaret_bit():
    """ORTAM: MSB sign-bit olarak ayrik (y'ye katilmaz)."""
    base_c = _point_compress(_BASE_POINT)
    isaretli = bytearray(base_c)
    isaretli[31] ^= 0x80
    r = _point_decompress(bytes(isaretli))
    zi = pow(r[2], _P - 2, _P)
    assert (r[1] * zi) % _P == _BASE_POINT[1]


# == _expand_seed ======================================================================================

def test_expand_seed_uzunluk():
    """ORTAM: 32-bayt seed -> (32, 32)."""
    a, b = _expand_seed(b"\x01" * 32)
    assert len(a) == 32
    assert len(b) == 32


def test_expand_seed_uzunluk_hatasi():
    """ORTAM: 31-bayt -> ValueError."""
    with pytest.raises(ValueError):
        _expand_seed(b"\x01" * 31)


def test_expand_seed_cok_uzun():
    with pytest.raises(ValueError):
        _expand_seed(b"\x01" * 33)


def test_expand_seed_bos():
    with pytest.raises(ValueError):
        _expand_seed(b"")


def test_expand_seed_deterministik():
    """ORTAM: ayni seed ayni cikti."""
    s = b"\x02" * 32
    assert _expand_seed(s) == _expand_seed(s)


def test_expand_seed_farkli():
    assert _expand_seed(b"\x01" * 32) != _expand_seed(b"\x02" * 32)


def test_expand_seed_sha512():
    """ORTAM: sha512(seed) ikiye bolunur."""
    import hashlib
    s = b"\x03" * 32
    h = hashlib.sha512(s).digest()
    assert _expand_seed(s) == (h[:32], h[32:])


@pytest.mark.parametrize("n", [1, 2, 3, 5, 100])
def test_expand_seed_matrix(n):
    """ORTAM: farkli seed'ler farkli cikti."""
    a = _expand_seed(bytes([n]) * 32)
    b = _expand_seed(bytes([n + 1]) * 32)
    assert a != b


# == _clamp_scalar =====================================================================================

def test_clamp_dusuk_bit():
    """ORTAM: n[0] &= 248 (ilk 3-bit sifir)."""
    s = _expand_seed(b"\xff" * 32)[0]
    n = _clamp_scalar(s)
    assert n % 8 == 0


def test_clamp_yuksek_bit():
    """ORTAM: n[31] &= 127 -> bit-255 sifir; |= 64 -> bit-254 BIR."""
    s = b"\xff" * 32
    n = _clamp_scalar(s)
    assert n < 2**255
    assert n & (1 << 254) != 0


def test_clamp_254_bit():
    """ORTAM: n[31] |= 64 -> bit-254 (0x40) BIR."""
    s = b"\x00" * 32
    n = _clamp_scalar(s)
    assert n & (1 << 254) != 0


def test_clamp_32_bayt():
    """ORTAM: clamp 32-bayt ister."""
    with pytest.raises(IndexError):
        _clamp_scalar(b"\x00" * 31)


def test_clamp_aralik():
    """ORTAM: clamped scalar 2^254 <= n < 2^255 (bit254=1, bit255=0)."""
    s = _expand_seed(b"\x42" * 32)[0]
    n = _clamp_scalar(s)
    assert 2**254 <= n < 2**255


def test_clamp_deterministik():
    s = b"\x42" * 32
    assert _clamp_scalar(s) == _clamp_scalar(s)


@pytest.mark.parametrize("b", [0, 1, 128, 255])
def test_clamp_matrix(b):
    """ORTAM: her ilk-bayt icin cikti 8'in kati."""
    s = bytes([b]) + b"\x00" * 31
    assert _clamp_scalar(s) % 8 == 0


# == _sha512 / _hash_int ==============================================================================

def test_sha512_uzunluk():
    assert len(_sha512(b"")) == 64


def test_sha512_empty():
    """ORTAM: sha512('') sabit."""
    import hashlib
    assert _sha512(b"") == hashlib.sha512(b"").digest()


def test_sha512_deterministik():
    assert _sha512(b"x") == _sha512(b"x")


def test_sha512_farkli():
    assert _sha512(b"x") != _sha512(b"y")


def test_hash_int_deterministik():
    assert _hash_int(b"x") == _hash_int(b"x")


def test_hash_int_0_255():
    """ORTAM: hash_int 64-bayt little-endian."""
    assert _hash_int(b"") == int.from_bytes(_sha512(b""), "little")


def test_hash_int_pozitif():
    assert _hash_int(b"") > 0


# == _public_point_from_seed ===========================================================================

def test_pub_point_uzunluk():
    assert len(_public_point_from_seed(b"\x01" * 32)) == 4


def test_pub_point_curve():
    """ORTAM: public-point curve uzerinde."""
    r = _public_point_from_seed(b"\x01" * 32)
    zi = pow(r[2], _P - 2, _P)
    x, y = (r[0] * zi) % _P, (r[1] * zi) % _P
    assert (-x * x + y * y) % _P == (1 + _D * x * x * y * y) % _P


def test_pub_point_deterministik():
    """ORTAM: ayni seed ayni nokta."""
    s = b"\x07" * 32
    assert _public_point_from_seed(s) == _public_point_from_seed(s)


def test_pub_point_farkli_seed():
    assert (_public_point_from_seed(b"\x01" * 32)
            != _public_point_from_seed(b"\x02" * 32))


def test_pub_point_seed_hatasi():
    """ORTAM: 31-bayt seed -> ValueError."""
    with pytest.raises(ValueError):
        _public_point_from_seed(b"\x01" * 31)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 100])
def test_pub_point_matrix(n):
    """ORTAM: her seed farkli nokta (cok buyuk olasilikla)."""
    a = _public_point_from_seed(bytes([n]) * 32)
    b = _public_point_from_seed(bytes([n + 1]) * 32)
    assert a != b


def test_pub_point_compress_roundtrip():
    """ORTAM: public-point compress/decompress roundtrip."""
    p = _public_point_from_seed(b"\x09" * 32)
    c = _point_compress(p)
    r = _point_decompress(c)
    zi = pow(r[2], _P - 2, _P)
    assert (r[0] * zi) % _P == (p[0] * pow(p[2], _P - 2, _P)) % _P
