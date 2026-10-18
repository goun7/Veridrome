"""
did:key — stdlib-only Ed25519 + multibase + did:key (W3C Core + did:key spec).

Bu modül Kredent'in (68-Kredent/kredent/crypto.py) did:key formatıyla BİREBİR
uyumludur: aynı base58btc alfabesi, aynı 0xed01 multicodec prefixi, aynı
``did:key:z6Mk...`` tanımlayıcı formu. Amaç: bir sertifika, Kredent'te üretilmiş
bir DID ile imzalanabilsin ve Veridrome'da — hiçbir ağır bağımlılık olmadan —
doğrulanabilsin.

Tasarım kararı ( Kredent-deseni):
  - Öncelikli yol: ``cryptography`` kütüphanesi (denetlenmiş, constant-time).
  - Her zaman mevcut olan yedek: saf-Python Ed25519 (RFC 8032), yalnızca
    ``hashlib`` (SHA-512) kullanır. Böylece DOĞRULAMA yolu — en sık çalışan
    ve bir kimlik standardının ağ etkisine bağlı olan işlem — sıfır opsiyonel
    bağımlılıkla çalışır.

Her iki yol da aynı 32-bayt seed ve 64-bayt imza formatını alır ve RFC 8032
test vektörleriyle çapraz doğrulanmıştır ( test/test_didkey.py).
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

# ---------------------------------------------------------------------------
# Base58 (Bitcoin alfabesi) — Kredent ile aynı
# ---------------------------------------------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}

# Ham Ed25519 açık anahtarı için multicodec prefixi: 0xed 0x01
ED25519_MULTICODEC_PREFIX = b"\xed\x01"
MULTIBASE_BASE58BTC_PREFIX = "z"

ED25519_KEY_LEN = 32
ED25519_SIG_LEN = 64


def b58encode(data: bytes) -> str:
    """Baytları Base58 (Bitcoin alfabesi) dizisine kodlar.

    Önde-gelen sıfır-baytlar '1' olarak kodlanır ( Bitcoin alfabesi standardı).
    """
    if not data:
        return ""
    num = int.from_bytes(data, byteorder="big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(B58_ALPHABET[rem])
    encoded = "".join(reversed(chars))

    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def b58decode(s: str) -> bytes:
    """Base58 (Bitcoin alfabesi) dizisini baytlara çözer.

    '1' karakteri önde-gelen sıfır-baytı temsil eder.
    """
    if not s:
        return b""
    num = 0
    for char in s:
        if char not in B58_MAP:
            raise ValueError(f"Geçersiz karakter {char!r} Base58 dizisinde")
        num = num * 58 + B58_MAP[char]

    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break

    body = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big") if num > 0 else b""
    return b"\x00" * pad + body


# ---------------------------------------------------------------------------
# Multibase + did:key
# ---------------------------------------------------------------------------
# Bir W3C did:key Ed25519 tanımlayıcısının tam hali:
#
#     did:key:z6Mk<multibase>
#
# burada multibase yükü ``base58btc(0xed 0x01 || <32-bayt açık-anahtar>)``.
# 0xed01 multicodec etiketi anahtarın Ed25519 olduğunu belirtir. Tanımlayıcı
# tamamıyla açık anahtardan türetildiği için did:key *self-resolving*'tir:
# doğrulama materyali tanımlayıcının kendisinden, hiçbir kayıt defteri, ağ
# erişimi veya güvenilir çözücü olmadan kurtarılabilir. Bu özellik, offline
# ``veridrome verify``'u mümkün kılar.

def encode_multibase_pubkey(raw_pubkey: bytes) -> str:
    """32-bayt Ed25519 açık anahtarını multibase dizisi olarak kodlar (``z6Mk...``)."""
    if len(raw_pubkey) != ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 açık anahtarı tam {ED25519_KEY_LEN} bayt olmalı, "
            f"{len(raw_pubkey)} bayt geldi"
        )
    return MULTIBASE_BASE58BTC_PREFIX + b58encode(ED25519_MULTICODEC_PREFIX + raw_pubkey)


def decode_multibase_pubkey(multibase_str: str) -> bytes:
    """Multibase dizisini ham 32-bayt Ed25519 açık anahtarına çözer."""
    if not multibase_str or multibase_str[0] != MULTIBASE_BASE58BTC_PREFIX:
        raise ValueError(
            f"Desteklenmeyen multibase prefixi {multibase_str[:1]!r}. "
            f"Beklenen {MULTIBASE_BASE58BTC_PREFIX!r} (base58btc)"
        )
    decoded = b58decode(multibase_str[1:])
    if not decoded.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError("Geçersiz multicodec prefixi; bu bir Ed25519 açık anahtarı değil")
    raw_key = decoded[len(ED25519_MULTICODEC_PREFIX):]
    if len(raw_key) != ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 açık anahtarı için {ED25519_KEY_LEN} bayt bekleniyordu, "
            f"{len(raw_key)} bayt geldi"
        )
    return raw_key


def did_from_multibase(multibase_pubkey: str) -> str:
    """Multibase açık anahtardan ``did:key`` tanımlayıcısı üretir."""
    return f"did:key:{multibase_pubkey}"


def multibase_from_did(did: str) -> str:
    """``did:key`` tanımlayıcısından multibase açık anahtarı çıkarır."""
    prefix = "did:key:"
    if not did.startswith(prefix):
        raise ValueError(f"Bu bir did:key tanımlayıcısı değil: {did!r}")
    return did[len(prefix):]


def pubkey_from_did(did: str) -> bytes:
    """``did:key`` tanımlayıcısından ham 32-bayt Ed25519 açık anahtarını kurtarır.

    Bu, did:key'in self-resolution özelliğidir: ağ yok, kayıt defteri yok.
    """
    return decode_multibase_pubkey(multibase_from_did(did))


def verification_method_from_did(did: str) -> str:
    """Bir did:key için kanonik verification-method kimliğini döndürür.

    did:key spesifikasyonuna göre fragment, multibase değerinin kendisidir.
    """
    return f"{did}#{multibase_from_did(did)}"


def is_did_key(did: str) -> bool:
    """``did`` geçerli bir ``did:key`` tanımlayıcısıysa True döner."""
    try:
        pubkey_from_did(did)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Saf-Python Ed25519 (RFC 8032)
# ---------------------------------------------------------------------------
# Standart Ed25519 algoritmasının referans inşası. Açıklık ve doğruluk için
# yazılmıştır, hız için değil. Constant-time davranış BURADA garanti edilmez;
    # ``cryptography`` yolu mevcut olduğunda kullanılır.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int, sign: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != sign:
        x = _P - x
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY, 0)
_BASE_POINT = (_BX, _BY, 1, (_BX * _BY) % _P)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    d = (z1 * 2 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (
        (e * f) % _P,
        (g * h) % _P,
        (f * g) % _P,
        (e * h) % _P,
    )


def _scalar_multiply(k: int, point):
    result = (0, 1, 1, 0)
    addend = point
    while k > 0:
        if k & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        k >>= 1
    return result


def _scalar_reduce(k: int) -> int:
    return k % _L


def _point_compress(point) -> bytes:
    x, y, z, _t = point
    zinv = pow(z, _P - 2, _P)
    x = (x * zinv) % _P
    y = (y * zinv) % _P
    out = y.to_bytes(32, "little")
    if x & 1:
        out = (int.from_bytes(out, "little") | (1 << 255)).to_bytes(32, "little")
    return out


def _point_decompress(data: bytes):
    if len(data) != 32:
        raise ValueError("Geçersiz Ed25519 nokta kodlama uzunluğu")
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:
        raise ValueError("Geçersiz Ed25519 noktası: y alan aralığında değil")
    x = _xrecover(y, sign)
    return (x, y, 1, (x * y) % _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _hash_int(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little")


def _expand_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """32-bayt Ed25519 seed'ini RFC 8032'ye göre (scalar, nonce-prefix) olarak böler."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed'i {ED25519_KEY_LEN} bayt olmalı")
    h = _sha512(seed)
    return h[:32], h[32:]


def _clamp_scalar(half: bytes) -> int:
    n = bytearray(half)
    n[0] &= 248
    n[31] &= 127
    n[31] |= 64
    return int.from_bytes(bytes(n), "little")


def _public_point_from_seed(seed: bytes):
    scalar_half, _ = _expand_seed(seed)
    return _scalar_multiply(_clamp_scalar(scalar_half), _BASE_POINT)


def py_sign(seed: bytes, message: bytes) -> bytes:
    """32-bayt seed ile ``message`` üzerinden saf-Python Ed25519 imzası üretir."""
    scalar_half, nonce_prefix = _expand_seed(seed)
    a = _clamp_scalar(scalar_half)
    public_point = _scalar_multiply(a, _BASE_POINT)
    public_encoded = _point_compress(public_point)

    r = _hash_int(nonce_prefix + message) % _L
    R = _scalar_multiply(r, _BASE_POINT)
    R_encoded = _point_compress(R)

    k = _hash_int(R_encoded + public_encoded + message) % _L
    s = (_scalar_reduce(r + k * a)) % _L
    return R_encoded + s.to_bytes(32, "little")


def py_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Saf-Python Ed25519 doğrulaması. Geçersiz girişte False döner."""
    if len(signature) != ED25519_SIG_LEN or len(public_key) != ED25519_KEY_LEN:
        return False
    try:
        R = _point_decompress(signature[:32])
        A = _point_decompress(public_key)
    except ValueError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False

    k = _hash_int(signature[:32] + public_key + message) % _L
    # Doğrula: s*B == R + k*A  (eşdeğer olarak -s*B + k*A + R == birim)
    lhs = _scalar_multiply(s, _BASE_POINT)
    rhs = _edwards_add(R, _scalar_multiply(k, A))

    def _norm(pt):
        x, y, z, _t = pt
        zinv = pow(z, _P - 2, _P)
        return ((x * zinv) % _P, (y * zinv) % _P)

    return _norm(lhs) == _norm(rhs)


# ---------------------------------------------------------------------------
# ``cryptography`` kütüphanesi üzerinden opsiyonel hızlı yol
# ---------------------------------------------------------------------------

try:  # pragma: no cover - import bulunabilirliği ortama bağlıdır
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _c_ed25519
    from cryptography.exceptions import InvalidSignature as _CInvalidSignature

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    _HAS_CRYPTOGRAPHY = False


def cryptography_sign(seed: bytes, message: bytes) -> bytes:
    """``cryptography`` ile imzalar (mevcut değilse hata fırlatır)."""
    priv = _c_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return priv.sign(message)


def cryptography_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """``cryptography`` ile doğrular (mevcut değilse hata fırlatır)."""
    try:
        pub = _c_ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except _CInvalidSignature:
        return False
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Birleşik API — Kredent crypto.py ile birebir aynı imza
# ---------------------------------------------------------------------------


def sign(seed: bytes, message: bytes) -> bytes:
    """``message`` üzerinden 64-bayt detached Ed25519 imzası üretir.

    ``cryptography`` mevcut olduğunda denetlenmiş implementation'ı kullanır,
    aksi halde gömülü saf-Python implementation'ına düşer.
    """
    if _HAS_CRYPTOGRAPHY:
        return cryptography_sign(seed, message)
    return py_sign(seed, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """64-bayt detached Ed25519 imzasını doğrular.

    Geçersiz girişte asla hata fırlatmaz; hatalı biçimli veya uyuşmayan imza,
    anahtar veya mesaj için ``False`` döner.
    """
    if _HAS_CRYPTOGRAPHY:
        try:
            return cryptography_verify(public_key, message, signature)
        except Exception:
            return False
    return py_verify(public_key, message, signature)


def derive_public_key(seed: bytes) -> bytes:
    """32-bayt Ed25519 seed'inden 32-bayt açık anahtarı türetir."""
    if _HAS_CRYPTOGRAPHY:
        priv = _c_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return priv.public_key().public_bytes_raw()
    return _point_compress(_public_point_from_seed(seed))


def generate_seed() -> bytes:
    """OS CSPRNG'den taze 32-bayt Ed25519 seed'i üretir."""
    return secrets.token_bytes(ED25519_KEY_LEN)


def generate_keypair() -> Tuple[bytes, str, str]:
    """Taze bir anahtar çifti üretir.

    ``(seed, did, multibase_pubkey)`` döndürür.
    """
    seed = generate_seed()
    return keypair_from_seed(seed)


def keypair_from_seed(seed: bytes) -> Tuple[bytes, str, str]:
    """Bir seed'den ``(seed, did, multibase_pubkey)`` türetir."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed'i {ED25519_KEY_LEN} bayt olmalı")
    raw_pub = derive_public_key(seed)
    multibase_pub = encode_multibase_pubkey(raw_pub)
    did = did_from_multibase(multibase_pub)
    return seed, did, multibase_pub


__all__ = [
    "b58encode",
    "b58decode",
    "encode_multibase_pubkey",
    "decode_multibase_pubkey",
    "did_from_multibase",
    "multibase_from_did",
    "pubkey_from_did",
    "verification_method_from_did",
    "is_did_key",
    "sign",
    "verify",
    "py_sign",
    "py_verify",
    "derive_public_key",
    "generate_seed",
    "generate_keypair",
    "keypair_from_seed",
    "ED25519_KEY_LEN",
    "ED25519_SIG_LEN",
]
