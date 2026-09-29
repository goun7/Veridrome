"""
Testler: Veridrome did:key modülü — Kredent ile çapraz-uyumluluk dahil.

Kapsam:
  - base58 kodlama/çözme yuvarlak-turu
  - did:key üretimi ve self-resolution ( pubkey_from_did)
  - Ed25519 imza/dojoğrulama ( hem ``cryptography`` hem saf-Python yolu)
  - RFC 8032 resmi test-vektörleri
  - Kredent ( 68-Kredent) ile BİREBİR DID-uyumluluğu — mesh-sinerjisinin temeli
"""

from __future__ import annotations

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from veridrome.certificate.didkey import (
    ED25519_KEY_LEN,
    ED25519_SIG_LEN,
    b58decode,
    b58encode,
    did_from_multibase,
    encode_multibase_pubkey,
    decode_multibase_pubkey,
    generate_keypair,
    is_did_key,
    keypair_from_seed,
    multibase_from_did,
    pubkey_from_did,
    py_sign,
    py_verify,
    sign,
    verify,
    verification_method_from_did,
    derive_public_key,
    _HAS_CRYPTOGRAPHY,
)

# Kredent — mesh-kardeşi ( çapraz-uyumluluk kanıtı)
_KREDENT = os.path.join(
    os.path.expanduser("~"), "projects", "01_unicorn", "68-Kredent"
)
_HAS_KREDENT = os.path.isdir(_KREDENT) and os.path.isfile(
    os.path.join(_KREDENT, "kredent", "crypto.py")
)


# ---------------------------------------------------------------------------
# Base58
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [b"", b"\x00", b"\x00\x00", b"hello world",
                                 bytes(range(256)), os.urandom(32)])
def test_b58_roundtrip(raw: bytes) -> None:
    assert b58decode(b58encode(raw)) == raw


def test_b58_known_vector() -> None:
    # Bitcoin-alfabesi klasik vektörü
    assert b58encode(bytes([0, 1, 2, 3])) == "1Ldp"


def test_b58_invalid_char_raises() -> None:
    with pytest.raises(ValueError):
        b58decode("0OIl")


# ---------------------------------------------------------------------------
# did:key üretimi ve self-resolution
# ---------------------------------------------------------------------------

def test_did_key_structure() -> None:
    seed, did, mb = generate_keypair()
    assert did.startswith("did:key:z6Mk")
    # multicodec 0xed01 → base58 'z' + '6Mk' öneki ile başlar
    assert mb.startswith("z6Mk")
    assert is_did_key(did)


def test_did_self_resolution() -> None:
    seed, did, _ = generate_keypair()
    pub = pubkey_from_did(did)
    assert len(pub) == ED25519_KEY_LEN
    # tekrar-üret: aynı-seed → aynı-DID ( deterministik)
    _, did2, _ = keypair_from_seed(seed)
    assert did == did2


def test_did_invalid_rejected() -> None:
    assert not is_did_key("did:key:notvalid")
    assert not is_did_key("did:web:example.com")
    assert not is_did_key("")
    with pytest.raises(ValueError):
        pubkey_from_did("did:key:z6MkBOGUS")


def test_verification_method_format() -> None:
    _, did, mb = generate_keypair()
    vm = verification_method_from_did(did)
    assert vm == f"{did}#{mb}"


def test_did_from_multibase_roundtrip() -> None:
    _, did, mb = generate_keypair()
    assert multibase_from_did(did) == mb
    assert did_from_multibase(mb) == did


# ---------------------------------------------------------------------------
# Ed25519 imza
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("msg", [b"", b"a", b"the quick brown fox",
                                 os.urandom(256)])
def test_sign_verify_roundtrip(msg: bytes) -> None:
    seed, did, _ = generate_keypair()
    sig = sign(seed, msg)
    assert len(sig) == ED25519_SIG_LEN
    assert verify(pubkey_from_did(did), msg, sig)


def test_sign_wrong_message_fails() -> None:
    seed, did, _ = generate_keypair()
    sig = sign(seed, b"message-a")
    assert not verify(pubkey_from_did(did), b"message-b", sig)


def test_sign_wrong_key_fails() -> None:
    seed_a, did_a, _ = generate_keypair()
    _, did_b, _ = generate_keypair()
    sig = sign(seed_a, b"message")
    assert not verify(pubkey_from_did(did_b), b"message", sig)


def test_pure_python_matches_cryptography_path() -> None:
    """Saf-Python ile ``cryptography`` yolları aynı imzayı üretir."""
    if not _HAS_CRYPTOGRAPHY:
        pytest.skip("cryptography kurulu değil")
    seed = bytes(range(32))
    msg = b"veridrome-crose-check"
    assert py_sign(seed, msg) == sign(seed, msg)
    assert py_verify(pubkey_from_did(keypair_from_seed(seed)[1]), msg, py_sign(seed, msg))


def test_derive_public_key_matches() -> None:
    seed = bytes(range(32))
    _, did, _ = keypair_from_seed(seed)
    assert derive_public_key(seed) == pubkey_from_did(did)

# ---------------------------------------------------------------------------
# RFC 8032 §7.1 resmi test-vektörleri ( Edwards25519) — IETF'den doğrulanmış
# ---------------------------------------------------------------------------

# ( seed, public-key, message-hex, signature) — RFC 8032 §7.1 TEST 1..3
_RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", _RFC8032_VECTORS)
def test_rfc8032_official_vectors(
    seed_hex: str, pub_hex: str, msg_hex: str, sig_hex: str
) -> None:
    """RFC 8032 §7.1 resmi Ed25519 test-vektörleri ( genel-anahtar + imza)."""
    seed = bytes.fromhex(seed_hex)
    msg = bytes.fromhex(msg_hex)
    expected_pub = bytes.fromhex(pub_hex)
    expected_sig = bytes.fromhex(sig_hex)

    assert derive_public_key(seed) == expected_pub
    assert py_sign(seed, msg) == expected_sig
    assert py_verify(expected_pub, msg, expected_sig)


def test_rfc8032_1023_byte_message_vector() -> None:
    """RFC 8032 §7.1 TEST 1024: 1023-bayt mesaj ( genel-anahtar uyumu)."""
    seed = bytes.fromhex(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
    )
    expected_pub = bytes.fromhex(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
    )
    assert derive_public_key(seed) == expected_pub


def test_rfc8032_sha_abc_vector() -> None:
    """RFC 8032 §7.1 TEST SHA(abc): 64-bayt mesaj ( tam imza denetimi)."""
    seed = bytes.fromhex(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
    )
    expected_pub = bytes.fromhex(
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
    )
    msg = bytes.fromhex(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )
    expected_sig = bytes.fromhex(
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
    )
    assert derive_public_key(seed) == expected_pub
    assert py_sign(seed, msg) == expected_sig
    assert py_verify(expected_pub, msg, expected_sig)


# ---------------------------------------------------------------------------
# Kredent ile çapraz-uyumluluk — mesh-sinerjisinin temeli
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _HAS_KREDENT, reason="Kredent ( 68-Kredent) bu makinede yok")
@pytest.mark.parametrize("seed_hex", [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
])
def test_kredent_did_compatibility(seed_hex: str) -> None:
    """Veridrome DID'leri Kredent DID'leriyle BİREBİR aynıdır."""
    sys.path.insert(0, _KREDENT)
    try:
        from kredent.crypto import keypair_from_seed as k_keypair
    finally:
        sys.path.pop(0)

    seed = bytes.fromhex(seed_hex)
    _, did, _ = keypair_from_seed(seed)
    _, _, _, k_did = k_keypair(seed)
    assert did == k_did


@pytest.mark.skipif(not _HAS_KREDENT, reason="Kredent ( 68-Kredent) bu makinede yok")
def test_kredent_signature_cross_validation() -> None:
    """Veridrome imzaları Kredent tarafından doğrulanır ve tersi."""
    sys.path.insert(0, _KREDENT)
    try:
        from kredent.crypto import sign as k_sign, verify as k_verify
    finally:
        sys.path.pop(0)

    seed, did, _ = generate_keypair()
    msg = b"veridrome-x-kredent-kanit"
    sig = sign(seed, msg)
    assert k_verify(pubkey_from_did(did), msg, sig)

    ksig = k_sign(seed, msg)
    assert verify(pubkey_from_did(did), msg, ksig)
