"""tests/test_crypto_dallar.py — veridrome.core.crypto dal-kesen testleri (147 satir).

Kural-1: mevcut modullere / conftest.py / mevcut testlere DOKUNULMADI; SADECE
bu yeni dosya eklendi.
Kural-4: saf in-memory (hashlib + cryptography Ed25519; network / RPC / subprocess YOK).

ORTAM-ANATOMI (olculen dallar):
- VeridromeAuthoritySigner.__init__(private_key=None):
    DAL-1 None -> Ed25519PrivateKey.generate() ile taze anahtar (iki ornek farkli)
    DAL-2 verilen private_key kullanilir, public_key ondan turetilir
- public_key_bytes: Raw encoding, tam 32 bayt
- public_key_base64: base64(public_key_bytes), ASCII, geri-cozulebilir
- sign(message): 64-bayt detached Ed25519 imza, deterministik (ayni anahtar+mesaj)
- sign_base64(message): base64(sign(message)) ile ayni
- verify(pub, msg, sig) [staticmethod]:
    DAL-3 gecerli imza -> True; bos mesaj imzasi -> True
    DAL-4 tahrif mesaj -> False
    DAL-5 baska anahtar -> False
    DAL-6 bozuk anahtar uzunlugu (0/16/33 bayt) -> False
    DAL-7 kisa / uzun / bos / rastgele imza -> False
- MerkleTreeAuditLog.__init__(leaves_data=None):
    DAL-8  None -> bos agac;  DAL-9  bos liste -> bos agac (falsy dal)
    DAL-10 liste -> her veri icin add_leaf cagrilir
- hash_leaf(data) [static]: SHA256(0x00 || data), 32 bayt (RFC 6962 leaf prefix)
- hash_children(l, r) [static]: SHA256(0x01 || l || r), 32 bayt; left/right sirali onemli
- add_leaf(data): hash_leaf doner ve leaves listesine ekler
- get_root():
    DAL-11 BOS agac -> sha256(b"") (domain-prefix YOK — ORTAM-OGRENDI)
    DAL-12 tek yaprak -> hash_leaf(data)
    DAL-13 cift guc (2/4/8) -> tam ikili katman
    DAL-14 TEK kalan son yaprak KENDISIYLE eslesir (3/5/7 yaprak)
    DAL-15 deterministik (ayni sirada ayni kok)
- get_root_hex(): "0x" + hex; 64 hex-karakter; get_root()'a esittir
- generate_proof(index):
    DAL-16 index<0 / >= len / bos-agac -> IndexError
    DAL-17 tek yaprak -> bos proof []
    DAL-18 her indeks icin proof uzunlugu = ceil(log2(n))
    DAL-19 cift indeks -> ("right", kardes); tek indeks -> ("left", kardes)
- verify_proof(leaf_data, proof, root) [classmethod]:
    DAL-20 tum indekslerin proof'u gecerli (n=1..33)
    DAL-21 yanlis kok -> False;  DAL-22 tahrif leaf -> False
    DAL-23 bos proof + tek-yaprak kok -> True (ozel durum)
    DAL-24 proof'ta tahrif kardes -> False
    DAL-25 yon "right" -> hash_children(current, sibling);
           "left" ve BILINMEYEN yon -> hash_children(sibling, current)
- generate_challenge_nonce(length=32):
    DAL-26 varsayilan 32 bayt; DAL-27 ozel uzunluk; DAL-28 benzersizlik
    DAL-29 length=0 -> b"";           DAL-30 negatif length -> ValueError
"""
from __future__ import annotations

import base64
import hashlib
import math
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from veridrome.core.crypto import (
    MerkleTreeAuditLog,
    VeridromeAuthoritySigner,
    generate_challenge_nonce,
)


# == VeridromeAuthoritySigner =========================================================================

class TestVeridromeAuthoritySigner:
    """__init__ / public_key_bytes / public_key_base64 / sign / sign_base64 / verify dallari."""

    def test_varsayilan_anahtar_uretilir(self):
        """DAL-1: __init__(None) -> generate(); iki ornek farkli anahtar."""
        s1 = VeridromeAuthoritySigner()
        s2 = VeridromeAuthoritySigner()
        assert len(s1.public_key_bytes) == 32
        assert len(s2.public_key_bytes) == 32
        assert s1.public_key_bytes != s2.public_key_bytes

    def test_gosterilen_anahtar_kullanilir(self):
        """DAL-2: verilen private_key kullanilir; public_key o anahtardan turetilir."""
        priv = ed25519.Ed25519PrivateKey.generate()
        s = VeridromeAuthoritySigner(priv)
        beklenen = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        assert s.public_key_bytes == beklenen
        # Ayni private_key ile ayni public_key (deterministik turetme)
        assert VeridromeAuthoritySigner(priv).public_key_bytes == beklenen

    def test_public_key_bytes_raw_32_bayt(self):
        """DAL: public_key_bytes Raw encoding, tam 32 bayt."""
        s = VeridromeAuthoritySigner()
        raw = s.public_key_bytes
        assert isinstance(raw, bytes)
        assert len(raw) == 32
        assert ed25519.Ed25519PublicKey.from_public_bytes(raw) is not None

    def test_public_key_base64_geri_cozulur(self):
        """DAL: public_key_base64 ASCII ve base64-decode == public_key_bytes."""
        s = VeridromeAuthoritySigner()
        b64 = s.public_key_base64
        assert isinstance(b64, str)
        assert b64 == base64.b64encode(s.public_key_bytes).decode("ascii")
        assert base64.b64decode(b64) == s.public_key_bytes

    def test_sign_64_bayt_deterministik(self):
        """DAL: sign() 64 bayt; ayni anahtar+mesaj -> ayni imza; farkli mesaj -> farkli."""
        s = VeridromeAuthoritySigner()
        msg = b"VERIDROME_DAL_TEST_MESAJI_2026"
        sig = s.sign(msg)
        assert isinstance(sig, bytes)
        assert len(sig) == 64
        assert s.sign(msg) == sig  # deterministik
        assert s.sign(b"farkli_mesaj") != sig

    def test_sign_base64_sign_ile_ayni(self):
        """DAL: sign_base64 == base64(sign)."""
        s = VeridromeAuthoritySigner()
        msg = b"base64_imza_testi"
        assert s.sign_base64(msg) == base64.b64encode(s.sign(msg)).decode("ascii")
        assert base64.b64decode(s.sign_base64(msg)) == s.sign(msg)

    def test_verify_gecerli_imza(self):
        """DAL-3: dogru anahtar+mesaj+imza -> True; bos mesaj da imzalanabilir."""
        s = VeridromeAuthoritySigner()
        pub = s.public_key_bytes
        msg = b"verify_dal_testi"
        assert VeridromeAuthoritySigner.verify(pub, msg, s.sign(msg)) is True
        # Bos mesaj gecerli bir imzadir
        assert VeridromeAuthoritySigner.verify(pub, b"", s.sign(b"")) is True

    def test_verify_tahrif_mesaj_reddedilir(self):
        """DAL-4: mesaj tahrif edilirse imza gecersiz."""
        s = VeridromeAuthoritySigner()
        pub = s.public_key_bytes
        sig = s.sign(b"orijinal_mesaj")
        assert VeridromeAuthoritySigner.verify(pub, b"tahrif_edilmis", sig) is False

    def test_verify_baska_anahtar_reddedilir(self):
        """DAL-5: gecerli imza ama yanlis anahtar -> False."""
        s1 = VeridromeAuthoritySigner()
        s2 = VeridromeAuthoritySigner()
        msg = b"ortak_mesaj"
        assert VeridromeAuthoritySigner.verify(s2.public_key_bytes, msg, s1.sign(msg)) is False

    @pytest.mark.parametrize("anahtar", [
        b"",
        b"kisa-16-bayt-anahtar",
        os.urandom(16),
        os.urandom(33),
        os.urandom(64),
    ], ids=["bos", "16-bayt", "rastgele-16", "rastgele-33", "rastgele-64"])
    def test_verify_bozuk_anahtar_reddedilir(self, anahtar):
        """DAL-6: 32-bayt olmayan her anahtar -> False (istisna YOK)."""
        s = VeridromeAuthoritySigner()
        msg = b"anahtar_uzunlugu_testi"
        assert VeridromeAuthoritySigner.verify(anahtar, msg, s.sign(msg)) is False

    @pytest.mark.parametrize("imza", [
        b"",
        b"kisa-32-bayt-imza-xxxxxxxxxxxxx",
        os.urandom(32),
        os.urandom(64),
        os.urandom(96),
    ], ids=["bos", "32-bayt", "rastgele-64", "rastgele-96", "rastgele-128"])
    def test_verify_gecersiz_imza_reddedilir(self, imza):
        """DAL-7: gecerli anahtar ama kisa/uzun/bos/rastgele imza -> False."""
        s = VeridromeAuthoritySigner()
        pub = s.public_key_bytes
        assert VeridromeAuthoritySigner.verify(pub, b"mesaj", imza) is False

    def test_verify_tip_guvenli_skalerlerle(self):
        """DAL: verify hicbir zaman istisra firlatmaz — sayisal/satr girdilerde False."""
        s = VeridromeAuthoritySigner()
        assert VeridromeAuthoritySigner.verify(None, b"m", b"s") is False
        assert VeridromeAuthoritySigner.verify(b"k", None, b"s") is False


# == MerkleTreeAuditLog ================================================================================

class TestMerkleHashFonksiyonlari:
    """hash_leaf / hash_children statik dallari (RFC 6962 prefix domain-separation)."""

    def test_hash_leaf_rfc6962(self):
        """DAL: hash_leaf = SHA256(0x00 || data), 32 bayt."""
        data = b"yaprak_verisi"
        beklenen = hashlib.sha256(b"\x00" + data).digest()
        assert MerkleTreeAuditLog.hash_leaf(data) == beklenen
        assert len(MerkleTreeAuditLog.hash_leaf(data)) == 32

    def test_hash_children_rfc6962(self):
        """DAL: hash_children = SHA256(0x01 || left || right), 32 bayt."""
        l = hashlib.sha256(b"\x00a").digest()
        r = hashlib.sha256(b"\x00b").digest()
        beklenen = hashlib.sha256(b"\x01" + l + r).digest()
        assert MerkleTreeAuditLog.hash_children(l, r) == beklenen
        assert len(MerkleTreeAuditLog.hash_children(l, r)) == 32

    def test_hash_children_sira_onemli(self):
        """DAL: left/right yer degisince cikti farkli olur."""
        a = hashlib.sha256(b"\x00a").digest()
        b = hashlib.sha256(b"\x00b").digest()
        assert MerkleTreeAuditLog.hash_children(a, b) != MerkleTreeAuditLog.hash_children(b, a)

    def test_domain_separation_prefix_farki(self):
        """ORTAM-OGRENDI: 0x00 leaf prefix ile 0x01 node prefix ayri domain'lerdir."""
        x = b"ayni_baytlar"
        assert MerkleTreeAuditLog.hash_leaf(x) != hashlib.sha256(x).digest()
        assert MerkleTreeAuditLog.hash_leaf(x) != MerkleTreeAuditLog.hash_children(x, x)

    def test_hash_leaf_bos_veri(self):
        """DAL: bos veri yine de prefix'lenir — sha256(b"")'den farkli."""
        assert MerkleTreeAuditLog.hash_leaf(b"") == hashlib.sha256(b"\x00").digest()


class TestMerkleTreeKok:
    """__init__ / add_leaf / get_root / get_root_hex dallari."""

    def test_init_none_bos_agac(self):
        """DAL-8: leaves_data=None -> bos agac."""
        assert MerkleTreeAuditLog().leaves == []
        assert MerkleTreeAuditLog(None).leaves == []

    def test_init_bos_liste_bos_agac(self):
        """DAL-9: bos liste -> falsy dal -> bos agac."""
        assert MerkleTreeAuditLog([]).leaves == []

    def test_init_liste_yapraklari_ekler(self):
        """DAL-10: liste verildiginde her eleman icin add_leaf cagrilir."""
        veri = [b"a", b"b", b"c"]
        tree = MerkleTreeAuditLog(veri)
        assert len(tree.leaves) == 3
        assert tree.leaves == [MerkleTreeAuditLog.hash_leaf(d) for d in veri]

    def test_add_leaf_hash_dondurur(self):
        """DAL: add_leaf hash_leaf(data) dondurur ve listeye ekler."""
        tree = MerkleTreeAuditLog()
        h = tree.add_leaf(b"x")
        assert h == MerkleTreeAuditLog.hash_leaf(b"x")
        assert tree.leaves == [h]

    def test_get_root_bos_agac_sha256_bos(self):
        """DAL-11: BOS agac kok'u sha256(b"")'dir — prefix YOK (ORTAM-OGRENDI).

        BULGU-KARAKTERIZASYON: bos-agac koku domain-separate EDILMEMIStir;
        hash_leaf(b"") = sha256(b"\\x00")'den farklidir, yani bos kok ile
        tek-yaprakli agacin kok'u ayni protokole tabi degildir.
        """
        tree = MerkleTreeAuditLog()
        assert tree.get_root() == hashlib.sha256(b"").digest()
        assert tree.get_root() != MerkleTreeAuditLog.hash_leaf(b"")

    def test_get_root_tek_yaprak(self):
        """DAL-12: tek yaprakli agacin koku o yapragin hash'idir."""
        tree = MerkleTreeAuditLog([b"tek"])
        assert tree.get_root() == MerkleTreeAuditLog.hash_leaf(b"tek")

    @pytest.mark.parametrize("veri", [
        [b"a", b"b"],
        [b"a", b"b", b"c", b"d"],
        [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"],
    ], ids=["2-yaprak", "4-yaprak", "8-yaprak"])
    def test_get_root_cift_guc_baimsiz_kontrol(self, veri):
        """DAL-13: cift-guc agaclarda kok hashlib ile birebir yeniden uretilir."""
        agac = MerkleTreeAuditLog(veri)
        duzey = [MerkleTreeAuditLog.hash_leaf(d) for d in veri]
        while len(duzey) > 1:
            duzey = [
                hashlib.sha256(b"\x01" + duzey[i] + duzey[i + 1]).digest()
                for i in range(0, len(duzey), 2)
            ]
        assert agac.get_root() == duzey[0]

    @pytest.mark.parametrize("n", [3, 5, 6, 7, 9, 15, 17])
    def test_get_root_tek_kalan_son_yaprak_kendisiyle_eslesir(self, n):
        """DAL-14: tek kalan son yaprak kendisiyle eslesir — hashlib ile dogrula."""
        veri = [f"v{i}".encode() for i in range(n)]
        agac = MerkleTreeAuditLog(veri)
        duzey = [MerkleTreeAuditLog.hash_leaf(d) for d in veri]
        while len(duzey) > 1:
            sonraki = []
            for i in range(0, len(duzey), 2):
                sol = duzey[i]
                sag = duzey[i + 1] if i + 1 < len(duzey) else sol
                sonraki.append(hashlib.sha256(b"\x01" + sol + sag).digest())
            duzey = sonraki
        assert agac.get_root() == duzey[0]

    def test_get_root_deterministik(self):
        """DAL-15: ayni sirada ayni yapraklar -> ayni kok; ekleme koku degistirir."""
        veri = [b"a", b"b", b"c"]
        t1 = MerkleTreeAuditLog(veri)
        t2 = MerkleTreeAuditLog(list(veri))
        assert t1.get_root() == t2.get_root()
        once = t1.get_root()
        t1.add_leaf(b"d")
        assert t1.get_root() != once

    def test_get_root_hex_formati(self):
        """DAL: get_root_hex '0x' + 64 hex-karakter; get_root()'a esittir."""
        tree = MerkleTreeAuditLog([b"a", b"b", b"c"])
        hex_kok = tree.get_root_hex()
        assert hex_kok.startswith("0x")
        assert len(hex_kok) == 66  # '0x' + 64 hex
        assert bytes.fromhex(hex_kok[2:]) == tree.get_root()

    def test_get_root_hex_bos_agac(self):
        """DAL: bos agacin hex koku da '0x' + sha256(b"") hex'idir."""
        assert MerkleTreeAuditLog().get_root_hex() == "0x" + hashlib.sha256(b"").hexdigest()


class TestMerkleProof:
    """generate_proof / verify_proof dallari."""

    @pytest.mark.parametrize("n,indeks", [
        (0, 0), (0, -1), (0, 5),      # bos agac
        (3, -1), (3, 3), (3, 99),     # dis sinir
        (1, 1), (1, -1),              # tek yaprak disi
    ], ids=["bos:0", "bos:-1", "bos:5", "n3:-1", "n3:3", "n3:99", "n1:1", "n1:-1"])
    def test_generate_proof_gecersiz_indeks_indexerror(self, n, indeks):
        """DAL-16: index<0 veya >= len(leaves) -> IndexError."""
        tree = MerkleTreeAuditLog([f"v{i}".encode() for i in range(n)])
        with pytest.raises(IndexError, match="Geçersiz yaprak indeksi"):
            tree.generate_proof(indeks)

    def test_generate_proof_tek_yaprak_bos_proof(self):
        """DAL-17: tek yaprakli agacta proof bostur (while len>1 girilmez)."""
        tree = MerkleTreeAuditLog([b"tek"])
        assert tree.generate_proof(0) == []

    @pytest.mark.parametrize("n", [2, 3, 4, 5, 7, 8, 9, 16, 17, 33])
    def test_proof_uzunlugu_ceil_log2(self, n):
        """DAL-18: n yaprak icin proof uzunlugu = ceil(log2(n))."""
        tree = MerkleTreeAuditLog([f"v{i}".encode() for i in range(n)])
        for i in range(n):
            assert len(tree.generate_proof(i)) == math.ceil(math.log2(n))

    @pytest.mark.parametrize("n", [2, 3, 5, 8])
    def test_generate_proof_yonleri(self, n):
        """DAL-19: cift indeks -> 'right'; tek indeks -> 'left'."""
        tree = MerkleTreeAuditLog([f"v{i}".encode() for i in range(n)])
        for i in range(n):
            yonler = [y for y, _ in tree.generate_proof(i)]
            # Ilk katman i'nin esitligine gore belirlenir
            assert yonler[0] == ("right" if i % 2 == 0 else "left")
            # Her yon ya 'right' ya 'left' olmalidir
            assert set(yonler) <= {"right", "left"}

    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33])
    def test_verify_proof_tum_indeksler_gecerli(self, n):
        """DAL-20: n=1..33 icin her indeksin proof'u kok'e dogrulanir."""
        veri = [f"yaprak_{i}".encode() for i in range(n)]
        tree = MerkleTreeAuditLog(veri)
        root = tree.get_root()
        for i, d in enumerate(veri):
            assert MerkleTreeAuditLog.verify_proof(d, tree.generate_proof(i), root) is True

    def test_verify_proof_yanlis_kok_reddedilir(self):
        """DAL-21: gecerli proof ama yanlis beklenen kok -> False."""
        veri = [b"a", b"b", b"c"]
        tree = MerkleTreeAuditLog(veri)
        proof = tree.generate_proof(1)
        yanlis_kok = hashlib.sha256(b"yanlis_kok").digest()
        assert MerkleTreeAuditLog.verify_proof(veri[1], proof, yanlis_kok) is False

    def test_verify_proof_tahrif_leaf_reddedilir(self):
        """DAL-22: dogru proof ama farkli leaf verisi -> False."""
        veri = [b"a", b"b", b"c", b"d"]
        tree = MerkleTreeAuditLog(veri)
        proof = tree.generate_proof(2)
        assert MerkleTreeAuditLog.verify_proof(b"tahrif", proof, tree.get_root()) is False

    def test_verify_proof_bos_proof_tek_yaprak_koku(self):
        """DAL-23: bos proof + tek-yaprak kok -> True; yanlis kok -> False."""
        tree = MerkleTreeAuditLog([b"tek"])
        root = tree.get_root()
        assert MerkleTreeAuditLog.verify_proof(b"tek", [], root) is True
        assert MerkleTreeAuditLog.verify_proof(b"baska", [], root) is False

    def test_verify_proof_tahrif_kardes_reddedilir(self):
        """DAL-24: proof icindeki bir kardes hash'i degisince -> False."""
        veri = [b"a", b"b", b"c"]
        tree = MerkleTreeAuditLog(veri)
        root = tree.get_root()
        proof = tree.generate_proof(0)
        bozuk = [(y, hashlib.sha256(b"bozuk_kardes").digest()) for y, _ in proof]
        assert MerkleTreeAuditLog.verify_proof(veri[0], bozuk, root) is False

    def test_verify_proof_yanlis_indeks_konumu_reddedilir(self):
        """DAL: baska bir indeksin proof'u bu leaf icin gecersizdir."""
        veri = [b"a", b"b", b"c", b"d"]
        tree = MerkleTreeAuditLog(veri)
        root = tree.get_root()
        # 0. yapragin verisi ama 3. yapragin proof'u -> False
        assert MerkleTreeAuditLog.verify_proof(veri[0], tree.generate_proof(3), root) is False

    def test_verify_proof_yon_semantigi(self):
        """DAL-25: 'right' -> hash_children(current, sibling); 'left' -> tersi.

        ORTAM-OGRENDI: 'right'/'left' DISINDAKI her yon degeri 'left' gibi
        islenir (else dalina duser) — bilinmeyen yon sessizce 'left' kabul edilir.
        """
        la = MerkleTreeAuditLog.hash_leaf(b"a")
        lb = MerkleTreeAuditLog.hash_leaf(b"b")
        kok = MerkleTreeAuditLog.hash_children(la, lb)

        # 0. yaprak (cift indeks): kardesi saga -> ("right", lb)
        assert MerkleTreeAuditLog.verify_proof(b"a", [("right", lb)], kok) is True
        # 1. yaprak (tek indeks): kardesi sola -> ("left", la)
        assert MerkleTreeAuditLog.verify_proof(b"b", [("left", la)], kok) is True

        # 'left' ile 'right' yer degisirse gecersiz
        assert MerkleTreeAuditLog.verify_proof(b"a", [("left", lb)], kok) is False

        # BILINMEYEN yon 'left' gibi islenir (else dali)
        assert MerkleTreeAuditLog.verify_proof(b"b", [("bilinmeyen", la)], kok) is True


# == generate_challenge_nonce ==========================================================================

class TestGenerateChallengeNonce:
    """generate_challenge_nonce dallari (OS CSPRNG)."""

    def test_varsayilan_uzunluk_32(self):
        """DAL-26: varsayilan length=32 -> 32 bayt."""
        assert len(generate_challenge_nonce()) == 32
        assert isinstance(generate_challenge_nonce(), bytes)

    @pytest.mark.parametrize("uzunluk", [1, 8, 16, 32, 64, 128, 256],
                             ids=["1", "8", "16", "32", "64", "128", "256"])
    def test_ozel_uzunluk(self, uzunluk):
        """DAL-27: istenen uzunluk kadar bayt doner."""
        assert len(generate_challenge_nonce(uzunluk)) == uzunluk

    def test_benzzersizlik(self):
        """DAL-28: arka arkaya cagrilarda degerler farklidir (50 x 32 bayt)."""
        noncelar = {generate_challenge_nonce() for _ in range(50)}
        assert len(noncelar) == 50

    def test_sifir_uzunluk_bos_bytelar(self):
        """DAL-29: length=0 -> b""."""
        assert generate_challenge_nonce(0) == b""

    def test_negatif_uzunluk_valueerror(self):
        """DAL-30: negatif length -> os.urandom ValueError firlatir."""
        with pytest.raises(ValueError):
            generate_challenge_nonce(-1)
