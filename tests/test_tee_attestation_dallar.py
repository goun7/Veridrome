"""tests/test_tee_attestation_dallar.py — veridrome.core.tee_attestation dal-kesen testleri.

Kural-1: mevcut modullere / conftest.py / mevcut testlere DOKUNULMADI; SADECE
bu yeni dosya eklendi.
Kural-3: git checkout -- . yapildi; ^ M = 0 dogrulandi (dosya yazilmadan once).
Kural-4: saf-bellek — gercek ag / RPC / subprocess YOK; aygit erisimi
monkeypatch + io.BytesIO ile, imza islemleri yerel cryptography anahtarlariyla.

MODUL-ANATOMISI (olculen dallar, kaynak: src/veridrome/core/tee_attestation.py):
- AttestationResult (frozen dataclass, L12-19):
    D1  tum alanlar atanan degerlerle okunur (is_valid/platform/pcr0/
        nonce_matched/message/claims)
    D2  frozen → attribute atama dataclasses.FrozenInstanceError fırlatır
- TEEAttestationVerifier.verify_attestation (classmethod, L28-53):
    D3  "AMD-SEV-SNP"/"AMD_SEV_SNP"/"SEV-SNP" → _verify_sev_snp (parametre)
    D4  "AWS-NITRO"/"AWS_NITRO_ENCLAVE"/"NITRO" → _verify_aws_nitro (parametre)
    D5  normalizasyon: kucuk harf + ceptaki bosluklar ("  amd-sev-snp  ")
    D6  desteklenmeyen platform → is_valid=False, pcr0="", claims={},
        message "Desteklenmeyen TEE platformu: '<orijinal>'" (L46-53)
    D7  verify_mock_or_real alias'i verify_attestation ile ayni cagrilabilir
    D8  bos platform "" → desteklenmeyen dal (strip/bosluk siniri)
- TEEAttestationVerifier._verify_crypto_signature (staticmethod, L58-78):
    D9  gecerli EC P-384 + SHA384 imza → True (L66-67)
    D10 P-384 denemesi basarisiz → SHA256 fallback basarili (P-256) → True
        (L69-75; dis except → ic try)
    D11 tahrif edilmis imza → her iki deneme basarisiz → False (L76-77)
    D12 tahrif edilmis veri → imza tutmuyor → False
    D13 gecersiz PEM → load_pem_public_key hatasi → False
    D14 EC olmayan (RSA) public key → isinstance False → son return False (L78)
    D14b dis try import hatasi → ic try importu yeniden dener; RSA ile
        L73 isinstance False → L78 (73->78 dali)
- TEEAttestationVerifier._verify_sev_snp (classmethod, L80-118):
    D15 tam gecerli (imzasiz) → is_valid=True,
        message "AMD SEV-SNP Attestation Verified", claims varsayilan
        policy=0x30000 / family_id=1
    D16 payload'da ozel policy/family_id → claims'e yansir
    D17 pcr0 buyuk/kucuk harf duyarsiz eslesme (L92 .lower())
    D18 nonce tam hex eslesmesi (L93 == dalı)
    D19 nonce ontek eslesmesi (L93 startswith expected_hex[:16])
    D20 pcr0 uyusmazligi → "PCR0 veya Nonce Uyuşmazlığı" (L104-105)
    D21 nonce uyusmazligi → ayni mesaj (L104-105)
    D22 imza mevcut + gecersiz → "AMD SEV-SNP Kriptografik Donanım İmzası
        Geçersiz" (L106-107)
    D23 imza mevcut + gecerli (P-384) → is_valid=True
    D24 imza base64 str olarak → cozulur; ham bytes olarak → dogrudan (L99)
    D25 bos payload {} → measurement/host_data varsayilan "" → uyusmazlik
- TEEAttestationVerifier._verify_aws_nitro (classmethod, L120-158):
    D26 pcrs sozluk "0" anahtari (str)
    D27 pcrs sozluk 0 anahtari (int) — falsy fallback (L128)
    D28 tam gecerli → "AWS Nitro Enclave Attestation Verified",
        claims module_id="enclave-1" / timestamp=0 varsayilan
    D29 ozel module_id/timestamp → claims'e yansir
    D30 pcr0 uyusmazligi → "PCR0 veya UserData Uyuşmazlığı" (L144-145)
    D31 user_data uyusmazligi → ayni mesaj
    D32 imza gecersiz → "AWS Nitro Enclave Kriptografik Donanım İmzası
        Geçersiz" (L146-147)
    D33 imza gecerli (P-256, base64 str) → is_valid=True
    D34 user_data ontek eslesmesi (L133)
- PhysicalTEEHardwareDriver.detect_hardware_tee (classmethod, L170-178):
    D35 /dev/sev-guest mevcut → "AMD-SEV-SNP" (L174-175)
    D36 /dev/nsm mevcut → "AWS-NITRO" (L176-177)
    D37 ikisi de yok → None (L178)
    D38 ikisi birden var → AMD oncelikli (siralama onemli)
- PhysicalTEEHardwareDriver.fetch_hardware_attestation (classmethod, L180-226):
    D39 AMD yerel aygit → 1184 bayt okuma, measurement=sha256(report[:384]),
        host_data=nonce.hex(), is_hardware_native=True (L189-200)
    D40 AMD aygit acilamiyor → emulasyona dusus (L201-202 except → L219)
    D41 AWS yerel aygit → 4096 bayt, pcrs.0=sha384(raw), user_data=nonce.hex(),
        module_id="i-native-enclave-01" (L205-214)
    D42 AWS aygit kisa okuma (4096'tan az) → yine de sha384 calisir (sinir)
    D43 AWS aygit acilamiyor → emulasyon (L215-216)
    D44 donanım yok → deterministik emulasyon: gold-image
        sha256(b"veridrome-tee-gold-image-v1.3") (L218-226)
    D45 emulasyon deterministik — ardisik cagrilarda ayni measurement

BULGULAR (sadece belgelendi, production'a DOKUNULMADI):
- BULGU-1 (L93, L133 — ORTA): nonce ontek kontrolu host_data.startswith(
  expected_hex[:16]) sadece ilk 8 baytin (16 hex karakter) eslesmesini ister;
  host_data'nin kalan kismini serbest birakir → nonce baglanmasi zayif.
- BULGU-2 (L93, L133 — DUSUK-ORTA): bos expected_nonce (b"") → hex "" →
  startswith("") her zaman True → nonce Kontrolu her hangi host_data icin
  gecer; bos nonce ile cagiran cagiranda sessiz zaafiyet.
- BULGU-3 (L97-101, L137-141 — DUSUK): imza kontrolu yalnizca hem "signature"
  hem "public_key" varsa yapilir; sadece biri verildiginde sig_valid=True
  kalir ve kapsam disinda birakilir (eksik alan sessizce gecilir).
- BULGU-4 (L92, L132 — DUSUK): pcr0 karsilastirmasi ondezlik_duyarsiz
  string eslesmesidir; bos pcr0 ("") ile bos expected_pcr0 ("") eslesir →
  bos measurement gecerli sayilir (D25/D30 sinir testlerinde kanitlandi).
"""
from __future__ import annotations

import base64
import builtins
import dataclasses
import hashlib
import io

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from veridrome.core.tee_attestation import (
    AttestationResult,
    PhysicalTEEHardwareDriver,
    TEEAttestationVerifier,
)

# Emulasyon gold-image sabiti (modul L219 ile ayni kaynak; bagimsiz oracle:
# hashlib.sha256(b"veridrome-tee-gold-image-v1.3").hexdigest())
GOLD_IMAGE_SHA256 = "0d95e3851c2cff23ba6221bbe7e36a939aadb5726e8806f427fa7d66d4e3ad7f"

PCR0_AMD = "0x98f12a4b8823901234567890abcdef1234567890abcdef1234567890abcdef"
PCR0_NITRO = "0xnitro_pcr0_hash_abcdef1234567890abcdef1234567890"


# == yardimcilar ====================================================================================

def _p386_keypair() -> tuple:
    """P-384 EC anahtar cifti uretir (saf bellek)."""
    priv = ec.generate_private_key(ec.SECP384R1())
    return priv, priv.public_key()


def _p256_keypair() -> tuple:
    """P-256 EC anahtar cifti uretir (saf bellek)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def _pub_pem(pub) -> str:
    """Public anahtari PEM metnine donusturur."""
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _sev_payload(**overrides) -> dict:
    """Gecerli bir SEV-SNP payload'i uretir; overrides ile degistirilebilir."""
    payload = {"measurement": PCR0_AMD, "host_data": "", "policy": 0x30000, "family_id": 1}
    payload.update(overrides)
    return payload


def _nitro_payload(**overrides) -> dict:
    """Gecerli bir AWS Nitro payload'i uretir; overrides ile degistirilebilir."""
    payload = {"pcrs": {"0": PCR0_NITRO}, "user_data": ""}
    payload.update(overrides)
    return payload


def _fake_open_factory(device_map: dict):
    """builtins.open yerine gecici fabrika: yalnizca bilinen aygit yollarini
    io.BytesIO ile yanitlar, digerleri gercek open'a devuelve edilir (Kural-4)."""
    real_open = builtins.open

    def fake_open(path, mode="r", *args, **kwargs):
        if path in device_map:
            return io.BytesIO(device_map[path])
        return real_open(path, mode, *args, **kwargs)

    return fake_open


# == AttestationResult ==============================================================================

class TestAttestationResult:
    """Frozen dataclass alan dalari (D1-D2)."""

    def test_alanlar_atanan_degerle_okunur(self):
        """D1: butun alanlar atanan degerlerle okunur."""
        claims = {"policy": 0x30000}
        sonuc = AttestationResult(
            is_valid=True,
            platform="AMD-SEV-SNP",
            pcr0=PCR0_AMD,
            nonce_matched=True,
            message="ok",
            claims=claims,
        )
        assert sonuc.is_valid is True
        assert sonuc.platform == "AMD-SEV-SNP"
        assert sonuc.pcr0 == PCR0_AMD
        assert sonuc.nonce_matched is True
        assert sonuc.message == "ok"
        assert sonuc.claims == claims

    def test_frozen_attribut_atama_reddedilir(self):
        """D2: frozen dataclass → attribute atama FrozenInstanceError fırlatır."""
        sonuc = AttestationResult(
            is_valid=False, platform="", pcr0="", nonce_matched=False,
            message="", claims={},
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            sonuc.is_valid = True


# == verify_attestation platform yonlendirmesi ======================================================

class TestVerifyAttestationPlatformYonlendirme:
    """verify_attestation platform normalizasyon ve yonlendirme dallari (D3-D8)."""

    @pytest.mark.parametrize("platform", ["AMD-SEV-SNP", "AMD_SEV_SNP", "SEV-SNP"])
    def test_amd_platform_yonlendirmesi(self, platform):
        """D3: AMD platform varyantlari _verify_sev_snp'e yonlenir."""
        sonuc = TEEAttestationVerifier.verify_attestation(
            platform=platform,
            attestation_payload=_sev_payload(host_data="aa" * 32),
            expected_pcr0=PCR0_AMD,
            expected_nonce=bytes.fromhex("aa" * 32),
        )
        assert sonuc.platform == "AMD-SEV-SNP"
        assert sonuc.is_valid is True

    @pytest.mark.parametrize("platform", ["AWS-NITRO", "AWS_NITRO_ENCLAVE", "NITRO"])
    def test_aws_platform_yonlendirmesi(self, platform):
        """D4: AWS platform varyantlari _verify_aws_nitro'ya yonlenir."""
        sonuc = TEEAttestationVerifier.verify_attestation(
            platform=platform,
            attestation_payload=_nitro_payload(user_data="bb" * 32),
            expected_pcr0=PCR0_NITRO,
            expected_nonce=bytes.fromhex("bb" * 32),
        )
        assert sonuc.platform == "AWS-NITRO"
        assert sonuc.is_valid is True

    @pytest.mark.parametrize("platform", ["  amd-sev-snp  ", "sev-snp", "  AMD_sev_snp  "])
    def test_normalizasyon_kucuk_harf_ve_bosluk_amd(self, platform):
        """D5: platform .upper().strip() ile normallesir → AMD yonu."""
        sonuc = TEEAttestationVerifier.verify_attestation(
            platform=platform,
            attestation_payload=_sev_payload(host_data="cc" * 32),
            expected_pcr0=PCR0_AMD,
            expected_nonce=bytes.fromhex("cc" * 32),
        )
        assert sonuc.platform == "AMD-SEV-SNP"
        assert sonuc.is_valid is True

    @pytest.mark.parametrize("platform", ["  aws-nitro  ", "  NitRo  ", "aws_NITRO_ENCLAVE"])
    def test_normalizasyon_kucuk_harf_ve_bosluk_aws(self, platform):
        """D5: AWS platformu da normallesir → AWS yonu."""
        sonuc = TEEAttestationVerifier.verify_attestation(
            platform=platform,
            attestation_payload=_nitro_payload(user_data="bb" * 32),
            expected_pcr0=PCR0_NITRO,
            expected_nonce=bytes.fromhex("bb" * 32),
        )
        assert sonuc.platform == "AWS-NITRO"
        assert sonuc.is_valid is True

    @pytest.mark.parametrize("platform", ["TPM", "intel-tdx", "", "  ", "apple"])
    def test_desteklenmeyen_platform(self, platform):
        """D6/D8: desteklenmeyen platform → is_valid=False, pcr0="", claims={}."""
        sonuc = TEEAttestationVerifier.verify_attestation(
            platform=platform,
            attestation_payload={"measurement": PCR0_AMD},
            expected_pcr0=PCR0_AMD,
            expected_nonce=b"\x01" * 32,
        )
        assert sonuc.is_valid is False
        assert sonuc.nonce_matched is False
        assert sonuc.pcr0 == ""
        assert sonuc.claims == {}
        # mesaj ORIJINAL platform metnini kullanir (L51)
        assert sonuc.message == f"Desteklenmeyen TEE platformu: '{platform}'"

    def test_alias_verify_mock_or_real_ayni_fonksiyon(self):
        """D7: verify_mock_or_real, verify_attestation ile ayni fonksiyon."""
        # classmethod: sinif uzerinden erisim her seferinde yeni bound object
        # uretir, bu yuzden __func__ ile karsilastirilir.
        assert (
            TEEAttestationVerifier.verify_mock_or_real.__func__
            is TEEAttestationVerifier.verify_attestation.__func__
        )
        sonuc = TEEAttestationVerifier.verify_mock_or_real(
            platform="NITRO",
            attestation_payload=_nitro_payload(user_data="bb" * 32),
            expected_pcr0=PCR0_NITRO,
            expected_nonce=bytes.fromhex("bb" * 32),
        )
        assert sonuc.is_valid is True
        assert sonuc.platform == "AWS-NITRO"


# == _verify_crypto_signature =======================================================================

class TestKriptografikImza:
    """_verify_crypto_signature ECDSA dogrulama dallari (D9-D14)."""

    def test_gecerli_p384_sha384_imza(self):
        """D9: gecerli EC P-384 + SHA384 imza → True."""
        priv, pub = _p386_keypair()
        veri = b"0xabc:deadbeef"
        imza = priv.sign(veri, ec.ECDSA(hashes.SHA384()))
        assert TEEAttestationVerifier._verify_crypto_signature(_pub_pem(pub), veri, imza) is True

    def test_sha256_fallback_p256(self):
        """D10: P-384 denemesi basarisiz → SHA256 fallback basarili (P-256)."""
        priv, pub = _p256_keypair()
        veri = b"0xabc:deadbeef"
        imza = priv.sign(veri, ec.ECDSA(hashes.SHA256()))
        # imza P-256+SHA256 ile uretiliyor; once SHA384 deneniyor, o basarisiz
        assert TEEAttestationVerifier._verify_crypto_signature(_pub_pem(pub), veri, imza) is True

    def test_tahrif_edilmis_imza(self):
        """D11: tahrif imza → her iki deneme basarisiz → False."""
        priv, pub = _p256_keypair()
        veri = b"0xabc:deadbeef"
        imza = bytearray(priv.sign(veri, ec.ECDSA(hashes.SHA256())))
        imza[0] ^= 0xFF
        assert TEEAttestationVerifier._verify_crypto_signature(_pub_pem(pub), veri, bytes(imza)) is False

    def test_tahrif_edilmis_veri(self):
        """D12: imza dogru ama veri degistirilmis → False."""
        priv, pub = _p386_keypair()
        imza = priv.sign(b"orijinal", ec.ECDSA(hashes.SHA384()))
        assert TEEAttestationVerifier._verify_crypto_signature(_pub_pem(pub), b"tahrif", imza) is False

    def test_gecersiz_pem(self):
        """D13: gecersiz PEM → yukleme hatasi → False."""
        gecerli_priv, gecerli_pub = _p256_keypair()
        imza = gecerli_priv.sign(b"x", ec.ECDSA(hashes.SHA256()))
        assert TEEAttestationVerifier._verify_crypto_signature("not-a-pem", b"x", imza) is False

    def test_ec_olmayan_rsa_anahtari(self):
        """D14: RSA public key → isinstance False → son return False (L78)."""
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = _pub_pem(rsa_priv.public_key())
        assert TEEAttestationVerifier._verify_crypto_signature(pem, b"x", b"\x00" * 64) is False

    def test_dis_try_import_hatasi_ic_try_rsa(self, monkeypatch):
        """D14b: dis try import hatasi → ic try importu yeniden dener; RSA
        anahtari ile L73 isinstance False → L78 return False (73->78 dali).
        sys.modules stub: 'ec' alt modulu ilk erisimde ImportError firlatır,
        ikinci erisimde gercek modulu dondurur (Kural-4 saf-bellek stub'i)."""
        import sys

        asym_paket = sys.modules["cryptography.hazmat.primitives.asymmetric"]
        gercek_ec = sys.modules["cryptography.hazmat.primitives.asymmetric.ec"]
        cagri = {"n": 0}

        class ZehirlenmisPaket:
            """Ilk getattr('ec') cagrisinda ImportError, ikincide gercek ec."""

            def __getattr__(self, isim):
                if isim == "ec":
                    cagri["n"] += 1
                    if cagri["n"] == 1:
                        raise ImportError("ilk deneme basarisiz")
                    return gercek_ec
                return getattr(asym_paket, isim)

        monkeypatch.setitem(
            sys.modules,
            "cryptography.hazmat.primitives.asymmetric",
            ZehirlenmisPaket(),
        )
        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = _pub_pem(rsa_priv.public_key())
        # dis try: import basarisiz → except; ic try: import basarili, RSA
        # anahtari EC olmadigi icin L73'ten L78'e atlar
        assert TEEAttestationVerifier._verify_crypto_signature(pem, b"x", b"\x00" * 64) is False
        # tam 3 erisim: (1) dis _handle_fromlist hasattr → ImportError,
        # (2) ic _handle_fromlist hasattr → OK, (3) ic IMPORT_FROM getattr
        assert cagri["n"] == 3


# == _verify_sev_snp ================================================================================

class TestSevSnpDogrulama:
    """_verify_sev_snp measurement/nonce/imza dallari (D15-D25)."""

    def _dogrula(self, payload, expected_pcr0=PCR0_AMD, expected_nonce=None):
        return TEEAttestationVerifier._verify_sev_snp(
            payload, expected_pcr0, expected_nonce if expected_nonce is not None else b"\x11" * 32,
        )

    def test_tam_gecerli_imzasiz(self):
        """D15: pcr+nonce gecerli, imza yok → basarili + varsayilan claims."""
        nonce = bytes.fromhex("aa" * 32)
        sonuc = self._dogrula(
            _sev_payload(host_data=nonce.hex()), expected_nonce=nonce,
        )
        assert sonuc.is_valid is True
        assert sonuc.nonce_matched is True
        assert sonuc.message == "AMD SEV-SNP Attestation Verified"
        assert sonuc.platform == "AMD-SEV-SNP"
        assert sonuc.pcr0 == PCR0_AMD
        assert sonuc.claims == {"policy": 0x30000, "family_id": 1}

    def test_ozel_policy_family_id_claimslere_yansir(self):
        """D16: payload policy/family_id degerleri claims'e gecer."""
        nonce = bytes.fromhex("aa" * 32)
        sonuc = self._dogrula(
            _sev_payload(host_data=nonce.hex(), policy=0x1, family_id=7), expected_nonce=nonce,
        )
        assert sonuc.claims == {"policy": 0x1, "family_id": 7}

    def test_pcr0_harf_buyuklugu_duyarsiz(self):
        """D17: pcr0 buyuk/kucuk harf duyarsiz eslesir."""
        nonce = bytes.fromhex("aa" * 32)
        sonuc = self._dogrula(
            _sev_payload(measurement=PCR0_AMD.upper(), host_data=nonce.hex()), expected_nonce=nonce,
        )
        assert sonuc.is_valid is True

    def test_nonce_tam_hex_eslesmesi(self):
        """D18: host_data nonce hex'in tamamina esit."""
        nonce = bytes.fromhex("aa" * 32)
        sonuc = self._dogrula(_sev_payload(host_data=nonce.hex()), expected_nonce=nonce)
        assert sonuc.nonce_matched is True

    def test_nonce_ontek_eslesmesi(self):
        """D19: host_data ontek (ilk 16 hex) eslesmesi yeterli (BULGU-1)."""
        nonce = bytes.fromhex("aa" * 32)
        host_data = nonce.hex()[:16] + "ffffffff" * 28  # kalan kisim serbest
        sonuc = self._dogrula(_sev_payload(host_data=host_data), expected_nonce=nonce)
        assert sonuc.nonce_matched is True
        assert sonuc.is_valid is True

    def test_pcr0_uyusmazligi(self):
        """D20: pcr0 uyusmazligi → 'PCR0 veya Nonce Uyuşmazlığı'."""
        nonce = bytes.fromhex("aa" * 32)
        sonuc = self._dogrula(
            _sev_payload(measurement="0x" + "00" * 32, host_data=nonce.hex()), expected_nonce=nonce,
        )
        assert sonuc.is_valid is False
        assert sonuc.pcr0 == "0x" + "00" * 32
        assert sonuc.message == "PCR0 veya Nonce Uyuşmazlığı"

    def test_nonce_uyusmazligi(self):
        """D21: nonce uyusmazligi → ayni mesaj, nonce_matched=False."""
        sonuc = self._dogrula(
            _sev_payload(host_data="ff" * 32), expected_nonce=bytes.fromhex("aa" * 32),
        )
        assert sonuc.is_valid is False
        assert sonuc.nonce_matched is False
        assert sonuc.message == "PCR0 veya Nonce Uyuşmazlığı"

    def test_imza_gecersiz(self):
        """D22: pcr+nonce gecerli ama imza gecersiz → imza mesaji."""
        priv, pub = _p256_keypair()
        veri = b"tahrif-edilmis-veri"
        imza = priv.sign(veri, ec.ECDSA(hashes.SHA256()))
        nonce = bytes.fromhex("aa" * 32)
        payload = _sev_payload(host_data=nonce.hex())
        payload["public_key"] = _pub_pem(pub)
        payload["signature"] = base64.b64encode(imza).decode("ascii")
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is False
        assert sonuc.message == "AMD SEV-SNP Kriptografik Donanım İmzası Geçersiz"

    def test_imza_gecerli_p384(self):
        """D23: pcr+nonce+P-384 imza hepsi gecerli → is_valid=True."""
        priv, pub = _p386_keypair()
        nonce = bytes.fromhex("aa" * 32)
        host_data = nonce.hex()
        veri = f"{PCR0_AMD}:{host_data}".encode("utf-8")
        imza = priv.sign(veri, ec.ECDSA(hashes.SHA384()))
        payload = _sev_payload(host_data=host_data)
        payload["public_key"] = _pub_pem(pub)
        payload["signature"] = base64.b64encode(imza).decode("ascii")
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is True
        assert sonuc.message == "AMD SEV-SNP Attestation Verified"

    @pytest.mark.parametrize("imza_turu", ["base64_str", "ham_bytes"])
    def test_imza_turu_str_ve_bytes(self, imza_turu):
        """D24: imza base64 str ise cozulur, ham bytes ise dogrudan kullanilir."""
        priv, pub = _p386_keypair()
        nonce = bytes.fromhex("aa" * 32)
        host_data = nonce.hex()
        imza = priv.sign(f"{PCR0_AMD}:{host_data}".encode("utf-8"), ec.ECDSA(hashes.SHA384()))
        payload = _sev_payload(host_data=host_data)
        payload["public_key"] = _pub_pem(pub)
        payload["signature"] = base64.b64encode(imza).decode("ascii") if imza_turu == "base64_str" else imza
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is True

    def test_bos_payload(self):
        """D25: bos payload → varsayilan degerlerle uyusmazlik."""
        sonuc = self._dogrula({})
        assert sonuc.is_valid is False
        assert sonuc.pcr0 == ""
        assert sonuc.message == "PCR0 veya Nonce Uyuşmazlığı"

    def test_bos_nonce_kontrolu_her_seyi_gectirir(self):
        """BULGU-2: bos expected_nonce → startswith("") her zaman True."""
        sonuc = self._dogrula(
            _sev_payload(host_data="ff" * 32), expected_nonce=b"",
        )
        assert sonuc.nonce_matched is True

    def test_tek_basina_imza_alani_atlanir(self):
        """BULGU-3: yalnizca 'signature' var, 'public_key' yok → sig kontrolu atlanir."""
        nonce = bytes.fromhex("aa" * 32)
        payload = _sev_payload(host_data=nonce.hex())
        payload["signature"] = "AAAA"
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is True


# == _verify_aws_nitro ==============================================================================

class TestAwsNitroDogrulama:
    """_verify_aws_nitro pcrs/user_data/imza dallari (D26-D34)."""

    def _dogrula(self, payload, expected_pcr0=PCR0_NITRO, expected_nonce=None):
        return TEEAttestationVerifier._verify_aws_nitro(
            payload, expected_pcr0, expected_nonce if expected_nonce is not None else b"\x22" * 32,
        )

    def test_pcrs_string_anahtar(self):
        """D26: pcrs sozlugu '0' (str) anahtari okunur."""
        nonce = bytes.fromhex("bb" * 32)
        sonuc = self._dogrula(
            {"pcrs": {"0": PCR0_NITRO}, "user_data": nonce.hex()}, expected_nonce=nonce,
        )
        assert sonuc.pcr0 == PCR0_NITRO
        assert sonuc.is_valid is True

    def test_pcrs_int_anahtar(self):
        """D27: pcrs sozlugu 0 (int) anahtari — falsy fallback (L128)."""
        nonce = bytes.fromhex("bb" * 32)
        sonuc = self._dogrula(
            {"pcrs": {0: PCR0_NITRO}, "user_data": nonce.hex()}, expected_nonce=nonce,
        )
        assert sonuc.pcr0 == PCR0_NITRO
        assert sonuc.is_valid is True

    def test_tam_gecerli_varsayilan_claims(self):
        """D28: tam gecerli → basarili mesaj + varsayilan claims."""
        nonce = bytes.fromhex("bb" * 32)
        sonuc = self._dogrula(
            {"pcrs": {"0": PCR0_NITRO}, "user_data": nonce.hex()}, expected_nonce=nonce,
        )
        assert sonuc.message == "AWS Nitro Enclave Attestation Verified"
        assert sonuc.platform == "AWS-NITRO"
        assert sonuc.claims == {"module_id": "enclave-1", "timestamp": 0}

    def test_ozel_module_id_timestamp_claimslere_yansir(self):
        """D29: ozel module_id/timestamp degerleri claims'e gecer."""
        nonce = bytes.fromhex("bb" * 32)
        sonuc = self._dogrula(
            {"pcrs": {"0": PCR0_NITRO}, "user_data": nonce.hex(),
             "module_id": "i-custom-42", "timestamp": 1700000000},
            expected_nonce=nonce,
        )
        assert sonuc.claims == {"module_id": "i-custom-42", "timestamp": 1700000000}

    def test_pcr0_uyusmazligi(self):
        """D30: pcr0 uyusmazligi → 'PCR0 veya UserData Uyuşmazlığı'."""
        nonce = bytes.fromhex("bb" * 32)
        sonuc = self._dogrula(
            {"pcrs": {"0": "0x" + "11" * 32}, "user_data": nonce.hex()}, expected_nonce=nonce,
        )
        assert sonuc.is_valid is False
        assert sonuc.message == "PCR0 veya UserData Uyuşmazlığı"

    def test_user_data_uyusmazligi(self):
        """D31: user_data uyusmazligi → ayni mesaj."""
        sonuc = self._dogrula(
            {"pcrs": {"0": PCR0_NITRO}, "user_data": "ff" * 32},
            expected_nonce=bytes.fromhex("bb" * 32),
        )
        assert sonuc.is_valid is False
        assert sonuc.nonce_matched is False
        assert sonuc.message == "PCR0 veya UserData Uyuşmazlığı"

    def test_imza_gecersiz(self):
        """D32: pcr+nonce gecerli ama imza gecersiz → imza mesaji."""
        priv, pub = _p256_keypair()
        imza = priv.sign(b"baska-veri", ec.ECDSA(hashes.SHA256()))
        nonce = bytes.fromhex("bb" * 32)
        payload = {"pcrs": {"0": PCR0_NITRO}, "user_data": nonce.hex()}
        payload["public_key"] = _pub_pem(pub)
        payload["signature"] = base64.b64encode(imza).decode("ascii")
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is False
        assert sonuc.message == "AWS Nitro Enclave Kriptografik Donanım İmzası Geçersiz"

    def test_imza_gecerli_p256(self):
        """D33: pcr+nonce+P-256 imza (base64 str) hepsi gecerli → is_valid=True."""
        priv, pub = _p256_keypair()
        nonce = bytes.fromhex("bb" * 32)
        user_data = nonce.hex()
        imza = priv.sign(f"{PCR0_NITRO}:{user_data}".encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        payload = {"pcrs": {"0": PCR0_NITRO}, "user_data": user_data}
        payload["public_key"] = _pub_pem(pub)
        payload["signature"] = base64.b64encode(imza).decode("ascii")
        sonuc = self._dogrula(payload, expected_nonce=nonce)
        assert sonuc.is_valid is True
        assert sonuc.message == "AWS Nitro Enclave Attestation Verified"

    def test_user_data_ontek_eslesmesi(self):
        """D34: user_data ontek (ilk 16 hex) eslesmesi yeterli (BULGU-1)."""
        nonce = bytes.fromhex("bb" * 32)
        user_data = nonce.hex()[:16] + "eeee" * 28
        sonuc = self._dogrula(
            {"pcrs": {"0": PCR0_NITRO}, "user_data": user_data}, expected_nonce=nonce,
        )
        assert sonuc.nonce_matched is True
        assert sonuc.is_valid is True

    def test_bos_pcr0_ve_bos_nonce_gecerli_sayilir(self):
        """BULGU-4: bos pcr0 ('') + bos expected_pcr0 + bos nonce → gecerli."""
        sonuc = self._dogrula({"pcrs": {}, "user_data": ""}, expected_pcr0="", expected_nonce=b"")
        assert sonuc.pcr0 == ""
        assert sonuc.is_valid is True
        assert sonuc.message == "AWS Nitro Enclave Attestation Verified"


# == detect_hardware_tee ============================================================================

class TestDonanimSurucuTespit:
    """detect_hardware_tee aygit tespit dallari (D35-D38)."""

    def test_sev_guest_aygiti_var(self, monkeypatch):
        """D35: /dev/sev-guest mevcut → 'AMD-SEV-SNP'."""
        monkeypatch.setattr(
            "os.path.exists", lambda p: p == PhysicalTEEHardwareDriver.SEV_GUEST_DEVICE,
        )
        assert PhysicalTEEHardwareDriver.detect_hardware_tee() == "AMD-SEV-SNP"

    def test_nsm_aygiti_var(self, monkeypatch):
        """D36: /dev/nsm mevcut → 'AWS-NITRO'."""
        monkeypatch.setattr(
            "os.path.exists", lambda p: p == PhysicalTEEHardwareDriver.AWS_NSM_DEVICE,
        )
        assert PhysicalTEEHardwareDriver.detect_hardware_tee() == "AWS-NITRO"

    def test_hicbir_aygit_yok(self, monkeypatch):
        """D37: iki aygit da yok → None."""
        monkeypatch.setattr("os.path.exists", lambda p: False)
        assert PhysicalTEEHardwareDriver.detect_hardware_tee() is None

    def test_iki_aygit_varsa_amd_oncelikli(self, monkeypatch):
        """D38: her iki aygit da varsa AMD once kontrol edilir."""
        monkeypatch.setattr("os.path.exists", lambda p: True)
        assert PhysicalTEEHardwareDriver.detect_hardware_tee() == "AMD-SEV-SNP"

    def test_aygit_sabitleri(self):
        """Sabitler dokumante edilen aygit yollari."""
        assert PhysicalTEEHardwareDriver.SEV_GUEST_DEVICE == "/dev/sev-guest"
        assert PhysicalTEEHardwareDriver.AWS_NSM_DEVICE == "/dev/nsm"


# == fetch_hardware_attestation =====================================================================

class TestDonanimAttestationAlma:
    """fetch_hardware_attestation donanim/emulasyon dallari (D39-D45)."""

    def test_amd_yerel_aygit_okuma(self, monkeypatch):
        """D39: AMD yerel aygit → 1184 bayt oku, measurement=sha256(report[:384])."""
        report = bytes(range(256)) * 4 + b"\x00" * 160  # 1184 bayt
        assert len(report) == 1184
        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: "AMD-SEV-SNP"),
        )
        monkeypatch.setattr(
            builtins, "open", _fake_open_factory({PhysicalTEEHardwareDriver.SEV_GUEST_DEVICE: report}),
        )
        nonce = bytes.fromhex("99" * 32)
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(nonce)
        assert sonuc["is_hardware_native"] is True
        assert sonuc["measurement"] == hashlib.sha256(report[:384]).hexdigest()
        assert sonuc["host_data"] == nonce.hex()
        assert sonuc["policy"] == 0x30000
        assert sonuc["family_id"] == 1

    def test_amd_aygit_acilamiyor_emulasyona_duser(self, monkeypatch):
        """D40: AMD aygiti open/read hatasi → emulasyona dusus (L201-202)."""
        real_open = builtins.open

        def hatali_open(path, mode="r", *args, **kwargs):
            if path == PhysicalTEEHardwareDriver.SEV_GUEST_DEVICE:
                raise OSError("aygit okunamiyor")
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: "AMD-SEV-SNP"),
        )
        monkeypatch.setattr(builtins, "open", hatali_open)
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(b"\x01" * 16)
        assert sonuc["is_hardware_native"] is False
        assert sonuc["measurement"] == GOLD_IMAGE_SHA256

    def test_aws_yerel_aygit_okuma(self, monkeypatch):
        """D41: AWS yerel aygit → 4096 bayt, pcrs.0=sha384(raw)."""
        raw_doc = b"\xAB" * 4096
        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: "AWS-NITRO"),
        )
        monkeypatch.setattr(
            builtins, "open", _fake_open_factory({PhysicalTEEHardwareDriver.AWS_NSM_DEVICE: raw_doc}),
        )
        nonce = bytes.fromhex("77" * 32)
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(nonce)
        assert sonuc["is_hardware_native"] is True
        assert sonuc["pcrs"] == {"0": hashlib.sha384(raw_doc).hexdigest()}
        assert sonuc["user_data"] == nonce.hex()
        assert sonuc["module_id"] == "i-native-enclave-01"

    def test_aws_aygit_kisa_okuma_siniri(self, monkeypatch):
        """D42: aygit 4096'tan az bayt donebilir — sha384 yine calisir (sinir)."""
        kisa_doc = b"\x01\x02\x03"  # 3 bayt: okuma isteginden az
        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: "AWS-NITRO"),
        )
        monkeypatch.setattr(
            builtins, "open", _fake_open_factory({PhysicalTEEHardwareDriver.AWS_NSM_DEVICE: kisa_doc}),
        )
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(b"\x01" * 16)
        assert sonuc["is_hardware_native"] is True
        assert sonuc["pcrs"]["0"] == hashlib.sha384(kisa_doc).hexdigest()

    def test_aws_aygit_acilamiyor_emulasyona_duser(self, monkeypatch):
        """D43: AWS aygiti open hatasi → emulasyon (L215-216)."""
        real_open = builtins.open

        def hatali_open(path, mode="r", *args, **kwargs):
            if path == PhysicalTEEHardwareDriver.AWS_NSM_DEVICE:
                raise OSError("nsm okunamiyor")
            return real_open(path, mode, *args, **kwargs)

        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: "AWS-NITRO"),
        )
        monkeypatch.setattr(builtins, "open", hatali_open)
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(b"\x02" * 16)
        assert sonuc["is_hardware_native"] is False
        assert sonuc["measurement"] == GOLD_IMAGE_SHA256

    def test_donanim_yok_emulasyon_gold_image(self, monkeypatch):
        """D44: donanim yok → deterministik emulasyon (gold-image)."""
        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: None),
        )
        nonce = bytes.fromhex("55" * 32)
        sonuc = PhysicalTEEHardwareDriver.fetch_hardware_attestation(nonce)
        assert sonuc["is_hardware_native"] is False
        # iki bagimsiz oracle: hardcoded sabit + hashlib
        assert sonuc["measurement"] == GOLD_IMAGE_SHA256
        assert sonuc["measurement"] == hashlib.sha256(b"veridrome-tee-gold-image-v1.3").hexdigest()
        assert sonuc["host_data"] == nonce.hex()
        assert sonuc["policy"] == 0x30000
        assert sonuc["family_id"] == 1

    def test_emulasyon_deterministik(self, monkeypatch):
        """D45: ardisik emulasyon cagrilari ayni measurement'i uretir."""
        monkeypatch.setattr(
            PhysicalTEEHardwareDriver, "detect_hardware_tee",
            classmethod(lambda cls: None),
        )
        birinci = PhysicalTEEHardwareDriver.fetch_hardware_attestation(b"\x03" * 16)
        ikinci = PhysicalTEEHardwareDriver.fetch_hardware_attestation(b"\x04" * 16)
        assert birinci["measurement"] == ikinci["measurement"] == GOLD_IMAGE_SHA256
