"""tests/test_revocation_dallar.py — veridrome.certificate.revocation dal-kesen testleri (201 satir).

Kural-1: mevcut modullere / conftest.py / mevcut testlere DOKUNULMADI; SADECE
bu yeni dosya eklendi.
Kural-4: saf in-memory (did:key Ed25519 stdlib-only; tek dis-bagimlilik yerel
dosya sistemidir ve SADECE tmp_path ile, pytest fixture'i tarafindan yonetilir;
network / RPC / subprocess YOK).

ORTAM-ANATOMI (olculen dallar):
- RevocationLedger(path): append-only hash-zincirli iptal-defteri.
- _read_lines():
    DAL-1  dosya yok (FileNotFoundError) -> []
    DAL-2  bos / whitespace-only satirlar filtrelenir
    DAL-3  OSError (yol bir DIZIN) -> RuntimeError "iptal-defteri-okunamadı" (fail-closed)
- read_entries():
    DAL-4  bos defter -> []
    DAL-5  gecerli JSON satirlari -> dict listesi (sira korunur)
    DAL-6  BOZUK JSON satir -> RuntimeError "sessiz-zincir-kopması-YOK" (fail-closed)
- verify_chain():
    DAL-7  bos defter -> True
    DAL-8  gecerli tek / iki giris -> True (prev + h baglari)
    DAL-9  kirik prev bagi -> False
    DAL-10 tahrif 'h' -> False
- revoked_cert_ids():
    DAL-11 bos -> set(); DAL-12 cert_id kumesi; DAL-13 eksik cert_id -> str(None)
- revoke(cert_id, revoked_by_seed, revoked_by_did, reason=""):
    DAL-14 cert_id 63 / 65 / 0 karakter -> ValueError "cert_id 64-hex olmalı"
    DAL-15 gecersiz did:key -> ValueError
    DAL-16 taze dosya -> prev=genesis(64x'0'), dosya OLUSTURULUR, h + signature ile doner
    DAL-17 mevcut deftere ekleme -> prev = son girisin 'h' (zincir baglantisi)
    DAL-18 bozuk kuyruk (son satir gecersiz JSON) -> RuntimeError "bozuk-kuyruk"
    DAL-19 reason varsayilan ""; DAL-20 ozel reason kaydedilir
    DAL-21 append-only: mevcut icerik KORUNUR (O_APPEND), taze dosya 0o600 modu
- verify_revocation_entry(entry):
    DAL-22 gecerli giris -> True (did:key self-resolving)
    DAL-23 tahrif imza -> False;   DAL-24 imza None -> False
    DAL-25 imza tipi bytes / int -> False;  DAL-26 gecersiz-base64 imza -> False
    DAL-27 revoked_by None / bos / gecersiz-did -> False
    DAL-28 baska anahtar imzasi -> False;  DAL-29 bilinmeyen ekstra anahtar -> False
    DAL-30 entry=None -> False (istisra guvenligi)
- check_revoked(cert_id, ledger):
    DAL-31 ledger=None -> {revoked:False, reason:"", entry:None, chain_valid:True}
    DAL-32 iptal-edilmis cert_id bulunur -> revoked:True + reason + signature_valid:True
    DAL-33 bulunamaz -> revoked:False + chain_valid
    DAL-34 kirik zincir + mevcut cert -> revoked:True, chain_valid:False
    DAL-35 bos defter -> bulunamaz, chain_valid:True

BULGULAR (production koduna DOKUNULMADI — GERCEK davranis test edildi):
- BULGU-1: revoke() cert_id icin SADECE len==64 kontrolu yapar. Hata mesaji
  "cert_id 64-hex olmalı" der ama HEX kontrolu YOKTUR: 64 karakterli hex-olmayan
  bir cert_id (ornegin 'g'*64) KABUL EDILIR.
- BULGU-2: revoke()'un os.open() SARILMAMISTIR. _read_lines() OSError'i
  RuntimeError ile sarar (fail-closed) ve dizin yolunda revoke() DA once
  _read_lines'tan dolayi RuntimeError firlatir. ANCAK okunabilen ama
  YAZILAMAYAN (0o444) bir dosyada _read_lines basarili olur ve sarilmamis
  os.open() ham PermissionError (OSError) firlatir — yazma yolu fail-closed
  DEGILDIR (asimetrik hata modeli).
- BULGU-3: verify_chain() dict-olmayan JSON satirinda False yerine
  AttributeError firlatir (read_entries dict-lik validate ETMEZ).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import stat

import pytest

from veridrome.certificate.didkey import (
    generate_keypair,
    is_did_key,
    sign,
)
from veridrome.certificate.revocation import (
    RevocationLedger,
    check_revoked,
    verify_revocation_entry,
)

_GENESIS = "0" * 64


def _cid(i: int = 0) -> str:
    """64-hex cert_id ornegi (hashlib ile uretilir)."""
    return hashlib.sha256(f"cert-{i}".encode("utf-8")).hexdigest()


def _kanonik(govde: dict) -> str:
    """Modulun _canonical davranisinin bagimsiz yeniden-uretimi."""
    return json.dumps(govde, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _valid_giris(seed: bytes, did: str, cert_id: str, reason: str = "neden",
                 prev: str = _GENESIS) -> dict:
    """revoke()'in urettigi yapi elle (bagimsiz) olusturur — dogrulama icin."""
    govde = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cert_id": cert_id,
        "revoked_by": did,
        "reason": reason,
        "prev": prev,
    }
    imza = base64.b64encode(sign(seed, _kanonik(govde).encode("utf-8"))).decode("ascii")
    giris = dict(govde)
    giris["signature"] = imza
    return giris


def _valid_defter(tmp_path, seed: bytes, did: str, n: int = 2,
                  yol: str = "ledger.jsonl"):
    """n gecerli girisli bir defter olusturur (revoke ile)."""
    lg = RevocationLedger(str(tmp_path / yol))
    girisler = [lg.revoke(_cid(i), seed, did, reason=f"neden-{i}") for i in range(n)]
    return lg, girisler


# == RevocationLedger okuma ============================================================================

class TestRevocationLedgerOkuma:
    """_read_lines / read_entries dallari (DAL-1..6)."""

    def test_dosya_yok_bos_liste(self, tmp_path):
        """DAL-1: olmayan dosya FileNotFoundError -> [] (sessiz bos baslangic)."""
        lg = RevocationLedger(str(tmp_path / "yok.jsonl"))
        assert lg.read_entries() == []

    def test_bos_ve_whitespace_satirlar_filtrelenir(self, tmp_path):
        """DAL-2: bos / whitespace-only satirlar okumada atlanir."""
        yol = tmp_path / "bosluk.jsonl"
        gecerli = json.dumps({"cert_id": _cid(), "prev": _GENESIS, "h": "x"})
        yol.write_text("\n   \n\t\n" + gecerli + "\n\n", encoding="utf-8")
        assert len(RevocationLedger(str(yol)).read_entries()) == 1

    def test_dizin_yolu_runtime_error_fail_closed(self, tmp_path):
        """DAL-3: yol bir dizin ise OSError -> RuntimeError (fail-closed)."""
        lg = RevocationLedger(str(tmp_path))  # tmp_path'in kendisi bir dizin
        with pytest.raises(RuntimeError, match="iptal-defteri-okunamadı"):
            lg.read_entries()

    def test_bos_dosya_bos_liste(self, tmp_path):
        """DAL-4: 0 baytlik dosya -> []."""
        yol = tmp_path / "bos.jsonl"
        yol.write_text("", encoding="utf-8")
        assert RevocationLedger(str(yol)).read_entries() == []

    def test_gecerli_json_satirlari_dict_listesi(self, tmp_path):
        """DAL-5: gecerli JSON satirlari dict listesi olarak, sirayla doner."""
        yol = tmp_path / "iki.jsonl"
        yol.write_text(
            json.dumps({"i": 0}) + "\n" + json.dumps({"i": 1}) + "\n",
            encoding="utf-8",
        )
        girisler = RevocationLedger(str(yol)).read_entries()
        assert girisler == [{"i": 0}, {"i": 1}]

    def test_bozuk_json_satiri_runtime_error(self, tmp_path):
        """DAL-6: bozuk JSON -> RuntimeError (sessiz zincir-kopmasi YOK)."""
        yol = tmp_path / "bozuk.jsonl"
        yol.write_text(
            json.dumps({"cert_id": _cid()}) + "\n{bu-gecerli-bir-json-degil}\n",
            encoding="utf-8",
        )
        with pytest.raises(RuntimeError, match="sessiz-zincir-kopması-YOK"):
            RevocationLedger(str(yol)).read_entries()


# == verify_chain =====================================================================================

class TestRevocationLedgerZincir:
    """verify_chain dallari (DAL-7..10 + BULGU-3)."""

    def test_bos_defter_zincir_gecerli(self, tmp_path):
        """DAL-7: giris yokken zincin dogal olarak gecerlidir."""
        assert RevocationLedger(str(tmp_path / "yok.jsonl")).verify_chain() is True

    @pytest.mark.parametrize("n", [1, 2, 3, 5])
    def test_gecerli_zincir(self, tmp_path, n):
        """DAL-8: revoke ile olusturulan n girislik zincir gecerli."""
        seed, did, _ = generate_keypair()
        lg, _ = _valid_defter(tmp_path, seed, did, n=n)
        assert lg.verify_chain() is True

    def test_kirik_prev_bagi_reddedilir(self, tmp_path):
        """DAL-9: ikinci girisin prev'i genesis'e cekilince zincir kirilir."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=2)
        yol = tmp_path / "ledger.jsonl"
        ikinci = dict(girisler[1])
        ikinci["prev"] = _GENESIS  # gercek prev = girisler[0]["h"]
        yol.write_text(json.dumps(girisler[0]) + "\n" + json.dumps(ikinci) + "\n",
                       encoding="utf-8")
        assert lg.verify_chain() is False

    def test_tahrif_h_reddedilir(self, tmp_path):
        """DAL-10: bir girisin 'h' degeri degisince zincir kirilir."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=2)
        yol = tmp_path / "ledger.jsonl"
        ilk = dict(girisler[0])
        ilk["h"] = "a" * 64
        yol.write_text(json.dumps(ilk) + "\n" + json.dumps(girisler[1]) + "\n",
                       encoding="utf-8")
        assert lg.verify_chain() is False

    def test_dict_olmayan_satirda_attribute_error(self, tmp_path):
        """BULGU-3: dict-olmayan JSON satirinda verify_chain AttributeError firlatir.

        read_entries() girisin dict oldugunu validate ETMEZ; verify_chain()
        entry.get(...) cagrisinda int uzerinde AttributeError ile crash olur.
        Production koduna DOKUNULMADI — gercek davranis belgelendi.
        """
        yol = tmp_path / "skaler.jsonl"
        yol.write_text("42\n", encoding="utf-8")
        with pytest.raises(AttributeError):
            RevocationLedger(str(yol)).verify_chain()


# == revoke ===========================================================================================

class TestRevocationLedgerRevoke:
    """revoke + revoked_cert_ids dallari (DAL-11..21 + BULGU-1/2)."""

    @pytest.mark.parametrize("uzunluk", [0, 1, 63, 65, 100],
                             ids=["0", "1", "63", "65", "100"])
    def test_gecersiz_uzunlukta_cert_id_valueerror(self, tmp_path, uzunluk):
        """DAL-14: cert_id uzunlugu 64 disinda -> ValueError."""
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        with pytest.raises(ValueError, match="cert_id 64-hex olmalı"):
            lg.revoke("a" * uzunluk, seed, did)

    @pytest.mark.parametrize("kotu_did", [
        "",
        "not-a-did",
        "did:key:",
        "did:web:example.com:z6Mkabc",
        "z6Mk" + "a" * 40,
    ], ids=["bos", "düz-metin", "did:key-bos-govde", "did:web", "prefix-siz"])
    def test_gecersiz_did_valueerror(self, tmp_path, kotu_did):
        """DAL-15: gecersiz did:key -> ValueError."""
        seed, _, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        with pytest.raises(ValueError, match="geçerli bir did:key değil"):
            lg.revoke(_cid(), seed, kotu_did)

    def test_taze_dosya_olusturulur_genesis_prev(self, tmp_path):
        """DAL-16: olmayan dosyaya revoke -> dosya olusur, prev=genesis, h+signature."""
        seed, did, _ = generate_keypair()
        yol = tmp_path / "taze.jsonl"
        lg = RevocationLedger(str(yol))
        giris = lg.revoke(_cid(), seed, did, reason="ilk-iptal")

        assert yol.exists()
        assert giris["prev"] == _GENESIS
        assert giris["cert_id"] == _cid()
        assert giris["revoked_by"] == did
        assert len(giris["h"]) == 64
        # h bir hex-dizedir
        assert all(c in "0123456789abcdef" for c in giris["h"])
        # imza base64 olarak 64-bayt Ed25519 imzasina cozulur
        assert isinstance(giris["signature"], str)
        assert len(base64.b64decode(giris["signature"])) == 64
        # timestamp ISO8601 biçiminde
        assert "T" in giris["timestamp"]

    def test_zincir_baglantisi_prev_son_h(self, tmp_path):
        """DAL-17: ikinci revoke'un prev'i ilk girisin h'sidir."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=2)
        assert girisler[1]["prev"] == girisler[0]["h"]
        assert girisler[0]["prev"] == _GENESIS

    def test_bozuk_kuyruk_runtime_error(self, tmp_path):
        """DAL-18: son satir gecersiz JSONsa revoke fail-closed RuntimeError."""
        seed, did, _ = generate_keypair()
        yol = tmp_path / "kirik.jsonl"
        yol.write_text(json.dumps({"h": _GENESIS}) + "\n{bozuk}\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="bozuk-kuyruk"):
            RevocationLedger(str(yol)).revoke(_cid(), seed, did)

    def test_reason_varsayilan_bos(self, tmp_path):
        """DAL-19: reason verilmezse "" kaydedilir."""
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        giris = lg.revoke(_cid(), seed, did)
        assert giris["reason"] == ""

    def test_reason_ozel_kaydedilir(self, tmp_path):
        """DAL-20: ozel reason (UTF-8) kaydedilir."""
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        giris = lg.revoke(_cid(), seed, did, reason="şüpheli-davranış: manipülasyon")
        assert giris["reason"] == "şüpheli-davranış: manipülasyon"

    def test_append_only_mevcut_icerik_korunur(self, tmp_path):
        """DAL-21: append-only — ikinci yazma ilk icerigi KORUR (yeniden-yazim YOK)."""
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        ilk = lg.revoke(_cid(0), seed, did)
        ikinci = lg.revoke(_cid(1), seed, did)

        satirlar = (tmp_path / "l.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(satirlar) == 2
        assert json.loads(satirlar[0]) == ilk  # ilk giris OLDUGU GIBI duruyor
        assert json.loads(satirlar[1]) == ikinci

    def test_taze_dosya_0600_modu(self, tmp_path):
        """DAL-21: taze olusturulan defter 0o600 (kanıt-gizliliği, AT-179)."""
        seed, did, _ = generate_keypair()
        yol = tmp_path / "mod.jsonl"
        RevocationLedger(str(yol)).revoke(_cid(), seed, did)
        mod = stat.S_IMODE(os.stat(str(yol)).st_mode)
        assert mod == 0o600

    def test_on_hex_olmayan_cert_id_kabul_edilir(self, tmp_path):
        """BULGU-1: 'cert_id 64-hex olmalı' mesaji var ama SADECE uzunluk kontrolu var.

        64 karakterli HEX-OLMAYAN bir cert_id ('g' hex degildir) KABUL EDILIR.
        Production koduna DOKUNULMADI — gercek davranis belgelendi.
        """
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path / "l.jsonl"))
        giris = lg.revoke("g" * 64, seed, did)  # 'g' hex alfabesinde yok
        assert giris["cert_id"] == "g" * 64
        assert lg.verify_chain() is True

    def test_yazma_yolu_fail_closed_degil(self, tmp_path):
        """BULGU-2: okunabilir ama read-only (0o444) dosyada os.open ham PermissionError.

        _read_lines (open 'r') basarili olur, sonra SARILMAMIS os.open()
        O_WRONLY|O_APPEND ham OSError firlatir — RuntimeError DEGIL.
        Production koduna DOKUNULMADI — gercek davranis belgelendi.
        """
        seed, did, _ = generate_keypair()
        yol = tmp_path / "ro.jsonl"
        RevocationLedger(str(yol)).revoke(_cid(), seed, did)  # okuma stepi calissin
        yol.chmod(0o444)
        try:
            with pytest.raises(OSError) as exc_info:
                RevocationLedger(str(yol)).revoke(_cid(1), seed, did)
            # PermissionError bir OSError'dir ama RuntimeError DEGIL
            assert not isinstance(exc_info.value, RuntimeError)
        finally:
            yol.chmod(0o644)

    def test_dizin_yolunda_revoke_runtime_error(self, tmp_path):
        """ORTAM-OGRENDI: revoke() dizin yolunda ONCE _read_lines'tan RuntimeError
        firlatir — okuma stepi sayesinde bu durum fail-closed'dir (os.open'e ULASMAZ)."""
        seed, did, _ = generate_keypair()
        lg = RevocationLedger(str(tmp_path))  # dizin
        with pytest.raises(RuntimeError, match="iptal-defteri-okunamadı"):
            lg.revoke(_cid(), seed, did)

    @pytest.mark.parametrize("n, beklenen", [(0, set()), (1, {"cid-0"}), (3, {"cid-0", "cid-1", "cid-2"})],
                             ids=["bos", "1", "3"])
    def test_revoked_cert_ids_kumesi(self, tmp_path, n, beklenen):
        """DAL-11/12: bos defter -> set(); n giris -> n cert_id."""
        yol = tmp_path / "l.jsonl"
        if n:
            for i in range(n):
                (tmp_path / "l.jsonl").write_text(
                    ((tmp_path / "l.jsonl").read_text(encoding="utf-8")
                     if (tmp_path / "l.jsonl").exists() else "")
                    + json.dumps({"cert_id": f"cid-{i}"}) + "\n",
                    encoding="utf-8",
                )
        assert RevocationLedger(str(yol)).revoked_cert_ids() == beklenen

    def test_eksik_cert_id_str_none(self, tmp_path):
        """DAL-13: cert_id anahtari yoksa str(None) = 'None' kumeye girer."""
        yol = tmp_path / "l.jsonl"
        yol.write_text(json.dumps({"prev": _GENESIS}) + "\n", encoding="utf-8")
        assert RevocationLedger(str(yol)).revoked_cert_ids() == {"None"}


# == verify_revocation_entry ===========================================================================

class TestVerifyRevocationEntry:
    """verify_revocation_entry dallari (DAL-22..30)."""

    def test_gecerli_giris_doğrulanir(self):
        """DAL-22: elle olusturulan gecerli giris -> True (did:key self-resolving)."""
        seed, did, _ = generate_keypair()
        assert verify_revocation_entry(_valid_giris(seed, did, _cid())) is True

    def test_revoke_urettiği_giris_doğrulanir(self, tmp_path):
        """DAL-22b: revoke()'in urettigi giris birebir dogrulanir (round-trip)."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=1)
        assert verify_revocation_entry(girisler[0]) is True

    def test_tahrif_imza_reddedilir(self):
        """DAL-23: gecerli base64 ama yanlis imza -> False."""
        seed, did, _ = generate_keypair()
        giris = _valid_giris(seed, did, _cid())
        giris["signature"] = base64.b64encode(b"X" * 64).decode("ascii")
        assert verify_revocation_entry(giris) is False

    def test_imza_yok_reddedilir(self):
        """DAL-24: signature None -> False (str tip kontrolu)."""
        seed, did, _ = generate_keypair()
        giris = _valid_giris(seed, did, _cid())
        giris["signature"] = None
        assert verify_revocation_entry(giris) is False

    @pytest.mark.parametrize("kotu_imza", [b"raw-bytes", 12345, [], {}],
                             ids=["bytes", "int", "liste", "dict"])
    def test_imza_yanlis_tip_reddedilir(self, kotu_imza):
        """DAL-25: signature str degilse -> False."""
        seed, did, _ = generate_keypair()
        giris = _valid_giris(seed, did, _cid())
        giris["signature"] = kotu_imza
        assert verify_revocation_entry(giris) is False

    def test_gecersiz_base64_imza_reddedilir(self):
        """DAL-26: str ama gecersiz base64 -> istisra yutulur, False doner."""
        seed, did, _ = generate_keypair()
        giris = _valid_giris(seed, did, _cid())
        giris["signature"] = "!!!bu-base64-degil!!!"
        assert verify_revocation_entry(giris) is False

    @pytest.mark.parametrize("kotu_did", [None, "", "not-a-did", "did:key:z6MkX"],
                             ids=["None", "bos", "düz-metin", "kisa-multibase"])
    def test_gecersiz_revoked_by_reddedilir(self, kotu_did):
        """DAL-27: revoked_by None/bos/geçersiz -> False."""
        seed, _, _ = generate_keypair()
        giris = _valid_giris(seed, "did:key:z6Mkgeçici", _cid())
        giris["revoked_by"] = kotu_did
        assert verify_revocation_entry(giris) is False

    def test_baska_anahtar_imzasi_reddedilir(self):
        """DAL-28: gecerli imza ama FARKLI anahtar -> False."""
        seed1, did1, _ = generate_keypair()
        seed2, _, _ = generate_keypair()
        # govde did1 uzerine ama imza seed2 ile
        giris = _valid_giris(seed2, did1, _cid())
        assert verify_revocation_entry(giris) is False

    def test_bilinmeyen_anahtar_reddedilir(self):
        """DAL-29: imzalanmamis ekstra alan imzayi bozar -> False."""
        seed, did, _ = generate_keypair()
        giris = _valid_giris(seed, did, _cid())
        giris["ekstra_alan"] = "imzada-yok"
        assert verify_revocation_entry(giris) is False

    def test_entry_none_reddedilir(self):
        """DAL-30: entry=None -> AttributeError yutulur, False doner."""
        assert verify_revocation_entry(None) is False

    def test_imza_tipi_dogrulanmis_did_key(self):
        """ORTAM: uretilen did gerçekten did:key formatindadir."""
        _, did, _ = generate_keypair()
        assert is_did_key(did) is True


# == check_revoked ====================================================================================

class TestCheckRevoked:
    """check_revoked dallari (DAL-31..35)."""

    def test_ledger_none_iptal_degil(self):
        """DAL-31: ledger=None -> iptal degil, zincir gecerli (varsayilan)."""
        sonuc = check_revoked(_cid(), None)
        assert sonuc == {
            "revoked": False,
            "reason": "",
            "entry": None,
            "chain_valid": True,
        }

    def test_iptal_edilmis_cert_id_bulunur(self, tmp_path):
        """DAL-32: mevcut cert_id -> revoked:True + reason + signature_valid:True."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=2)
        sonuc = check_revoked(_cid(0), lg)
        assert sonuc["revoked"] is True
        assert sonuc["reason"] == "neden-0"
        assert sonuc["entry"]["cert_id"] == _cid(0)
        assert sonuc["chain_valid"] is True
        assert sonuc["signature_valid"] is True

    def test_bulunamaz_iptal_degil(self, tmp_path):
        """DAL-33: defterde olmayan cert_id -> revoked:False, chain_valid:True."""
        seed, did, _ = generate_keypair()
        lg, _ = _valid_defter(tmp_path, seed, did, n=2)
        sonuc = check_revoked("0" * 64, lg)
        assert sonuc["revoked"] is False
        assert sonuc["reason"] == ""
        assert sonuc["entry"] is None
        assert sonuc["chain_valid"] is True
        # bulunamayan durumda signature_valid anahtari YOK (ORTAM-OGRENDI)
        assert "signature_valid" not in sonuc

    def test_kirik_zincir_cert_yine_de_iptal(self, tmp_path):
        """DAL-34: zincir kirik AMA cert_id mevcut -> revoked:True, chain_valid:False."""
        seed, did, _ = generate_keypair()
        lg, girisler = _valid_defter(tmp_path, seed, did, n=2)
        yol = tmp_path / "ledger.jsonl"
        kirik = dict(girisler[0])
        kirik["h"] = "f" * 64  # h tahrif edildi
        yol.write_text(json.dumps(kirik) + "\n" + json.dumps(girisler[1]) + "\n",
                       encoding="utf-8")
        sonuc = check_revoked(_cid(0), lg)
        assert sonuc["revoked"] is True
        assert sonuc["chain_valid"] is False
        # imza hala bagimsiz olarak dogrulanabilir
        assert sonuc["signature_valid"] is True

    def test_bos_defter_bulunamaz(self, tmp_path):
        """DAL-35: bos defter -> iptal degil, zincir gecerli."""
        lg = RevocationLedger(str(tmp_path / "yok.jsonl"))
        sonuc = check_revoked(_cid(), lg)
        assert sonuc["revoked"] is False
        assert sonuc["chain_valid"] is True
