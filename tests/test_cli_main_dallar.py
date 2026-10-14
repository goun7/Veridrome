"""
test_cli_main_dallar.py — Dal-kesen (branch-coverage) testler: src/veridrome/cli/main.py

Hedeflenen public yüzey (73-Veridrome/veridrome):
  * command_list_tasks        — görev-havuzu listeleme
  * command_verify            — did:key (self-resolving) ve eski W3C-VC doğrulama
  * _load_signing_seed        — imzalama-tohumu yükleme (env/dosya/üretim)
  * command_certify           — test-sonuçlarından did:key sertifika üretimi
  * command_keygen            — yeni did:key imzalama anahtarı üretimi
  * command_revoke            — append-only iptal-defterine giriş ekleme
  * command_mcp               — MCP stdio sunucusu başlatma
  * command_run_evaluation    — ajan değerlendirme koşumu (profiller + canlı uç)
  * command_serve             — FastAPI/uvicorn sunucu başlatma
  * main                      — argparse alt-komut dispatch
  * command_run_mock          — geriye-dönük-uyumluluk alias'ı

DAL HARİTASI (D1..D62):
  command_list_tasks:
    D1  başarı: rc=0 döner
    D2  başarı: 20 görev + havuz başlıkları (PUBLIC_CANARY/DYNAMIC_HIDDEN) yazılır
  command_verify — did:key yolu:
    D3  dosya-açılamaz (yok) → rc=1
    D4  dosya-geçersiz-JSON → rc=1
    D5  geçerli sertifika → rc=0 + doğrulama-çıktısı
    D6  gerçek-tahriz (merkle_root değiştirilmiş) → rc=1 + hata listesi
    D7  açık --ledger ile iptal-edilmiş → rc=1 + "iptal edilmiş"
    D7b boş-iptal-nedeni → "neden-belirtilmemiş" (or-sınırı)
    D8  açık --ledger, iptal-edilmemiş → rc=0
    D9  --ledger yok, VERIDROME_HOME varsayılan-defteri var → iptal denetlenir
    D10 --ledger yok, varsayılan-defter yok → ledger=None → rc=0
    D11 uyarılı-sonuç → uyarılar yazdırılır, rc=0; hatalı-sonuç → rc=1
  command_verify — eski W3C-VC yolu:
    D12 did:key değil + --pubkey yok → rc=1 "zorunlu"
    D13 proofValue yok → rc=1
    D14 base64 çözme-hatası → rc=1
    D15 geçerli imza → rc=0 + metrik-çıktısı
    D16 geçersiz imza → rc=1 "İMZASI GEÇERSİZ"
  _load_signing_seed:
    D17 VERIDROME_SEED_HEX geçerli-32byte → doğrudan döner
    D18 geçersiz-hex (ValueError) → yok sayılır, üretim/devam yoluna düşülür
    D19 geçerli-hex ama uzunluk ≠32 → yok sayılır
    D20 VERIDROME_HOME/seed.hex geçerli → dosyadan okunur
    D21 seed.hex bozuk → yenisi üretilir
    D22 hiçbiri yok → üretilir + 0600 dosyaya yazılır
    D23 home dizini yaratılamaz (OSError) → tohum yine döner
  command_certify:
    D24 --results dosyası yok (FileNotFoundError) → rc=1
    D25 --results geçersiz JSON (ValueError) → rc=1
    D26 --results geçerli + --out → sertifika dosyaya yazılır, rc=0
    D27 --results yok → run_pytest_json(pytest_args) çağrılır (varsayılan tests/)
    D28 koşum exit-code≠0 → rc=2 (fail-closed)
    D29 entries boş → rc=2 (kanıtsız-yok)
    D30 builder.build ValueError → rc=2
    D31 --out yok → sertifika stdout'a JSON olarak basılır
    D32 --out dizini yok (OSError) → rc=1 "Çıktı yazılamadı"
    D33 test-dosyası-hash'i: gerçek dosya → sha256 sertifikaya gömülür
    D34 hash_files OSError → atlanır, sertifika yine üretilir
  command_keygen:
    D35 başarı: rc=0 + DID + seed.hex 0600 yazılır
    D36 home yaratılamaz (OSError) → stderr-uyarısı, rc=0
  command_revoke:
    D37 sertifika-dosyası yok → rc=1
    D38 cert_id yok → rc=1
    D39 cert_id uzunluğu ≠64 → rc=1
    D40 başarı: append-only giriş yazılır, rc=0
    D41 defter-bozuk-kuyruk (RuntimeError) → rc=1 (fail-closed)
    D42 ledger_path=None → VERIDROME_HOME varsayılan-defteri kullanılır
  command_mcp:
    D43 serve_stdio çağrılır, rc=0
  command_run_evaluation:
    D44 honest-profil → rc=0 + "ONAYLANDI"
    D45 overfit-profil → rc=2 + ANTI_GAMING ret
    D46 failing-profil → rc=2 + SCORE_INSUFFICIENT
    D47 canlı-uç 200 → sahte-httpx ile rc=0 + "live" kimliği
    D48 canlı-uç 500 → http_error → rc=2
    D49 canlı-uç exception → connection_error → rc=2
    D50 açık --agent-id → birebir kullanılır
    D51 --runs-per-task → "n=40" gibi Bernoulli adım-sayısı yazdırılır
    D52 command_run_mock alias'ı aynı fonksiyonu işaret eder
  command_serve:
    D53 uvicorn.run(app, host, port) çağrılır, rc=0
  main:
    D54 list-tasks dispatch → SystemExit(command_list_tasks())
    D55 serve dispatch (host/port)
    D56 run dispatch (agent-type/endpoint/runs)
    D57 verify dispatch (cert_file/pubkey/ledger)
    D58 certify dispatch (commit/repo/out)
    D59 keygen dispatch
    D60 revoke dispatch (cert_file/reason)
    D61 mcp dispatch
    D62 alt-komut yok → yardım-basım + SystemExit(1)

KURAL: SADECE YENI DOSYA; production/conftest/mevcut-testlere DOKUNULMAZ.
Bağımlı alt-sistemler (httpx/uvicorn/MCP/pytest-koşusu) monkeypatch ile
SAF-BELLEK taklit edilir — gerçek ağ/socket/subprocess YOK; sertifika
anahtarları ve defterler tmp_path içinde izole edilir (VERIDROME_HOME).
"""

from __future__ import annotations

import json
import os
import stat
import sys

import httpx
import pytest
import uvicorn

import veridrome.certificate.pytest_parser as pytest_parser_mod
import veridrome.cli.main as cli_main
import veridrome.mcp_server as mcp_server_mod
from veridrome.certificate.core import CertificateBuilder, VerifyResult
from veridrome.certificate.didkey import generate_keypair
from veridrome.certificate.revocation import RevocationLedger
from veridrome.cli.main import (
    _load_signing_seed,
    command_certify,
    command_keygen,
    command_list_tasks,
    command_mcp,
    command_revoke,
    command_run_evaluation,
    command_run_mock,
    command_serve,
    command_verify,
    main,
)
from veridrome.core.crypto import VeridromeAuthoritySigner

_COMMIT = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4"

_SONUCLAR = [
    {"name": "tests/test_a.py::test_one", "outcome": "passed", "duration_ms": 12.0},
    {"name": "tests/test_a.py::test_two", "outcome": "passed", "duration_ms": 34.0},
    {"name": "tests/test_b.py::test_three", "outcome": "passed", "duration_ms": 110.0},
]


# ---------------------------------------------------------------------------
# Ortak yardımcılar — SAF-BELLEK izolasyonu
# ---------------------------------------------------------------------------


@pytest.fixture
def ev(monkeypatch, tmp_path):
    """İzole VERIDROME_HOME: gerçek ~/.veridrome ASLA dokunulmaz."""
    home = tmp_path / "ev"
    monkeypatch.setenv("VERIDROME_HOME", str(home))
    monkeypatch.delenv("VERIDROME_SEED_HEX", raising=False)
    return home


def _rapor_zarfi(entries):
    """parse_pytest_json'ın okuduğu pytest-json-report zarfı."""
    gecen = sum(1 for e in entries if e.get("outcome") == "passed")
    return {
        "tests": entries,
        "summary": {"total": len(entries), "passed": gecen,
                    "failed": len(entries) - gecen, "skipped": 0},
    }


def _sertifika(tmp_path, results=None, valid_days=7):
    """Gerçek did:key-imzalı sertifika üretip dosyaya yazar (bellek-içi kripto)."""
    seed, did, _ = generate_keypair()
    cert = CertificateBuilder(seed, did).build(
        test_results=results or _SONUCLAR,
        repo_url="https://github.com/org/repo",
        commit_sha=_COMMIT,
        job_id="job-dal-1",
        valid_days=valid_days,
    )
    yol = tmp_path / "sertifika.json"
    yol.write_text(json.dumps(cert, ensure_ascii=False), encoding="utf-8")
    return str(yol), cert


class TestCommandListTasks:
    """command_list_tasks dalları: D1-D2."""

    def test_basari_rc_sifir(self):
        """D1: listeleme başarılıdır ve 0 döner."""
        assert command_list_tasks() == 0

    def test_basari_havuz_ciktisi(self, capsys):
        """D2: çıktıda 20 görev, havuz tipleri ve başlık-satırları vardır."""
        command_list_tasks()
        out = capsys.readouterr().out
        assert "Toplam 20 Görev" in out
        assert "PUBLIC_CANARY" in out and "DYNAMIC_HIDDEN" in out
        assert "T01" in out and "T20" in out
        assert "Kuponlu Sepet Onayı" in out


class TestCommandVerifyDidKey:
    """command_verify did:key (self-resolving) yolu: D3-D11."""

    def test_dosya_yoksa_red(self, capsys):
        """D3: sertifika dosyası bulunamaz → rc=1."""
        rc = command_verify("/yok/böyle/bir/dosya.json")
        assert rc == 1
        assert "açılamadı" in capsys.readouterr().out

    def test_gecersiz_json_red(self, tmp_path, capsys):
        """D4: dosya geçersiz JSON → rc=1."""
        yol = tmp_path / "bozuk.json"
        yol.write_text("{geçersiz", encoding="utf-8")
        rc = command_verify(str(yol))
        assert rc == 1
        assert "açılamadı" in capsys.readouterr().out

    def test_gecerli_sertifika_kabul(self, tmp_path, capsys):
        """D5: gerçek did:key sertifikası → rc=0 + bağımsız doğrulama çıktısı."""
        yol, _ = _sertifika(tmp_path)
        rc = command_verify(yol)
        assert rc == 0
        out = capsys.readouterr().out
        assert "SERTİFİKA GEÇERLİ" in out
        assert "3 passed / 3" in out
        assert "did:key" in out

    def test_tahriz_edilmis_sertifika_red(self, tmp_path, capsys):
        """D6: merkle_root tahriz edilmiş → content-hash tutmaz → rc=1."""
        yol, cert = _sertifika(tmp_path)
        cert["credentialSubject"]["merkle_root"] = "0x" + "ff" * 32
        (tmp_path / "tahriz.json").write_text(
            json.dumps(cert, ensure_ascii=False), encoding="utf-8")
        rc = command_verify(str(tmp_path / "tahriz.json"))
        assert rc == 1
        out = capsys.readouterr().out
        assert "SERTİFİKA GEÇERSİZ" in out
        assert "content_hash" in out

    def test_acik_ledger_iptalet_red(self, tmp_path, ev, capsys):
        """D7: --ledger ile iptal-edilmiş sertifika → rc=1 + iptal-hatası."""
        yol, cert = _sertifika(tmp_path)
        ledger = str(tmp_path / "ledger.jsonl")
        # Önce sertifikayı iptal-defterine koy (command_revoke: gerçek append-only zincir)
        command_revoke(yol, "güvenlik-nedeni", ledger)
        rc = command_verify(yol, ledger_path=ledger)
        assert rc == 1
        out = capsys.readouterr().out
        assert "iptal edilmiş" in out
        assert "güvenlik-nedeni" in out

    def test_bos_iptal_nedeni_varsayilan_mesaj(self, tmp_path, ev, capsys):
        """D7b: reason='' → check_revoked boş-döner → 'neden-belirtilmemiş'."""
        yol, _ = _sertifika(tmp_path)
        ledger = str(tmp_path / "ledger.jsonl")
        command_revoke(yol, "", ledger)
        rc = command_verify(yol, ledger_path=ledger)
        assert rc == 1
        assert "neden-belirtilmemiş" in capsys.readouterr().out

    def test_acik_ledger_iptal_edilmemis_kabul(self, tmp_path, ev, capsys):
        """D8: --ledger var ama sertifika iptal-edilmemiş → rc=0."""
        yol, _ = _sertifika(tmp_path)
        ledger = str(tmp_path / "ledger.jsonl")
        # Boş (var-olmayan) defter → boş okuma → iptal değil
        rc = command_verify(yol, ledger_path=ledger)
        assert rc == 0
        assert "SERTİFİKA GEÇERLİ" in capsys.readouterr().out

    def test_varsayilan_ledger_iptal_denetlenir(self, tmp_path, ev, capsys):
        """D9: --ledger yok → VERIDROME_HOME/revocations.jsonl kullanılır."""
        yol, _ = _sertifika(tmp_path)
        # command_revoke, varsayılan-deftere yazar (aynı VERIDROME_HOME)
        command_revoke(yol, "test-nedeni", None)
        assert (ev / "revocations.jsonl").exists()
        rc = command_verify(yol)  # --ledger YOK
        assert rc == 1
        assert "iptal edilmiş" in capsys.readouterr().out

    def test_varsayilan_ledger_yoksa_kabul(self, tmp_path, ev, capsys):
        """D10: --ledger yok + varsayılan-defter yok → ledger=None → rc=0."""
        yol, _ = _sertifika(tmp_path)
        assert not (ev / "revocations.jsonl").exists()
        rc = command_verify(yol)
        assert rc == 0
        assert "SERTİFİKA GEÇERLİ" in capsys.readouterr().out

    def test_uyarili_sonuc_rc_sifir(self, tmp_path, monkeypatch, capsys):
        """D11 (sınır): verify uyarı dönerse uyarılar yazdırılır, rc=0."""
        yol, _ = _sertifika(tmp_path)

        def _uyarili_verify(cert, now=None):
            sonuc = VerifyResult()
            sonuc.valid = True
            sonuc.content_hash_valid = True
            sonuc.signature_valid = True
            sonuc.temporal_valid = True
            sonuc.subject_ok = True
            sonuc.warnings.append("örnek-uyarı")
            return sonuc

        monkeypatch.setattr(cli_main, "verify_certificate", _uyarili_verify)
        rc = command_verify(yol)
        assert rc == 0
        assert "örnek-uyarı" in capsys.readouterr().out

    def test_hatali_sonuc_rc_bir(self, tmp_path, monkeypatch, capsys):
        """D11 (başarısızlık): verify geçersiz dönerse hatalar yazdırılır."""
        yol, _ = _sertifika(tmp_path)

        def _hatali_verify(cert, now=None):
            sonuc = VerifyResult()
            sonuc.errors.append("örnek-hata")
            return sonuc

        monkeypatch.setattr(cli_main, "verify_certificate", _hatali_verify)
        rc = command_verify(yol)
        assert rc == 1
        out = capsys.readouterr().out
        assert "SERTİFİKA GEÇERSİZ" in out
        assert "örnek-hata" in out


class TestCommandVerifyLegacyW3C:
    """command_verify eski W3C-VC (--pubkey) yolu: D12-D16."""

    def _legacy_dosya(self, tmp_path, imzaci=None, mesaj=None, proof=None):
        """Eski W3C-VC zarfı: did:key olmayan tip + otorite imzası."""
        imzaci = imzaci or VeridromeAuthoritySigner()
        govde = {
            "type": ["VerifiableCredential"],  # VeridromeTestPassCertificate YOK
            "credentialSubject": {
                "id": "urn:kredent:agent:legacy",
                "metrics": {"medianSuccess": 0.95, "anomalyScore": 0.1},
                "merkleRoot": "0x" + "ab" * 32,
            },
            "validUntil": "2027-01-01T00:00:00+00:00",
        }
        kanonik = json.dumps(govde, sort_keys=True).encode("utf-8")
        govde["proof"] = proof if proof is not None else {
            "proofValue": imzaci.sign_base64(mesaj if mesaj is not None else kanonik)
        }
        yol = tmp_path / "legacy.json"
        yol.write_text(json.dumps(govde), encoding="utf-8")
        return str(yol), imzaci

    def test_pubkey_yoksa_zorunlu_uyarisi(self, tmp_path, capsys):
        """D12: did:key değil + --pubkey yok → rc=1 'zorunlu'."""
        yol, _ = self._legacy_dosya(tmp_path)
        rc = command_verify(yol)  # pubkey_b64=None
        assert rc == 1
        assert "--pubkey zorunlu" in capsys.readouterr().out

    def test_proofvalue_yoksa_red(self, tmp_path, capsys):
        """D13: proof var ama proofValue yok → rc=1."""
        yol, imzaci = self._legacy_dosya(tmp_path, proof={"type": "Ed25519Signature2020"})
        rc = command_verify(yol, pubkey_b64=imzaci.public_key_base64)
        assert rc == 1
        assert "proofValue" in capsys.readouterr().out

    def test_base64_cozme_hatasi(self, tmp_path, capsys):
        """D14: --pubkey geçersiz-base64 → rc=1."""
        yol, _ = self._legacy_dosya(tmp_path)
        rc = command_verify(yol, pubkey_b64="!!!!-geçersiz-!!!!")
        assert rc == 1
        assert "Base64 çözme hatası" in capsys.readouterr().out

    def test_gecerli_imza_kabul(self, tmp_path, capsys):
        """D15: gerçek otorite imzası → rc=0 + metrik çıktısı."""
        yol, imzaci = self._legacy_dosya(tmp_path)
        rc = command_verify(yol, pubkey_b64=imzaci.public_key_base64)
        assert rc == 0
        out = capsys.readouterr().out
        assert "SERTİFİKA GEÇERLİ" in out
        assert "%95.00" in out  # medianSuccess 0.95 → %95.00

    def test_gecersiz_imza_red(self, tmp_path, capsys):
        """D16: farklı-mesaj imzası → Ed25519 doğrulaması başarısız → rc=1."""
        yol, imzaci = self._legacy_dosya(tmp_path, mesaj=b"baska-bir-mesaj")
        rc = command_verify(yol, pubkey_b64=imzaci.public_key_base64)
        assert rc == 1
        assert "İMZASI GEÇERSİZ" in capsys.readouterr().out


class TestLoadSigningSeed:
    """_load_signing_seed dalları: D17-D23."""

    def test_env_gecerli_tohum_doğrudan_doner(self, monkeypatch, ev):
        """D17: VERIDROME_SEED_HEX geçerli 32-byte hex → birebir döner."""
        monkeypatch.setenv("VERIDROME_SEED_HEX", "ab" * 32)
        assert _load_signing_seed() == bytes.fromhex("ab" * 32)
        # çevre-yolu seçilince dosyaya DOKUNULMAZ
        assert not (ev / "seed.hex").exists()

    def test_env_gecersiz_hex_yoksayilir(self, monkeypatch, ev):
        """D18: geçersiz hex (ValueError) → yok sayılır, yenisi üretilir."""
        monkeypatch.setenv("VERIDROME_SEED_HEX", "zzz-geçersiz")
        seed = _load_signing_seed()
        assert isinstance(seed, bytes) and len(seed) == 32
        assert seed != bytes.fromhex("ab" * 32)

    def test_env_uzunluk_yanlis_yoksayilir(self, monkeypatch, ev):
        """D19: geçerli hex ama 32-byte DEĞİL → yok sayılır."""
        monkeypatch.setenv("VERIDROME_SEED_HEX", "cd" * 16)  # 16 byte
        seed = _load_signing_seed()
        assert len(seed) == 32
        assert seed != bytes.fromhex("cd" * 16)

    def test_home_seed_dosyasindan_okunur(self, ev):
        """D20: VERIDROME_HOME/seed.hex geçerli → dosyadan okunur."""
        ev.mkdir()
        (ev / "seed.hex").write_text("ef" * 32, encoding="utf-8")
        assert _load_signing_seed() == bytes.fromhex("ef" * 32)

    def test_bozuk_seed_dosyasi_yeniden_uretilir(self, ev):
        """D21: seed.hex bozuk-içerik (ValueError) → yenisi üretilir."""
        ev.mkdir()
        (ev / "seed.hex").write_text("bozuk-içerik", encoding="utf-8")
        seed = _load_signing_seed()
        assert len(seed) == 32
        assert seed != "bozuk-içerik".encode("utf-8")

    def test_hicbir_sey_yoksa_uretilir_ve_0600_yazilir(self, ev):
        """D22: tohum yok → yeni 32-byte üretilir, 0600-modunda kaydedilir."""
        seed = _load_signing_seed()
        dosya = ev / "seed.hex"
        assert len(seed) == 32
        assert dosya.exists()
        assert dosya.read_text(encoding="utf-8").strip() == seed.hex()
        mod = stat.S_IMODE(os.stat(dosya).st_mode)
        assert mod == 0o600

    def test_home_yaratilamazsa_tozu_yine_doner(self, tmp_path, monkeypatch):
        """D23: home mevcut-bir DOSYA ise makedirs OSError atar → tohum döner."""
        engel = tmp_path / "ev-dosyasi"
        engel.write_text("engel", encoding="utf-8")
        monkeypatch.setenv("VERIDROME_HOME", str(engel))
        monkeypatch.delenv("VERIDROME_SEED_HEX", raising=False)
        seed = _load_signing_seed()
        assert isinstance(seed, bytes) and len(seed) == 32


class TestCommandCertify:
    """command_certify dalları: D24-D34."""

    def test_results_dosyasi_yok_red(self, tmp_path, ev, capsys):
        """D24: --results dosyası yok → FileNotFoundError → rc=1."""
        rc = command_certify(
            results_path=str(tmp_path / "yok.json"), pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=None, valid_days=7,
        )
        assert rc == 1
        assert "okunamadı" in capsys.readouterr().out

    def test_results_gecersiz_json_red(self, tmp_path, ev, capsys):
        """D25: --results geçersiz JSON → ValueError → rc=1."""
        yol = tmp_path / "bozuk.json"
        yol.write_text("{bozuk", encoding="utf-8")
        rc = command_certify(
            results_path=str(yol), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 1
        assert "okunamadı" in capsys.readouterr().out

    def test_results_gecerli_out_dosyaya_yazilir(self, tmp_path, ev, capsys):
        """D26: --results + --out → did:key sertifikası diske yazılır, rc=0."""
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(_SONUCLAR)), encoding="utf-8")
        out = tmp_path / "sert.json"
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url="https://github.com/org/repo", job_id="job-c-1",
            agent_did=None, out_path=str(out), valid_days=7,
        )
        assert rc == 0
        assert out.exists()
        cert = json.loads(out.read_text(encoding="utf-8"))
        assert len(cert["cert_id"]) == 64
        assert cert["credentialSubject"]["summary"]["passed"] == 3
        # özet stderr'de did:key ile basılır
        assert "did:key:" in capsys.readouterr().err

    def test_results_yoksa_pytest_kosusu_cagrilir(self, tmp_path, ev, monkeypatch):
        """D27: --results yok → run_pytest_json(pytest_args|['tests/']) çağrılır."""
        cagrilar = []

        def _fake_run(args=None, pytest_cmd=None):
            cagrilar.append(list(args or []))
            return {"entries": list(_SONUCLAR), "summary": {"total": 3, "passed": 3,
                    "failed": 0, "skipped": 0}, "source": "fake", "exit_code": 0}

        monkeypatch.setattr(pytest_parser_mod, "run_pytest_json", _fake_run)
        rc = command_certify(
            results_path=None, pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 0
        assert cagrilar == [["tests/"]]  # varsayılan-argüman dalı

    def test_pytest_gecersiz_exit_code_fail_closed(self, tmp_path, ev, monkeypatch, capsys):
        """D28: koşum exit-code≠0 → rc=2 (failing-testlerle sertifika YOK)."""
        def _fake_run(args=None, pytest_cmd=None):
            return {"entries": list(_SONUCLAR), "summary": {"total": 3, "passed": 3,
                    "failed": 0, "skipped": 0}, "source": "fake", "exit_code": 1}

        monkeypatch.setattr(pytest_parser_mod, "run_pytest_json", _fake_run)
        rc = command_certify(
            results_path=None, pytest_args=["tests/"], commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 2
        assert "exit-code=1" in capsys.readouterr().out

    def test_bos_entries_fail_closed(self, tmp_path, ev, monkeypatch, capsys):
        """D29: hiç test-sonucu yok → rc=2 (kanıtsız sertifika YOK)."""
        def _fake_run(args=None, pytest_cmd=None):
            return {"entries": [], "summary": {"total": 0, "passed": 0,
                    "failed": 0, "skipped": 0}, "source": "fake", "exit_code": 0}

        monkeypatch.setattr(pytest_parser_mod, "run_pytest_json", _fake_run)
        rc = command_certify(
            results_path=None, pytest_args=["tests/"], commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 2
        out = capsys.readouterr().out
        assert "Hiç test-sonucu bulunamadı" in out

    def test_builder_hatasi_fail_closed(self, tmp_path, ev, monkeypatch, capsys):
        """D30: builder.build ValueError → rc=2 'Sertifika üretilemedi'."""
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(_SONUCLAR)), encoding="utf-8")

        class _PatlayanBuilder:
            def __init__(self, seed, did):
                pass

            def build(self, **kwargs):
                raise ValueError("örnek-inşa-hatası")

        monkeypatch.setattr(cli_main, "CertificateBuilder", _PatlayanBuilder)
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 2
        assert "üretilemedi" in capsys.readouterr().out

    def test_out_yoksa_stdouta_basilir(self, tmp_path, ev, capsys):
        """D31: --out yok → sertifika JSON'u stdout'a basılır, rc=0."""
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(_SONUCLAR)), encoding="utf-8")
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=7,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert '"cert_id"' in out
        assert "VeridromeTestPassCertificate" in out

    def test_out_yazilamadiysa_rc_bir(self, tmp_path, ev, capsys):
        """D32: --out mevcut-olmayan dizinde → OSError → rc=1."""
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(_SONUCLAR)), encoding="utf-8")
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None,
            out_path=str(tmp_path / "yok-dizin" / "sert.json"), valid_days=7,
        )
        assert rc == 1
        assert "yazılamadı" in capsys.readouterr().out

    def test_test_dosyasi_hashi_certe_gomulur(self, tmp_path, ev):
        """D33: entry adındaki gerçek dosya → sha256 sertifikaya gömülür."""
        gercek_dosya = tmp_path / "test_x.py"
        gercek_dosya.write_text("# örnek\n", encoding="utf-8")
        entries = [{"name": f"{gercek_dosya}::test_a", "outcome": "passed",
                    "duration_ms": 5.0}]
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(entries)), encoding="utf-8")
        out = tmp_path / "sert.json"
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=str(out),
            valid_days=7,
        )
        assert rc == 0
        cert = json.loads(out.read_text(encoding="utf-8"))
        dosya_hashleri = cert["credentialSubject"]["test_files"]
        assert dosya_hashleri[0]["path"] == str(gercek_dosya)
        import hashlib as _hl
        beklenen = _hl.sha256("# örnek\n".encode("utf-8")).hexdigest()
        assert dosya_hashleri[0]["sha256"] == beklenen

    def test_hash_files_hatasi_atlanir(self, tmp_path, ev, monkeypatch):
        """D34: hash_files OSError atarsa atlanır, sertifika yine üretilir."""
        gercek_dosya = tmp_path / "test_y.py"
        gercek_dosya.write_text("# y\n", encoding="utf-8")
        entries = [{"name": f"{gercek_dosya}::test_b", "outcome": "passed"}]
        rapor = tmp_path / "rapor.json"
        rapor.write_text(json.dumps(_rapor_zarfi(entries)), encoding="utf-8")

        def _patlatan_hash(paths):
            raise OSError("örnek-okuma-hatası")

        monkeypatch.setattr(cli_main, "hash_files", _patlatan_hash)
        out = tmp_path / "sert.json"
        rc = command_certify(
            results_path=str(rapor), pytest_args=None, commit_sha=_COMMIT,
            repo_url=None, job_id=None, agent_did=None, out_path=str(out),
            valid_days=7,
        )
        assert rc == 0
        cert = json.loads(out.read_text(encoding="utf-8"))
        # hata-yolu → test_files None → name-derived zayıf-etiketi
        assert cert["credentialSubject"]["hash_source"] == "name-derived"


class TestCommandKeygen:
    """command_keygen dalları: D35-D36."""

    def test_basari_did_ve_seed_yazilir(self, ev, capsys):
        """D35: rc=0 + DID yazdırılır + seed.hex 0600 yazılır (tohum ASLA basılmaz)."""
        rc = command_keygen()
        assert rc == 0
        out = capsys.readouterr().out
        assert "did:key:z" in out
        dosya = ev / "seed.hex"
        assert dosya.exists()
        icerik = dosya.read_text(encoding="utf-8").strip()
        assert len(icerik) == 64  # 32-byte hex
        assert stat.S_IMODE(os.stat(dosya).st_mode) == 0o600
        # tohum asla ekrana basılmaz
        assert icerik not in out

    def test_home_yaratilamazsa_uyari_rc_sifir(self, tmp_path, monkeypatch, capsys):
        """D36: home bir DOSYA ise makedirs OSError → stderr-uyarısı, rc=0."""
        engel = tmp_path / "engel"
        engel.write_text("x", encoding="utf-8")
        monkeypatch.setenv("VERIDROME_HOME", str(engel))
        rc = command_keygen()
        assert rc == 0
        assert "yazılamadı" in capsys.readouterr().err


class TestCommandRevoke:
    """command_revoke dalları: D37-D42."""

    def _cagri(self, cert_path, reason="neden", ledger=None):
        return command_revoke(cert_path, reason, ledger)

    def test_dosya_yok_red(self, tmp_path, ev, capsys):
        """D37: sertifika dosyası yok → rc=1."""
        rc = self._cagri(str(tmp_path / "yok.json"))
        assert rc == 1
        assert "açılamadı" in capsys.readouterr().out

    def test_cert_id_yok_red(self, tmp_path, ev, capsys):
        """D38: cert_id alanı yok → rc=1 'değil'."""
        yol = tmp_path / "cert.json"
        yol.write_text(json.dumps({"type": ["X"]}), encoding="utf-8")
        rc = self._cagri(str(yol))
        assert rc == 1
        assert "değil" in capsys.readouterr().out

    def test_cert_id_uzunlugu_yanlis_red(self, tmp_path, ev, capsys):
        """D39: cert_id 64-karakter DEĞİL → rc=1."""
        yol = tmp_path / "cert.json"
        yol.write_text(json.dumps({"cert_id": "q" * 8}), encoding="utf-8")
        rc = self._cagri(str(yol))
        assert rc == 1

    def test_basari_append_only_giris_yazilir(self, tmp_path, ev, capsys):
        """D40: geçerli sertifika → zincir-girişi yazılır, rc=0."""
        yol, cert = _sertifika(tmp_path)
        ledger = str(tmp_path / "ledger.jsonl")
        rc = self._cagri(yol, "örnek-iptal", ledger)
        assert rc == 0
        out = capsys.readouterr().out
        assert "iptal-edildi" in out
        assert "örnek-iptal" in out
        assert cert["cert_id"] in out
        # defterde tek append-only satır vardır
        satirlar = [s for s in (tmp_path / "ledger.jsonl").read_text(
            encoding="utf-8").splitlines() if s.strip()]
        assert len(satirlar) == 1
        giris = json.loads(satirlar[0])
        assert giris["cert_id"] == cert["cert_id"]
        assert giris["reason"] == "örnek-iptal"

    def test_bozuk_defter_fail_closed(self, tmp_path, ev, capsys):
        """D41: defter-bozuk-kuyruk → RuntimeError → rc=1 (fail-closed)."""
        yol, _ = _sertifika(tmp_path)
        ledger = tmp_path / "ledger.jsonl"
        ledger.write_text("geçersiz-json-satırı\n", encoding="utf-8")
        rc = self._cagri(yol, "neden", str(ledger))
        assert rc == 1
        assert "fail-closed" in capsys.readouterr().out

    def test_value_error_fail_closed(self, tmp_path, ev, monkeypatch, capsys):
        """D41b: revoke ValueError → rc=1 (fail-closed)."""
        yol, _ = _sertifika(tmp_path)

        class _StubLedger:
            def __init__(self, path):
                pass

            def revoke(self, *args, **kwargs):
                raise ValueError("stub-value-error")

        monkeypatch.setattr(cli_main, "RevocationLedger", _StubLedger)
        rc = self._cagri(yol, "neden", str(tmp_path / "ledger.jsonl"))
        assert rc == 1
        assert "fail-closed" in capsys.readouterr().out

    def test_ledger_yoksa_varsayilana_yazilir(self, tmp_path, ev, capsys):
        """D42: ledger_path=None → VERIDROME_HOME/revocations.jsonl kullanılır."""
        yol, _ = _sertifika(tmp_path)
        rc = self._cagri(yol, "varsayılan", None)
        assert rc == 0
        assert (ev / "revocations.jsonl").exists()


class TestCommandMcp:
    """command_mcp dalları: D43."""

    def test_serve_stdio_cagrilir(self, monkeypatch):
        """D43: MCP stdio sunucusu çağrılır ve rc=0 döner (sunucu taklit)."""
        cagrilar = []

        def _fake_serve_stdio():
            cagrilar.append(1)

        monkeypatch.setattr(mcp_server_mod, "serve_stdio", _fake_serve_stdio)
        rc = command_mcp()
        assert rc == 0
        assert cagrilar == [1]


class TestCommandRunEvaluation:
    """command_run_evaluation dalları: D44-D52."""

    def test_honest_profil_onaylanir(self, capsys):
        """D44: honest simülasyon → sertifikalı → rc=0."""
        rc = command_run_evaluation(agent_type="honest", runs_per_task=1)
        assert rc == 0
        out = capsys.readouterr().out
        assert "ONAYLANDI" in out
        assert "urn:kredent:agent:profile-honest" in out
        assert "Simülasyon Profili: honest" in out

    def test_overfit_profil_reddedilir(self, capsys):
        """D45: overfit profil → ANTI_GAMING ret → rc=2."""
        rc = command_run_evaluation(agent_type="overfit", runs_per_task=1)
        assert rc == 2
        out = capsys.readouterr().out
        assert "REDDEDİLDİ" in out
        assert "ANTI_GAMING" in out

    def test_failing_profil_reddedilir(self, capsys):
        """D46: failing profil → SCORE_INSUFFICIENT → rc=2."""
        rc = command_run_evaluation(agent_type="failing", runs_per_task=1)
        assert rc == 2
        out = capsys.readouterr().out
        assert "REDDEDİLDİ" in out
        assert "SCORE_INSUFFICIENT" in out

    def _httpx_taklit(self, monkeypatch, status=200, data=None, hata=None):
        """httpx.Client'i SAF-BELLEK taklit eder (gerçek socket YOK)."""
        data = data or {"passed": True, "latency_sec": 5.0, "cost_usd": 0.01,
                        "actions": ["click", "type", "submit"]}

        class _Cevap:
            status_code = status

            def json(self):
                return data

        class _Client:
            def __init__(self, timeout=None):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def post(self, url, json=None):
                if hata is not None:
                    raise hata
                return _Cevap()

        monkeypatch.setattr(httpx, "Client", _Client)

    def test_canli_uc_200_onaylanir(self, monkeypatch, capsys):
        """D47: canlı uç-nokta 200 → sahte-httpx ile rc=0 + 'live' kimliği."""
        self._httpx_taklit(monkeypatch, status=200)
        rc = command_run_evaluation(
            agent_type="honest", endpoint="http://sahte.uc/nokta",
            runs_per_task=1,
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Canlı Uç Nokta: http://sahte.uc/nokta" in out
        assert "urn:kredent:agent:live-honest" in out

    def test_canli_uc_500_reddedilir(self, monkeypatch, capsys):
        """D48: 500 durum-kodu → http_error → tüm görevler başarısız → rc=2."""
        self._httpx_taklit(monkeypatch, status=500)
        rc = command_run_evaluation(
            agent_type="honest", endpoint="http://sahte.uc/hata",
            runs_per_task=1,
        )
        assert rc == 2
        assert "REDDEDİLDİ" in capsys.readouterr().out

    def test_canli_uc_baglanti_hatasi_reddedilir(self, monkeypatch, capsys):
        """D49: bağlantı-istisnası → connection_error → rc=2."""
        self._httpx_taklit(monkeypatch, hata=RuntimeError("bağlantı-koptu"))
        rc = command_run_evaluation(
            agent_type="honest", endpoint="http://sahte.uc/kopuk",
            runs_per_task=1,
        )
        assert rc == 2
        assert "REDDEDİLDİ" in capsys.readouterr().out

    def test_acik_agent_id_kullanilir(self, capsys):
        """D50: --agent-id verilirse çözümlenen kimlik birebi olur."""
        rc = command_run_evaluation(
            agent_id="urn:kredent:agent:özel-ajan", runs_per_task=1,
        )
        assert rc == 0
        assert "urn:kredent:agent:özel-ajan" in capsys.readouterr().out

    def test_runs_per_task_bernoulli_adim_sayisi(self, capsys):
        """D51: --runs-per-task=2 → 'n=40' (2×20 görev) yazdırılır."""
        rc = command_run_evaluation(agent_type="honest", runs_per_task=2)
        assert rc == 0
        out = capsys.readouterr().out
        assert "(n=40 Bernoulli adımı)" in out

    def test_alias_ayni_fonksiyon(self):
        """D52: command_run_mock, command_run_evaluation ile aynı nesnedir."""
        assert command_run_mock is command_run_evaluation


class TestCommandServe:
    """command_serve dalları: D53."""

    def test_uvicorn_cagrilir(self, monkeypatch):
        """D53: uvicorn.run(app, host, port) çağrılır, rc=0 (sunucu taklit)."""
        cagrilar = []
        monkeypatch.setattr(uvicorn, "run", lambda app, host=None, port=None,
                            log_level=None: cagrilar.append((app, host, port)))
        rc = command_serve("1.2.3.4", 9999)
        assert rc == 0
        assert len(cagrilar) == 1
        app, host, port = cagrilar[0]
        assert host == "1.2.3.4" and port == 9999
        assert app is not None  # gerçek FastAPI uygulaması (import-only)


class TestMainDispatch:
    """main() argparse-dispatch dalları: D54-D62."""

    def _dispatch(self, monkeypatch, argv, fake_fonk, isim):
        monkeypatch.setattr(sys, "argv", argv)
        monkeypatch.setattr(cli_main, isim, fake_fonk)
        with pytest.raises(SystemExit) as exc:
            main()
        return exc.value.code

    def test_list_tasks_dispatch(self, monkeypatch):
        """D54: 'list-tasks' → SystemExit(command_list_tasks())."""
        kod = self._dispatch(monkeypatch, ["veridrome", "list-tasks"],
                             lambda: 7, "command_list_tasks")
        assert kod == 7

    def test_serve_dispatch(self, monkeypatch):
        """D55: 'serve --host --port' → command_serve(host, port)."""
        kayit = {}
        kod = self._dispatch(
            monkeypatch, ["veridrome", "serve", "--host", "1.2.3.4", "--port", "9999"],
            lambda host="127.0.0.1", port=8000: kayit.update(host=host, port=port) or 0,
            "command_serve",
        )
        assert kod == 0
        assert kayit == {"host": "1.2.3.4", "port": 9999}

    def test_run_dispatch(self, monkeypatch):
        """D56: 'run --agent-type --endpoint --runs-per-task' → dispatch."""
        kayit = {}
        kod = self._dispatch(
            monkeypatch,
            ["veridrome", "run", "--agent-type", "failing", "--endpoint",
             "http://u.c/e", "--runs-per-task", "2"],
            lambda agent_type="honest", endpoint=None, agent_id=None,
            runs_per_task=3: kayit.update(agent_type=agent_type, endpoint=endpoint,
                                          agent_id=agent_id,
                                          runs_per_task=runs_per_task) or 2,
            "command_run_evaluation",
        )
        assert kod == 2
        assert kayit == {"agent_type": "failing", "endpoint": "http://u.c/e",
                         "agent_id": None, "runs_per_task": 2}

    def test_verify_dispatch(self, monkeypatch):
        """D57: 'verify cert --pubkey --ledger' → command_verify(...)."""
        kayit = {}
        kod = self._dispatch(
            monkeypatch, ["veridrome", "verify", "c.json", "--pubkey", "K",
                          "--ledger", "L"],
            lambda cert_path, pubkey_b64=None, ledger_path=None:
            kayit.update(cert_path=cert_path, pubkey_b64=pubkey_b64,
                         ledger_path=ledger_path) or 0,
            "command_verify",
        )
        assert kod == 0
        assert kayit == {"cert_path": "c.json", "pubkey_b64": "K", "ledger_path": "L"}

    def test_certify_dispatch(self, monkeypatch):
        """D58: 'certify --commit --repo --out' → command_certify(...)."""
        kayit = {}
        kod = self._dispatch(
            monkeypatch, ["veridrome", "certify", "--commit", "abc123", "--repo",
                          "r", "--out", "o.json"],
            lambda results_path=None, pytest_args=None, commit_sha=None,
            repo_url=None, job_id=None, agent_did=None, out_path=None,
            valid_days=365: kayit.update(commit_sha=commit_sha, repo_url=repo_url,
                                        out_path=out_path,
                                        valid_days=valid_days) or 3,
            "command_certify",
        )
        assert kod == 3
        assert kayit == {"commit_sha": "abc123", "repo_url": "r",
                         "out_path": "o.json", "valid_days": 365}

    def test_keygen_dispatch(self, monkeypatch):
        """D59: 'keygen' → command_keygen()."""
        kod = self._dispatch(monkeypatch, ["veridrome", "keygen"],
                             lambda: 0, "command_keygen")
        assert kod == 0

    def test_revoke_dispatch(self, monkeypatch):
        """D60: 'revoke cert --reason' → command_revoke(cert, reason, None)."""
        kayit = {}
        kod = self._dispatch(
            monkeypatch, ["veridrome", "revoke", "c.json", "--reason", "neden"],
            lambda cert_path, reason, ledger_path=None:
            kayit.update(cert_path=cert_path, reason=reason,
                         ledger_path=ledger_path) or 0,
            "command_revoke",
        )
        assert kod == 0
        assert kayit == {"cert_path": "c.json", "reason": "neden", "ledger_path": None}

    def test_mcp_dispatch(self, monkeypatch):
        """D61: 'mcp' → command_mcp()."""
        kod = self._dispatch(monkeypatch, ["veridrome", "mcp"],
                             lambda: 0, "command_mcp")
        assert kod == 0

    def test_alt_komut_yoksa_yardim_ve_exit_bir(self, monkeypatch, capsys):
        """D62: alt-komut yok → yardım basılır + SystemExit(1)."""
        monkeypatch.setattr(sys, "argv", ["veridrome"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        assert "usage:" in capsys.readouterr().out
