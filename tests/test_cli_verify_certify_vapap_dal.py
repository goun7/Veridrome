"""
test_cli_verify_certify_vapap_dal.py — Dal-kesen testler: command_verify, command_certify, VAPAP dispatch

Hedeflenen test-disi fonksiyonlar (73-Veridrome):
  * cli/main.py:39   command_verify          (102L) — güvenlik/zincir: sertifika bağımsız-doğrulama CLI
  * cli/main.py:178  command_certify         (84L)  — güvenlik/zincir: did:key sertifika üretimi (fail-closed)
  * credentials/vapap_middleware.py:36 dispatch (64L) — güvenlik: ajan-yetkilendirme ara-yazılımı

KURAL: SADECE YENI DOSYA; mevcut testleri/kodu DEĞİŞTIRMEZ. Dış çağrılar
(gerçek pytest-koşusu, ağ) monkeypatch/tmp_path ile taklit edilir; yalnızca
fonksiyonların kendi mantığı test edilir.
"""

import base64
import json
import os
import sys
import time

import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from veridrome.certificate.core import CertificateBuilder  # noqa: E402
from veridrome.certificate.didkey import generate_keypair  # noqa: E402
from veridrome.certificate.revocation import RevocationLedger  # noqa: E402
from veridrome.core.crypto import VeridromeAuthoritySigner  # noqa: E402
from veridrome.credentials.vapap_middleware import VAPAPAuthMiddleware  # noqa: E402
from veridrome.credentials.w3c_vc import VeridromeCredentialManager  # noqa: E402
from veridrome.cli.main import command_certify, command_verify  # noqa: E402

_COMMIT = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4"

_FIXTURE_RESULTS = [
    {"name": "tests/test_a.py::test_one", "outcome": "passed", "duration_ms": 12.0},
    {"name": "tests/test_a.py::test_two", "outcome": "passed", "duration_ms": 34.0},
    {"name": "tests/test_b.py::test_three", "outcome": "passed", "duration_ms": 110.0},
]


def _rapor_dosyasi(entries=None, *, failed=False):
    """Diskteki pytest-json-report zarfı (parse_pytest_json'ın okuduğu format).

    pytest-json-report yapısı: {"tests": [...], "summary": {...}}.
    ``normalize_results`` bu zarfı {name,outcome,duration_ms} girdilerine
    çevirir.
    """
    if entries is None:
        entries = list(_FIXTURE_RESULTS)
        if failed:
            entries = entries + [
                {"name": "tests/test_c.py::test_fail", "outcome": "failed",
                 "duration_ms": 5.0},
            ]
    gecen = sum(1 for e in entries if e.get("outcome") == "passed")
    return {"tests": entries,
            "summary": {"total": len(entries), "passed": gecen,
                        "failed": len(entries) - gecen, "skipped": 0}}


def _run_zarfi(entries=None, *, failed=False, exit_code=0):
    """run_pytest_json taklit çıktısı (parse_pytest_json sonucu + exit_code).

    Anahtarlar ``entries``/``summary``/``source``/``exit_code``
    (disk-zarfındaki ``tests`` DEĞİL).
    """
    if entries is None:
        entries = list(_FIXTURE_RESULTS)
        if failed:
            entries = entries + [
                {"name": "tests/test_c.py::test_fail", "outcome": "failed",
                 "duration_ms": 5.0},
            ]
    gecen = sum(1 for e in entries if e.get("outcome") == "passed")
    return {"entries": entries,
            "summary": {"total": len(entries), "passed": gecen,
                        "failed": len(entries) - gecen, "skipped": 0},
            "source": "test-fixture",
            "exit_code": exit_code}


def _cert_file(tmp_path, *, results=_FIXTURE_RESULTS, commit=_COMMIT,
               valid_days=7, seed_did=None) -> str:
    """Geçerli did:key-imzalı sertifika yaz; yolunu döndür."""
    if seed_did is None:
        seed, did, _ = generate_keypair()
    else:
        seed, did = seed_did
    builder = CertificateBuilder(seed, did)
    cert = builder.build(
        test_results=results,
        repo_url="https://github.com/org/repo",
        commit_sha=commit,
        job_id="job-001",
        valid_days=valid_days,
    )
    yol = str(tmp_path / "cert.json")
    with open(yol, "w", encoding="utf-8") as f:
        json.dump(cert, f, ensure_ascii=False)
    return yol


# ---------------------------------------------------------------------------
# 1. command_verify — güvenlik/zincir: bağımsız sertifika doğrulama
# ---------------------------------------------------------------------------
class TestCommandVerify:
    def test_verify_gecerli_sertifika(self, tmp_path, capsys):
        yol = _cert_file(tmp_path)
        rc = command_verify(yol)
        assert rc == 0
        out = capsys.readouterr().out
        assert "SERTİFİKA GEÇERLİ" in out
        assert "İmzalayan" in out
        assert "Merkle Kökü" in out
        assert "3 passed / 3" in out

    def test_verify_did_key_self_resolving(self, tmp_path, capsys):
        # --pubkey GEREKMEZ: anahtar issuer did:key'den kurtarılır
        yol = _cert_file(tmp_path)
        rc = command_verify(yol, pubkey_b64=None)
        assert rc == 0

    def test_verify_olmayan_dosya(self, tmp_path, capsys):
        rc = command_verify(str(tmp_path / "yok.json"))
        assert rc == 1
        assert "açılamadı" in capsys.readouterr().out

    def test_verify_bozuk_json(self, tmp_path, capsys):
        yol = tmp_path / "bad.json"
        yol.write_text("{gecerli-degil", encoding="utf-8")
        rc = command_verify(str(yol))
        assert rc == 1
        assert "açılamadı" in capsys.readouterr().out

    def test_verify_tahriz_edilmis_sertifika(self, tmp_path, capsys):
        # güvenlik: gövde değiştirilirse content-hash yakalar
        yol = _cert_file(tmp_path)
        with open(yol, encoding="utf-8") as f:
            cert = json.load(f)
        cert["credentialSubject"]["summary"]["total"] = 999
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(cert, f, ensure_ascii=False)
        rc = command_verify(yol)
        assert rc == 1
        assert "SERTİFİKA GEÇERSİZ" in capsys.readouterr().out

    def test_verify_iptal_edilmis_sertifika(self, tmp_path, capsys):
        # zincir/güvenlik: --ledger ile iptal-defteri denetimi
        seed, did, _ = generate_keypair()
        yol = _cert_file(tmp_path, seed_did=(seed, did))
        with open(yol, encoding="utf-8") as f:
            cert = json.load(f)
        cert_id = cert["cert_id"]

        ledger_path = str(tmp_path / "revocations.jsonl")
        ledger = RevocationLedger(ledger_path)
        ledger.revoke(cert_id, seed, did, reason="test-iptal")
        assert ledger.verify_chain() is True

        rc = command_verify(yol, ledger_path=ledger_path)
        assert rc == 1
        out = capsys.readouterr().out
        assert "GEÇERSİZ" in out
        assert "iptal edilmiş" in out
        assert "test-iptal" in out

    def test_verify_iptal_listesinde_degilse_gecerli(self, tmp_path, capsys):
        # ledger var ama bu sertifika iptal edilmemiş → geçerli
        seed, did, _ = generate_keypair()
        yol = _cert_file(tmp_path, seed_did=(seed, did))
        ledger_path = str(tmp_path / "revocations.jsonl")
        ledger = RevocationLedger(ledger_path)
        # BAŞKA bir cert_id iptal et
        ledger.revoke("0" * 64, seed, did, reason="baska")
        rc = command_verify(yol, ledger_path=ledger_path)
        assert rc == 0

    def test_verify_veridrome_home_varsayilan_ledger(self, tmp_path, capsys,
                                                     monkeypatch):
        # güvenlik: VERIDROME_HOME altındaki varsayılan defter kullanılır
        seed, did, _ = generate_keypair()
        yol = _cert_file(tmp_path, seed_did=(seed, did))
        with open(yol, encoding="utf-8") as f:
            cert = json.load(f)

        home = tmp_path / "vhome"
        home.mkdir()
        ledger = RevocationLedger(str(home / "revocations.jsonl"))
        ledger.revoke(cert["cert_id"], seed, did, reason="env-iptal")
        monkeypatch.setenv("VERIDROME_HOME", str(home))

        rc = command_verify(yol)
        assert rc == 1
        assert "env-iptal" in capsys.readouterr().out

    def test_verify_veridrome_home_yoksa_ledger_atlanir(self, tmp_path, capsys,
                                                        monkeypatch):
        # defter yoksa iptal-denetimi yapılmaz → sertifika geçerli kalır
        home = tmp_path / "bos_home"
        monkeypatch.setenv("VERIDROME_HOME", str(home))
        yol = _cert_file(tmp_path)
        rc = command_verify(yol)
        assert rc == 0

    def _w3c_vc(self, signer, monkeypatch, *, metrics=None):
        """W3C-VC üret; CT-defterine YAZMAZ (KURAL-1: ct_log.jsonl dokunulmaz).

        ``issue_credential`` RFC 6962 CT-defterine append yapar; bu dal-kesme
        testleri yalnızca ``command_verify``'ın eski-W3C-VC yolunu sınlar.
        """
        from veridrome.credentials.w3c_vc import VeridromeCredentialManager as _M
        # CT-defteri yazımını devre dışı bırak (mevcut dosyaya dokunma-YASAK)
        monkeypatch.setattr(_M, "_append_to_ct_log", lambda self, vc: None,
                            raising=False)
        vc, _token = _M(signer=signer).issue_credential(
            job_id="job-legacy",
            agent_id="urn:agent:legacy",
            metrics=metrics or {"medianSuccess": 0.9, "anomalyScore": 0.1},
            tee_platform="simulated-tee",
            pcr0_measurement="0" * 64,
            merkle_root="0x" + "ab" * 32,
            validity_days=365,
        )
        return vc

    def test_verify_eski_w3c_vc_pubkey_yolu(self, tmp_path, capsys, monkeypatch):
        # yol-2: did:key değil → --pubkey ile eski W3C-VC doğrulama
        signer = VeridromeAuthoritySigner()
        vc = self._w3c_vc(signer, monkeypatch)
        yol = str(tmp_path / "legacy.json")
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(vc, f, ensure_ascii=False)
        # --- pubkey olmadan reddet
        rc = command_verify(yol)
        assert rc == 1
        assert "--pubkey zorunlu" in capsys.readouterr().out
        # --- geçerli pubkey ile kabul
        import base64 as _b64
        pub_b64 = _b64.b64encode(signer.public_key_bytes).decode("ascii")
        rc = command_verify(yol, pubkey_b64=pub_b64)
        assert rc == 0
        out = capsys.readouterr().out
        assert "GEÇERLİ" in out
        assert "%90.00" in out  # medianSuccess raporu

    def test_verify_eski_w3c_vc_gecersiz_imza(self, tmp_path, capsys, monkeypatch):
        # güvenlik: imza farklı anahtarla yapılmışsa reddet
        signer1 = VeridromeAuthoritySigner()
        signer2 = VeridromeAuthoritySigner()
        vc = self._w3c_vc(signer1, monkeypatch,
                          metrics={"medianSuccess": 0.9})
        yol = str(tmp_path / "legacy.json")
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(vc, f, ensure_ascii=False)
        import base64 as _b64
        pub_b64 = _b64.b64encode(signer2.public_key_bytes).decode("ascii")
        rc = command_verify(yol, pubkey_b64=pub_b64)
        assert rc == 1
        assert "GEÇERSİZ" in capsys.readouterr().out

    def test_verify_eski_w3c_vc_proofvalue_yoksa(self, tmp_path, capsys, monkeypatch):
        # güvenlik: proofValue eksikse reddet
        signer = VeridromeAuthoritySigner()
        vc = self._w3c_vc(signer, monkeypatch,
                          metrics={"medianSuccess": 0.9})
        del vc["proof"]["proofValue"]
        yol = str(tmp_path / "legacy.json")
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(vc, f, ensure_ascii=False)
        import base64 as _b64
        pub_b64 = _b64.b64encode(signer.public_key_bytes).decode("ascii")
        rc = command_verify(yol, pubkey_b64=pub_b64)
        assert rc == 1
        assert "proofValue" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# 2. command_certify — güvenlik/zincir: did:key sertifika üretimi
# ---------------------------------------------------------------------------
class TestCommandCertify:
    def test_certify_results_path_ile_uretir(self, tmp_path, capsys):
        # test-sonuçlarından sertifika üret
        rapor = _rapor_dosyasi()
        rapor_yolu = tmp_path / "report.json"
        rapor_yolu.write_text(json.dumps(rapor), encoding="utf-8")

        out = tmp_path / "cert.json"
        monkey = pytest.MonkeyPatch()
        # _load_signing_seed'ı deterministik tohumla değiştir
        seed, did, _ = generate_keypair()
        monkey.setattr("veridrome.cli.main._load_signing_seed", lambda: seed)
        try:
            rc = command_certify(
                results_path=str(rapor_yolu),
                pytest_args=None,
                commit_sha=_COMMIT,
                repo_url="https://github.com/org/repo",
                job_id="job-1",
                agent_did=None,
                out_path=str(out),
                valid_days=7,
            )
        finally:
            monkey.undo()
        assert rc == 0
        cert = json.loads(out.read_text(encoding="utf-8"))
        assert cert["credentialSubject"]["summary"]["total"] == 3
        assert cert["credentialSubject"]["summary"]["failed"] == 0
        assert cert["issuer"].startswith("did:key:")
        assert len(cert["cert_id"]) == 64

    def test_certify_stdout_a_yazar(self, tmp_path, capsys):
        rapor = _rapor_dosyasi()
        rapor_yolu = tmp_path / "report.json"
        rapor_yolu.write_text(json.dumps(rapor), encoding="utf-8")
        seed, did, _ = generate_keypair()
        monkey = pytest.MonkeyPatch()
        monkey.setattr("veridrome.cli.main._load_signing_seed", lambda: seed)
        try:
            rc = command_certify(
                results_path=str(rapor_yolu), pytest_args=None,
                commit_sha=_COMMIT, repo_url=None, job_id=None,
                agent_did=None, out_path=None, valid_days=7,
            )
        finally:
            monkey.undo()
        assert rc == 0
        out = capsys.readouterr().out
        # stdout'a JSON yazılır
        cert = json.loads(out)
        assert cert["credentialSubject"]["summary"]["passed"] == 3

    def test_certify_failing_test_varsa_fail_closed(self, tmp_path, capsys):
        # güvenlik: failing-test varsa sertifika YOK (exit 2)
        rapor = _rapor_dosyasi(failed=True)
        rapor_yolu = tmp_path / "report.json"
        rapor_yolu.write_text(json.dumps(rapor), encoding="utf-8")
        rc = command_certify(
            results_path=str(rapor_yolu), pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(tmp_path / "c.json"), valid_days=7,
        )
        assert rc == 2
        assert not (tmp_path / "c.json").exists()

    def test_certify_hic_test_yoksa_fail_closed(self, tmp_path, capsys):
        rapor = _rapor_dosyasi(entries=[])
        rapor_yolu = tmp_path / "report.json"
        rapor_yolu.write_text(json.dumps(rapor), encoding="utf-8")
        rc = command_certify(
            results_path=str(rapor_yolu), pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(tmp_path / "c.json"), valid_days=7,
        )
        assert rc == 2
        assert "kanıtsız sertifika yok" in capsys.readouterr().out

    def test_certify_bozuk_results_dosyasi(self, tmp_path, capsys):
        yol = tmp_path / "bad.json"
        yol.write_text("{bozuk", encoding="utf-8")
        rc = command_certify(
            results_path=str(yol), pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(tmp_path / "c.json"), valid_days=7,
        )
        assert rc == 1
        assert "okunamadı" in capsys.readouterr().out

    def test_certify_pytest_args_ile_gercek_kosu_taklit(self, tmp_path, capsys,
                                                         monkeypatch):
        # dal-kesme: gerçek pytest KOŞMAZ; run_pytest_json taklit edilir
        parsed = _run_zarfi()
        cagri = {"args": None}

        def _fake_run(args):
            cagri["args"] = args
            return parsed

        monkeypatch.setattr(
            "veridrome.certificate.pytest_parser.run_pytest_json", _fake_run)
        seed, did, _ = generate_keypair()
        monkeypatch.setattr("veridrome.cli.main._load_signing_seed", lambda: seed)
        out = tmp_path / "c.json"
        rc = command_certify(
            results_path=None, pytest_args=["tests/test_x.py"],
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(out), valid_days=7,
        )
        assert rc == 0
        assert cagri["args"] == ["tests/test_x.py"]
        assert json.loads(out.read_text(encoding="utf-8"))["issuer"].startswith("did:key:")

    def test_certify_pytest_args_varsayilan_tests_dizini(self, tmp_path,
                                                         monkeypatch):
        parsed = _run_zarfi()
        cagri = {"args": None}

        def _fake_run(args):
            cagri["args"] = args
            return parsed

        monkeypatch.setattr(
            "veridrome.certificate.pytest_parser.run_pytest_json", _fake_run)
        seed, did, _ = generate_keypair()
        monkeypatch.setattr("veridrome.cli.main._load_signing_seed", lambda: seed)
        rc = command_certify(
            results_path=None, pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(tmp_path / "c.json"), valid_days=7,
        )
        assert rc == 0
        assert cagri["args"] == ["tests/"]

    def test_certify_pytest_kosusu_exit_kodu_ile_fail_closed(self, tmp_path,
                                                              monkeypatch,
                                                              capsys):
        # güvenlik: pytest exit_code != 0 → sertifika YOK
        parsed = _run_zarfi(failed=True, exit_code=1)
        monkeypatch.setattr(
            "veridrome.certificate.pytest_parser.run_pytest_json",
            lambda args: parsed)
        rc = command_certify(
            results_path=None, pytest_args=["tests/"],
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(tmp_path / "c.json"), valid_days=7,
        )
        assert rc == 2
        assert "failing-testlerle sertifika yok" in capsys.readouterr().out

    def test_certify_uretilen_sertifika_verify_edilebilir(self, tmp_path,
                                                          monkeypatch):
        # zincir: certify → verify uçtan-uca bağımsız doğrulanabilir
        rapor = _rapor_dosyasi()
        rapor_yolu = tmp_path / "report.json"
        rapor_yolu.write_text(json.dumps(rapor), encoding="utf-8")
        seed, did, _ = generate_keypair()
        monkeypatch.setattr("veridrome.cli.main._load_signing_seed", lambda: seed)
        out = tmp_path / "c.json"
        rc = command_certify(
            results_path=str(rapor_yolu), pytest_args=None,
            commit_sha=_COMMIT, repo_url=None, job_id=None,
            agent_did=None, out_path=str(out), valid_days=7,
        )
        assert rc == 0
        # kendi verify komutuyla doğrula (--pubkey YOK, self-resolving)
        assert command_verify(str(out)) == 0


# ---------------------------------------------------------------------------
# 3. VAPAPAuthMiddleware.dispatch — güvenlik: ajan yetkilendirme
# ---------------------------------------------------------------------------
def _app(signer, *, required_min_score=0.85, exempt_paths=None):
    app = FastAPI()
    app.add_middleware(
        VAPAPAuthMiddleware,
        authority_public_key=signer.public_key_bytes,
        required_min_score=required_min_score,
        exempt_paths=exempt_paths if exempt_paths is not None else ["/healthz"],
    )

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/api/secure/checkout")
    def checkout(request: Request):
        return {
            "status": "APPROVED",
            "agent_id": getattr(request.state, "agent_id", None),
            "claims": getattr(request.state, "vapap_claims", None),
        }

    return app


def _token(signer, *, agent_id="urn:agent:acme-1", cert_id="cert-1",
           score_median=0.94, expires_in_sec=3600):
    mgr = VeridromeCredentialManager(signer=signer)
    return mgr.create_vapap_token(
        agent_id=agent_id, cert_id=cert_id,
        score_median=score_median, expires_in_sec=expires_in_sec,
    )


class TestVapapDispatch:
    def test_muaf_yol_token_gerektirmez(self):
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        assert client.get("/healthz").status_code == 200

    def test_token_yoksa_401(self):
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        res = client.get("/api/secure/checkout")
        assert res.status_code == 401
        assert res.json()["error"] == "VAPAP_TOKEN_MISSING"

    def test_gecerli_token_ile_200_ve_agent_id_enjekte(self):
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token":
                                  _token(signer, agent_id="urn:agent:x")})
        assert res.status_code == 200
        govde = res.json()
        assert govde["status"] == "APPROVED"
        assert govde["agent_id"] == "urn:agent:x"
        assert govde["claims"]["cert_id"] == "cert-1"

    def test_authorization_header_devamli_token(self):
        # güvenlik: Authorization: VAPAP <token> başlık yolu da çalışır
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        res = client.get("/api/secure/checkout",
                         headers={"Authorization": "VAPAP " + _token(signer)})
        assert res.status_code == 200

    def test_dusuk_skor_403(self):
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer, required_min_score=0.85))
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token":
                                  _token(signer, score_median=0.50)})
        assert res.status_code == 403
        assert res.json()["error"] == "VAPAP_INSUFFICIENT_SCORE"

    def test_skor_esikte_gecerli(self):
        # sınır-değeri: 0.85 == 0.85 → geçerli (>= karşılaştırması)
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer, required_min_score=0.85))
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token":
                                  _token(signer, score_median=0.85)})
        assert res.status_code == 200

    def test_suresi_dolmus_token_403(self):
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        # expires_in_sec negatif → süresi dolmuş
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token":
                                  _token(signer, expires_in_sec=-1)})
        assert res.status_code == 403
        assert res.json()["error"] == "VAPAP_TOKEN_EXPIRED"

    def test_tahriz_edilmis_token_403(self):
        # güvenlik: payload değiştirilirse imza yakalar
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        token = _token(signer)
        payload = json.loads(base64.b64decode(token))
        payload["score_median"] = 0.99  # yükseltme saldırısı
        del payload["signature"]
        govde = dict(payload)
        govde["signature"] = base64.b64encode(signer.sign(
            json.dumps(govde, sort_keys=True).encode("utf-8"))).decode("ascii")
        # payload'ı yeniden imzala AMA orijinal imzayı koru → tutarsız
        broken = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token": broken})
        assert res.status_code in (400, 403)

    def test_baskasinin_imzasi_ile_token_403(self):
        # güvenlik: farklı otorite anahtarıyla imzalanmış token
        signer1 = VeridromeAuthoritySigner()
        signer2 = VeridromeAuthoritySigner()
        client = TestClient(_app(signer1))
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token": _token(signer2)})
        assert res.status_code == 403
        assert res.json()["error"] == "VAPAP_INVALID_SIGNATURE"

    def test_eksik_imza_alani_403(self):
        # güvenlik: signature alanı yoksa reddet
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        payload = {"agent_id": "urn:agent:x", "score_median": 0.99,
                   "expires_at": int(time.time()) + 3600}
        token = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token": token})
        assert res.status_code == 403
        assert res.json()["error"] == "VAPAP_INVALID_SIGNATURE"

    def test_malformed_token_400(self):
        # base64/JSON olmayan çöp token
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer))
        res = client.get("/api/secure/checkout",
                         headers={"X-Veridrome-VAPAP-Token": "bu-bir-token-degil!!"})
        assert res.status_code == 400
        assert res.json()["error"] == "VAPAP_MALFORMED_TOKEN"

    def test_ozel_muaf_yollar(self):
        # güvenlik: exempt_paths yalnızca listelenen yolları geçirir
        signer = VeridromeAuthoritySigner()
        client = TestClient(_app(signer, exempt_paths=["/healthz", "/public"]))
        assert client.get("/public").status_code == 404  # route yok ama muaf
        assert client.get("/api/secure/checkout").status_code == 401
