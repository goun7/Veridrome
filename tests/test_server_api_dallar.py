"""
test_server_api_dallar.py — Dal-kesen (branch-coverage) testler: src/veridrome/server/api.py

Hedeflenen public yüzey (FastAPI uygulama-fabrikası + REST/SSE uçnoktaları):
  * create_app                          — uygulama fabrikası (varsayılan/verilen bağımlılıklar)
  * dashboard_index   GET /             — statik HTML gösterge-paneli
  * healthz           GET /healthz      — sağlık-bilgisi
  * submit_evaluation POST /v1/evaluations/submit — değerlendirme gönderimi (senkron)
  * stream_evaluation GET /v1/evaluations/{job_id}/stream — SSE olay-akışı
  * get_certificate   GET /v1/certificates/{cert_id:path} (+ "/verify" dalı)
  * revoke_certificate POST /v1/certificates/{cert_id:path}/revoke

DAL HARİTASI (D1..D48):
  create_app:
    D1  varsayılan create_app() FastAPI uygulaması üretir (title/version)
    D2  modül-seviyesi `app` tekil FastAPI örneğidir; her create_app yenisi
    D3  verilen koşucu (runner) birebir kullanılır (çağrım kaydıyla kanıtlanır)
    D4  verilen credential_manager kabul edilir ama hiçbir uçnoktada kullanılmaz
        (BULGU B2: ölü parametre — doğrulama sınıf-metodu + uygulamanın imzalayıcısı)
    D5  koşucu verilmezse gerçek EvaluationRunner kurulur ve tam koşum çalışır
  dashboard/healthz:
    D6  GET / → 200 + text/html + DASHBOARD_HTML birebir
    D7  GET /healthz → status=ok, service=veridrome-api, version=1.3.0
  submit — doğrulama (422) dalları:
    D8  eksik agent_id / endpoint_url / runtime_manifest / manifest.model → 422
    D9  manifest.cost_cap_usd varsayılanı (10.0) kabul edilir
    D10 geçersiz türler (cost_cap_usd dize) → 422
  submit — simüle-etki-alanı dalları:
    D11 acme.ai/internal/example.com/mock alt-dizeleri → httpx ÇAĞRILMAZ
        (BULGU B3: altdizge eşleşmesi "https://evil.example/?x=acme.ai" yi de simüle sayar)
    D12 http şeması ile başlamayan URL → baseline (httpx çağrılmaz)
    D13 boş endpoint_url → baseline
    D14 başarılı koşum → 202 + yanıt gövdesi sabit alanları
    D15 D14: yanıt "status":"PROCESSING" derken koşum SENKRON tamamlanmıştır
        (BULGU B1: jobs_db'de COMPLETED — API sözleşmesi yanıltıcı)
  submit — gerçek httpx dalları:
    D16 http 200 + passed verisi → ajan JSON yanıtı metriclere yansır (maliyet/gecikme)
    D17 http 200 + passed=false → sertifikasız, cert_id düşer
    D18 http 200 olmaması (503) → http_error_* dalı → başarısız koşum
    D19 httpx istisnası → connection_error dalı → başarısız koşum
        (BULGU B8: iki dal dış-gözlemle ayırt edilemez)
  submit — job_id:
    D20 sabit zaman (time.time monkeypatch) → deterministik job-id
    D21 6-karakterden kısa agent_id → tüm kimlik sonek olur
    D22 aynı saniye + aynı agent → AYNI job_id → jobs_db üzerine-yazma (BULGU B5)
    D23 farklı agent → farklı job_id
  stream:
    D24 bilinmeyen job_id → 404 "Koşum bulunamadı."
    D25 tam SSE akış sırası (JOB_STARTED/TEE_ALLOCATED/20×TASK_EVALUATING/JOB_COMPLETED)
    D26 TASK_EVALUATING kümesi T01..T20 + yüzde ilerleme (ilk 5%, son 100%)
    D27 stream kendi TaskRegistry'sini kurar — koşucuya verilen 2-görevli
        küme görmezden gelinir (BULGU B4)
    D28 red raporu → JOB_COMPLETED status=OVERFIT_REJECT, is_certified=false
    D29 koşucu istisnası → job QUEUED kalır → rapor-yok varsayılanları
        (status PASSED, is_certified true, boş merkle, düşen cert_id)
    D30 JOB_COMPLETED merkle-kökü + sertifika-kimliği rapordan yansır
  GET certificate:
    D31 bilinmeyen sertifika → 404
    D32 geçerli sertifika → VC birebir döner
    D33 iptal edilmiş → 410 + REVOKED + sebep
    D34 çok-bölümlü cert_id yolu → 404
    D35 gerçek-koşucu VC yapısal W3C alanları taşır
  verify dalı:
    D36 bilinmeyen → 404
    D37 geçerli → is_valid true + subject + expires_at
        (BULGU B9: SADECE varsayılan create_app yolunda — enjekte koşucuda
         anahtar uyuşmazlığı → is_valid false; D49)
    D38 iptal → is_valid false + CERTIFICATE_REVOKED
    D39 geçersiz imza → is_valid false
    D40 proofsuz VC → is_valid false
    D41 eksik credentialSubject → 500 (BULGU B7: uçnokta VC yapısına duyarlı)
    D49 enjekte koşucu (kendi imzalayıcısıyla) → VC doğrulaması false
        (BULGU B9: imza runner'ın anahtarıyla, doğrulama uygulamanınkiyle)
  revoke:
    D42 bilinmeyen → 404
    D43 başarılı iptal → SUCCESS + is_revoked true
    D44 sebep saklanır (410'dan okunur)
    D45 iki-kez iptal → SUCCESS + sebep üstüne-yazar
    D46 "/revoke/revoke" çift-yolu → str.replace tüm-geçiş davranışı (BULGU B6)
    D47 sebep yok → 422; boş sebep → 200 (sınır)
    D48 iptal sonrası GET → 410 + verify false (uçtan-uca akış)

BULGULAR (testlerle belle):
  B1  submit yanıt gövdesi "status":"PROCESSING" der ama koşum SENKRON'dur ve
      jobs_db'de COMPLETED'dır — API sözleşmesi yanıltıcı (D15).
  B2  create_app(..., credential_manager=...) kabul edilir ama hiçbir uçnoktada
      kullanılmaz; doğrulama sınıf-metodu + uygulamanın kendi imzalayıcısıyla
      yapılır — ölü parametre (D4).
  B3  is_simulated_domain URL içinde ALTDİZGE eşleştirir — "https://evil.example/?x=acme.ai"
      simüle sınıflanır, gerçek ajan HTTP çağrısı atlanır (güvenlik-açısı) (D11).
  B4  stream_evaluation kendi TaskRegistry()'sini kurar — koşucuya verilen özel
      kayıt-defteri görmezden gelinir, her zaman 20 görev akar (D27).
  B5  job_id saniye-çözünürlüklüdür: aynı saniye + aynı agent → aynı job_id →
      jobs_db kaydının üzerine yazılır (çarpışma) (D22).
  B6  revoke_certificate cert_id.replace("/revoke", "") KULLANIR — son-ek değil
      tüm geçişler soyulur (D46).
  B7  GET /verify eksik/bozuk yapılı VC'lerde 500 verir — kırılgan uçnokta (D41).
  B8  http_error_503 ile connection_error dış-gözlemle ayırt edilemez (ikisi de
      "geçersiz koşum" sonucuna indirgenir) — hata sınıflandırması kaybolur (D18/D19).
  B9  create_app(runner=...) ENJEKTE edilen koşucu kendi imzalayıcısıyla VC üretir,
      ama GET /verify uygulamanın iç authority_signer public-key'ini kullanır —
      imza-anahtar uyuşmazlığı: enjekte-runner sertifikaları her zaman false
      doğrulanır. Sadece varsayılan yolda anahtarlar tutarlıdır (D37/D49).

KURAL: SADECE YENİ DOSYA; production/conftest/mevcut-testlere DOKUNULMAZ.
Tüm koşumlar SAF-BELLEK'tir — ağ/RPC/subprocess/socket YOK; httpx monkeypatch
ile izlenir, TestClient ASGI taşışması kullanır (gerçek socket açılmaz),
VERIDROME_HOME ve çalışma-dizini tmp_path ile izole edilir.
"""

from __future__ import annotations

import dataclasses
import json
import time
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from veridrome.core.anti_gaming import AntiGamingMetrics
from veridrome.runner import EvaluationReport, EvaluationRunner
from veridrome.server import api as api_mod
from veridrome.server.api import app as modul_appi
from veridrome.server.api import create_app
from veridrome.server.dashboard_html import DASHBOARD_HTML
from veridrome.tasks.models import (
    EnvironmentSpec,
    InvariantSpec,
    PoolType,
    TaskCategory,
    TaskSpec,
)

_SABIT_ZAMAN = 1_761_000_000.0  # deterministik job_id için (time.time yerine)


# ---------------------------------------------------------------------------
# Yardımcılar — SAF-BELLEK stub'ları
# ---------------------------------------------------------------------------


def _gorev(task_id: str, pool_type: PoolType) -> TaskSpec:
    """Minimal geçerli TaskSpec (koşucunun ihtiyaç duyduğu tek alanlarla)."""
    return TaskSpec(
        task_id=task_id,
        title=f"Stub {task_id}",
        category=TaskCategory.E_COMMERCE,
        pool_type=pool_type,
        objective=f"Stub amaç {task_id}",
        environment=EnvironmentSpec(target_url="https://sandbox.veridrome.internal/stub"),
        invariants=[InvariantSpec(rule_type="dom_element_state", selector="#x", must_exist=True)],
    )


class _KucukKutuk:
    """2-görevli kayıt-defteri stub'ı — gerçek koşucuyu hızlı tutar."""

    def __init__(self) -> None:
        self._tasks = [_gorev("ST01", PoolType.PUBLIC_CANARY), _gorev("ST02", PoolType.DYNAMIC_HIDDEN)]

    def list_all(self):
        return list(self._tasks)


def _hizli_kosucu() -> EvaluationRunner:
    """Gerçek EvaluationRunner ama sadece 2 görevle (4 koşum toplam)."""
    return EvaluationRunner(task_registry=_KucukKutuk())


class _KosucuStub:
    """run_evaluation'ı atlayan koşucu stub'ı — rapor şeklini test belirler."""

    def __init__(self, rapor: EvaluationReport | None = None, hata: Exception | None = None) -> None:
        self.rapor = rapor
        self.hata = hata
        self.cagrilar: list[dict] = []

    def run_evaluation(self, **kwargs):
        self.cagrilar.append(kwargs)
        if self.hata is not None:
            raise self.hata
        rapor = self.rapor
        api_job_id = kwargs.get("job_id")
        if rapor is not None and api_job_id:
            # DİKKAT: api job_id'yi aşağı aktarır (AT-188); stub raporu
            # (varsa VC kimliğiyle) bu job-id'ye hizalar ki akış/kök-depo
            # tutarlı olsun. Aynı hizalama gerçek koşucuda rapor+VC'de yapılır.
            rapor = dataclasses.replace(rapor, job_id=api_job_id)
            if rapor.verifiable_credential:
                vc = dict(rapor.verifiable_credential)
                vc["id"] = f"urn:veridrome:cert:{api_job_id}"
                rapor = dataclasses.replace(rapor, verifiable_credential=vc)
        return rapor


def _stub_gonder(rapor, agent_id="urn:agent:stub", **gonder_kwargs):
    """Stub koşuculu uygulama kurar + gönderim yapar; (client, job_id, cert_id) döner.

    Stub (AT-188 akışına uygun olarak) raporun job_id'sini ve VC "id" alanını
    api tarafından aşağı-aktarılan job-id'ye hizalar; bu yüzden cert_id her
    durumda "urn:veridrome:cert:{job_id}" olur.
    """
    stub = _KosucuStub(rapor=rapor)
    client = TestClient(create_app(runner=stub))
    res = _gonder(client, agent_id=agent_id, **gonder_kwargs)
    job_id = res.json()["job_id"]
    cert_id = f"urn:veridrome:cert:{job_id}"
    return client, job_id, cert_id


def _anti_gaming(verdict: str = "PASSED") -> AntiGamingMetrics:
    return AntiGamingMetrics(
        d_ks=0.0, p_ks=1.0, rho_spearman=0.0, p_spearman=1.0,
        delta_entropy=0.0, jsd=0.0, anomaly_score=0.0,
        is_overfit=False, is_sandbagging=False, verdict=verdict,
    )


def _rapor(
    job_id: str = "job-stub-1",
    agent_id: str = "urn:agent:stub",
    verdict: str = "PASSED",
    is_certified: bool = True,
    vc: dict | None = None,
    merkle_root: str = "0x" + "cc" * 32,
) -> EvaluationReport:
    """El-yapımı EvaluationReport (stub koşucu uçlarında)."""
    if vc is None and is_certified:
        vc = _fake_vc(job_id=job_id, agent_id=agent_id)
    return EvaluationReport(
        job_id=job_id,
        agent_id=agent_id,
        timestamp="2026-01-01T00:00:00+00:00",
        total_tasks=2,
        runs_per_task=2,
        median_success_rate=1.0 if is_certified else 0.0,
        iqr_success_rate=0.0,
        mean_cost_per_task=0.03,
        p95_latency_sec=10.5,
        anti_gaming=_anti_gaming(verdict),
        tee_valid=True,
        merkle_root=merkle_root,
        is_certified=is_certified,
        rejection_reason=None if is_certified else "SCORE_INSUFFICIENT",
        certificate_token="stub-token" if is_certified else None,
        verifiable_credential=vc,
    )


def _fake_vc(job_id: str = "job-stub-1", agent_id: str = "urn:agent:stub") -> dict:
    """Yapısal olarak geçerli ama İMZASIZ VC (doğrulama kırmızı dalı için)."""
    return {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": f"urn:veridrome:cert:{job_id}",
        "type": ["VerifiableCredential", "VeridromeAgentCertification"],
        "issuer": "did:veridrome:authority:mainnet",
        "validFrom": "2020-01-01T00:00:00+00:00",
        "validUntil": "2099-01-01T00:00:00+00:00",
        "credentialSubject": {"id": agent_id, "metrics": {"medianSuccess": 1.0}},
        "proof": {"type": "Ed25519Signature2020", "proofValue": "aW52YWxpZCBzaWduYXR1cmU="},
    }


class _Cevap:
    """httpx.Response taklidi (SAF-BELLEK)."""

    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _HttpxIzci:
    """api.py içinden `import httpx` ile alınan modüldeki httpx.Client'in
    yerine geçen SAF-BELLEK izci — hiçbir bağlantı açmaz."""

    def __init__(self, cevap_factory=None, hata: Exception | None = None) -> None:
        self.cevap_factory = cevap_factory or (lambda url, govde: _Cevap(200, {"passed": True}))
        self.hata = hata
        self.cagrilar: list[tuple] = []
        self.zaman_asimi = None

    def __call__(self, timeout=None, **kwargs):
        self.zaman_asimi = timeout
        return _Oturum(self)


class _Oturum:
    def __init__(self, izci: _HttpxIzci) -> None:
        self.izci = izci

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json=None, **kwargs):
        self.izci.cagrilar.append((url, json))
        if self.izci.hata is not None:
            raise self.izci.hata
        return self.izci.cevap_factory(url, json)


def _gonder(
    client: TestClient,
    agent_id: str = "urn:agent:0x98f12a",
    endpoint_url: str = "https://agent.acme.ai/v1/act",
    **payload_kalıntısı,
):
    """Değerlendirme gönderimi için tekdüze istek-gövdesi."""
    payload = {
        "agent_id": agent_id,
        "endpoint_url": endpoint_url,
        "runtime_manifest": {"model": "test-model", "cost_cap_usd": 5.0},
    }
    payload.update(payload_kalıntısı)
    return client.post("/v1/evaluations/submit", json=payload)


def _sse_olaylari(text: str) -> list[dict]:
    """SSE akış metninden `data: {...}` olaylarını çıkarır."""
    return [json.loads(satir[len("data: "):]) for satir in text.splitlines() if satir.startswith("data: ")]


@pytest.fixture(autouse=True)
def izole_ev(tmp_path, monkeypatch):
    """Kural-4: VERIDROME_HOME + çalışma-dizini izolasyonu (SAF-BELLEK)."""
    monkeypatch.setenv("VERIDROME_HOME", str(tmp_path / ".veridrome"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# create_app — fabrika dalları (D1..D5)
# ---------------------------------------------------------------------------


class TestCreateApp:
    def test_varsayilan_create_app_fastapi_uretir(self):
        app = create_app()
        assert isinstance(app, FastAPI)
        assert app.title == "Veridrome Evaluation & Attestation API"
        assert app.version == "1.3.0"

    def test_modul_seviyesi_app_tekil_fastapi(self):
        assert isinstance(modul_appi, FastAPI)
        assert create_app() is not modul_appi  # her çağrı yeni uygulama
        assert api_mod.app is modul_appi

    def test_verilen_kosucu_birebir_kullanilir(self):
        stub = _KosucuStub(rapor=_rapor())
        app = create_app(runner=stub)
        client = TestClient(app)
        res = _gonder(client)
        assert res.status_code == 202
        assert len(stub.cagrilar) == 1
        cagri = stub.cagrilar[0]
        assert cagri["agent_id"] == "urn:agent:0x98f12a"
        assert cagri["runs_per_task"] == 2
        assert cagri["job_id"] == res.json()["job_id"]  # AT-188: job_id aşağı aktarılır
        assert callable(cagri["task_executor_fn"])

    def test_verilen_credential_manager_kabul_edilir_ama_kullanilmaz(self):
        # BULGU B2: parametre kabul edilir, hiçbir uçnokta cred_mgr'ye dokunmaz.
        cred_mgr = MagicMock(name="credential_manager-izci")
        stub = _KosucuStub(rapor=_rapor())
        app = create_app(runner=stub, credential_manager=cred_mgr)
        client = TestClient(app)
        job_id = _gonder(client).json()["job_id"]
        cert_id = f"urn:veridrome:cert:{job_id}"
        assert client.get(f"/v1/certificates/{cert_id}").status_code == 200
        assert client.get(f"/v1/certificates/{cert_id}/verify").status_code == 200
        assert cred_mgr.call_count == 0
        assert len(cred_mgr.method_calls) == 0

    def test_kosucu_verilmezse_gecerli_degerlendirme_kosar(self):
        # Varsayılan create_app() — gerçek koşucu + tam 20-görev kayıt-defteri.
        app = create_app()
        client = TestClient(app)
        res = _gonder(client, endpoint_url="https://agent.acme.ai/v1/act")
        assert res.status_code == 202
        job_id = res.json()["job_id"]
        assert job_id.startswith("job-")
        # tam koşum sertifikalandıysa sertifika mevcuttur
        assert client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}").status_code in (200, 404)
        # akış tamamlanır
        res = client.get(f"/v1/evaluations/{job_id}/stream")
        assert res.status_code == 200
        assert "JOB_COMPLETED" in res.text


# ---------------------------------------------------------------------------
# dashboard + healthz (D6..D7)
# ---------------------------------------------------------------------------


class TestDashboardVeHealthz:
    def test_dashboard_html_icerigi_birebir(self):
        client = TestClient(create_app(runner=_KosucuStub(rapor=_rapor())))
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert res.text == DASHBOARD_HTML  # içerik birebir (bozulma denetimi)

    def test_healthz_alanlari(self):
        client = TestClient(create_app(runner=_KosucuStub(rapor=_rapor())))
        res = client.get("/healthz")
        assert res.status_code == 200
        govde = res.json()
        assert govde == {"status": "ok", "service": "veridrome-api", "version": "1.3.0"}


# ---------------------------------------------------------------------------
# submit — doğrulama (422) dalları (D8..D10)
# ---------------------------------------------------------------------------


class TestSubmitDogrulama:
    @pytest.mark.parametrize("eksik_alan", ["agent_id", "endpoint_url", "runtime_manifest"])
    def test_eksik_alan_422(self, eksik_alan):
        client = TestClient(create_app(runner=_KosucuStub(rapor=_rapor())))
        payload = {
            "agent_id": "urn:agent:x1",
            "endpoint_url": "https://agent.acme.ai/v1/act",
            "runtime_manifest": {"model": "m", "cost_cap_usd": 1.0},
        }
        del payload[eksik_alan]
        res = client.post("/v1/evaluations/submit", json=payload)
        assert res.status_code == 422

    @pytest.mark.parametrize("gecersiz_manifest", [
        {},  # model eksik (zorunlu alan)
        {"model": "m", "cost_cap_usd": "on-dolar"},  # float bekler, dize verildi
    ])
    def test_gecersiz_manifest_422(self, gecersiz_manifest):
        client = TestClient(create_app(runner=_KosucuStub(rapor=_rapor())))
        res = _gonder(client, runtime_manifest=gecersiz_manifest)
        assert res.status_code == 422

    def test_manifest_cost_cap_varsayilani_kabul_edilir(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client, runtime_manifest={"model": "m"})  # cost_cap verilmedi
        assert res.status_code == 202
        assert res.json()["job_id"] == f"job-{int(_SABIT_ZAMAN)}-98f12a"


# ---------------------------------------------------------------------------
# submit — simüle etki-alanı + yanıt gövdesi (D11..D15)
# ---------------------------------------------------------------------------


class TestSubmitSimule:
    @pytest.mark.parametrize("simule_url", [
        "https://agent.acme.ai/v1/act",       # acme.ai altdizgesi
        "https://sandbox.veridrome.internal/v1/act",  # internal altdizgesi
        "https://evil.example/?x=acme.ai",    # B3: altdizge her-yerde geçerli
        "https://host.mock/v1/act",           # mock altdizgesi
    ])
    def test_simule_alan_httpx_cagrilmaz(self, simule_url, monkeypatch):
        # BULGU B3: altdizge eşleşmesi URL'nin neresinde olursa olsun simüle sayar.
        izci = _HttpxIzci()
        monkeypatch.setattr(httpx, "Client", izci)
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client, endpoint_url=simule_url)
        assert res.status_code == 202
        assert izci.cagrilar == []  # gerçek HTTP dalı tetiklenmedi
        assert res.json()["job_id"] == f"job-{int(_SABIT_ZAMAN)}-98f12a"

    @pytest.mark.parametrize("http_disi_url", [
        "ftp://runner.realai.io/act",  # http şeması ile başlamıyor
        "",                             # boş uçnokta
    ])
    def test_http_disi_url_baseline_kullanir(self, http_disi_url, monkeypatch):
        izci = _HttpxIzci()
        monkeypatch.setattr(httpx, "Client", izci)
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client, endpoint_url=http_disi_url)
        assert res.status_code == 202
        assert izci.cagrilar == []  # baseline dalı: çağrı yok
        assert res.json()["job_id"] == f"job-{int(_SABIT_ZAMAN)}-98f12a"

    def test_basarili_kosum_yanit_govdesi_sablonlari(self):
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client)
        assert res.status_code == 202
        govde = res.json()
        assert govde["estimated_duration_sec"] == 300  # sabit (BULGU: görev sayısından bağımsız)
        assert govde["tee_environment"] == "AMD-SEV-SNP"
        assert govde["status"] == "PROCESSING"  # BULGU B1: aşağıda COMPLETED kanıtı

    def test_yanit_processing_derken_kosum_tamamlanmistir(self):
        # BULGU B1: yanıt "PROCESSING" der ama submit SENKRON'dur — akışta
        # hemen JOB_COMPLETED + sertifika görülür.
        client = TestClient(create_app(runner=_hizli_kosucu()))
        job_id = _gonder(client).json()["job_id"]
        res = client.get(f"/v1/evaluations/{job_id}/stream")
        assert res.status_code == 200
        olaylar = _sse_olaylari(res.text)
        tamam = [o for o in olaylar if o["event"] == "JOB_COMPLETED"]
        assert len(tamam) == 1
        assert tamam[0]["is_certified"] is True
        assert client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}").status_code == 200


# ---------------------------------------------------------------------------
# submit — gerçek httpx dalları (D16..D19)
# ---------------------------------------------------------------------------


class TestSubmitHttpxDali:
    def _kur(self, monkeypatch, izci):
        monkeypatch.setattr(httpx, "Client", izci)
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        return TestClient(create_app(runner=_hizli_kosucu()))

    def test_http_200_ajan_verisi_metriclere_yansir(self, monkeypatch):
        izci = _HttpxIzci(cevap_factory=lambda url, govde: _Cevap(200, {
            "passed": True, "latency_sec": 1.5, "cost_usd": 0.02, "actions": ["git", "push"],
        }))
        client = self._kur(monkeypatch, izci)
        res = _gonder(client, endpoint_url="https://agent.realai.io/v1/act")
        assert res.status_code == 202
        job_id = res.json()["job_id"]

        # 2 görev × 2 koşum = 4 çağrı; her çağrı doğru gövdeyle
        assert len(izci.cagrilar) == 4
        url, govde = izci.cagrilar[0]
        assert url == "https://agent.realai.io/v1/act"
        assert govde["task_id"] in ("ST01", "ST02")
        assert "objective" in govde and govde["run_idx"] in (0, 1)
        assert izci.zaman_asimi == 5.0  # sabit zaman-aşımı

        # ajan JSON yanıtı VC metriclerine yansır (bağımsız doğrulama)
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}")
        assert res.status_code == 200
        metrics = res.json()["credentialSubject"]["metrics"]
        assert metrics["costPerTaskUsd"] == 0.02
        assert metrics["p95LatencySec"] == 1.5
        assert metrics["medianSuccess"] == 1.0

    def test_http_200_passed_false_sertifikasiz(self, monkeypatch):
        izci = _HttpxIzci(cevap_factory=lambda url, govde: _Cevap(200, {
            "passed": False, "latency_sec": 1.0, "cost_usd": 0.01, "actions": ["x"],
        }))
        client = self._kur(monkeypatch, izci)
        job_id = _gonder(client, endpoint_url="https://agent.realai.io/v1/act").json()["job_id"]
        # medyan 0.0 < 0.80 → SCORE_INSUFFICIENT → VC yok
        assert client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}").status_code == 404
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        tamam = [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]
        assert tamam["is_certified"] is False

    def test_http_200_degil_http_error_dali(self, monkeypatch):
        # BULGU B8: 503 yanıtı "http_error_503" eylem-dalına düşer — dış-gözlemde
        # connection_error ile aynı sonucu verir (sınıflandırma kaybolur).
        izci = _HttpxIzci(cevap_factory=lambda url, govde: _Cevap(503, {}))
        client = self._kur(monkeypatch, izci)
        job_id = _gonder(client, endpoint_url="https://agent.realai.io/v1/act").json()["job_id"]
        assert len(izci.cagrilar) == 4
        assert client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}").status_code == 404
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        assert [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]["is_certified"] is False

    def test_httpx_istisnasi_connection_error_dali(self, monkeypatch):
        izci = _HttpxIzci(hata=RuntimeError("boom"))
        client = self._kur(monkeypatch, izci)
        job_id = _gonder(client, endpoint_url="https://agent.realai.io/v1/act").json()["job_id"]
        assert len(izci.cagrilar) == 4  # istisna executor içinde yakalanır
        assert client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}").status_code == 404
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        assert [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]["is_certified"] is False


# ---------------------------------------------------------------------------
# submit — job_id dalları (D20..D23)
# ---------------------------------------------------------------------------


class TestSubmitJobId:
    def test_sabit_zaman_deterministik_job_id(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client, agent_id="urn:agent:0x98f12a")
        assert res.json()["job_id"] == f"job-{int(_SABIT_ZAMAN)}-98f12a"

    def test_kisa_agent_id_tamami_sonek_olur(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        res = _gonder(client, agent_id="kisa")
        assert res.json()["job_id"] == f"job-{int(_SABIT_ZAMAN)}-kisa"

    def test_ayni_saniye_ayni_agent_job_id_carpisir(self, monkeypatch):
        # BULGU B5: saniye-çözünürlüklü job_id → aynı saniye + aynı agent
        # AYNI job_id üretir; ikinci submit jobs_db'de birincinin üzerine yazar.
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        ilk = _gonder(client, agent_id="urn:agent:0x98f12a").json()
        ikinci = _gonder(client, agent_id="urn:agent:0x98f12a").json()
        assert ilk["job_id"] == ikinci["job_id"]
        # üzerine-yazma: akış yine tek job için çalışır
        res = client.get(f"/v1/evaluations/{ikinci['job_id']}/stream")
        assert res.status_code == 200
        assert "JOB_COMPLETED" in res.text

    def test_farkli_agent_farkli_job_id(self, monkeypatch):
        monkeypatch.setattr(time, "time", lambda: _SABIT_ZAMAN)
        client = TestClient(create_app(runner=_hizli_kosucu()))
        a = _gonder(client, agent_id="urn:agent:aaaaaa").json()["job_id"]
        b = _gonder(client, agent_id="urn:agent:bbbbbb").json()["job_id"]
        assert a != b


# ---------------------------------------------------------------------------
# stream_evaluation (D24..D30)
# ---------------------------------------------------------------------------


class TestStream:
    def test_bilinmeyen_job_404(self):
        client = TestClient(create_app(runner=_KosucuStub()))
        res = client.get("/v1/evaluations/job-yok/stream")
        assert res.status_code == 404
        assert res.json()["detail"] == "Koşum bulunamadı."

    def test_tam_sse_akisi_sirasi(self):
        stub = _KosucuStub(rapor=_rapor(job_id="job-akisi-1"))
        client = TestClient(create_app(runner=stub))
        job_id = _gonder(client).json()["job_id"]
        res = client.get(f"/v1/evaluations/{job_id}/stream")
        assert res.status_code == 200
        assert "text/event-stream" in res.headers["content-type"]
        olaylar = _sse_olaylari(res.text)
        siralar = [o["event"] for o in olaylar]
        assert siralar[0] == "JOB_STARTED"
        assert siralar[1] == "TEE_ALLOCATED"
        assert siralar[2] == "TASK_EVALUATING"
        assert siralar[-1] == "JOB_COMPLETED"
        # TEE olayı sabit donanım ölçümü taşır
        tee = olaylar[1]
        assert tee["platform"] == "AMD-SEV-SNP"
        assert tee["pcr0"] == "0x98f12a4b8823901234567890abcdef"

    def test_task_evaluating_kumesi_ve_ilerleme(self):
        client = TestClient(create_app(runner=_hizli_kosucu()))
        job_id = _gonder(client).json()["job_id"]
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        gorev_olaylari = [o for o in olaylar if o["event"] == "TASK_EVALUATING"]
        # BULGU B4'in kanıtı: stream kendi TaskRegistry'sini kullanır —
        # koşucunun 2-görevli stub kümesi DEĞİL, her zaman T01..T20 akar.
        assert [o["task_id"] for o in gorev_olaylari] == [f"T{i:02d}" for i in range(1, 21)]
        assert gorev_olaylari[0]["progress"] == "5%"   # int(1/20*100)
        assert gorev_olaylari[-1]["progress"] == "100%"
        assert gorev_olaylari[0]["pool"] == "PUBLIC_CANARY"
        assert gorev_olaylari[1]["pool"] == "DYNAMIC_HIDDEN"
        assert all("title" in o for o in gorev_olaylari)

    def test_stream_kendi_taskregistry_kurar(self):
        # BULGU B4: 2-görevli kayıt-defteriyle koşan değerlendirme — akış
        # yine 20 görev olayı üretir (enjekte edilen küme görmezden gelinir).
        stub = _KosucuStub(rapor=_rapor(job_id="job-ozel-kutuk"))
        client = TestClient(create_app(runner=stub))
        job_id = _gonder(client).json()["job_id"]
        assert len(stub.cagrilar) == 1
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        gorev_olaylari = [o for o in olaylar if o["event"] == "TASK_EVALUATING"]
        assert len(gorev_olaylari) == 20  # 2 değil!

    def test_red_raporu_job_completed_yansir(self):
        rapor = _rapor(job_id="job-red-1", verdict="OVERFIT_REJECT",
                       is_certified=False, vc=None)
        client = TestClient(create_app(runner=_KosucuStub(rapor=rapor)))
        job_id = _gonder(client).json()["job_id"]
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        tamam = [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]
        assert tamam["status"] == "OVERFIT_REJECT"
        assert tamam["is_certified"] is False

    def test_kosucu_istisnasi_rapor_yok_varsayilanlari(self):
        # Koşucu istisna fırlatır → submit 500 ama job QUEUED kalır; akış
        # rapor-yok (None) varsayılanlarını kullanır: PASSED/true/boş merkle.
        stub = _KosucuStub(hata=RuntimeError("koşucu- patladı"))
        client = TestClient(create_app(runner=stub), raise_server_exceptions=False)
        res = _gonder(client)
        assert res.status_code == 500
        job_id = res.json().get("job_id") if res.headers.get("content-type", "").startswith("application/json") else None
        # 500 gövdesi JSON olmayabilir; job_id'yi stub kaydından al
        assert len(stub.cagrilar) == 1
        job_id = stub.cagrilar[0]["job_id"]
        res = client.get(f"/v1/evaluations/{job_id}/stream")
        assert res.status_code == 200
        olaylar = _sse_olaylari(res.text)
        tamam = [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]
        assert tamam["status"] == "PASSED"      # report None → varsayılan
        assert tamam["is_certified"] is True    # report None → varsayılan
        assert tamam["merkle_root"] == ""       # report None → varsayılan
        assert tamam["certificate_id"] == f"urn:veridrome:cert:{job_id}"

    def test_job_completed_merkle_koku_ve_cert_id_rapordan(self):
        kok = "0x" + "ab" * 32
        rapor = _rapor(job_id="job-merkle-1", merkle_root=kok)
        client, job_id, cert_id = _stub_gonder(rapor)
        olaylar = _sse_olaylari(client.get(f"/v1/evaluations/{job_id}/stream").text)
        tamam = [o for o in olaylar if o["event"] == "JOB_COMPLETED"][0]
        assert tamam["merkle_root"] == kok
        # vc kimliği api job-id'sine hizalanır (AT-188 akışı)
        assert tamam["certificate_id"] == cert_id == f"urn:veridrome:cert:{job_id}"


# ---------------------------------------------------------------------------
# get_certificate — GET dalları (D31..D35)
# ---------------------------------------------------------------------------


class TestSertifikaGetir:
    def test_bilinmeyen_sertifika_404(self):
        client = TestClient(create_app(runner=_KosucuStub()))
        res = client.get("/v1/certificates/urn:veridrome:cert:job-yok")
        assert res.status_code == 404
        assert res.json()["detail"] == "Sertifika bulunamadı."

    def test_gecerli_sertifika_vc_birebir_doner(self):
        vc = _fake_vc(job_id="job-vc-1", agent_id="urn:agent:vc")
        rapor = _rapor(job_id="job-vc-1", agent_id="urn:agent:vc", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor, agent_id="urn:agent:vc")
        res = client.get(f"/v1/certificates/{cert_id}")
        assert res.status_code == 200
        beklenen = dict(vc)
        beklenen["id"] = cert_id  # VC kimliği api job-id'sine hizalanır
        assert res.json() == beklenen  # kök-deposuna yazılan VC birebir okunur

    def test_iptal_edilmis_sertifika_410(self):
        vc = _fake_vc(job_id="job-iptal-1")
        rapor = _rapor(job_id="job-iptal-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "güvenlik"})
        res = client.get(f"/v1/certificates/{cert_id}")
        assert res.status_code == 410
        govde = res.json()
        assert govde["status"] == "REVOKED"
        assert govde["reason"] == "güvenlik"

    def test_cok_bolumlu_cert_id_yolu_404(self):
        client = TestClient(create_app(runner=_KosucuStub()))
        res = client.get("/v1/certificates/a/b/c")
        assert res.status_code == 404

    def test_gercek_kosucu_vc_w3c_yapisi(self):
        client = TestClient(create_app(runner=_hizli_kosucu()))
        job_id = _gonder(client).json()["job_id"]
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}")
        assert res.status_code == 200
        vc = res.json()
        assert set(vc) >= {"@context", "id", "type", "issuer", "validFrom",
                           "validUntil", "credentialSubject", "proof"}
        assert vc["id"] == f"urn:veridrome:cert:{job_id}"
        assert vc["issuer"] == "did:veridrome:authority:mainnet"
        assert vc["proof"]["type"] == "Ed25519Signature2020"
        assert "merkleRoot" in vc["credentialSubject"]


# ---------------------------------------------------------------------------
# verify dalı (D36..D41)
# ---------------------------------------------------------------------------


class TestSertifikaDogrula:
    def test_bilinmeyen_dogrulama_404(self):
        client = TestClient(create_app(runner=_KosucuStub()))
        res = client.get("/v1/certificates/urn:veridrome:cert:job-yok/verify")
        assert res.status_code == 404

    def test_gecerli_dogrulama_is_valid_true(self):
        # Varsayılan create_app() yolu: koşucu uygulamanın authority_signer'ını
        # paylaşır → imza-anahtarları tutarlı → is_valid True (BULGU B9'un
        # tek-tutarlı-dalı).
        client = TestClient(create_app())
        job_id = _gonder(client, agent_id="urn:agent:dogrula").json()["job_id"]
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}/verify")
        assert res.status_code == 200
        govde = res.json()
        assert govde["is_valid"] is True
        assert govde["subject"] == "urn:agent:dogrula"
        assert govde["cert_id"] == f"urn:veridrome:cert:{job_id}"
        assert "expires_at" in govde and govde["expires_at"]

    def test_enjekte_kosucu_anahtar_uyumsuzlugu(self):
        # BULGU B9: create_app(runner=...) enjekte edilen koşucu KENDİ
        # VeridromeAuthoritySigner'ıyla imzalar; GET /verify uygulamanın iç
        # imzalayıcısının public-key'ini kullanır → geçerli imzaya rağmen
        # is_valid her zaman False döner (anahtar uyuşmazlığı).
        client = TestClient(create_app(runner=_hizli_kosucu()))
        job_id = _gonder(client).json()["job_id"]
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}")
        assert res.status_code == 200  # sertifika GERÇEK ve yapısal olarak geçerli
        vc = res.json()
        assert "proof" in vc and vc["proof"]["proofValue"]
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{job_id}/verify")
        assert res.status_code == 200
        assert res.json()["is_valid"] is False  # ama imza-anahtarı uyuşmuyor

    def test_iptal_edilmis_dogrulama_false(self):
        client = TestClient(create_app(runner=_hizli_kosucu()))
        job_id = _gonder(client).json()["job_id"]
        cert_id = f"urn:veridrome:cert:{job_id}"
        client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "kötüye-kullanım"})
        res = client.get(f"/v1/certificates/{cert_id}/verify")
        assert res.status_code == 200  # 200 ama içerik red
        govde = res.json()
        assert govde["is_valid"] is False
        assert govde["reason"] == "CERTIFICATE_REVOKED"

    def test_gecersiz_imza_dogrulama_false(self):
        vc = _fake_vc(job_id="job-imza-1")  # imza geçersiz
        rapor = _rapor(job_id="job-imza-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        res = client.get(f"/v1/certificates/{cert_id}/verify")
        assert res.status_code == 200
        assert res.json()["is_valid"] is False  # imza-doğrulaması kırmızı dalı

    def test_proofsuz_vc_dogrulama_false(self):
        vc = _fake_vc(job_id="job-noproof-1")
        del vc["proof"]
        rapor = _rapor(job_id="job-noproof-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        res = client.get(f"/v1/certificates/{cert_id}/verify")
        assert res.status_code == 200
        assert res.json()["is_valid"] is False  # 'proofValue' yok dalı

    def test_eksik_credential_subject_500(self):
        # BULGU B7: GET /verify, VC'de credentialSubject/validUntil yoksa
        # beklenmedik KeyError → 500 (uçnokta VC yapısına duyarlı).
        vc = _fake_vc(job_id="job-eksik-1")
        del vc["credentialSubject"]
        rapor = _rapor(job_id="job-eksik-1", vc=vc)
        stub = _KosucuStub(rapor=rapor)
        client = TestClient(create_app(runner=stub), raise_server_exceptions=False)
        _gonder(client)
        res = client.get(f"/v1/certificates/urn:veridrome:cert:{stub.cagrilar[0]['job_id']}/verify")
        assert res.status_code == 500


# ---------------------------------------------------------------------------
# revoke_certificate (D42..D48)
# ---------------------------------------------------------------------------


class TestSertifikaIptal:
    def test_bilinmeyen_iptal_404(self):
        client = TestClient(create_app(runner=_KosucuStub()))
        res = client.post("/v1/certificates/urn:veridrome:cert:job-yok/revoke",
                          json={"reason": "test"})
        assert res.status_code == 404
        assert res.json()["detail"] == "Sertifika bulunamadı."

    def test_basarili_iptal(self):
        vc = _fake_vc(job_id="job-iptal-ok")
        rapor = _rapor(job_id="job-iptal-ok", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        res = client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "neden-1"})
        assert res.status_code == 200
        govde = res.json()
        assert govde["status"] == "SUCCESS"
        assert govde["cert_id"] == cert_id
        assert govde["is_revoked"] is True

    def test_iptal_sebebi_saklanir(self):
        vc = _fake_vc(job_id="job-sebep-1")
        rapor = _rapor(job_id="job-sebep-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": " Sebep-42 "})
        govde = client.get(f"/v1/certificates/{cert_id}").json()
        assert govde["status"] == "REVOKED"
        assert govde["reason"] == " Sebep-42 "

    def test_iki_kez_iptal_sebep_ustune_yazar(self):
        vc = _fake_vc(job_id="job-iki-1")
        rapor = _rapor(job_id="job-iki-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        ilk = client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "ilk"})
        ikinci = client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "ikinci"})
        assert ilk.status_code == 200 and ikinci.status_code == 200
        assert ikinci.json()["is_revoked"] is True
        govde = client.get(f"/v1/certificates/{cert_id}").json()
        assert govde["reason"] == "ikinci"  # üstüne-yazma

    def test_cift_revoke_yolu_replace_all(self):
        # BULGU B6: target = cert_id.replace("/revoke", "") — SON-EK değil
        # TÜM geçişler soyulur. ".../revoke/revoke" → cert_id "<id>/revoke".
        vc = _fake_vc(job_id="job-cift-1")
        rapor = _rapor(job_id="job-cift-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        res = client.post(f"/v1/certificates/{cert_id}/revoke/revoke", json={"reason": "çift"})
        assert res.status_code == 200
        assert res.json()["cert_id"] == cert_id  # replace-all doğru hedefi buldu

    def test_iptal_sebep_yoksa_422_bos_sebep_200(self):
        vc = _fake_vc(job_id="job-sebep-sinir")
        rapor = _rapor(job_id="job-sebep-sinir", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        # reason alanı zorunlu → istek-gövdesinde yoksa doğrulama hatası
        res = client.post(f"/v1/certificates/{cert_id}/revoke", json={})
        assert res.status_code == 422
        # boş dize kabul edilir (min-uzunluk yok) — sınır dalı
        res = client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": ""})
        assert res.status_code == 200
        assert client.get(f"/v1/certificates/{cert_id}").json()["reason"] == ""

    def test_iptal_sonrasi_get_ve_dogrulama_akisi(self):
        # Uçtan-uca: iptal → GET 410 + verify false (CERTIFICATE_REVOKED).
        vc = _fake_vc(job_id="job-akis-1")
        rapor = _rapor(job_id="job-akis-1", vc=vc)
        client, job_id, cert_id = _stub_gonder(rapor)
        client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "akış-nedeni"})
        assert client.get(f"/v1/certificates/{cert_id}").status_code == 410
        res = client.get(f"/v1/certificates/{cert_id}/verify")
        assert res.json() == {"is_valid": False, "reason": "CERTIFICATE_REVOKED"}
