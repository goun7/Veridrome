"""
test_runner_dallar.py — Dal-kesen (branch-coverage) testler: src/veridrome/runner.py

Hedeflenen public yüzey (73-Veridrome/veridrome):
  * EvaluationRunner.__init__        — imzalayıcı/kütük varsayılanları
  * EvaluationRunner.run_evaluation  — n-koşum orkestrasyonu, anti-gaming,
    TEE tasdiki, istatistiksel özet, Merkle-dahil-kanıtı ve sertifika kararı
  * AgentRunResult / EvaluationReport — veri-modelleri (dataclass)
  * generate_challenge_nonce (runner aduzayında yeniden-ihrac)

DAL HARİTASI (D1..D34):
  __init__:
    D1  authority_signer verilmezse varsayılan VeridromeAuthoritySigner üretilir
    D2  verilen authority_signer birebir kullanılır (nesne-kimliği)
    D3  task_registry verilmezse varsayılan TaskRegistry (20 görev) kurulur
    D4  verilen task_registry kullanılır (toplam görev sayısı stub'a bağlı)
    D5  _at168_first_leaf başlangıçta None'dır
  run_evaluation — kimlik/koşum:
    D6  job_id verilmezse "job-<zaman>-<agent_id[-6:]>" üretilir
    D7  job_id verilirse birebir kullanılır ve VC "id" alanına yansır
    D8  her görev runs_per_task kez koşturulur (çağrım sayısı = görev*koşum)
    D9  başarısız koşum 0.0 skoruna çevrilir (AgentRunResult.passed=False)
  run_evaluation — havuz ayrımı:
    D10 PUBLIC_CANARY görevlerin gecikme/eylemleri pub_* listelerine gider
    D11 DYNAMIC_HIDDEN görevlerin gecikme/eylemleri priv_* listelerine gider
  run_evaluation — TEE:
    D12 tee_payload None → SIMULATED tasdik (geçer, pcr0 boş)
    D13 tee_payload {} (boş-dict sınırı) → yine SIMULATED dal
    D14 tee_payload + geçerli SEV-SNP ölçümü → gerçek tasdik doğrulaması
    D15 tee_payload + hatalı ölçüm → TEE_FAIL ret nedeni
    D16 tee_payload + bilinmeyen platform → "Desteklenmeyen" TEE_FAIL
    D17 ret-önceliği: TEE_FAIL, ANTI_GAMING'den önce gelir
  run_evaluation — anti-gaming:
    D18 overfit profil → "ANTI_GAMING_OVERFIT_REJECT" ret
    D19 sandbagging (yavaş-ama-başarılı) → "ANTI_GAMING_SANDBAGGING_ALERT" ret
  run_evaluation — sertifika kararı:
    D20 median < 0.80 → "SCORE_INSUFFICIENT" ret
    D21 median tam 0.80 (>= sınırı) → sertifikalandırılır
    D22 tam başarı → is_certified + certificate_token + VC üretilir
    D23 red durumunda certificate_token ve verifiable_credential None kalır
    D24 certified VC W3C yapısal alanlarını taşır (@context/type/issuer...)
  run_evaluation — istatistik:
    D25 boş kütük → median/iqr/mean/p95 = 0.0 (boş-liste sınır dalları)
    D26 tek görev → iqr else-dalı (len<=1) → 0.0
    D27 iki farklı-skorelu görev → percentile dalı → iqr > 0
  run_evaluation — Merkle:
    D28 VC merkleInclusionProof leafIndex=0 + leafData + path taşır ve
        verify_proof ile kök BAĞIMSIZ yeniden hesaplanır (AT-168)
    D29 generate_proof istisnası → fail-safe: kanıt None, yine certified
    D30 _at168_first_leaf koşum sonrası None'a sıfırlanır; 2. koşumda doluşur
    D31 AgentRunResult.trace_leaf, iz-verisinin RFC-6962 yaprak-hash'ine eşit
    D32 merkle_root_hex "0x"ön-ekli 66-hex'tir
  veri-modelleri:
    D33 AgentRunResult / EvaluationReport alan atama/okuma ve eşitlik
    D34 generate_challenge_nonce uzunluk parametresi ve rastgelelik

KURAL: SADECE YENI DOSYA; production/conftest/mevcut-testlere DOKUNULMAZ.
Tüm koşumlar SAF-BELLEK'tir — ağ/RPC/subprocess/socket yok; TEE nonce'leri
monkeypatch ile sabitlenir, kayıt defterleri stub'lanır.
"""

from __future__ import annotations

import hashlib
import json

import pytest

import veridrome.runner as runner_mod
from veridrome.core.anti_gaming import AntiGamingMetrics
from veridrome.core.crypto import MerkleTreeAuditLog
from veridrome.runner import AgentRunResult, EvaluationReport, EvaluationRunner
from veridrome.tasks.models import (
    EnvironmentSpec,
    InvariantSpec,
    PoolType,
    TaskCategory,
    TaskSpec,
)

_SABIT_NONCE = bytes(range(32))  # TEE testsinde determinantik meydan-okuması


def _sonuc_gozlemcisi(monkeypatch):
    """run_evaluation içinde kurulan AgentRunResult örneklerini yakalayan gözlemci.

    run_evaluation sonuç listesini dışarı vermez; bu yüzden sınıf, kayıt-eden
    bir alt-sınıfla değiştirilir (SAF-BELLEK, üretim-koduna DOKUNMAZ).
    """
    yakalanan: list[AgentRunResult] = []
    asil = runner_mod.AgentRunResult

    class _Gozlemci(asil):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            yakalanan.append(self)

    monkeypatch.setattr(runner_mod, "AgentRunResult", _Gozlemci)
    return yakalanan


# ---------------------------------------------------------------------------
# Yardımcılar — SAF-BELLEK kayıt-defteri stub'ları ve koşum-proflleri
# ---------------------------------------------------------------------------


class _KutukStub:
    """EvaluationRunner'ın sadece list_all() çağırdığı kayıt-defteri stub'ı."""

    def __init__(self, tasks):
        self._tasks = list(tasks)

    def list_all(self):
        return list(self._tasks)


def _gorev(task_id: str, pool_type: PoolType) -> TaskSpec:
    """Minimal geçerli TaskSpec (havuz tipi dışında tüm alanlar sabit)."""
    return TaskSpec(
        task_id=task_id,
        title=f"Stub-Görev {task_id}",
        category=TaskCategory.E_COMMERCE,
        pool_type=pool_type,
        objective="Stub hedefi",
        environment=EnvironmentSpec(target_url="https://stub.veridrome.internal/x"),
        invariants=[InvariantSpec(rule_type="dom_selector_text", selector="#s")],
    )


def _dürüst_isleyici(task, run_idx):
    """Başarılı, düşük-maliyet, düşük-gecikme deterministik koşum profili."""
    return True, 10.0 + (run_idx * 0.2), 0.04, ["click", "type", "submit"]


def _hatakli_isleyici(task, run_idx):
    """Tüm koşumlar başarısız — SCORE_INSUFFICIENT için."""
    return False, 10.0, 0.04, ["click", "type", "submit"]


class TestEvaluationRunnerBaslatma:
    """EvaluationRunner.__init__ dalları: D1-D5."""

    def test_varsayilan_imzalayici_uretilir(self):
        """D1: authority_signer=None → yeni VeridromeAuthoritySigner."""
        runner = EvaluationRunner()
        assert runner.signer is not None
        # Ed25519 açık-anahtar 32 bayttır (gerçek kriptografi, bellek-içi)
        assert len(runner.signer.public_key_bytes) == 32

    def test_verilen_imzalayici_kullanilir(self):
        """D2: verilen signer nesnesi birebir tutulur (kimlik karşılaştırması)."""
        from veridrome.core.crypto import VeridromeAuthoritySigner

        signer = VeridromeAuthoritySigner()
        runner = EvaluationRunner(authority_signer=signer)
        assert runner.signer is signer

    def test_varsayilan_kutuk_yirmi_gorev_icerir(self):
        """D3: task_registry=None → 20 görevli gerçek TaskRegistry."""
        runner = EvaluationRunner()
        assert len(runner.registry.list_all()) == 20

    def test_verilen_kutuk_kullanilir(self):
        """D4: verilen stub registry kullanılır → total_tasks stub'a bağlı."""
        stub = _KutukStub([_gorev("S1", PoolType.PUBLIC_CANARY)])
        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:stub", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        assert rapor.total_tasks == 1

    def test_ilk_yaprak_baslangicta_none(self):
        """D5: _at168_first_leaf başlangıçta None (AT-168 koruması)."""
        runner = EvaluationRunner()
        assert runner._at168_first_leaf is None


class TestRunEvaluationKimlik:
    """run_evaluation kimlik/koşum dalları: D6-D9."""

    def test_job_id_verilmezse_zaman_tabanli_uretilir(self):
        """D6: job_id None → 'job-<int>-<agent_id[-6:]>' biçiminde üretilir."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:abcdef123456",
            task_executor_fn=_hatakli_isleyici,
            runs_per_task=1,
        )
        assert rapor.job_id.startswith("job-")
        assert rapor.job_id.endswith("-123456")
        zaman_kismi = rapor.job_id[len("job-"):].rsplit("-", 1)[0]
        assert zaman_kismi.isdigit()

    def test_acik_job_id_birebir_kullanilir(self):
        """D7: verilen job_id değiştirilmez ve VC id alanına yansır."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:tail6",
            task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
            job_id="job-test-42",
        )
        assert rapor.job_id == "job-test-42"
        assert rapor.verifiable_credential["id"] == "urn:veridrome:cert:job-test-42"

    @pytest.mark.parametrize("runs_per_task,beklenen_cagri", [(1, 20), (2, 40), (3, 60)])
    def test_her_gorev_n_kez_kosturulur(self, runs_per_task, beklenen_cagri):
        """D8:executor her görevde runs_per_task kez çağrılır (20 görev)."""
        runner = EvaluationRunner()
        cagrilar = []

        def isleyici(task, run_idx):
            cagrilar.append((task.task_id, run_idx))
            return _dürüst_isleyici(task, run_idx)

        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:n-kez", task_executor_fn=isleyici,
            runs_per_task=runs_per_task,
        )
        assert len(cagrilar) == beklenen_cagri
        # Her görevin koşum-indeksleri 0..n-1 aralıksızdır
        for task_id in {t for t, _ in cagrilar}:
            idxler = sorted(r for t, r in cagrilar if t == task_id)
            assert idxler == list(range(runs_per_task))
        assert rapor.runs_per_task == runs_per_task

    def test_basarisiz_kosum_sifir_skora_cevrilir(self, monkeypatch):
        """D9: passed=False → AgentRunResult.passed False, görev skoru 0.0."""
        sonuclar = _sonuc_gozlemcisi(monkeypatch)
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:sifir", task_executor_fn=_hatakli_isleyici,
            runs_per_task=1,
        )
        assert len(sonuclar) == 20
        assert all(s.passed is False for s in sonuclar)
        assert rapor.median_success_rate == 0.0
        assert rapor.rejection_reason is not None
        assert "SCORE_INSUFFICIENT" in rapor.rejection_reason


class TestRunEvaluationHavuzAyrımı:
    """run_evaluation havuz (public/private) ayrımı dalları: D10-D11."""

    def test_havuz_gorevleri_pub_ve_priv_listelerine_ayrilir(self):
        """D10+D11: PUBLIC_CANARY → pub_*, DYNAMIC_HIDDEN → priv_* toplanır.

        Anti-gaming motoruna giden eylem/gecikme listeleri havuz bazında
        ayrılır; bu, her iki dalın da işlendiğini ürettiği çıktıyla kanıtlar.
        """
        stub = _KutukStub([
            _gorev("PUB1", PoolType.PUBLIC_CANARY),
            _gorev("PUB2", PoolType.PUBLIC_CANARY),
            _gorev("PRV1", PoolType.DYNAMIC_HIDDEN),
            _gorev("PRV2", PoolType.DYNAMIC_HIDDEN),
        ])
        havuz_cagrimalari = {"PUB": 0, "PRV": 0}

        def isleyici(task, run_idx):
            if task.pool_type == PoolType.PUBLIC_CANARY:
                havuz_cagrimalari["PUB"] += 1
            else:
                havuz_cagrimalari["PRV"] += 1
            return _dürüst_isleyici(task, run_idx)

        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:havuz", task_executor_fn=isleyici,
            runs_per_task=2,
        )
        # 2 pub görev × 2 koşum = 4 pub çağrı; aynı şekilde 4 priv çağrı
        assert havuz_cagrimalari == {"PUB": 4, "PRV": 4}
        # Tüm görevler başarılı olduğu için median 1.0 → sertifikalı
        assert rapor.is_certified is True
        assert rapor.median_success_rate == 1.0

    def test_havuz_bilgisi_karar_verilerine_yansir(self):
        """D10/D11 provin latens farklılaşması sandbagging tespit eder.

        Pub görevlerde hızlı, gizli görevlerde çok-yavaş (ama başarılı) bir
        koşum, priv_* gecikme listesinin büyümesiyle SANDBAGGING_ALERT verir.
        """
        priv_gorev = _gorev("PRV", PoolType.DYNAMIC_HIDDEN)
        pub_gorev = _gorev("PUB", PoolType.PUBLIC_CANARY)
        stub = _KutukStub([pub_gorev] * 4 + [priv_gorev] * 4)

        def isleyici(task, run_idx):
            if task.pool_type == PoolType.PUBLIC_CANARY:
                return True, 10.0, 0.04, ["click", "type", "submit"]
            return True, 55.0 + run_idx, 0.04, ["click", "type", "submit"]

        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:yavas-ama-dogru", task_executor_fn=isleyici,
            runs_per_task=3,
        )
        assert rapor.anti_gaming.verdict == "SANDBAGGING_ALERT"
        assert rapor.rejection_reason == "ANTI_GAMING_SANDBAGGING_ALERT"
        assert rapor.is_certified is False


class TestRunEvaluationTee:
    """run_evaluation TEE donanım-tasdiki dalları: D12-D17."""

    def test_tee_payload_yoksa_simulated_mod(self):
        """D12: tee_payload=None → SIMULATED tasdik (geçer, donanımsız)."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:sim", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        assert rapor.tee_valid is True
        tee = rapor.verifiable_credential["credentialSubject"]["teeAttestation"]
        assert tee["platform"] == "SIMULATED"
        assert tee["pcr0"] == ""

    def test_bos_dict_payload_simulated_moda_duser(self):
        """D13: tee_payload={} (boş-dict sınırı) → yine SIMULATED dal."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:sim2", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1, tee_payload={},
        )
        assert rapor.tee_valid is True
        assert rapor.is_certified is True

    def test_gecerli_sev_snp_tasdiki_kabul_edilir(self, monkeypatch):
        """D14: gerçek SEV-SNP doğrulaması — nonce monkeypatch ile sabit."""
        monkeypatch.setattr(
            runner_mod, "generate_challenge_nonce", lambda length=32: _SABIT_NONCE
        )
        pcr0 = "ab" * 16  # 32-hex ölçüm
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:hw", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1, tee_platform="AMD-SEV-SNP",
            tee_payload={"measurement": pcr0, "host_data": _SABIT_NONCE.hex()},
            expected_pcr0=pcr0,
        )
        assert rapor.tee_valid is True
        assert rapor.is_certified is True
        tee = rapor.verifiable_credential["credentialSubject"]["teeAttestation"]
        assert tee["platform"] == "AMD-SEV-SNP"
        assert tee["pcr0"] == pcr0

    def test_hatali_olcum_tee_fail_ile_reddedilir(self, monkeypatch):
        """D15: measurement eşleşmezse → 'TEE_FAIL: PCR0 veya Nonce Uyuşmazlığı'."""
        monkeypatch.setattr(
            runner_mod, "generate_challenge_nonce", lambda length=32: _SABIT_NONCE
        )
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:bad-pcr", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1, tee_platform="AMD-SEV-SNP",
            tee_payload={"measurement": "ff" * 16, "host_data": _SABIT_NONCE.hex()},
            expected_pcr0="ab" * 16,
        )
        assert rapor.tee_valid is False
        assert rapor.is_certified is False
        assert rapor.rejection_reason is not None
        assert rapor.rejection_reason.startswith("TEE_FAIL:")
        assert "PCR0 veya Nonce Uyuşmazlığı" in rapor.rejection_reason

    def test_bilinmeyen_platform_tee_fail_verir(self):
        """D16: desteklenmeyen platform → 'Desteklenmeyen TEE platformu'."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:unknown-tee", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1, tee_platform="GPU-TEE",
            tee_payload={"measurement": "ab" * 16, "host_data": "00" * 32},
            expected_pcr0="ab" * 16,
        )
        assert rapor.tee_valid is False
        assert "Desteklenmeyen TEE platformu" in (rapor.rejection_reason or "")

    def test_tee_fail_anti_gamingden_once_gelir(self):
        """D17: hem TEE geçersiz hem overfit → ret nedeni TEE_FAIL (öncelik)."""
        runner = EvaluationRunner()

        def overfit_isleyici(task, run_idx):
            if task.pool_type == PoolType.PUBLIC_CANARY:
                return True, 8.0, 0.02, ["click", "type"]
            return False, 25.0, 0.35, ["random_search", "retry_loop", "fail"]

        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:cift-hata", task_executor_fn=overfit_isleyici,
            runs_per_task=2, tee_platform="GPU-TEE",
            tee_payload={"measurement": "ff" * 16},
        )
        assert rapor.rejection_reason is not None
        assert rapor.rejection_reason.startswith("TEE_FAIL:")
        # overfit de tetiklenmiş olmalı ama red açıklamasında öncelik TEE'dir
        assert rapor.anti_gaming.verdict == "OVERFIT_REJECT"


class TestRunEvaluationAntiGaming:
    """run_evaluation anti-gaming karar dalları: D18-D19."""

    def test_overfit_profil_reddedilir(self):
        """D18: public'te-başarılı/gizlide-başarısız → OVERFIT_REJECT."""
        runner = EvaluationRunner()

        def overfit_isleyici(task, run_idx):
            if task.pool_type == PoolType.PUBLIC_CANARY:
                return True, 8.0, 0.02, ["click", "type"]
            return False, 25.0, 0.35, ["random_search", "retry_loop", "fail"]

        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:overfit-dal", task_executor_fn=overfit_isleyici,
            runs_per_task=2,
        )
        assert rapor.anti_gaming.verdict == "OVERFIT_REJECT"
        assert rapor.rejection_reason == "ANTI_GAMING_OVERFIT_REJECT"
        assert rapor.is_certified is False

    def test_dürüst_profil_anti_gaming_gecer(self):
        """D19 (başarı-dalı): tüm havuzlarda başarılı → verdict PASSED."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:honest-dal", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        assert rapor.anti_gaming.verdict == "PASSED"
        assert rapor.anti_gaming.is_overfit is False


class TestRunEvaluationSertifikaKarari:
    """run_evaluation sertifika kararı dalları: D20-D24."""

    def test_dusuk_median_score_insufficient_ile_reddedilir(self):
        """D20: median 0.0 < 0.80 → SCORE_INSUFFICIENT (verdict PASSED iken)."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:dusuk", task_executor_fn=_hatakli_isleyici,
            runs_per_task=1,
        )
        assert rapor.anti_gaming.verdict == "PASSED"
        assert rapor.rejection_reason is not None
        assert rapor.rejection_reason.startswith("SCORE_INSUFFICIENT")
        assert rapor.is_certified is False

    def test_median_tam_0_80_siniri_gecer(self):
        """D21: median tam 0.80 → '>= 0.80' sınır-koşulu sertifikalar (5 koşumda 4/5)."""
        stub = _KutukStub([
            _gorev("E1", PoolType.PUBLIC_CANARY),
            _gorev("E2", PoolType.PUBLIC_CANARY),
        ])

        def dort_bes_isleyici(task, run_idx):
            # 5 koşumun 4'ü başarılı → görev skoru tam 0.80
            return run_idx < 4, 10.0, 0.04, ["click", "type", "submit"]

        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:sirp", task_executor_fn=dort_bes_isleyici,
            runs_per_task=5,
        )
        assert rapor.median_success_rate == 0.8
        assert rapor.is_certified is True
        assert rapor.rejection_reason is None

    def test_tam_basari_sertifika_ve_token_uretir(self):
        """D22: tam başarı → is_certified + token + VC üçlüğü üretilir."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:full", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        assert rapor.is_certified is True
        assert rapor.certificate_token is not None
        assert rapor.verifiable_credential is not None
        # token, VC proof-value ile aynı imzadır
        assert rapor.verifiable_credential["proof"]["proofValue"] == rapor.certificate_token

    def test_red_halinde_token_ve_vc_yoktur(self):
        """D23: red → certificate_token=None, verifiable_credential=None."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:red", task_executor_fn=_hatakli_isleyici,
            runs_per_task=1,
        )
        assert rapor.certificate_token is None
        assert rapor.verifiable_credential is None

    def test_certified_vc_w3c_yapisini_tasir(self):
        """D24: üretilen VC W3C yapısal alanlarını veüretilen metrikleri taşır."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:w3c", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1, job_id="job-w3c-1",
        )
        vc = rapor.verifiable_credential
        assert "https://www.w3.org/ns/credentials/v2" in vc["@context"]
        assert "VerifiableCredential" in vc["type"]
        assert vc["issuer"] == "did:veridrome:authority:mainnet"
        assert vc["validFrom"] and vc["validUntil"]
        konu = vc["credentialSubject"]
        assert konu["id"] == "urn:kredent:agent:w3c"
        assert konu["metrics"]["medianSuccess"] == 1.0
        assert konu["merkleRoot"] == rapor.merkle_root


class TestRunEvaluationIstatistik:
    """run_evaluation istatistiksel-özет dalları: D25-D27."""

    def test_bos_kutuk_tum_sifir_istatistik(self):
        """D25: boş kayıt-defteri → median/iqr/mean/p95 = 0.0 ve SCORE red."""
        stub = _KutukStub([])
        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:bos", task_executor_fn=_dürüst_isleyici,
            runs_per_task=3,
        )
        assert rapor.total_tasks == 0
        assert rapor.median_success_rate == 0.0
        assert rapor.iqr_success_rate == 0.0
        assert rapor.mean_cost_per_task == 0.0
        assert rapor.p95_latency_sec == 0.0
        assert rapor.rejection_reason is not None
        assert "SCORE_INSUFFICIENT" in rapor.rejection_reason

    def test_tek_gorev_iqr_else_dalina_duser(self):
        """D26: tek görevli kütük → len(scores)<=1 → iqr else-dalı 0.0."""
        stub = _KutukStub([_gorev("TEK", PoolType.PUBLIC_CANARY)])
        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:tek", task_executor_fn=_dürüst_isleyici,
            runs_per_task=2,
        )
        assert rapor.iqr_success_rate == 0.0

    def test_iki_farkli_skor_percentile_dali_hesaplanir(self):
        """D27: farklı skorlu iki görev → percentile dalı → iqr > 0 (0.5)."""
        stub = _KutukStub([
            _gorev("A", PoolType.PUBLIC_CANARY),
            _gorev("B", PoolType.DYNAMIC_HIDDEN),
        ])

        def karisik_isleyici(task, run_idx):
            if task.task_id == "A":
                return True, 10.0, 0.04, ["click", "type", "submit"]
            return False, 10.0, 0.04, ["click", "type", "submit"]

        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:percentil", task_executor_fn=karisik_isleyici,
            runs_per_task=2,
        )
        # [1.0, 0.0] → q75=0.75, q25=0.25 → iqr 0.5
        assert rapor.iqr_success_rate == 0.5
        assert rapor.median_success_rate == 0.5


class TestRunEvaluationMerkleKanit:
    """run_evaluation Merkle-dahil-kanıtı (AT-168) dalları: D28-D32."""

    def test_vc_merkle_kaniti_bagimsiz_dogrulanir(self):
        """D28: leafIndex=0 + leafData + path → verify_proof kökü yeniden hesaplar."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:kanit", task_executor_fn=_dürüst_isleyici,
            runs_per_task=2,
        )
        kanit = rapor.verifiable_credential["credentialSubject"]["merkleInclusionProof"]
        assert kanit is not None
        assert kanit["leafIndex"] == 0

        # leafData, ilk izin JSON metnidir (task_id/run/passed/lat/cost/actions)
        ilk_iz = json.loads(kanit["leafData"])
        assert ilk_iz["task_id"] == "T01"
        assert ilk_iz["run"] == 0
        assert ilk_iz["passed"] is True

        # RFC-6962 denetim-yolu ile kök BAĞIMSIZ olarak yeniden hesaplanır
        yol = [(adim["side"], bytes.fromhex(adim["hash"][2:])) for adim in kanit["path"]]
        yaprak_verisi = kanit["leafData"].encode("utf-8")
        beklenen_kok = bytes.fromhex(rapor.merkle_root[2:])
        assert MerkleTreeAuditLog.verify_proof(yaprak_verisi, yol, beklenen_kok) is True

    def test_generate_proof_istisnasi_fail_safe(self, monkeypatch):
        """D29: generate_proof istisna atarsa kanıt None olur ama sertifika verilir."""
        def _patlatan_proof(self, index):
            raise RuntimeError("bilinçli-test-hatası")

        monkeypatch.setattr(MerkleTreeAuditLog, "generate_proof", _patlatan_proof)
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:fail-safe", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        # fail-safe: kanıt üretilmez → alan None; sertifika yine geçerli
        assert rapor.is_certified is True
        assert rapor.verifiable_credential["credentialSubject"]["merkleInclusionProof"] is None

    def test_ilk_yaprak_kosum_sonrasi_sifirlanir(self):
        """D30: _at168_first_leaf koşum sonrası None; 2. koşumda yeniden dolar."""
        runner = EvaluationRunner()
        runner.run_evaluation(
            agent_id="urn:kredent:agent:reset", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        assert runner._at168_first_leaf is None
        rapor2 = runner.run_evaluation(
            agent_id="urn:kredent:agent:reset2", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        kanit = rapor2.verifiable_credential["credentialSubject"]["merkleInclusionProof"]
        assert kanit is not None and kanit["leafData"] is not None

    def test_trace_leaf_rfc6962_yaprak_hashine_esit(self, monkeypatch):
        """D31: AgentRunResult.trace_leaf = SHA256(0x00 || iz-JSON) (RFC-6962)."""
        sonuclar = _sonuc_gozlemcisi(monkeypatch)
        stub = _KutukStub([_gorev("T1", PoolType.PUBLIC_CANARY)])

        def isleyici(task, run_idx):
            return True, 12.5, 0.05, ["click"]

        runner = EvaluationRunner(task_registry=stub)
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:leaf", task_executor_fn=isleyici,
            runs_per_task=1,
        )
        beklenen_iz = json.dumps({
            "task_id": "T1", "run": 0, "passed": True,
            "lat": 12.5, "cost": 0.05, "actions": ["click"],
        }).encode("utf-8")
        beklenen_hash = hashlib.sha256(b"\x00" + beklenen_iz).digest()
        assert len(sonuclar) == 1
        assert sonuclar[0].trace_leaf == beklenen_hash
        # yaprak aynı zamanda imzalı Merkle kökünü oluşturan hash'tir
        assert sonuclar[0].trace_leaf == MerkleTreeAuditLog.hash_leaf(beklenen_iz)
        assert rapor.merkle_root == "0x" + beklenen_hash.hex()

    def test_merkle_kok_hex_formati(self):
        """D32: merkle_root_hex '0x' ön-ekli 64-hex (toplam 66 karakter)."""
        runner = EvaluationRunner()
        rapor = runner.run_evaluation(
            agent_id="urn:kredent:agent:kok", task_executor_fn=_dürüst_isleyici,
            runs_per_task=1,
        )
        kok = rapor.merkle_root
        assert kok.startswith("0x")
        assert len(kok) == 66
        int(kok[2:], 16)  # geçerli hex olmalı


class TestVeriModelleri:
    """AgentRunResult / EvaluationReport veri-modeli dalları: D33."""

    def test_agent_run_result_alanlari(self):
        """D33 (a): AgentRunResult alan atama/okuma ve eşitlik."""
        sonuc = AgentRunResult(
            task_id="T9", run_index=2, passed=False, latency_sec=3.5,
            cost_usd=0.12, actions=["a", "b"], trace_leaf=b"\x01" * 32,
        )
        assert sonuc.task_id == "T9"
        assert sonuc.run_index == 2
        assert sonuc.passed is False
        assert sonuc.latency_sec == 3.5
        assert sonuc.cost_usd == 0.12
        assert sonuc.actions == ["a", "b"]
        assert sonuc.trace_leaf == b"\x01" * 32
        # dataclass __eq__: aynı alanlar → eşit
        diger = AgentRunResult("T9", 2, False, 3.5, 0.12, ["a", "b"], b"\x01" * 32)
        assert sonuc == diger

    def test_evaluation_report_alanlari(self):
        """D33 (b): EvaluationReport alan atama/okuma; Optional alanlar None."""
        ag = AntiGamingMetrics(
            d_ks=0.0, p_ks=1.0, rho_spearman=1.0, p_spearman=0.0,
            delta_entropy=0.0, jsd=0.0, anomaly_score=0.0,
            is_overfit=False, is_sandbagging=False, verdict="PASSED",
        )
        rapor = EvaluationReport(
            job_id="job-x", agent_id="urn:kredent:agent:dm", timestamp="2026-01-01T00:00:00+00:00",
            total_tasks=1, runs_per_task=1, median_success_rate=1.0,
            iqr_success_rate=0.0, mean_cost_per_task=0.04, p95_latency_sec=10.0,
            anti_gaming=ag, tee_valid=True, merkle_root="0x" + "ab" * 32,
            is_certified=False, rejection_reason=None,
            certificate_token=None, verifiable_credential=None,
        )
        assert rapor.job_id == "job-x"
        assert rapor.rejection_reason is None
        assert rapor.certificate_token is None
        assert rapor.verifiable_credential is None
        assert rapor.merkle_root == "0x" + "ab" * 32
        assert rapor.timestamp == "2026-01-01T00:00:00+00:00"


class TestChallengeNonce:
    """generate_challenge_nonce (runner aduzayı) dalları: D34."""

    @pytest.mark.parametrize("uzunluk", [8, 16, 32, 64])
    def test_nonce_uzunluk_parametresi(self, uzunluk):
        """D34 (a): istenen uzunlukta rastgele nonce üretilir."""
        nonce = runner_mod.generate_challenge_nonce(uzunluk)
        assert isinstance(nonce, bytes)
        assert len(nonce) == uzunluk

    def test_nonce_varsayilan_uzunluk_32(self):
        """D34 (b): varsayılan uzunluk 32 bayttır."""
        assert len(runner_mod.generate_challenge_nonce()) == 32

    def test_nonce_cagrimlar_arasinda_farklidir(self):
        """D34 (c): art arda üretilen nonce'ler birbirinden farklıdır."""
        ornekler = {runner_mod.generate_challenge_nonce(32) for _ in range(64)}
        assert len(ornekler) > 50  # rastgelelik (os.urandom) yüksek-olasılıkla
