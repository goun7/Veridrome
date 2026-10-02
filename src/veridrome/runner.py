"""
Veridrome Runner & Orchestrator (Python 3.12+)
Ajan değerlendirme koşumunu yönetir: n=3 medyan/IQR, Triangulation Canary,
Anti-Gaming anomali denetimi ve kriptografik sertifika üretimi.
"""

from __future__ import annotations
import datetime
from dataclasses import dataclass, field
import json
import time
from typing import Any, Callable, Dict, List, Optional
import numpy as np

from veridrome.core.anti_gaming import AntiGamingEngine, AntiGamingMetrics
from veridrome.core.crypto import MerkleTreeAuditLog, VeridromeAuthoritySigner, generate_challenge_nonce
from veridrome.core.tee_attestation import TEEAttestationVerifier, AttestationResult
from veridrome.tasks.models import PoolType, TaskSpec
from veridrome.tasks.registry import TaskRegistry


@dataclass
class AgentRunResult:
    task_id: str
    run_index: int
    passed: bool
    latency_sec: float
    cost_usd: float
    actions: List[str]
    trace_leaf: bytes


@dataclass
class EvaluationReport:
    job_id: str
    agent_id: str
    timestamp: str
    total_tasks: int
    runs_per_task: int
    median_success_rate: float
    iqr_success_rate: float
    mean_cost_per_task: float
    p95_latency_sec: float
    anti_gaming: AntiGamingMetrics
    tee_valid: bool
    merkle_root: str
    is_certified: bool
    rejection_reason: Optional[str]
    certificate_token: Optional[str]
    verifiable_credential: Optional[Dict[str, Any]]


class EvaluationRunner:
    """Veridrome ana orkestrasyon motoru."""

    def __init__(
        self,
        authority_signer: Optional[VeridromeAuthoritySigner] = None,
        task_registry: Optional[TaskRegistry] = None,
    ):
        self.signer = authority_signer or VeridromeAuthoritySigner()
        self.registry = task_registry or TaskRegistry()
        # AT-168: ilk-audit-yaprağının-ham-baytları ( Merkle-dahil-kanıtı-için).
        # run_evaluation-içinde-set-edilir; burada-başlatılır-ki-hasattr-
        # kontrolü-her-yinelemede-çalışmasın.
        self._at168_first_leaf: Optional[bytes] = None

    def run_evaluation(
        self,
        agent_id: str,
        task_executor_fn: Callable[[TaskSpec, int], Tuple[bool, float, float, List[str]]],
        tee_platform: str = "AMD-SEV-SNP",
        tee_payload: Optional[Dict[str, Any]] = None,
        expected_pcr0: str = "0x98f12a4b8823901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        runs_per_task: int = 3,
        job_id: Optional[str] = None,
    ) -> EvaluationReport:
        """
        Tüm görevleri n tekrar ile koşar ve nihai rapor ile sertifikayı üretir.

        job_id açık-olarak-verilebilir ( çağıran-api-belirler). Verilmezse-zaman-
        tabanlı-üretilir. AT-188-düzeltmesi: job_id-merkezi-olarak-belirlenmezse
        saniye-sınırı-aşımında-çağıran-ve-koşucu-farklı-job_id-üretir, sertifika
        beklenenden-farklı-bir-anahtar-altına-yazılır-ve-404-döner ( yarış-koşulu).
        """
        if not job_id:
            job_id = f"job-{int(time.time())}-{agent_id[-6:]}"
        challenge_nonce = generate_challenge_nonce(32)
        tasks = self.registry.list_all()

        merkle_tree = MerkleTreeAuditLog()
        results: List[AgentRunResult] = []

        pub_scores: List[float] = []
        priv_scores: List[float] = []
        pub_actions: List[str] = []
        priv_actions: List[str] = []
        pub_latencies: List[float] = []
        priv_latencies: List[float] = []

        # Her görevi n kez koştur
        for task in tasks:
            task_run_passes = []
            for r_idx in range(runs_per_task):
                passed, lat, cost, actions = task_executor_fn(task, r_idx)
                task_run_passes.append(1.0 if passed else 0.0)

                trace_data = json.dumps({
                    "task_id": task.task_id,
                    "run": r_idx,
                    "passed": passed,
                    "lat": lat,
                    "cost": cost,
                    "actions": actions,
                }).encode("utf-8")

                leaf = merkle_tree.add_leaf(trace_data)

                # AT-168: İLK-yaprak-verisini-birebir-sakla ( baytları-sonradan-
                # yeniden-kurmak-JSON-serileştirmesinde-ayrışır; ham-bayt-zorunlu).
                if self._at168_first_leaf is None:
                    self._at168_first_leaf = trace_data

                results.append(AgentRunResult(
                    task_id=task.task_id,
                    run_index=r_idx,
                    passed=passed,
                    latency_sec=lat,
                    cost_usd=cost,
                    actions=actions,
                    trace_leaf=leaf,
                ))

                if task.pool_type == PoolType.PUBLIC_CANARY:
                    pub_latencies.append(lat)
                    pub_actions.extend(actions)
                else:
                    priv_latencies.append(lat)
                    priv_actions.extend(actions)

            avg_score = float(np.mean(task_run_passes))
            if task.pool_type == PoolType.PUBLIC_CANARY:
                pub_scores.append(avg_score)
            else:
                priv_scores.append(avg_score)

        # Anti-gaming analizi
        ag_metrics = AntiGamingEngine.evaluate(
            public_scores=pub_scores,
            private_scores=priv_scores,
            public_actions=pub_actions,
            private_actions=priv_actions,
            public_latencies=pub_latencies,
            private_latencies=priv_latencies,
        )

        # TEE Donanım Tasdiki
        # [Fix-2026-10-02] Eksik payload onceki kodda BEKLENEN degerlerle
        # dolduruluyordu (self-fulfilling attestation): verify_attestation
        # olusturulan olcumu beklenen pcr0 ile karsilastirip her seferinde
        # geciyordu ve rapor sahte bir 'dogrulanmis olcum' tasimisti.
        # Donanimsiz prototip akisini korumak icin simulasyonu ACIKCA
        # etiketle: dogrulama gecer ama platform SIMULATED'dir, pcr0 bos
        # kalir ve sertifika hardware-attested DEGILDIR.
        if not tee_payload:
            tee_res = AttestationResult(
                is_valid=True,
                platform="SIMULATED",
                pcr0="",
                nonce_matched=False,
                message="Donanimsal TEE kaniti saglanmadi — SIMULATED mod; sertifika hardware-attested DEGIL",
                claims={},
            )
        else:
            tee_res = TEEAttestationVerifier.verify_attestation(
                platform=tee_platform,
                attestation_payload=tee_payload,
                expected_pcr0=expected_pcr0,
                expected_nonce=challenge_nonce,
            )

        # İstatistiksel özetler
        all_task_scores = pub_scores + priv_scores
        median_score = float(np.median(all_task_scores)) if all_task_scores else 0.0
        q75, q25 = np.percentile(all_task_scores, [75, 25]) if len(all_task_scores) > 1 else (0.0, 0.0)
        iqr_score = float(q75 - q25)

        all_costs = [r.cost_usd for r in results]
        all_latencies = [r.latency_sec for r in results]
        mean_cost = float(np.mean(all_costs)) if all_costs else 0.0
        p95_latency = float(np.percentile(all_latencies, 95)) if all_latencies else 0.0

        merkle_root_hex = merkle_tree.get_root_hex()

        # AT-168-BULGU-1-düzeltmesi ( additive): VC-artık-bağımsız-doğrulanabilir
        # bir Merkle-dahil-kanıtı-taşır. Önceden-merkleRoot-SADECE-yazdırılıp
        # imza-doğrulaması-yapılıyordu ( sahte-kök-geçiyordu). İlk-yaprağın-
        # verisi-ve-audit-path'ı-VC'ye-gömülür; doğrulayıcı-verify_proof-ile-
        # kökü-BAĞIMSIZ-yeniden-hesaplar ( RFC-6962).
        merkle_proof_leaf = None
        merkle_proof_path = None
        try:
            if results and self._at168_first_leaf is not None:
                merkle_proof_leaf = self._at168_first_leaf
                _path = merkle_tree.generate_proof(0)
                merkle_proof_path = [
                    {"side": side, "hash": "0x" + h.hex()}
                    for side, h in _path
                ]
        except Exception:
            merkle_proof_path = None   # kanıt-üretilmezse-alan-yok ( fail-safe)
        self._at168_first_leaf = None   # bir-sonraki-koşu-için-sıfırla

        # Sertifika Kararı
        is_certified = (
            tee_res.is_valid
            and ag_metrics.verdict == "PASSED"
            and median_score >= 0.80
        )

        rejection_reason = None
        if not tee_res.is_valid:
            rejection_reason = f"TEE_FAIL: {tee_res.message}"
        elif ag_metrics.verdict != "PASSED":
            rejection_reason = f"ANTI_GAMING_{ag_metrics.verdict}"
        elif median_score < 0.80:
            rejection_reason = f"SCORE_INSUFFICIENT (Median: {median_score} < 0.80)"

        cert_token = None
        vc_payload = None

        if is_certified:
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            expires_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat()

            vc_payload = {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://w3id.org/security/suites/ed25519-2020/v1",
                    "https://schema.veridrome.io/v1",
                ],
                "id": f"urn:veridrome:cert:{job_id}",
                "type": ["VerifiableCredential", "VeridromeAgentCertification"],
                "issuer": "did:veridrome:authority:mainnet",
                "validFrom": now_iso,
                "validUntil": expires_iso,
                "credentialSubject": {
                    "id": agent_id,
                    "metrics": {
                        "medianSuccess": round(median_score, 4),
                        "iqr": round(iqr_score, 4),
                        "costPerTaskUsd": round(mean_cost, 4),
                        "p95LatencySec": round(p95_latency, 2),
                        "anomalyScore": ag_metrics.anomaly_score,
                    },
                    "teeAttestation": {
                        "platform": tee_res.platform,
                        "pcr0": tee_res.pcr0,
                    },
                    "merkleRoot": merkle_root_hex,
                    "merkleInclusionProof": {
                        "leafIndex": 0,
                        "leafData": merkle_proof_leaf.decode("utf-8")
                                    if merkle_proof_leaf else None,
                        "path": merkle_proof_path,
                    } if merkle_proof_path else None,
                },
            }

            canonical_vc_bytes = json.dumps(vc_payload, sort_keys=True).encode("utf-8")
            signature_b64 = self.signer.sign_base64(canonical_vc_bytes)
            vc_payload["proof"] = {
                "type": "Ed25519Signature2020",
                "created": now_iso,
                "verificationMethod": "did:veridrome:authority:mainnet#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": signature_b64,
            }
            cert_token = signature_b64

        return EvaluationReport(
            job_id=job_id,
            agent_id=agent_id,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_tasks=len(tasks),
            runs_per_task=runs_per_task,
            median_success_rate=round(median_score, 4),
            iqr_success_rate=round(iqr_score, 4),
            mean_cost_per_task=round(mean_cost, 4),
            p95_latency_sec=round(p95_latency, 2),
            anti_gaming=ag_metrics,
            tee_valid=tee_res.is_valid,
            merkle_root=merkle_root_hex,
            is_certified=is_certified,
            rejection_reason=rejection_reason,
            certificate_token=cert_token,
            verifiable_credential=vc_payload,
        )
