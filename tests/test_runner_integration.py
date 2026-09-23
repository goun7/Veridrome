import json
import pytest
from veridrome.core.crypto import VeridromeAuthoritySigner
from veridrome.runner import EvaluationRunner


def test_runner_honest_agent_certification_flow():
    signer = VeridromeAuthoritySigner()
    runner = EvaluationRunner(authority_signer=signer)

    def honest_agent_executor(task, r_idx):
        # %95 başarı, düşük varyans
        return True, 10.0 + (r_idx * 0.2), 0.04, ["click", "type", "submit"]

    report = runner.run_evaluation(
        agent_id="urn:kredent:agent:test-honest",
        task_executor_fn=honest_agent_executor,
        runs_per_task=2,
    )

    assert report.is_certified is True
    assert report.rejection_reason is None
    assert report.median_success_rate == 1.0
    assert report.anti_gaming.verdict == "PASSED"
    assert report.certificate_token is not None
    assert report.verifiable_credential is not None

    # W3C VC çevrimdışı kriptografik doğrulaması
    vc = report.verifiable_credential
    proof = vc["proof"]
    sig_b64 = proof["proofValue"]

    vc_copy = dict(vc)
    del vc_copy["proof"]
    canonical_bytes = json.dumps(vc_copy, sort_keys=True).encode("utf-8")

    import base64
    sig_bytes = base64.b64decode(sig_b64)
    is_valid = VeridromeAuthoritySigner.verify(signer.public_key_bytes, canonical_bytes, sig_bytes)
    assert is_valid is True


def test_runner_overfit_agent_rejection():
    runner = EvaluationRunner()

    def overfit_agent_executor(task, r_idx):
        is_public = (task.pool_type.value == "PUBLIC_CANARY")
        if is_public:
            return True, 8.0, 0.02, ["click", "type"]
        else:
            return False, 25.0, 0.35, ["random_search", "retry_loop", "fail"]

    report = runner.run_evaluation(
        agent_id="urn:kredent:agent:test-overfit",
        task_executor_fn=overfit_agent_executor,
        runs_per_task=2,
    )

    assert report.is_certified is False
    assert "ANTI_GAMING_OVERFIT_REJECT" in str(report.rejection_reason)
    assert report.certificate_token is None
