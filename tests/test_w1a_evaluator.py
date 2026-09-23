import asyncio
import os
import tempfile
import hashlib
from veridrome.core.w1a_evaluator import InvariantRule, W1aEvaluator


def test_w1a_evaluator_network_and_db_assertions():
    captured_requests = [
        {"url": "https://sandbox.veridrome.internal/api/checkout/confirm", "status": 200},
        {"url": "https://sandbox.veridrome.internal/api/analytics", "status": 204},
    ]
    db_snapshot = {
        "cart.items[0].sku": "ALT-92",
        "cart.total": 74.50,
    }

    evaluator = W1aEvaluator(
        page=None,
        captured_requests=captured_requests,
        db_snapshot=db_snapshot,
    )

    rules = [
        InvariantRule(rule_type="network_assert", selector="/api/checkout/confirm", status_code=200),
        InvariantRule(rule_type="db_assert", selector="cart.items[0].sku", expected_db_value="ALT-92"),
    ]

    passed, msg, results = asyncio.run(evaluator.evaluate_invariants(rules))
    assert passed is True
    assert msg == "W1A_ALL_INVARIANTS_SATISFIED"
    assert len(results) == 2


def test_w1a_evaluator_network_assertion_failure():
    captured_requests = [
        {"url": "https://sandbox.veridrome.internal/api/checkout/confirm", "status": 500},
    ]

    evaluator = W1aEvaluator(captured_requests=captured_requests)
    rules = [
        InvariantRule(rule_type="network_assert", selector="/api/checkout/confirm", status_code=200),
    ]

    passed, msg, _ = asyncio.run(evaluator.evaluate_invariants(rules))
    assert passed is False
    assert "Beklenen HTTP isteği yakalanamadı" in msg


def test_w1a_evaluator_file_assertion():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"VERIDROME_EXPORT_CSV_DATA_ROW_1")
        tmp_path = tmp.name

    try:
        expected_hash = hashlib.sha256(b"VERIDROME_EXPORT_CSV_DATA_ROW_1").hexdigest()
        evaluator = W1aEvaluator()
        rules = [
            InvariantRule(
                rule_type="file_assert",
                expected_file_path=tmp_path,
                expected_file_hash=expected_hash,
            )
        ]
        passed, msg, _ = asyncio.run(evaluator.evaluate_invariants(rules))
        assert passed is True
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
