import pytest
from veridrome.core.crypto import MerkleTreeAuditLog
from veridrome.telemetry.otel_tracer import VeridromeOTelTracer


def test_otel_tracer_records_genai_spans():
    tracer = VeridromeOTelTracer(service_name="veridrome-test-agent")

    rec1 = tracer.record_agent_llm_step(
        step_name="step_01_reasoning",
        system="claude",
        model="claude-3-5-sonnet-20241022",
        prompt_tokens=450,
        completion_tokens=85,
        latency_ms=1250.0,
        extra_attributes={"task.id": "T01"},
    )

    rec2 = tracer.record_agent_llm_step(
        step_name="step_02_action",
        system="claude",
        model="claude-3-5-sonnet-20241022",
        prompt_tokens=520,
        completion_tokens=32,
        latency_ms=850.0,
    )

    records = tracer.get_all_records()
    assert len(records) == 2
    assert records[0].prompt_tokens == 450
    assert records[1].name == "step_02_action"

    # Canonical bytes ile Merkle Tree oluşturma
    tree = MerkleTreeAuditLog()
    leaf1 = tree.add_leaf(rec1.to_canonical_json_bytes())
    leaf2 = tree.add_leaf(rec2.to_canonical_json_bytes())

    assert len(leaf1) == 32
    assert len(leaf2) == 32
    root = tree.get_root()
    assert len(root) == 32
