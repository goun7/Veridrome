"""
Veridrome Telemetry: OpenTelemetry GenAI Semantic Conventions Tracer (Python 3.12+)
Ajanın LLM çağrılarını, token maliyetlerini ve araç adımlarını
OpenTelemetry standartlarına (gen_ai.*) uygun olarak kaydeder ve Merkle yaprağı üretir.
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


@dataclass
class GenAISpanRecord:
    span_id: str
    trace_id: str
    name: str
    system: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_canonical_json_bytes(self) -> bytes:
        data = {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "name": self.name,
            "system": self.system,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms": self.latency_ms,
            "attributes": self.attributes,
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")


class VeridromeOTelTracer:
    """
    OpenTelemetry v1.28 GenAI semantiğiyle uyumlu izleme motoru.
    """

    def __init__(self, service_name: str = "veridrome-agent-runner"):
        self.service_name = service_name
        self.provider = TracerProvider()
        self.memory_exporter = InMemorySpanExporter()
        self.provider.add_span_processor(SimpleSpanProcessor(self.memory_exporter))
        self.tracer = self.provider.get_tracer(self.service_name)
        self.records: List[GenAISpanRecord] = []

    def record_agent_llm_step(
        self,
        step_name: str,
        system: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        extra_attributes: Optional[Dict[str, Any]] = None,
    ) -> GenAISpanRecord:
        """Bir LLM token ve model akıl yürütme adımını OTel span olarak kaydeder."""
        attrs = {
            "gen_ai.system": system,
            "gen_ai.request.model": model,
            "gen_ai.usage.input_tokens": prompt_tokens,
            "gen_ai.usage.output_tokens": completion_tokens,
        }
        if extra_attributes:
            attrs.update(extra_attributes)

        with self.tracer.start_as_current_span(step_name, attributes=attrs) as span:
            ctx = span.get_span_context()
            span_id = f"{ctx.span_id:016x}"
            trace_id = f"{ctx.trace_id:032x}"

            record = GenAISpanRecord(
                span_id=span_id,
                trace_id=trace_id,
                name=step_name,
                system=system,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency_ms=latency_ms,
                attributes=attrs,
            )
            self.records.append(record)
            return record

    def clear(self) -> None:
        self.memory_exporter.clear()
        self.records.clear()

    def get_all_records(self) -> List[GenAISpanRecord]:
        return list(self.records)
