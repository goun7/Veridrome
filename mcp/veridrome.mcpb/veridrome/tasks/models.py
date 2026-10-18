"""
Veridrome Tasks: Pydantic Veri Modelleri (Python 3.12+)
Görev şartnameleri, ortam tanımları ve değişmezlik kuralları.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class PoolType(str, Enum):
    PUBLIC_CANARY = "PUBLIC_CANARY"
    DYNAMIC_HIDDEN = "DYNAMIC_HIDDEN"


class TaskCategory(str, Enum):
    E_COMMERCE = "e_commerce"
    SAAS_ADMIN = "saas_admin"
    FINOPS = "finops"
    MODERN_UI = "modern_ui"
    DATA_EXTRACTION = "data_extraction"


class InvariantSpec(BaseModel):
    rule_type: str
    selector: Optional[str] = None
    expected_regex: Optional[str] = None
    must_exist: bool = True
    status_code: Optional[int] = None
    expected_db_value: Any = None
    expected_file_hash: Optional[str] = None
    expected_file_path: Optional[str] = None


class EnvironmentSpec(BaseModel):
    target_url: str
    auth_required: bool = False
    synthetic_dom_mutation: bool = True
    preserve_aria_semantics: bool = True


class TaskSpec(BaseModel):
    task_id: str
    title: str
    category: TaskCategory
    pool_type: PoolType
    timeout_seconds: int = 180
    max_browser_steps: int = 25
    cost_cap_usd: float = 0.50
    objective: str
    environment: EnvironmentSpec
    invariants: List[InvariantSpec]
