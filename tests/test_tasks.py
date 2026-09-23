import pytest
from veridrome.tasks.models import PoolType, TaskCategory
from veridrome.tasks.registry import TaskRegistry
from veridrome.tasks.fixtures import SAMPLE_DB_SNAPSHOTS


def test_task_registry_has_exact_20_tasks():
    registry = TaskRegistry()
    tasks = registry.list_all()
    assert len(tasks) == 20

    task_ids = [t.task_id for t in tasks]
    expected_ids = [f"T{i:02d}" for i in range(1, 21)]
    assert task_ids == expected_ids


def test_task_registry_pool_distribution():
    registry = TaskRegistry()
    public_tasks = registry.filter_by_pool(PoolType.PUBLIC_CANARY)
    hidden_tasks = registry.filter_by_pool(PoolType.DYNAMIC_HIDDEN)

    assert len(public_tasks) == 12  # %60 Açık Canary
    assert len(hidden_tasks) == 8   # %40 Döner-Gizli


def test_task_registry_categories_coverage():
    registry = TaskRegistry()
    ecom = registry.filter_by_category(TaskCategory.E_COMMERCE)
    saas = registry.filter_by_category(TaskCategory.SAAS_ADMIN)
    finops = registry.filter_by_category(TaskCategory.FINOPS)
    ui = registry.filter_by_category(TaskCategory.MODERN_UI)
    extract = registry.filter_by_category(TaskCategory.DATA_EXTRACTION)

    assert len(ecom) == 4
    assert len(saas) == 5
    assert len(finops) == 4
    assert len(ui) == 3
    assert len(extract) == 4


def test_sample_db_snapshots_cover_db_assert_tasks():
    registry = TaskRegistry()
    for task in registry.list_all():
        for inv in task.invariants:
            if inv.rule_type == "db_assert":
                assert task.task_id in SAMPLE_DB_SNAPSHOTS
                assert inv.selector in SAMPLE_DB_SNAPSHOTS[task.task_id]
                assert SAMPLE_DB_SNAPSHOTS[task.task_id][inv.selector] == inv.expected_db_value
