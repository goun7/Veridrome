import asyncio
import pytest
from veridrome.harness.playwright_harness import PlaywrightHarness
from veridrome.server.sandbox_app import SandboxServer
from veridrome.tasks.registry import TaskRegistry


def test_live_playwright_browser_e2e_task_execution():
    server = SandboxServer(host="127.0.0.1", port=0)
    base_url = server.start()

    try:
        registry = TaskRegistry()
        task_t01 = registry.get("T01")
        assert task_t01 is not None

        harness = PlaywrightHarness(headless=True)

        async def agent_workflow(page):
            # Ajan kuponu uygular ve doğrular
            await page.fill("#coupon-input", "SPRING26")
            await page.click("#apply-coupon-btn")
            # POST isteği tetiklensin diye ödeme butonuna basar
            await page.evaluate("fetch('/api/checkout/confirm', {method: 'POST'})")

        passed, msg, elapsed, requests = asyncio.run(
            harness.execute_task_flow(
                task=task_t01,
                base_url=base_url,
                agent_actions_fn=agent_workflow,
            )
        )

        assert passed is True
        assert msg == "W1A_ALL_INVARIANTS_SATISFIED"
        assert elapsed > 0.0
        assert any("/api/checkout/confirm" in r["url"] and r["status"] == 200 for r in requests)

    finally:
        server.stop()
