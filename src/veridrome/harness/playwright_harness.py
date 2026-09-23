"""
Veridrome Harness: Canlı Playwright Tarayıcı Doğrulama Motoru (Python 3.12+)
Headless Chromium oturumu açarak web sitelerinde ajan eylemlerini yürütür,
ağ trafiğini yakalar ve W1a makine assert kontrollerini uygular.
"""

from __future__ import annotations
import asyncio
from typing import Any, Callable, Dict, List, Optional, Tuple
from playwright.async_api import Page, async_playwright, Response

from veridrome.core.dom_mutator import SyntheticDOMMutator
from veridrome.core.w1a_evaluator import InvariantRule, W1aEvaluator
from veridrome.tasks.models import TaskSpec


class PlaywrightHarness:
    """Canlı Playwright tarayıcı oturum orkestratörü."""

    def __init__(self, headless: bool = True, dom_mutator: Optional[SyntheticDOMMutator] = None):
        self.headless = headless
        self.dom_mutator = dom_mutator

    async def execute_task_flow(
        self,
        task: TaskSpec,
        base_url: str,
        agent_actions_fn: Callable[[Page], Any],
        db_snapshot: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, float, List[Dict[str, Any]]]:
        """
        Görevi canlı tarayıcıda koşturur ve W1a değişmezlerini doğrular.
        (GeçtiMi, Mesaj, SüreSaniye, Ağİstekleri) döndürür.
        """
        captured_requests: List[Dict[str, Any]] = []
        target_path = task.environment.target_url.replace("https://sandbox.veridrome.internal", "")
        full_target_url = f"{base_url.rstrip('/')}/{target_path.lstrip('/')}"

        start_time = asyncio.get_event_loop().time()

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(viewport={"width": 1280, "height": 720})

            page = await context.new_page()

            # Ağ isteklerini ve durum kodlarını dinle
            async def handle_response(response: Response):
                captured_requests.append({
                    "url": response.url,
                    "status": response.status,
                    "method": response.request.method,
                })

            page.on("response", handle_response)

            # Sayfaya git
            await page.goto(full_target_url, wait_until="networkidle")

            # Eğer sentetik DOM mutasyonu aktifse, sayfadaki HTML'i dönüştür
            if task.environment.synthetic_dom_mutation and self.dom_mutator:
                raw_html = await page.content()
                mutated_html = self.dom_mutator.mutate_html(raw_html)
                await page.set_content(mutated_html)

            # Ajan eylemlerini icra et
            try:
                await agent_actions_fn(page)
            except Exception as e:
                await browser.close()
                elapsed = asyncio.get_event_loop().time() - start_time
                return False, f"Ajan eylem hatası: {str(e)}", elapsed, captured_requests

            # W1a Invariant kurallarını hazırla
            rules = [
                InvariantRule(
                    rule_type=inv.rule_type,
                    selector=inv.selector,
                    expected_regex=inv.expected_regex,
                    must_exist=inv.must_exist,
                    status_code=inv.status_code,
                    expected_db_value=inv.expected_db_value,
                )
                for inv in task.invariants
            ]

            # Invariant kontrolünü icra et
            evaluator = W1aEvaluator(
                page=page,
                captured_requests=captured_requests,
                db_snapshot=db_snapshot,
            )
            passed, msg, _ = await evaluator.evaluate_invariants(rules)

            elapsed = asyncio.get_event_loop().time() - start_time
            await browser.close()
            return passed, msg, elapsed, captured_requests
