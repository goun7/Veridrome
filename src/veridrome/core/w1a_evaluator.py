"""
Veridrome Core: W1a Deterministik Makine Assert Motoru (Python 3.12+)
Hakem LLM kullanmaksızın DOM, Ağ (HTTP), Veritabanı ve Dosya Invariant'larını doğrular.
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class InvariantRule:
    """Tekil bir W1a değişmezlik kuralı."""
    rule_type: str  # 'dom_selector_text' | 'dom_element_state' | 'network_assert' | 'db_assert' | 'file_assert'
    selector: Optional[str] = None
    expected_regex: Optional[str] = None
    must_exist: bool = True
    status_code: Optional[int] = None
    expected_db_value: Any = None
    expected_file_hash: Optional[str] = None
    expected_file_path: Optional[str] = None


class W1aEvaluator:
    """
    Deterministik makine assert motoru.
    Görevin tamamlanıp tamamlanmadığını matematiksel ve fiziksel ortam durumuyla denetler.
    """

    def __init__(
        self,
        page: Any = None,
        captured_requests: Optional[List[Dict[str, Any]]] = None,
        db_snapshot: Optional[Dict[str, Any]] = None,
    ):
        self.page = page
        self.captured_requests = captured_requests or []
        self.db_snapshot = db_snapshot or {}

    async def evaluate_invariants(self, rules: List[InvariantRule]) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Verilen tüm kuralları sırayla doğrular.
        (GeçtiMi, Mesaj, KuralSonuçlarıListesi) döndürür.
        """
        rule_results: List[Dict[str, Any]] = []

        for idx, rule in enumerate(rules):
            passed = False
            message = ""

            if rule.rule_type == "dom_selector_text":
                passed, message = await self._assert_dom_text(rule, idx)

            elif rule.rule_type == "dom_element_state":
                passed, message = await self._assert_dom_element(rule, idx)

            elif rule.rule_type == "network_assert":
                passed, message = self._assert_network(rule, idx)

            elif rule.rule_type == "db_assert":
                passed, message = self._assert_db(rule, idx)

            elif rule.rule_type == "file_assert":
                passed, message = self._assert_file(rule, idx)

            else:
                passed, message = False, f"Bilinmeyen kural türü: {rule.rule_type}"

            rule_results.append({
                "rule_index": idx,
                "rule_type": rule.rule_type,
                "passed": passed,
                "message": message,
            })

            if not passed:
                return False, f"Rule #{idx} ({rule.rule_type}) Başarısız: {message}", rule_results

        return True, "W1A_ALL_INVARIANTS_SATISFIED", rule_results

    async def _assert_dom_text(self, rule: InvariantRule, idx: int) -> Tuple[bool, str]:
        if not rule.selector or not rule.expected_regex:
            return False, f"Eksik selector veya regex ({rule.selector}, {rule.expected_regex})"

        if self.page is None:
            return False, "Playwright Page nesnesi mevcut değil."

        element = await self.page.query_selector(rule.selector)
        if not element:
            return False, f"DOM Element bulunamadı: '{rule.selector}'"

        text = (await element.inner_text()).strip()
        if not re.search(rule.expected_regex, text):
            return False, f"Metin uyuşmazlığı: Beklenen regex r'{rule.expected_regex}', Gelen: '{text}'"

        return True, "OK"

    async def _assert_dom_element(self, rule: InvariantRule, idx: int) -> Tuple[bool, str]:
        if not rule.selector:
            return False, "Eksik selector."

        if self.page is None:
            return False, "Playwright Page nesnesi mevcut değil."

        element = await self.page.query_selector(rule.selector)
        exists = element is not None
        if exists != rule.must_exist:
            return False, f"Element varlık durumu ihlali: '{rule.selector}' (Beklenen: {rule.must_exist}, Gelen: {exists})"

        return True, "OK"

    def _assert_network(self, rule: InvariantRule, idx: int) -> Tuple[bool, str]:
        if not rule.selector or rule.status_code is None:
            return False, "Eksik ağ kural parametresi."

        matched = any(
            req.get("status") == rule.status_code and rule.selector in req.get("url", "")
            for req in self.captured_requests
        )
        if not matched:
            return False, f"Beklenen HTTP isteği yakalanamadı: '{rule.selector}' -> {rule.status_code}"

        return True, "OK"

    def _assert_db(self, rule: InvariantRule, idx: int) -> Tuple[bool, str]:
        if not rule.selector:
            return False, "Eksik DB anahtar seçicisi."

        actual_val = self.db_snapshot.get(rule.selector)
        if actual_val != rule.expected_db_value:
            return False, f"DB durumu uyuşmuyor: '{rule.selector}' == {actual_val} (Beklenen: {rule.expected_db_value})"

        return True, "OK"

    def _assert_file(self, rule: InvariantRule, idx: int) -> Tuple[bool, str]:
        if not rule.expected_file_path:
            return False, "Eksik dosya yolu."

        if not os.path.exists(rule.expected_file_path):
            return False, f"Beklenen dosya mevcut değil: {rule.expected_file_path}"

        if rule.expected_file_hash:
            with open(rule.expected_file_path, "rb") as f:
                content = f.read()
                actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != rule.expected_file_hash:
                return False, f"Dosya SHA256 uyuşmazlığı: Gelen: {actual_hash} (Beklenen: {rule.expected_file_hash})"

        return True, "OK"
