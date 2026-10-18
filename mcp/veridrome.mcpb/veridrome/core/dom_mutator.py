"""
Veridrome Core: Sentetik DOM Mutasyon Motoru (Python 3.12+)
HTML ağacının CSS class ve ID tanımlarını HMAC ile dönüştürürken,
WAI-ARIA erişilebilirlik özniteliklerini koruyarak modellerin
statik XPath/ID ezberlemesini imkansız kılar.
"""

from __future__ import annotations
import hashlib
import hmac
from typing import Dict, List, Set
from bs4 import BeautifulSoup, Tag


class SyntheticDOMMutator:
    """
    DOM ağacını sözde-rastgele (HMAC) dönüştürücü.
    Statik ezberi imkansız kılar, ancak WAI-ARIA erişilebilirlik ağacını korur.
    """

    PRESERVED_ATTRIBUTES: Set[str] = {
        "role",
        "type",
        "name",
        "placeholder",
        "value",
        "href",
        "src",
        "action",
        "method",
        "tabindex",
        "aria-label",
        "aria-labelledby",
        "aria-describedby",
        "aria-hidden",
        "aria-expanded",
        "aria-checked",
        "aria-disabled",
        "aria-required",
        "aria-selected",
    }

    def __init__(self, secret_seed: bytes):
        if not secret_seed or len(secret_seed) < 16:
            raise ValueError("Seed en az 16 baytlık kriptografik entropi içermelidir.")
        self.secret_seed = secret_seed
        self._id_cache: Dict[str, str] = {}
        self._class_cache: Dict[str, str] = {}

    def _hash_identifier(self, identifier: str, cache: Dict[str, str], prefix_type: str) -> str:
        if identifier in cache:
            return cache[identifier]
        h = hmac.new(self.secret_seed, identifier.encode("utf-8"), hashlib.sha256).hexdigest()[:10]
        prefix = "".join(c for c in identifier[:4] if c.isalnum()) or prefix_type
        mutated = f"vrm_{prefix}_{h}"
        cache[identifier] = mutated
        return mutated

    def mutate_id(self, original_id: str) -> str:
        return self._hash_identifier(original_id, self._id_cache, "id")

    def mutate_class(self, original_class: str) -> str:
        return self._hash_identifier(original_class, self._class_cache, "cls")

    def mutate_html(self, html_content: str) -> str:
        """HTML içeriğini mutasyona uğratıp string olarak döndürür."""
        soup = BeautifulSoup(html_content, "html.parser")
        for tag in soup.find_all(True):
            if not isinstance(tag, Tag):
                continue

            # ID mutasyonu
            if tag.get("id"):
                tag["id"] = self.mutate_id(str(tag["id"]))

            # Class listesi mutasyonu
            if tag.get("class"):
                current_classes = tag["class"] if isinstance(tag["class"], list) else [str(tag["class"])]
                tag["class"] = [self.mutate_class(str(c)) for c in current_classes]

            # data-testid ve benzeri test özniteliklerinin mutasyonu
            for attr in list(tag.attrs.keys()):
                if attr.startswith("data-test") or attr.startswith("data-cy") or attr.startswith("data-qa"):
                    tag[attr] = self._hash_identifier(str(tag[attr]), self._id_cache, "test")

        return str(soup)

    def get_id_mapping(self) -> Dict[str, str]:
        """Eski ID -> Yeni ID haritasını döndürür."""
        return dict(self._id_cache)

    def get_class_mapping(self) -> Dict[str, str]:
        """Eski Class -> Yeni Class haritasını döndürür."""
        return dict(self._class_cache)
