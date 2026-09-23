import os
import pytest
from bs4 import BeautifulSoup
from veridrome.core.dom_mutator import SyntheticDOMMutator
from veridrome.tasks.fixtures import SAMPLE_ECOM_CART_HTML


def test_dom_mutator_initialization_seed_validation():
    with pytest.raises(ValueError, match="en az 16 baytlık"):
        SyntheticDOMMutator(b"too_short")

    valid_seed = os.urandom(16)
    mutator = SyntheticDOMMutator(valid_seed)
    assert mutator.secret_seed == valid_seed


def test_dom_mutator_scrambles_ids_and_classes():
    seed = b"test_seed_12345678"
    mutator = SyntheticDOMMutator(seed)
    mutated_html = mutator.mutate_html(SAMPLE_ECOM_CART_HTML)

    soup = BeautifulSoup(mutated_html, "html.parser")

    # Orijinal ID'ler bulunmamalı
    assert soup.find(id="cart-container") is None
    assert soup.find(id="cart-total-amount") is None

    # Mutasyona uğramış ID'ler prefix taşımalı
    id_map = mutator.get_id_mapping()
    assert "cart-container" in id_map
    assert id_map["cart-container"].startswith("vrm_cart_")

    # WAI-ARIA etiketleri ve roller korunmalı
    btn = soup.find("button", {"role": "button"})
    assert btn is not None
    assert btn.get("role") == "button"


def test_dom_mutator_deterministic_under_same_seed():
    seed = b"identical_seed_1234"
    mutator1 = SyntheticDOMMutator(seed)
    mutator2 = SyntheticDOMMutator(seed)

    h1 = mutator1.mutate_html(SAMPLE_ECOM_CART_HTML)
    h2 = mutator2.mutate_html(SAMPLE_ECOM_CART_HTML)
    assert h1 == h2
