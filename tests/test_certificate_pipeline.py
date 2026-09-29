"""
Testler: sertifika-ürütm hattının geri-dönüş-korunması ( regression-guards).

AT-189: pytest ``-v`` çıktısındaki BOŞLUKLU parametrize-kimlikleri
( "[hello world]", "[the quick brown fox]") eski ``\\S+::\\S+`` örüntüsüyle
sessizce düşüyordu → sertifika 98 yerine 94 test sayıyordu. Bu test o
sessiz-düşüşü yakalar.

Ayrıca CLI ``verify``'in --ledger verilmediğinde varsayılan iptal-defterine
( VERIDROME_HOME/revocations.jsonl) düşmesini güvenceye-alır — yoksa revoke
edilmiş bir sertifika hâlâ "geçerli" görünürdü.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from veridrome.certificate.pytest_parser import _parse_verbose_stdout


# ---------------------------------------------------------------------------
# AT-189: boşluklu-nodeid'ler yakalanmalı
# ---------------------------------------------------------------------------

_VERBOSE_SAMPLE = """\
tests/test_a.py::test_one PASSED [ 12%]
tests/test_certificate_didkey.py::test_b58_roundtrip[hello world] PASSED [ 38%]
tests/test_certificate_didkey.py::test_b58_roundtrip[the quick brown fox] PASSED [ 51%]
tests/test_certificate_didkey.py::test_sign_verify_roundtrip[a] PASSED [ 52%]

========================= 4 passed in 0.01s =========================
"""


def test_verbose_parser_captures_space_in_nodeids() -> None:
    """Boşluk içeren parametrize-kimlikleri düşürülmemeli ( AT-189)."""
    entries = _parse_verbose_stdout(_VERBOSE_SAMPLE)
    names = [e["name"] for e in entries]
    assert names == [
        "tests/test_a.py::test_one",
        "tests/test_certificate_didkey.py::test_b58_roundtrip[hello world]",
        "tests/test_certificate_didkey.py::test_b58_roundtrip[the quick brown fox]",
        "tests/test_certificate_didkey.py::test_sign_verify_roundtrip[a]",
    ]
    assert all(e["outcome"] == "passed" for e in entries)


def test_verbose_parser_no_false_positives_on_summary_lines() -> None:
    """Özet/ilerleme satırları test olarak sayılmamalı ( yanlış-pozitif-yok)."""
    sample = (
        "========================= 4 passed in 0.01s =========================\n"
        "tests/test_a.py::test_one PASSED [100%]\n"
        "\n"
        "98 tests collected in 2.10s\n"
    )
    entries = _parse_verbose_stdout(sample)
    assert len(entries) == 1
    assert entries[0]["name"] == "tests/test_a.py::test_one"


@pytest.mark.skipif(
    not os.path.isfile(
        os.path.join(os.path.dirname(__file__), "test_certificate_didkey.py")
    ),
    reason="didkey-test-dosyası-bu-koşumda-yok",
)
def test_full_suite_certification_count_matches_collection() -> None:
    """Ayrıştırma, pytest'in toplama-sayısıyla uyuşmalı ( AT-189 gerçek-kanıt).

    Bu test-dosyasını kullanırız çünkü içinde BOŞLUKLU parametrize-kimlikler
    var ( "[hello world]", "[the quick brown fox]") — eski örüntü bunları
    düşürürdü. ``tests/``-tümünü koşmak yerine bu tek-hızlı-dosyayı kullanırız
    ( özyineleme-yok, hızlı).
    """
    from veridrome.certificate.pytest_parser import run_pytest_json

    target = os.path.join(os.path.dirname(__file__), "test_certificate_didkey.py")
    parsed = run_pytest_json([target])
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", target, "--collect-only", "-q", "-o", "addopts="],
        capture_output=True, text=True,
    )
    import re
    m = re.search(r"(\d+) tests? collected", collected.stdout)
    assert m, f"toplama-sayısı-çözülemedi: {collected.stdout[-200:]!r}"
    collected_n = int(m.group(1))
    assert parsed["summary"]["total"] == collected_n, (
        f"ayrıştırma {parsed['summary']['total']} test gördü, "
        f"pytest {collected_n} topladı ( sessiz-düşüş-regresyonu)"
    )


# ---------------------------------------------------------------------------
# CLI verify: varsayılan iptal-defteri ( --ledger yokken)
# ---------------------------------------------------------------------------

def _cli_env(tmp_path):
    env = dict(os.environ)
    env["VERIDROME_HOME"] = str(tmp_path)
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "..", "src")
    return env


def _run_cli(env, *args):
    return subprocess.run(
        [sys.executable, "-m", "veridrome.cli.main", *args],
        capture_output=True, text=True, env=env,
    )


def test_cli_verify_flags_revoked_default_ledger(tmp_path) -> None:
    """revoke varsayılan-deftere yazar; verify --ledger'sız da orayı okumalı."""
    env = _cli_env(tmp_path)

    # sertifika-üret
    results = tmp_path / "results.json"
    results.write_text(json.dumps([
        {"name": "tests/x.py::t1", "outcome": "passed"},
    ]), encoding="utf-8")
    cert = tmp_path / "cert.json"
    r = _run_cli(env, "certify", "--results", str(results),
                 "--commit", "a" * 40, "--out", str(cert))
    assert r.returncode == 0, r.stderr

    # revoke ( varsayılan-deftere yazar)
    r = _run_cli(env, "revoke", str(cert), "--reason", "regression-test")
    assert r.returncode == 0, r.stderr
    assert os.path.isfile(str(tmp_path / "revocations.jsonl"))

    # verify — --ledger VERİLMEDİ → iptal-edilmiş olmalı
    r = _run_cli(env, "verify", str(cert))
    assert r.returncode == 1, r.stdout
    assert "iptal" in r.stdout


def test_cli_verify_clean_when_no_ledger(tmp_path) -> None:
    """İptal-defteri yoksa verify temiz-sertifika için başarılı-olmalı."""
    env = _cli_env(tmp_path)
    results = tmp_path / "results.json"
    results.write_text(json.dumps([
        {"name": "tests/x.py::t1", "outcome": "passed"},
    ]), encoding="utf-8")
    cert = tmp_path / "cert.json"
    r = _run_cli(env, "certify", "--results", str(results),
                 "--commit", "b" * 40, "--out", str(cert))
    assert r.returncode == 0, r.stderr
    assert not os.path.isfile(str(tmp_path / "revocations.jsonl"))

    r = _run_cli(env, "verify", str(cert))
    assert r.returncode == 0, r.stdout
    assert "GEÇERLİ" in r.stdout
