"""
Veridrome — pytest test-sonucu okuyucu.

pytest'in JSON rapor formatını ( pytest-json-report / ``--report-json``)
Veridrome sertifika-çekirdeğinin kabul ettiği normalize forma çevirir.

Ayrıca ``--collect-only`` çıktısından veya CLI ``--tb`` çıktısından DA
değil — yalnızca yapısal JSON girdi. Belirsiz girdi için fail-closed.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from veridrome.certificate.core import normalize_results, summarize


def parse_pytest_json(path: str) -> Dict[str, Any]:
    """Bir pytest-json-report dosyasını okur ve normalize eder.

    pytest-json-report yapısı ( özet):
      {
        "created": ..., "duration": ..., "summary": {"passed": N, ...},
        "tests": [
          {"nodeid": "tests/x.py::test_a", "outcome": "passed",
           "duration": 0.12, "call": {"duration": 0.11, "outcome": "passed"}},
          ...
        ]
      }

    Bu fonksiyon, her test için {name, outcome, duration_ms} üretir.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"pytest JSON raporu bulunamadı: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"pytest JSON raporu geçersiz JSON: {path} — {exc}") from exc

    entries = normalize_results(data)
    summary = summarize(entries)
    return {
        "entries": entries,
        "summary": summary,
        "source": path,
        "raw_summary": data.get("summary") if isinstance(data, dict) else None,
    }


def run_pytest_json(
    args: Optional[List[str]] = None,
    pytest_cmd: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """pytest'i çalıştırır, JSON rapor üretir ve normalize eder.

    ``pytest_cmd`` verilmezse ``[sys.executable, "-m", "pytest"]`` kullanılır.

    JSON üretimi için sıralama şudur:
      1. ``pytest-json-report`` eklentisi kuruluysa ``--report-json`` kullanılır.
      2. Değilse, pytest'in ``-v`` satırlarından toplanan sonuçlarla
         standart ``--json`` yokluğunda bile bir JSON raporu inşa edilir.

    Bu, "gerçek-kullanımda-çalışsın" ilkesidir: ekstra-kurulum-talep-etme.
    """
    import os
    import tempfile

    cmd = list(pytest_cmd or [sys.executable, "-m", "pytest"])
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    try:
        # Önce eklenti yolu ( en zengin veri)
        full_cmd = cmd + (list(args or [])) + ["--report-json", report_path, "-q"]
        proc = subprocess.run(full_cmd, capture_output=True, text=True)
        try:
            parsed = parse_pytest_json(report_path)
            parsed["exit_code"] = proc.returncode
            parsed["report_format"] = "pytest-json-report"
            return parsed
        except (ValueError, FileNotFoundError):
            pass

        # Eklenti yok → stdout'tan topla ( son-çare-yolu).
        # NOT: -q, -v'yi bastırır; pyproject addopts'taki -q'yu override
        # etmek için -o addopts= ile piniyoruz.
        collect_cmd = cmd + (list(args or [])) + ["-v", "--tb=no", "-o", "addopts="]
        proc2 = subprocess.run(collect_cmd, capture_output=True, text=True)
        entries = _parse_verbose_stdout(proc2.stdout)
        summary = summarize(entries)
        return {
            "entries": entries,
            "summary": summary,
            "source": "stdout",
            "report_format": "verbose-stdout",
            "exit_code": proc2.returncode,
            "stdout_tail": proc2.stdout[-2000:],
        }
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass


# pytest -v çıktı satır örüntüsü:
#   tests/test_a.py::test_one PASSED [ 12%]
# AT-189: nodeid boşluk içerebilir ( parametrize kimliklerinde — örn.
#   "[hello world]", "[the quick brown fox]"). \S+::\S+ bu satırları
# sessizce düşürür ve sertifika-özetini yanlış sayar ( 98→94). Bu yüzden
# nodeid boşluklara-izin-veren-greedy-olmayan gruptur; outcome, satırdaki
# ilk büyük-harfli-anahtar-kelime olarak eşleşir.
_VERBOSE_RE = re.compile(
    r"^(?P<nodeid>.+?)\s+(?P<outcome>PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASSED)(?:\s|$)"
)


def _parse_verbose_stdout(stdout: str) -> List[Dict[str, Any]]:
    """pytest ``-v`` çıktısından test-sonuçlarını toplar ( son-çare-yolu)."""
    out: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        m = _VERBOSE_RE.match(line.strip())
        if not m:
            continue
        out.append({
            "name": m.group("nodeid"),
            "outcome": m.group("outcome").lower(),
        })
    return out


__all__ = ["parse_pytest_json", "run_pytest_json"]
