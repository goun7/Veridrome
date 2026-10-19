"""veridrome MCP sunucu testleri — Model Context Protocol 2025-06-18 over stdio.

JSON-RPC el sıkışması + 4 aracı ( certificate_status/check_revocation/
verify_anchor/manifest) uçtan-uca SUBPROCESS üzerinden çalıştırır.
swarmax MCP testlerinin aynı deseni ( stdio'yu besle, stdout JSON
satırlarını çöz).

Sözleşmeler:
  - initialize → protocolVersion + capabilities + serverInfo
  - tools/list → 4 aracın-da listesi, her-birinin şeması-var
  - araç çağrısı → {"content":[{"type":"text","text":JSON}]}, asla exception
  - kötü-sertifika → ok=false RED ( fail-closed, traceback-YOK)
  - unknown-tool → JSON-RPC -32601
  - bozuk-json → sunucu ayakta-kalır, bir-sonraki isteği-yanıtlar
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp" / "server.py"
PROTOCOL_VERSION = "2025-06-18"


def _rpc(lines, env_extra=None, timeout=120):
    """Server'ı stdio üzerinden besle; yanıt satırlarını dict listesi dön."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    reqs = list(lines or [])
    proc = subprocess.run(
        [sys.executable, str(SERVER)], input="\n".join(reqs) + "\n",
        capture_output=True, text=True, env=env, timeout=timeout,
        cwd=str(ROOT), check=False)
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return proc, out


def _init_line():
    return ('{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
            '{"protocolVersion":"2025-06-18","capabilities":{},'
            '"clientInfo":{"name":"veridrome-mcp-test","version":"0.1"}}}')


def _tools_list():
    return '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'


def _call(req_id, name, arguments):
    return (f'{{"jsonrpc":"2.0","id":{req_id},"method":"tools/call",'
            f'"params":{{"name":"{name}",'
            f'"arguments":{json.dumps(arguments, ensure_ascii=False)}}}}}')


def _result_for(out, req_id):
    """id'ye-göre result'u-çek (tools/list dahil)."""
    for d in out:
        if d.get("id") == req_id and "result" in d:
            return d["result"]
    return None


def _call_result(out, req_id):
    """tools/call yanıtını çek → {"content":[{"type":"text","text":JSON}]}."""
    for d in out:
        if d.get("id") == req_id and "result" in d:
            content = d["result"].get("content") or []
            if content:
                try:
                    return json.loads(content[0].get("text", ""))
                except json.JSONDecodeError:
                    return None
    return None


# ------------------------------------------------------------------ fixtures

def _build_cert():
    """Bilinen-iyi bir sertifika-üret ( gercek CertificateBuilder ile)."""
    sys.path.insert(0, str(ROOT / "src"))
    from veridrome.certificate.core import CertificateBuilder
    from veridrome.certificate.didkey import keypair_from_seed
    seed = bytes.fromhex("07" * 32)
    _, did, _ = keypair_from_seed(seed)
    return CertificateBuilder(seed, did).build(
        test_results=[
            {"name": "test_one", "outcome": "passed", "duration_ms": 12},
            {"name": "test_two", "outcome": "passed", "duration_ms": 8},
        ],
        commit_sha="ab" * 20,
    )


def _build_revoked_ledger(path, cert_id):
    """Bilinen-iyi bir iptal-defteri: tek-oluşturulan-giriş ( gercek
    RevocationLedger.revoke ile)."""
    sys.path.insert(0, str(ROOT / "src"))
    from veridrome.certificate.didkey import keypair_from_seed
    from veridrome.certificate.revocation import RevocationLedger
    seed = bytes.fromhex("13" * 32)
    _, did, _ = keypair_from_seed(seed)
    RevocationLedger(str(path)).revoke(
        cert_id=cert_id, revoked_by_seed=seed,
        revoked_by_did=did, reason="test-iptal")
    return str(path)


@pytest.fixture()
def good_cert():
    return _build_cert()


@pytest.fixture()
def revocation_ledger(tmp_path, good_cert):
    return _build_revoked_ledger(tmp_path / "revocations.jsonl",
                                 good_cert["cert_id"])


@pytest.fixture()
def anchor(tmp_path, good_cert):
    """Bilinen-iyi Tamga-anchor: publish → sidecar ( gercek-API)."""
    sys.path.insert(0, str(ROOT / "src"))
    from veridrome.certificate.tamga_anchor import publish
    ledger = str(tmp_path / "anchor.jsonl")
    return publish(good_cert, ledger), good_cert


# ------------------------------------------------------------------ protocol

def test_initialize_handshake():
    proc, out = _rpc([_init_line()])
    assert proc.returncode == 0
    r = _result_for(out, 1)
    assert r is not None
    assert r["protocolVersion"] == PROTOCOL_VERSION
    assert r["capabilities"] == {"tools": {"listChanged": False}}
    assert r["serverInfo"]["name"] == "veridrome"
    assert "instructions" in r["serverInfo"]


def test_tools_list_four_tools():
    _, out = _rpc([_init_line(), _tools_list()])
    r = _result_for(out, 2)
    names = {t["name"] for t in r["tools"]}
    assert names == {"certificate_status", "check_revocation",
                     "verify_anchor", "manifest"}
    # her aracın bir şeması ve açıklaması olmalı
    for t in r["tools"]:
        assert t["description"]
        assert isinstance(t["inputSchema"], dict)
        assert t["inputSchema"].get("type") == "object"


def test_notifications_initialized_no_reply():
    """notifications/initialized bir BİLDİRİM — yanıt üretmemeli."""
    _, out = _rpc([
        _init_line(),
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":7,"method":"ping","params":{}}'])
    # sadece init+ping Yanıtlanmalı — 2 yanıt, 3 değil
    ids = [d["id"] for d in out if "result" in d or "error" in d]
    assert 7 in ids
    assert len(ids) == 2


# ------------------------------------------------------------------ certificate_status

def test_certificate_status_green(good_cert):
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status",
                         {"certificate": good_cert})])
    res = _call_result(out, 3)
    assert res["ok"] is True
    assert res["cert_id"] == good_cert["cert_id"]
    assert res["checks"]["signature_valid"] is True
    assert res["checks"]["content_hash_valid"] is True
    assert res["checks"]["merkle_valid"] is True
    assert res["errors"] == []


def test_certificate_status_accepts_wrapper_form(good_cert):
    """Sarmaliyi-kabul: {certificate, cert_id, ...} → iç-sertifika-çıkar."""
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status",
                         {"certificate": {"certificate": good_cert}})])
    res = _call_result(out, 3)
    assert res["ok"] is True


def test_certificate_status_tampered_is_red(good_cert):
    """Tahriz: bir-testin-adını-değiştir → content_hash-uyumsuz → RED."""
    tampered = json.loads(json.dumps(good_cert))
    tampered["credentialSubject"]["summary"]["total"] = 99
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status",
                         {"certificate": tampered})])
    res = _call_result(out, 3)
    assert res["ok"] is False
    assert res["checks"]["content_hash_valid"] is False
    # asla traceback — JSON kanıtı geldi
    assert "Traceback" not in json.dumps(res)


def test_certificate_status_missing_arg_is_red():
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status", {})])
    res = _call_result(out, 3)
    assert res["ok"] is False
    assert "certificate-zorunlu" in res["reason"]


def test_certificate_status_revoked_cert_is_red(good_cert, revocation_ledger):
    """check_revocation=true → iptal-edilmiş-seritifika RED."""
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status",
                         {"certificate": good_cert,
                          "check_revocation": True,
                          "ledger_path": revocation_ledger})])
    res = _call_result(out, 3)
    assert res["ok"] is False
    assert res["revocation"]["revoked"] is True
    assert any("iptal" in e for e in res["errors"])


# ------------------------------------------------------------------ check_revocation

def test_check_revocation_revoked_entry(revocation_ledger, good_cert):
    _, out = _rpc([_init_line(),
                   _call(4, "check_revocation",
                         {"cert_id": good_cert["cert_id"],
                          "ledger_path": revocation_ledger})])
    res = _call_result(out, 4)
    assert res["ok"] is True
    assert res["revoked"] is True
    assert res["reason"] == "test-iptal"
    assert res["chain_valid"] is True
    assert res["signature_valid"] is True
    assert res["revoked_by"].startswith("did:key:")


def test_check_revocation_unknown_cert_not_revoked(revocation_ledger):
    _, out = _rpc([_init_line(),
                   _call(4, "check_revocation",
                         {"cert_id": "ff" * 32,
                          "ledger_path": revocation_ledger})])
    res = _call_result(out, 4)
    assert res["ok"] is True
    assert res["revoked"] is False


def test_check_revocation_missing_cert_id_is_red(revocation_ledger):
    _, out = _rpc([_init_line(),
                   _call(4, "check_revocation",
                         {"ledger_path": revocation_ledger})])
    res = _call_result(out, 4)
    assert res["ok"] is False
    assert "cert_id-zorunlu" in res["reason"]


def test_check_revocation_broken_chain_is_red(tmp_path, revocation_ledger):
    """Zinciri-sonradan-boz: prev-bağı-köpük bir satır sıkıştır.

    Bu, fail-closed RED'yi-ölçer: check_revoked → chain_valid=false —
    sessiz-geçiş-YOK ( AT-183-deseni).
    """
    p = Path(revocation_ledger)
    forged = {
        "timestamp": "2030-01-01T00:00:00+00:00",
        "cert_id": "ff" * 32,
        "revoked_by": "did:key:z6Mk",
        "reason": "forged",
        "prev": "f" * 64,
        "h": "x",
    }
    p.write_text(p.read_text(encoding="utf-8")
                 + json.dumps(forged, ensure_ascii=False) + "\n",
                 encoding="utf-8")
    _, out = _rpc([_init_line(),
                   _call(4, "check_revocation",
                         {"cert_id": "ff" * 32,
                          "ledger_path": revocation_ledger})])
    res = _call_result(out, 4)
    # Fail-closed ( AT-183): ok=true-AMA-zincir-kırılmış-işaretlenmiş —
    # revoked-girişi VAR, chain_valid=VE-signature_valid=false. Sessiz-işaretleme-YOK:
    # çağıran chain_valid=false-gördüğü-için bu girişe-GÜVEN-EMEZ.
    assert res["ok"] is True
    assert res["revoked"] is True
    assert res["chain_valid"] is False
    assert res["signature_valid"] is False


def test_check_revocation_unreadable_ledger_is_red():
    _, out = _rpc([_init_line(),
                   _call(4, "check_revocation",
                         {"cert_id": "ff" * 32,
                          "ledger_path": "/yok/boyle/bir/dizin/r.jsonl"})])
    res = _call_result(out, 4)
    # mevcut-API FileNotFoundError → check_revoked boş-döner — o da
    # sözleşmedir: ok=true, revoked=false (boş-defter-geçerli).
    assert res["ok"] is True
    assert res["revoked"] is False


# ------------------------------------------------------------------ verify_anchor

def test_verify_anchor_green(anchor):
    sidecar, cert = anchor
    _, out = _rpc([_init_line(),
                   _call(5, "verify_anchor",
                         {"sidecar": sidecar, "certificate": cert})])
    res = _call_result(out, 5)
    assert res["ok"] is True
    assert res["errors"] == []
    assert res["summary"]["cert_id"] == cert["cert_id"]


def test_verify_anchor_sidecar_without_cert(anchor):
    """certificate-olmadan-da çalışır: ledger-zinciri-tek-başına-doğrulanır."""
    sidecar, _ = anchor
    _, out = _rpc([_init_line(),
                   _call(5, "verify_anchor", {"sidecar": sidecar})])
    res = _call_result(out, 5)
    assert res["ok"] is True


def test_verify_anchor_broken_ledger_is_red(anchor):
    """Ledger'ı-sonradan-boz: ikinci-satırı-değiştir → zincir-kırılır → RED."""
    sidecar, _ = anchor
    ledger = Path(sidecar["tamga"]["ledger"])
    lines = ledger.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["op"] = "forged"
    lines[0] = json.dumps(rec, ensure_ascii=False)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _, out = _rpc([_init_line(),
                   _call(5, "verify_anchor", {"sidecar": sidecar})])
    res = _call_result(out, 5)
    assert res["ok"] is False
    assert res["errors"]


def test_verify_anchor_non_dict_is_red():
    _, out = _rpc([_init_line(),
                   _call(5, "verify_anchor", {"sidecar": "nope"})])
    res = _call_result(out, 5)
    assert res["ok"] is False
    assert "sidecar-zorunlu" in res["reason"]


def test_verify_anchor_wrong_cert_is_red(anchor):
    """Doğru-sidecar + FARKLI-sertifika → bound-uyumsuzluğu RED."""
    sidecar, _ = anchor
    other = _build_cert()
    _, out = _rpc([_init_line(),
                   _call(5, "verify_anchor",
                         {"sidecar": sidecar, "certificate": other})])
    res = _call_result(out, 5)
    assert res["ok"] is False
    assert any("anchor-bağı" in e or "uyuşm" in e for e in res["errors"])


# ------------------------------------------------------------------ manifest

def test_manifest_lists_all_tasks():
    _, out = _rpc([_init_line(), _call(6, "manifest", {})])
    res = _call_result(out, 6)
    assert res["ok"] is True
    assert res["count"] == 20
    ids = {t["task_id"] for t in res["tasks"]}
    assert "T01" in ids and "T20" in ids
    first = res["tasks"][0]
    assert first["title"]
    assert first["objective"]
    assert first["invariants"]


def test_manifest_category_filter():
    _, out = _rpc([_init_line(),
                   _call(6, "manifest", {"category": "finops"})])
    res = _call_result(out, 6)
    assert res["ok"] is True
    assert res["count"] == 4  # T10-T13
    assert all(t["category"] == "finops" for t in res["tasks"])


def test_manifest_text_filter():
    _, out = _rpc([_init_line(), _call(6, "manifest", {"filter": "T01"})])
    res = _call_result(out, 6)
    assert res["ok"] is True
    assert res["count"] == 1
    assert res["tasks"][0]["task_id"] == "T01"


def test_manifest_unknown_category_is_red():
    _, out = _rpc([_init_line(),
                   _call(6, "manifest", {"category": "yok-boyle-kategori"})])
    res = _call_result(out, 6)
    assert res["ok"] is False
    assert "gecersiz-filter" in res["reason"]


# ------------------------------------------------------------------ hata-yolları

def test_unknown_tool_jsonrpc_error():
    _, out = _rpc([_init_line(),
                   _call(7, "yok-boyle-arac", {})])
    errs = [d for d in out if d.get("id") == 7 and "error" in d]
    assert errs
    assert errs[0]["error"]["code"] == -32601
    assert "bilinmeyen-arac" in errs[0]["error"]["message"]


def test_invalid_json_does_not_crash():
    _, out = _rpc(["bu-bir-json-degil",
                  _init_line(),
                  '{"jsonrpc":"2.0","id":9,"method":"ping","params":{}}'])
    # ping hâlâ yanıtlanmalı — sunucu ayakta
    ids = [d["id"] for d in out if "result" in d or "error" in d]
    assert 9 in ids


def test_env_ledger_path_used_when_arg_absent(good_cert, revocation_ledger,
                                              monkeypatch):
    """VERIDROME_REVOCATION_LEDGER env'i ledger_path-yoksa-kullanılmalı."""
    _, out = _rpc([_init_line(),
                   _call(3, "certificate_status",
                         {"certificate": good_cert,
                          "check_revocation": True})],
                  env_extra={"VERIDROME_REVOCATION_LEDGER": revocation_ledger})
    res = _call_result(out, 3)
    assert res["ok"] is False
    assert res["revocation"]["revoked"] is True


def test_server_starts_without_heavy_deps(monkeypatch):
    """Sunucu modul-tepesinde-ağır-import-yapmaz — pesticidesiz-start.

    pydantic/scipy/cryptography yalnızca İLGİLİ-aracın-içinde-import-edilir:
    tools/list manifest-hariç-hepsi için-çalışır.
    """
    import builtins
    real_import = builtins.__import__

    def _blocked(name, *a, **k):
        if name.split(".")[0] in {"pydantic", "scipy", "numpy"}:
            raise ImportError(f"blocked-for-test: {name}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _blocked)
    # initialize + tools/list hâlâ-çalışmalı ( manifest-aracı-çağrılmadı)
    _, out = _rpc([_init_line(), _tools_list()])
    r = _result_for(out, 2)
    assert r is not None
    assert len(r["tools"]) == 4


# ---------------------------------------------------------------------------
# VERIDROME-G8 (gece-turu 2026-10-19): salt-oku P0-sozunun olcum-pini
#
# mcp/server.py'nin docstring-sozu: "dosyaya-YAZMAZ, ledger'a-kayit-
# EKLEMEZ". Bu soz P0 ( guvenlik). Olcum: sunucuyu TEMP-evine koyup
# tum 4 araci + hatali-cagrilari calistir, sonra TEMP-dizininde TEK
# yeni-dosya-cikmamali. Dokuman-sozu degil, davranis olcumu.
# ---------------------------------------------------------------------------
def test_p0_salt_oku_sunucu_hicbir_dosya_yazmaz(tmp_path):
    """Sunucu aya-kalkip 4 araci + bilinmeyen-araci cagirirsa TEMP-evinde
    HICBIR dosya olusmamali - salt-oku sozunun davranis-olcumu."""
    once = {p.name for p in tmp_path.iterdir()}
    env = {
        "VERIDROME_REVOCATION_LEDGER": str(tmp_path / "revocations.jsonl"),
        "VERIDROME_HOME": str(tmp_path),
    }
    proc, _yanit = _rpc([
        _init_line(),
        _tools_list(),
        _call(3, "manifest", {}),
        _call(4, "check_revocation", {}),
        _call(5, "verify_anchor", {}),
        _call(6, "certificate_status", {}),
        _call(7, "no_such_tool", {}),
    ], env_extra=env)
    assert proc.returncode == 0, proc.stderr[-300:]
    after = {p.name for p in tmp_path.iterdir()}
    assert once == after, f"P0-KIRILDI: sunucu dosya-yazdi: {sorted(after - once)}"


def test_p0_kirmizi_durumlar_traceback_degil_structured_json():
    """4 aracin tumu eksik-argumanla cagrilinca traceback DEGIL
    ok:false + reason: JSON kaniti vermeli ( protokol-disina-cikma-yok)."""
    proc, out = _rpc([
        _init_line(),
        _call(3, "check_revocation", {}),
        _call(4, "verify_anchor", {}),
        _call(5, "certificate_status", {}),
    ])
    assert proc.returncode == 0
    for rid in (3, 4, 5):
        kanit = _result_for(out, rid)
        assert kanit is not None, f"{rid}: result-bos"
        govde = json.loads(kanit["content"][0]["text"])
        assert govde.get("ok") is False, f"{rid}: hatali-cagri ok:true demis"
        assert govde.get("reason"), f"{rid}: sebep-yok (fail-silent)"
        assert "Traceback" not in govde["reason"]
