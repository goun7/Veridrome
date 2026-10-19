#!/usr/bin/env python3
"""veridrome MCP sunucusu — Model Context Protocol 2025-06-18 over stdio.

Veridrome'un doğrulama-çekirdeğini (sunucu-üreten-DEĞIL, salt-DOĞRULAYAN)
AI ajanlarına MCP araçları olarak sunar. swarmax/tamga MCP sunucuları ile
aynı sözleşme:

  • SAF STDLIB taşıması — ham ``json`` + ``sys.stdin`` JSON-RPC; hiçbir
    MCP-SDK'sı yoktur ( ``src/veridrome/mcp_server.py`` zaten böyle çalışır,
    bu sunucu onun güvenli-depolama-yazmayan-aynasıdır).
  • HİÇBİR ZAMAN exception — her araç GREEN/RED JSON kanıtı döndürür;
    traceback DEĞİL "ok:false, reason:…" ( tamga AT-192 message-RED).
  • SALT-OKUMA/üretim — mevcut ``mcp_server.py``'ın aksine bu cephe
    anahtar-üretmez, dosyaya-YAZMAZ, ledger'a-kayıt-EKLEMEZ. Sadece
    mevcut sertifikaları/defterleri/zincirleri DOĞRULAR. Anahtar-yönetimi
    ve yazma-yolu "veridrome" CLI'ına aittir; MCP-cephesine DEĞIL.

  • ``_jsonable`` özyineli-dönüştürücü + ``_text`` son-kapısı — swarmax
    sunucusunda REAL-BUG olarak bulunan ``sqlite3.Row``-çökmesini burada
    da önler: herhangi bir seri-olmayan-değer ( Row/nesne/tarih) bile
    JSON kanıdına düşer, sunucu ASLA traceback basmaz.

Araçlar ( hepsi MEVCUT veridrome API'lerinin sıfır-yeni-mantıkla sarması):
  certificate_status   bir sertifikayı bağımsız-doğrula ( verify_certificate)
  check_revocation     iptal-defterinin-çözümlemesi ( check_revoked)
  verify_anchor        Tamga-çapasını ledger'a-karşı-doğrula ( tamga_anchor)
  manifest             görev-kütüğünü listele ( TaskRegistry)

Çalıştırma:
  python3 mcp/server.py                    # stdio JSON-RPC
  (istemci tarafı: "command": "python",
   "args": ["<repo>/mcp/server.py"],
   "env": {"VERIDROME_REVOCATION_LEDGER": "/yol/revocations.jsonl"})
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "veridrome"
SERVER_VERSION = "0.1.0"

ROOT = Path(__file__).resolve().parents[1]
# src/veridrome paketini içe-aktarmak için. Ağır bağımlılıklar ( pydantic,
# scipy, cryptography) yalnızca İLGİLİ aracın içinde import-edilir —
# modul-tepesinde DEĞIL — böylece sunucu her koşulda START-alır.
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

DEFAULT_LEDGER = ROOT / "data" / "revocations.jsonl"

# tamga_anchor.verify() bu sayılardan fazla-kayıt-yazmamak-üzere-denetler;
# CLI-cephesine-bırakmak-için-burada-yok.


def _result(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code: int, msg: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": code, "message": msg}}


def _jsonable(obj):
    """Özyineli JSON-dönüştürücü — swarmax-MCP real-bug'autından-gelen-güvenlik.

    ``sqlite3.Row`` ( ve herhangi bir ``keys()``-taşıyan eşlenik) düz-dict'e,
    ``tuple`` liste-ye, ``datetime``/``bytes`` ISO-dizesine-çevrilir.
    ``mcp_server.py`` CRASH-eden-yol ( jcs-dolaşıp serialize-edilemeyen
    ``bound``-değerleri) burada KORUNMUŞTUR — sunucu ASLA traceback basmaz.
    """
    if isinstance(obj, sqlite3.Row):
        # Row.keys() liste-döndürür — `k in obj` Row'da değer-araması yapar
        # ( SIM118 burada yanlış-uyarır), keys() gereklidir.
        return {k: _jsonable(obj[k]) for k in obj.keys()}  # noqa: SIM118
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()
    if isinstance(obj, set):
        return sorted(_jsonable(v) for v in obj)
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    return obj


def _text(payload: dict) -> dict:
    """Asla-exception sözleşmesinin-son-kapısı: serileştirme-başarısızlığı
    bile JSON kanıtı döndürür ( tamga AT-192 message-RED disiplini)."""
    try:
        text = json.dumps(_jsonable(payload), ensure_ascii=False)
    except Exception as e:  # noqa: BLE001 — son-kapı, traceback-YASAK
        text = json.dumps(
            {"ok": False,
             "reason": f"serilestirme-hatasi: {type(e).__name__}: {e}"},
            ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}]}


def _resolve_ledger(args: dict) -> str:
    """İptal-defteri yolu: argüman → env → repo-altı varsayılan."""
    p = args.get("ledger_path")
    if isinstance(p, str) and p:
        return p
    env = os.environ.get("VERIDROME_REVOCATION_LEDGER")
    if isinstance(env, str) and env:
        return env
    return str(DEFAULT_LEDGER)


def _bool_arg(args: dict, key: str, default: bool) -> bool:
    """check_revocation gibi opsiyonel-bayraklar: yalnızca gerçek-bool
    kabul-eder — "false"-dizesi-yanlış-doğru-sanmasın."""
    v = args.get(key)
    return v if isinstance(v, bool) else default


# --- araç implementasyonları ----------------------------------------------------

def _tool_certificate_status(args: dict) -> dict:
    """Bir test-geçişi sertifikasını BAĞIMSIZ olarak doğrula ( zero-trust).

    ``verify_certificate`` HERŞEYİ dosyadan-yeniden-hesaplar: did:key-self-
    resolving imza, content_hash, Merkle-kökü, süre-geçerliliği. Bu cephe
    yalnızca MEVCUT API'yı çağırır — yeni-mantik YOK.
    """
    cert = args.get("certificate")
    if not isinstance(cert, dict):
        return {"ok": False, "reason": "certificate-zorunlu (JSON-nesne)"}

    # Sarmaliyi-kabul ( mevcut-mcp_server.py ile aynı-UX): certify
    # {certificate, cert_id, ...} SARMALI döner — iç-sertifikayı-çıkart.
    if "certificate" in cert and isinstance(cert.get("certificate"), dict):
        cert = cert["certificate"]

    check_rev = _bool_arg(args, "check_revocation", False)
    out: dict = {"ok": False, "cert_id": cert.get("cert_id"),
                 "checks": {}, "errors": [], "warnings": []}
    try:
        from veridrome.certificate.core import verify_certificate
        res = verify_certificate(cert)
        out["checks"] = {
            "content_hash_valid": res.content_hash_valid,
            "signature_valid": res.signature_valid,
            "temporal_valid": res.temporal_valid,
            "merkle_valid": res.merkle_valid,
            "subject_ok": res.subject_ok,
        }
        out["errors"] = list(res.errors)
        out["warnings"] = list(res.warnings)
        out["ok"] = bool(res.valid)
    except Exception as e:  # noqa: BLE001 — cephedeki her hata JSON kanıtı
        out["ok"] = False
        out["errors"].append(f"dogrulama-hatasi: {type(e).__name__}: {e}")

    if check_rev:
        try:
            from veridrome.certificate.revocation import check_revoked
            rev = check_revoked(str(cert.get("cert_id", "")),
                                _ledger(args))
            out["revocation"] = {
                "revoked": rev.get("revoked", False),
                "reason": rev.get("reason", ""),
                "chain_valid": rev.get("chain_valid", True),
                "signature_valid": rev.get("signature_valid"),
            }
            if rev.get("revoked"):
                out["ok"] = False
                out["errors"].append(
                    f"sertifika-iptal-edilmis: "
                    f"{rev.get('reason') or 'neden-belirtilmemis'}")
        except Exception as e:  # noqa: BLE001 — kötü-defter RED, çöküş-DEGIL
            out["ok"] = False
            out["revocation"] = {"revoked": False, "error": str(e)}
            out["errors"].append(f"iptal-defteri-hatasi: "
                                 f"{type(e).__name__}: {e}")
    return out


def _tool_check_revocation(args: dict) -> dict:
    """Bir cert_id'nin iptal-durumunu appropriate-defterden oku.

    Defter-rotası argümanda veya ``VERIDROME_REVOCATION_LEDGER`` env'inde
    verilir; ikisi-yoksa repo-altı ``data/revocations.jsonl``. Bozuk-defter
    ( kırılmış-zincir) fail-closed RED'dir — sessiz-geçiş-YOK.
    """
    cert_id = args.get("cert_id")
    if not isinstance(cert_id, str) or not cert_id:
        return {"ok": False, "reason": "cert_id-zorunlu (string)"}

    from veridrome.certificate.revocation import (
        RevocationLedger,
        check_revoked,
    )

    path = _resolve_ledger(args)
    ledger = RevocationLedger(path)
    try:
        rev = check_revoked(cert_id, ledger)
    except Exception as e:  # noqa: BLE001 — okunamayan-defter RED
        return {"ok": False, "cert_id": cert_id, "ledger": path,
                "reason": f"iptal-defteri-okunamadi: {type(e).__name__}: {e}"}

    return {
        "ok": True,
        "cert_id": cert_id,
        "ledger": path,
        "revoked": bool(rev.get("revoked")),
        "reason": rev.get("reason", ""),
        "chain_valid": bool(rev.get("chain_valid", True)),
        "signature_valid": rev.get("signature_valid"),
        "revoked_by": (rev.get("entry") or {}).get("revoked_by"),
    }


def _tool_verify_anchor(args: dict) -> dict:
    """Bir Tamga-anchor sidecar'ı, adını-verdiği ledger'a-karşı doğrula.

    ``tamga_anchor.verify`` mevcut-API'dir: TÜM zinciri genesinden-yeniden-
    doğrular ve sidecar'ın-iddia ettiği seq/h/bound/digest birebir-sılar.
    Bu cephe sadece çağırır — yeni-mantik YAZMAZ.
    """
    sidecar = args.get("sidecar")
    if not isinstance(sidecar, dict):
        return {"ok": False, "reason": "sidecar-zorunlu (JSON-nesne)"}
    cert = args.get("certificate")
    if cert is not None and not isinstance(cert, dict):
        return {"ok": False, "reason": "certificate (JSON-nesne) veya-boş"}

    from veridrome.certificate.tamga_anchor import (
        verify as verify_anchor,
    )

    try:
        res = verify_anchor(sidecar, cert)
    except Exception as e:  # noqa: BLE001 — kötü-girdi RED, çöküş-DEGIL
        return {"ok": False, "reason": f"anchor-hatasi: "
                                       f"{type(e).__name__}: {e}"}

    return {
        "ok": bool(res.get("valid")),
        "errors": list(res.get("errors", [])),
        "summary": res.get("summary", {}),
    }


def _tool_manifest(args: dict) -> dict:
    """Görev-kütüğünü ( T01-T20) listele — kimse-nelerin-istenildiğini
    bilmek için sandbox'a-girmesine-gerek-yok.

    ``filter`` verilirse task_id/kategori-üzerinden-süzüp-o-alt-kümeyi
    döndürür; bilinmeyen-filter boş-liste ( fail-open burada güvenli:
    bu KEŞİF aracıdır, doğrulama değil).
    """
    from veridrome.tasks.registry import (
        PoolType,
        TaskCategory,
        TaskRegistry,
    )

    registry = TaskRegistry()
    tasks = []
    filt = args.get("filter")
    category = args.get("category")
    pool = args.get("pool_type")
    try:
        if isinstance(category, str) and category:
            tasks = registry.filter_by_category(TaskCategory(category))
        elif isinstance(pool, str) and pool:
            tasks = registry.filter_by_pool(PoolType(pool))
        else:
            tasks = registry.list_all()
    except (KeyError, ValueError) as e:
        return {"ok": False, "reason": f"gecersiz-filter: {e}"}

    if isinstance(filt, str) and filt:
        needle = filt.lower()
        tasks = [t for t in tasks
                 if needle in t.task_id.lower() or needle in t.title.lower()]

    return {
        "ok": True,
        "count": len(tasks),
        "tasks": [
            {"task_id": t.task_id, "title": t.title,
             "category": t.category.value if hasattr(t.category, "value")
             else str(t.category),
             "pool_type": t.pool_type.value if hasattr(t.pool_type, "value")
             else str(t.pool_type),
             "objective": t.objective,
             "invariants": [
                 {"rule_type": inv.rule_type, "selector": inv.selector}
                 for inv in t.invariants]}
            for t in tasks],
    }


def _ledger(args: dict):
    """RevocationLedger-üretici — check-path'i yalnız-paslamak-için."""
    from veridrome.certificate.revocation import RevocationLedger
    return RevocationLedger(_resolve_ledger(args))


TOOLS = {
    "certificate_status": {
        "handler": _tool_certificate_status,
        "description": (
            "Bir test-geçişi sertifikasını BAĞIMSIZ olarak doğrular: "
            "Ed25519-imza ( did:key self-resolving), content_hash, "
            "Merkle-kökü, süre-geçerliliği. check_revocation=true verilirse "
            "iptal-defteri de denetlenir. Salt-oku/üretme-YAPMAZ. "
            "Dönüş: {ok, cert_id, checks, errors, warnings, revocation?} "
            "— herhangi-bir-denç-kırılırsa ok=false RED."),
        "schema": {
            "type": "object",
            "properties": {
                "certificate": {
                    "type": "object",
                    "description": ("Doğrulanacak sertifika JSON'u. Doğrudan-"
                                    "sertifika VEYA sarmal "
                                    "{certificate, cert_id, ...} kabul-edilir."),
                },
                "check_revocation": {
                    "type": "boolean",
                    "description": ("İptal-defteri de denetlensin mi "
                                    "( varsayılan: false — deftersiz-"
                                    "doğrulama mümkündür)."),
                },
                "ledger_path": {
                    "type": "string",
                    "description": ("İptal-defteri yolu ( opsiyonel — verilmezse "
                                    "VERIDROME_REVOCATION_LEDGER env'i veya "
                                    "repo-altı data/revocations.jsonl)."),
                }},
            "required": ["certificate"],
        }},
    "check_revocation": {
        "handler": _tool_check_revocation,
        "description": (
            "Bir cert_id'nin iptal-durumunu append-only hash-zincirli "
            "defterden okur. Defter-zinciri kırılmışsa chain_valid=false. "
            "Salt-oku. Dönüş: {ok, cert_id, ledger, revoked, reason, "
            "chain_valid, signature_valid, revoked_by?} — ok=false yalnızca "
            "defter-okunamadıysa ( RED)."),
        "schema": {
            "type": "object",
            "properties": {
                "cert_id": {
                    "type": "string",
                    "description": "Sertifika kimliği ( 64-hex sha256).",
                },
                "ledger_path": {
                    "type": "string",
                    "description": "İptal-defteri yolu ( opsiyonel).",
                }},
            "required": ["cert_id"],
        }},
    "verify_anchor": {
        "handler": _tool_verify_anchor,
        "description": (
            "Bir Tamga-anchor sidecar'ı, adını-verdiği ledger'a-karşı "
            "bağımsız-doğrular: TÜM zinciri genesinden-yeniden-doğrular ve "
            "sidecar'ın seq/h/bound/digest'iddialarını-birebilir. "
            "certificate-argümanı-verilirse sidecar-bağı sertifikadan-"
            "yeniden-hesaplayıp-karşılaştırır. Salt-oku. "
            "Dönüş: {ok, errors, summary} — ok=false RED."),
        "schema": {
            "type": "object",
            "properties": {
                "sidecar": {
                    "type": "object",
                    "description": "publish()'in-döndürdüğü anchor-sidecar'ı.",
                },
                "certificate": {
                    "type": "object",
                    "description": ("İlgili sertifika ( opsiyonel — verilirse "
                                    "bağı-yeniden-hesaplanıp-karşılaştırılır)."),
                }},
            "required": ["sidecar"],
        }},
    "manifest": {
        "handler": _tool_manifest,
        "description": (
            "Veridrome görev-kütüğünü ( T01-T20) listeler: task_id, başlık, "
            "kategori, havuz, amaç ve invariant-kuralları. Keşif-aracı — "
            "ajan-sandbox'a-girmeden-nelerin-istenildiğini-görür. "
            "Dönüş: {ok, count, tasks} — bilinmeyen-filter ok=false RED."),
        "schema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": ("Kategori-süzme ( opsiyonel): e_commerce, "
                                    "saas_admin, finops, modern_ui, "
                                    "data_extraction."),
                },
                "pool_type": {
                    "type": "string",
                    "description": "Havuz-süzme ( opsiyonel): PUBLIC_CANARY.",
                },
                "filter": {
                    "type": "string",
                    "description": "task_id/başlık-üzerinden-serbest-metin süzme.",
                }},
            "required": [],
        }},
}


def _tools_list_result() -> dict:
    return {"tools": [
        {"name": name,
         "description": spec["description"],
         "inputSchema": spec["schema"]}
        for name, spec in TOOLS.items()]}


def _handle_call(req_id, params: dict) -> dict | None:
    name = params.get("name")
    args = params.get("arguments")
    if not isinstance(args, dict):
        args = {}
    spec = TOOLS.get(name)
    if spec is None:
        return _err(req_id, -32601, f"bilinmeyen-arac: {name}")
    try:
        payload = spec["handler"](args)
    except Exception as e:  # noqa: BLE001 — hiçbir yol exception'a düşmez
        payload = {"ok": False,
                   "reason": f"arac-ic-hata: {type(e).__name__}: {e}"}
    return _result(req_id, _text(payload))


def main() -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            sys.stdout.write(
                json.dumps(_err(None, -32600, "gecersiz-json")) + "\n")
            sys.stdout.flush()
            continue
        if not isinstance(req, dict):
            sys.stdout.write(
                json.dumps(_err(None, -32600, "istek-bir-nesne-degil")) + "\n")
            sys.stdout.flush()
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            sys.stdout.write(json.dumps(_result(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "instructions": (
                        "Veridrome doğrulama-cepnesi ( salt-oku). "
                        "certificate_status → sertifika-bağımsız-doğrulama; "
                        "check_revocation → iptal-defteri-sorgusu; "
                        "verify_anchor → Tamga-zinciri-çapa-doğrulaması; "
                        "manifest → görev-kütüğü. Her araç JSON kanıtı döner, "
                        "asla exception fırlatmaz. Defter-yolu "
                        "VERIDROME_REVOCATION_LEDGER env'inde veya "
                        "ledger_path argümanında verilir."),
                }})) + "\n")
        elif method == "notifications/initialized":
            continue  # bildirim — yanıt yok
        elif method == "tools/list":
            sys.stdout.write(
                json.dumps(_result(req_id, _tools_list_result())) + "\n")
        elif method == "tools/call":
            resp = _handle_call(req_id, req.get("params") or {})
            if resp is not None:
                sys.stdout.write(
                    json.dumps(resp, ensure_ascii=False) + "\n")
        elif method == "ping":
            sys.stdout.write(json.dumps(_result(req_id, {})) + "\n")
        elif req_id is not None:
            sys.stdout.write(json.dumps(_err(
                req_id, -32601, f"bilinmeyen-method: {method}")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
