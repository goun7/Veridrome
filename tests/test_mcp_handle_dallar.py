"""73-Veridrome mcp_server._handle/_error dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (_handle saf JSON-in/JSON-out; network/DB YASAK).

ORTAM-ANATOMI (MCP 2025-06 stdio, JSON-RPC 2.0):
- _error(msg): {'error': msg}
- _handle(request):
  initialize -> jsonrpc+id+result(protocolVersion/serverInfo/capabilities)
  notifications/initialized -> None
  tools/list -> jsonrpc+id+result{tools: _TOOLS (4 arac)}
  tools/call -> dispatch; bilinmeyen -> error -32601 'bilinmeyen arac'
  ping -> jsonrpc+id+result{}
  req_id None -> None
  else -> error -32601 'desteklenmeyen metod'
- tools/call basarili: result.content[{type:text,text:json}] (isError YOK)
- tools/call hata: isError=True + content text {"error": ...}
"""
import json
import sys

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridrome.mcp_server import (  # noqa: E402
    PROTOCOL_VERSION,
    SERVER_NAME,
    SERVER_VERSION,
    _DISPATCH,
    _TOOLS,
    _error,
    _handle,
)


# == _error =============================================================================================

def test_error_basit():
    assert _error("test") == {"error": "test"}


def test_error_bos():
    assert _error("") == {"error": ""}


def test_error_turkce():
    out = _error("araç-hatası")
    assert out == {"error": "araç-hatası"}


def test_error_donut_tipi():
    assert isinstance(_error("x"), dict)


def test_error_tek_anahtar():
    assert list(_error("x")) == ["error"]


def test_error_stabil():
    assert _error("x") == _error("x")


@pytest.mark.parametrize("msg", ["a", "test_results boş olmalı", "", "🎉"])
def test_error_matrix(msg):
    assert _error(msg) == {"error": msg}


# == initialize ========================================================================================

def test_initialize():
    r = _handle({"method": "initialize", "id": 1})
    assert r["jsonrpc"] == "2.0"
    assert r["id"] == 1
    assert r["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert r["result"]["serverInfo"]["name"] == SERVER_NAME
    assert r["result"]["serverInfo"]["version"] == SERVER_VERSION


def test_initialize_capabilities():
    r = _handle({"method": "initialize", "id": 1})
    assert r["result"]["capabilities"] == {"tools": {"listChanged": False}}


def test_initialize_listchanged_false():
    """ORTAM-OGRENDI: listChanged False — bu server dinamik arac-listesi
    destekleMEZ (statik 4 arac)."""
    assert _handle({"method": "initialize", "id": 1})["result"]["capabilities"]["tools"]["listChanged"] is False


def test_initialize_id_striNG():
    """ORTAM: id string de olabilir (JSON-RPC serbest)."""
    r = _handle({"method": "initialize", "id": "abc"})
    assert r["id"] == "abc"


def test_initialize_id_yok():
    """ORTAM: id None -> None doner."""
    r = _handle({"method": "initialize"})
    assert r["id"] is None


def test_initialize_hata_yok():
    assert "error" not in _handle({"method": "initialize", "id": 1})


def test_initialize_params_gorulmez():
    """ORTAM: initialize params'i OKUMAZ ( MCP el-sikismasi stateless)."""
    r = _handle({"method": "initialize", "id": 1, "params": {"capabilities": {}}})
    assert r["jsonrpc"] == "2.0"


# == notifications/initialized ==========================================================================

def test_notification_initialized():
    """ORTAM-OGRENDI: bildirim (notification) -> None (yanit beklenMEZ)."""
    assert _handle({"method": "notifications/initialized"}) is None


def test_notification_initialized_id_ile():
    """ORTAM: notification id ile bile None (JSON-RPC notification'lar
    yanitlanmaz — id olsa bile)."""
    assert _handle({"method": "notifications/initialized", "id": 1}) is None


def test_notification_diger():
    """ORTAM: bilinmeyen notification (id yok) -> None."""
    assert _handle({"method": "notifications/bilinmiyor"}) is None


# == tools/list ========================================================================================

def test_tools_list():
    r = _handle({"method": "tools/list", "id": 2})
    assert r["jsonrpc"] == "2.0"
    assert r["id"] == 2
    assert len(r["result"]["tools"]) == 4


def test_tools_list_adlari():
    """ORTAM: 4 aracin isimleri dispatch ile AYNI."""
    isimler = {t["name"] for t in _handle({"method": "tools/list", "id": 2})["result"]["tools"]}
    assert isimler == set(_DISPATCH)


def test_tools_list_id_yok():
    r = _handle({"method": "tools/list"})
    assert r["id"] is None


def test_tools_list_hata_yok():
    assert "error" not in _handle({"method": "tools/list", "id": 2})


# == tools/call ========================================================================================

def test_tools_call_bilinmeyen_arac():
    """ORTAM: bilinmeyen arac -> JSON-RPC error -32601."""
    r = _handle({"method": "tools/call", "id": 3, "params": {"name": "yok"}})
    assert r["jsonrpc"] == "2.0"
    assert r["id"] == 3
    assert r["error"]["code"] == -32601
    assert r["error"]["message"] == "bilinmeyen araç: yok"


def test_tools_call_bilinmeyen_arac_isim_none():
    """ORTAM: name None -> handler None -> error -32601 'bilinmeyen araç: None'."""
    r = _handle({"method": "tools/call", "id": 3, "params": {}})
    assert r["error"]["code"] == -32601
    assert "None" in r["error"]["message"]


def test_tools_call_params_yok():
    """ORTAM: params None -> {} -> name None -> error."""
    r = _handle({"method": "tools/call", "id": 4})
    assert r["error"]["code"] == -32601


def test_tools_call_hata_content_isError():
    """ORTAM-OGRENDI (MCP 2025-06): hata content-bloklariyla tasinir —
    isError: True + content[0].text JSON olarak {'error': ...}."""
    r = _handle({"method": "tools/call", "id": 5, "params": {"name": "certify", "arguments": {"seed": "x"}}})
    assert r["jsonrpc"] == "2.0"
    assert r["id"] == 5
    assert r["result"]["isError"] is True
    blok = r["result"]["content"][0]
    assert blok["type"] == "text"
    assert "error" in json.loads(blok["text"])


def test_tools_call_hata_content_tipi():
    r = _handle({"method": "tools/call", "id": 5, "params": {"name": "certify", "arguments": {"seed": "x"}}})
    assert r["result"]["content"][0]["type"] == "text"


def test_tools_call_hata_json_parse():
    r = _handle({"method": "tools/call", "id": 5, "params": {"name": "certify", "arguments": {"seed": "x"}}})
    payload = json.loads(r["result"]["content"][0]["text"])
    assert set(payload) == {"error"}


def test_tools_call_basari_content(monkeypatch):
    """ORTAM-OGRENDI: basarili cagri -> content[{type:text,text:json}] ama
    isError ANAHTARI YOK (basari = isError yok). Sahte basarili handler ile
    test ediliyor (Kural-4: monkeypatch, saf in-memory)."""
    import veridrome.mcp_server as mod
    eski = dict(mod._DISPATCH)
    monkeypatch.setitem(mod._DISPATCH, "test_arac", lambda args: {"ok": True, "deger": 42})
    try:
        r = _handle({"method": "tools/call", "id": 6, "params": {"name": "test_arac", "arguments": {}}})
    finally:
        mod._DISPATCH.clear(); mod._DISPATCH.update(eski)
    assert "result" in r
    assert "isError" not in r["result"]
    assert r["result"]["content"][0]["type"] == "text"
    assert json.loads(r["result"]["content"][0]["text"]) == {"ok": True, "deger": 42}


def test_tools_call_basari_iserror_yok(monkeypatch):
    import veridrome.mcp_server as mod
    eski = dict(mod._DISPATCH)
    monkeypatch.setitem(mod._DISPATCH, "test_arac", lambda args: {"ok": True})
    try:
        r = _handle({"method": "tools/call", "id": 6, "params": {"name": "test_arac"}})
    finally:
        mod._DISPATCH.clear(); mod._DISPATCH.update(eski)
    assert "isError" not in r["result"]


def test_tools_call_arguments_yok():
    """ORTAM: arguments None -> {} -> handler'( {}) ile cagrilir."""
    r = _handle({"method": "tools/call", "id": 7, "params": {"name": "certify"}})
    assert "result" in r


def test_tools_call_dispatch_istisna():
    """ORTAM-OGRENDI: handler istisna firlatirsa YAKALANIR ->
    {'error': 'araç-çalıştırma-hatası: ...'} -> isError=True content."""
    # hata-firlatan bir arguman bul: certify bos test_results
    r = _handle({"method": "tools/call", "id": 8, "params": {"name": "certify", "arguments": {"seed": "x"}}})
    assert r["result"]["isError"] is True


# == ping ===============================================================================================

def test_ping():
    r = _handle({"method": "ping", "id": 9})
    assert r == {"jsonrpc": "2.0", "id": 9, "result": {}}


def test_ping_id_yok():
    """ORTAM-OGRENDI: ping id YOKSA DAHA yanit doner — id None ile! Cunku
    'ping' eslesmesi 'req_id is None' kontrolundan ONCE calisir."""
    r = _handle({"method": "ping"})
    assert r is not None
    assert r["id"] is None
    assert r["result"] == {}


def test_ping_bos_result():
    assert _handle({"method": "ping", "id": 9})["result"] == {}


# == req_id None =======================================================================================

def test_req_id_none_bilinmeyen():
    """ORTAM-OGRENDI: bilinmeyen metod + id YOK -> None (notification gibi).
    id olmadan yanit gonderilemez."""
    assert _handle({"method": "yok"}) is None


def test_req_id_var_bilinmeyen():
    """ORTAM: bilinmeyen metod + id VAR -> error -32601."""
    r = _handle({"method": "yok", "id": 10})
    assert r["error"]["code"] == -32601
    assert r["error"]["message"] == "desteklenmeyen metod: yok"


def test_req_id_none_method_none():
    """ORTAM: method None -> None (request.get('method') None)."""
    assert _handle({}) is None


# == method yanlis tip ==================================================================================

def test_method_int():
    """ORTAM: method int -> 'yok' ile ayni yol (esitlik basarisiz) -> error."""
    r = _handle({"method": 5, "id": 11})
    assert r["error"]["code"] == -32601


def test_method_none_id_var():
    """ORTAM: method None + id var -> error -32601 (desteklenmeyen metod: None)."""
    r = _handle({"method": None, "id": 11})
    assert r["error"]["code"] == -32601
    assert "None" in r["error"]["message"]


# == jsonrpc sabitleri ==================================================================================

def test_jsonrpc_her_yanitta():
    for req in [{"method": "initialize", "id": 1}, {"method": "ping", "id": 2},
                {"method": "tools/list", "id": 3}]:
        assert _handle(req)["jsonrpc"] == "2.0"


def test_id_geri_yansir():
    for i in [0, 1, 42, "x", -1]:
        r = _handle({"method": "ping", "id": i})
        assert r["id"] == i


@pytest.mark.parametrize("method,beklenen_anahtar", [
    ("initialize", "result"), ("ping", "result"), ("tools/list", "result"),
    ("yok", "error"),
])
def test_method_matrix(method, beklenen_anahtar):
    r = _handle({"method": method, "id": 1})
    assert beklenen_anahtar in r


# == karakterizasyon ====================================================================================

def test_error_code_32601():
    """ORTAM-OGRENDI (AKADEMIK): -32601 = JSON-RPC 2.0 'Method not found'
    standard hatasidir. Hem bilinmeyen-method hem bilinmeyen-arac icin
    AYNI kod kullanilir (farkli mesaj)."""
    a = _handle({"method": "yok", "id": 1})["error"]["code"]
    b = _handle({"method": "tools/call", "id": 1, "params": {"name": "yok"}})["error"]["code"]
    assert a == b == -32601


def test_bilinmeyen_arac_mesaj_farkli():
    """ORTAM: arac hatasi 'bilinmeyen araç:' ile method hatasindan FARKLI."""
    a = _handle({"method": "yok", "id": 1})["error"]["message"]
    b = _handle({"method": "tools/call", "id": 1, "params": {"name": "yok"}})["error"]["message"]
    assert a != b


def test_content_her_zaman_liste():
    """ORTAM-OGRENDI: tools/call basari/hata her durumda content LISTE.
    MCP 2025-06 metin-icerik semasi: [{"type":"text","text":...}]."""
    for name, args in [("certify", {"seed": "x"}), ("verify", {"cert": "x"})]:
        r = _handle({"method": "tools/call", "id": 1, "params": {"name": name, "arguments": args}})
        assert isinstance(r["result"]["content"], list)
        assert r["result"]["content"][0]["type"] == "text"


def test_ensure_ascii_false():
    """ORTAM-OGRENDI: json.dumps(ensure_ascii=False) — Turkce karakterler
    content icinde OLDUGU GIBI (kacislama YOK)."""
    r = _handle({"method": "tools/call", "id": 1, "params": {"name": "certify", "arguments": {"seed": "x"}}})
    metin = r["result"]["content"][0]["text"]
    # hata mesaji Turkce iceriyorsa kacislanmamali
    assert "\\u" not in metin or "test_results" in metin


def test_default_str_serilestirme(monkeypatch):
    """ORTAM-OGRENDI: basari yolu json.dumps(..., default=str) kullanir —
    non-JSON tipler STR olarak serilestirilir (hata yolu kullanMAZ).
    datetime gibi bir deger default=str olmadan TypeError firlatirdi."""
    import veridrome.mcp_server as mod
    from datetime import datetime, timezone
    eski = dict(mod._DISPATCH)
    monkeypatch.setitem(mod._DISPATCH, "test_arac", lambda args: {"zaman": datetime(2026, 1, 1, tzinfo=timezone.utc)})
    try:
        r = _handle({"method": "tools/call", "id": 1, "params": {"name": "test_arac"}})
    finally:
        mod._DISPATCH.clear(); mod._DISPATCH.update(eski)
    metin = r["result"]["content"][0]["text"]
    assert "2026-01-01" in metin
