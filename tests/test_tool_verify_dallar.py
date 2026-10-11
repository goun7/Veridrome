"""73-Veridrome mcp_server._tool_verify dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (verify_certificate/check_revoked MONKEYPATCH — dis cagri YOK).
MCP tool: certificate dogrulama + iptal-kontrolu.
"""
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, ".")
sys.path.insert(0, "src")
from veridrome import mcp_server  # noqa: E402
from veridrome.mcp_server import _tool_verify, _error  # noqa: E402


def _result(valid=True, errors=None):
    """Fake verify_certificate result."""
    return SimpleNamespace(to_dict=lambda: {
        "valid": valid,
        "errors": list(errors or []),
        "digest": "abc",
    })


def _ok(monkeypatch, valid=True, errors=None):
    monkeypatch.setattr(mcp_server, "verify_certificate",
                        lambda c: _result(valid, errors))


@pytest.fixture()
def fx(monkeypatch):
    return monkeypatch


# == certificate tip-kontrolu ==========================================================================

def test_cert_str_hata():
    """ORTAM: certificate str -> hata."""
    r = _tool_verify({"certificate": "x"})
    assert r == {"error": "certificate bir JSON nesnesi olmalı"}


def test_cert_none():
    """ORTAM: certificate None -> hata."""
    r = _tool_verify({"certificate": None})
    assert "error" in r


def test_cert_eksik():
    """ORTAM: certificate anahtari YOK -> hata."""
    r = _tool_verify({})
    assert "error" in r


def test_cert_list():
    r = _tool_verify({"certificate": [1]})
    assert "error" in r


def test_cert_int():
    r = _tool_verify({"certificate": 42})
    assert "error" in r


def test_error_msg_icerik():
    r = _error("test-msg")
    assert r == {"error": "test-msg"}


def test_error_returns_dict():
    assert isinstance(_error("x"), dict)


# == gecerli dogrulama =================================================================================

def test_gecerli_cert(fx):
    _ok(fx, valid=True)
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["valid"] is True
    assert r["digest"] == "abc"


def test_cert_id_eklenir(fx):
    """ORTAM: out['cert_id'] = cert.get('cert_id')."""
    _ok(fx)
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["cert_id"] == "c1"


def test_cert_id_eksik(fx):
    """ORTAM: cert_id YOK -> None."""
    _ok(fx)
    r = _tool_verify({"certificate": {}})
    assert r["cert_id"] is None


def test_gecersiz_cert(fx):
    _ok(fx, valid=False, errors=["imza-hata"])
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["valid"] is False
    assert "imza-hata" in r["errors"]


def test_errors_listesi(fx):
    _ok(fx, valid=False, errors=["a", "b"])
    r = _tool_verify({"certificate": {}})
    assert r["errors"] == ["a", "b"]


def test_bos_errors(fx):
    _ok(fx)
    r = _tool_verify({"certificate": {}})
    assert r["errors"] == []


# == check_revocation ==================================================================================

def test_revocation_default_true(fx):
    """ORTAM: check_revocation default True (iptal-kontrolu yapilir)."""
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    cekildi = []
    fx.setattr(mcp_server, "check_revoked",
                lambda cid, *a, **k: cekildi.append(cid) or {"revoked": False})
    _tool_verify({"certificate": {"cert_id": "c1"}})
    assert cekildi == ["c1"]


def test_revocation_false_atlanir(fx):
    """ORTAM: check_revocation=False -> kontrol ATLANIR."""
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    cekildi = []
    fx.setattr(mcp_server, "check_revoked",
                lambda cid, *a, **k: cekildi.append(cid) or {"revoked": False})
    r = _tool_verify({"certificate": {"cert_id": "c1"},
                      "check_revocation": False})
    assert cekildi == []
    assert "revocation" not in r


def test_revoked_false_gecerli(fx):
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    fx.setattr(mcp_server, "check_revoked",
               lambda cid, *a, **k: {"revoked": False})
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["revocation"] == {"revoked": False}
    assert r["valid"] is True


def test_revoked_true_gecersiz(fx):
    """ORTAM: revoked -> valid=False + errors'a ek."""
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    fx.setattr(mcp_server, "check_revoked",
               lambda cid, *a, **k: {"revoked": True, "reason": "kullanici"})
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["valid"] is False
    assert any("iptal" in str(e) for e in r["errors"])


def test_revoked_true_errors_uzar(fx):
    fx.setattr(mcp_server, "verify_certificate",
               lambda c: _result(errors=["a"]))
    fx.setattr(mcp_server, "check_revoked",
               lambda cid, *a, **k: {"revoked": True, "reason": "x"})
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert len(r["errors"]) == 2


def test_revocation_kopyasi(fx):
    """ORTAM: out['revocation'] = rev (referans)."""
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    rev = {"revoked": False}
    fx.setattr(mcp_server, "check_revoked", lambda cid, *a, **k: rev)
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["revocation"] is rev


# == cesitli ==========================================================================================

def test_returns_dict(fx):
    _ok(fx)
    assert isinstance(_tool_verify({"certificate": {}}), dict)


def test_to_dict_korunur(fx):
    """ORTAM: result.to_dict() butun anahtarlar korunur."""
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    r = _tool_verify({"certificate": {}})
    assert "digest" in r


def test_extra_args_yoksay(fx):
    _ok(fx)
    r = _tool_verify({"certificate": {}, "extra": "x"})
    assert "extra" not in r


def test_cert_kullanilmaz(fx):
    """ORTAM: production degil — verify_certificate cagrilir."""
    calls = []
    fx.setattr(mcp_server, "verify_certificate",
               lambda c: calls.append(c) or _result())
    _tool_verify({"certificate": {"cert_id": "c1"}})
    assert calls == [{"cert_id": "c1"}]


def test_repeatable(fx):
    _ok(fx)
    a = _tool_verify({"certificate": {"cert_id": "c1"}})
    b = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert a["valid"] == b["valid"]


@pytest.mark.parametrize("bad", ["x", None, [1], 42, 3.14, True, (1,)])
def test_bad_cert_matrix(bad):
    r = _tool_verify({"certificate": bad})
    assert "error" in r


@pytest.mark.parametrize("revoked", [True, False])
def test_revocation_matrix(fx, revoked):
    fx.setattr(mcp_server, "verify_certificate", lambda c: _result())
    fx.setattr(mcp_server, "check_revoked",
               lambda cid, *a, **k: {"revoked": revoked})
    r = _tool_verify({"certificate": {"cert_id": "c1"}})
    assert r["valid"] is not revoked
