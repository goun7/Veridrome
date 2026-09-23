import urllib.request
import json
import pytest
from veridrome.server.sandbox_app import SandboxServer


def test_sandbox_server_lifecycle_and_endpoints():
    server = SandboxServer(host="127.0.0.1", port=0)
    base_url = server.start()
    assert server.actual_port > 0

    try:
        # GET /healthz
        with urllib.request.urlopen(f"{base_url}/healthz") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"

        # GET /ecom/cart
        with urllib.request.urlopen(f"{base_url}/ecom/cart") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "Alışveriş Sepeti" in html
            assert "$74.50" in html

        # GET /ecom/product/101 (T02)
        with urllib.request.urlopen(f"{base_url}/ecom/product/101") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "Stokta Muadil" in html

        # GET /saas/invoices (T06)
        with urllib.request.urlopen(f"{base_url}/saas/invoices") as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
            assert "14" in html

        # POST /api/card/limit (T12)
        req_limit = urllib.request.Request(
            f"{base_url}/api/card/limit",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_limit) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "LIMIT_UPDATED"
            assert data["new_limit"] == 5000

        # POST /api/checkout/confirm
        req = urllib.request.Request(
            f"{base_url}/api/checkout/confirm",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "CONFIRMED"

    finally:
        server.stop()
