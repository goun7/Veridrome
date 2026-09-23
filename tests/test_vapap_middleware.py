import time
import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from veridrome.core.crypto import VeridromeAuthoritySigner
from veridrome.credentials.vapap_middleware import VAPAPAuthMiddleware
from veridrome.credentials.w3c_vc import VeridromeCredentialManager


def create_protected_test_app(signer: VeridromeAuthoritySigner):
    app = FastAPI()
    app.add_middleware(
        VAPAPAuthMiddleware,
        authority_public_key=signer.public_key_bytes,
        required_min_score=0.85,
        exempt_paths=["/healthz"],
    )

    @app.get("/healthz")
    def public_endpoint():
        return {"status": "ok"}

    @app.get("/api/secure/checkout")
    def secure_checkout(request: Request):
        return {
            "status": "APPROVED",
            "agent_id": getattr(request.state, "agent_id", None),
        }

    return app


def test_vapap_middleware_flow():
    signer = VeridromeAuthoritySigner()
    cred_mgr = VeridromeCredentialManager(signer=signer)
    app = create_protected_test_app(signer)
    client = TestClient(app)

    # 1. Muaf uç nokta token gerektirmez
    res = client.get("/healthz")
    assert res.status_code == 200

    # 2. Token olmadan korunan uç nokta -> 401 Unauthorized
    res = client.get("/api/secure/checkout")
    assert res.status_code == 401
    assert res.json()["error"] == "VAPAP_TOKEN_MISSING"

    # 3. Geçerli token ile başarılı yetkilendirme -> 200 OK
    valid_token = cred_mgr.create_vapap_token(
        agent_id="urn:kredent:agent:acme-bot-1",
        cert_id="cert-9821",
        score_median=0.94,
        expires_in_sec=3600,
    )
    res = client.get(
        "/api/secure/checkout",
        headers={"X-Veridrome-VAPAP-Token": valid_token},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "APPROVED"
    assert res.json()["agent_id"] == "urn:kredent:agent:acme-bot-1"

    # 4. Yetersiz puanlı ajan token'ı -> 403 Forbidden
    low_score_token = cred_mgr.create_vapap_token(
        agent_id="urn:kredent:agent:bad-bot",
        cert_id="cert-0001",
        score_median=0.65,  # 0.85 barajının altında
        expires_in_sec=3600,
    )
    res = client.get(
        "/api/secure/checkout",
        headers={"X-Veridrome-VAPAP-Token": low_score_token},
    )
    assert res.status_code == 403
    assert res.json()["error"] == "VAPAP_INSUFFICIENT_SCORE"

    # 5. Süresi dolmuş token -> 403 Forbidden
    expired_token = cred_mgr.create_vapap_token(
        agent_id="urn:kredent:agent:old-bot",
        cert_id="cert-old",
        score_median=0.95,
        expires_in_sec=-10,  # Geçmiş tarih
    )
    res = client.get(
        "/api/secure/checkout",
        headers={"X-Veridrome-VAPAP-Token": expired_token},
    )
    assert res.status_code == 403
    assert res.json()["error"] == "VAPAP_TOKEN_EXPIRED"
