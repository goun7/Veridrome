import json
import pytest
from starlette.testclient import TestClient
from veridrome.server.api import create_app


def test_api_server_endpoints():
    app = create_app()
    client = TestClient(app)

    # 0. Web Dashboard
    res = client.get("/")
    assert res.status_code == 200
    assert "VERIDROME" in res.text
    assert "ARENA" in res.text
    assert "text/html" in res.headers["content-type"]

    # 1. Health check
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # 2. Submit evaluation
    payload = {
        "agent_id": "urn:kredent:agent:0x98f12a4b8823",
        "endpoint_url": "https://agent.acme.ai/v1/act",
        "runtime_manifest": {
            "model": "claude-3-5-sonnet-20241022",
            "cost_cap_usd": 10.0,
        },
    }
    res = client.post("/v1/evaluations/submit", json=payload)
    assert res.status_code == 202
    data = res.json()
    assert "job_id" in data
    job_id = data["job_id"]

    # 3. Stream SSE events
    res = client.get(f"/v1/evaluations/{job_id}/stream")
    assert res.status_code == 200
    assert "JOB_STARTED" in res.text

    # AT-188: submit-evaluation-SENKRON-dur: fonksiyon-dönmeden-önce-sertifika
    # certificates_db'ye-yazılır. job_id-çağıran-tarafından-belirlenip-koşucuya
    # aktarılır-ki-saniye-sınırı-aşımında-farklı-job_id-üretilip-404-dönmesin
    # ( eski-yarış-koşulu). Artık-bekleme/anket-gerekmez.
    cert_id = f"urn:veridrome:cert:{job_id}"
    res = client.get(f"/v1/certificates/{cert_id}")
    assert res.status_code == 200
    cert_data = res.json()
    assert cert_data["id"] == cert_id

    # 5. Verify certificate
    res = client.get(f"/v1/certificates/{cert_id}/verify")
    assert res.status_code == 200
    assert res.json()["is_valid"] is True

    # 6. Revoke certificate
    res = client.post(f"/v1/certificates/{cert_id}/revoke", json={"reason": "Security exploit detected"})
    assert res.status_code == 200
    assert res.json()["is_revoked"] is True

    # 7. Re-verify revoked certificate
    res = client.get(f"/v1/certificates/{cert_id}/verify")
    assert res.status_code == 200
    assert res.json()["is_valid"] is False
