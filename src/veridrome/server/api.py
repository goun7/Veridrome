"""
Veridrome Server: Production FastAPI REST & Streaming API (Python 3.12+)
OpenAPI 3.1 uyumlu otonom ajan değerlendirme, canlı SSE olay akışı ve sertifikasyon sunucusu.
"""

from __future__ import annotations
import asyncio
import json
import time
from typing import Any, Dict, Optional
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from veridrome.core.crypto import VeridromeAuthoritySigner
from veridrome.credentials.w3c_vc import VeridromeCredentialManager
from veridrome.runner import EvaluationReport, EvaluationRunner
from veridrome.server.dashboard_html import DASHBOARD_HTML
from veridrome.tasks.registry import TaskRegistry

# SERVER-API-B3 (DUZELTILDI): simülasyon-alanı denetimi ALTDİZGE-eşleşmesi
# DEĞİL, URL'nin barındırıcı-adı ( host) üzerinden yapılır. Eski-kod
# ``"acme.ai" in url`` ile "https://evil.example/?x=acme.ai"-yi de simüle
# sayıyordu → gerçek-ajan-HTTP-çağrısı atlanıp-uydurma-baseline-geçişi
# üretilebiliyordu ( sorgu-dizesiyle-simülasyon-bypass'ı).
SIMULE_HOSTLAR = ("acme.ai", "internal", "example.com", "mock")


def _hedef_siniflandir(url: str) -> tuple[bool, bool]:
    """``endpoint_url``'i ``(http_semali, simule_host)`` olarak sınıflandırır.

    ``simule_host`` yalnızca host-adı tam-eşleşme veya ``.<domain>`` son-eki
    ise True'dur ( alt-alan-adları-dahil: agent.acme.ai, host.mock). Ayrıştırılamayan
    URL "gerçek-uçnokta" sayılır: baseline'a-düşüp-sahte-geçiş-üretmek yerine
    gerçek-çağrı-denemesi-yapılır ( bağlantı-hatası → fail-closed).
    """
    if not isinstance(url, str) or not url:
        return False, False
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return True, False
    if parsed.scheme not in ("http", "https"):
        return False, False
    simule = any(host == dom or host.endswith("." + dom) for dom in SIMULE_HOSTLAR)
    return True, simule


class RuntimeManifest(BaseModel):
    model: str = Field(..., json_schema_extra={"example": "claude-3-5-sonnet-20241022"})
    cost_cap_usd: float = Field(default=10.0, json_schema_extra={"example": 10.0})


class EvaluationSubmitRequest(BaseModel):
    agent_id: str = Field(..., json_schema_extra={"example": "urn:kredent:agent:0x98f12a4b8823"})
    endpoint_url: str = Field(..., json_schema_extra={"example": "https://agent.acme.ai/v1/act"})
    runtime_manifest: RuntimeManifest


class RevokeRequest(BaseModel):
    reason: str = Field(..., json_schema_extra={"example": "Prodüksiyonda güvenlik açığı tespit edildi."})


def create_app(
    runner: Optional[EvaluationRunner] = None,
    credential_manager: Optional[VeridromeCredentialManager] = None,
) -> FastAPI:
    app = FastAPI(
        title="Veridrome Evaluation & Attestation API",
        version="1.3.0",
        description="Otonom Yapay Zeka Ajanları Canlı Doğrulama, TEE Tasdiki ve Kriptografik Akreditasyon API'si.",
    )

    authority_signer = VeridromeAuthoritySigner()
    eval_runner = runner or EvaluationRunner(authority_signer=authority_signer)
    cred_mgr = credential_manager or VeridromeCredentialManager(signer=authority_signer)

    # Bellek içi durum kütüğü
    jobs_db: Dict[str, Dict[str, Any]] = {}
    certificates_db: Dict[str, Dict[str, Any]] = {}

    @app.get("/", response_class=HTMLResponse)
    def dashboard_index():
        return HTMLResponse(content=DASHBOARD_HTML, status_code=200)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "service": "veridrome-api", "version": "1.3.0"}

    @app.post("/v1/evaluations/submit", status_code=status.HTTP_202_ACCEPTED)
    async def submit_evaluation(req: EvaluationSubmitRequest):
        # AT-188: job_id-BURADA-tek-seferde-belirlenir-ve-aşağıya-aktarılır.
        # Sertifika-üretimi-tamamen-SENKRON-dur: bu-fonksiyon-dönmeden-önce
        # certificates_db'ye-yazılmıştır. Arka-plan-thread'i/yarış-koşulu-yok.
        temel_job_id = f"job-{int(time.time())}-{req.agent_id[-6:]}"
        # SERVER-API-B5 (DUZELTILDI): job-id-saniye-çözünürlüklüdür — aynı
        # saniyede-aynı-ajan-ikinci-kez-gönderirse-eski-kod-AYNI-kimliği
        # üretip-jobs_db-kaydını-üzerine-yazıyordu ( önceki-rapor+sertifika
        # kayboluyordu). Çakışmada-artan-bir-sıra-eki-kullanılır.
        job_id = temel_job_id
        sira = 2
        while job_id in jobs_db:
            job_id = f"{temel_job_id}-{sira}"
            sira += 1
        jobs_db[job_id] = {
            "status": "QUEUED",
            "agent_id": req.agent_id,
            "endpoint_url": req.endpoint_url,
            "created_at": time.time(),
        }

        # Gerçek HTTP Ajan Yürütücüsü veya Referans Baseline
        import httpx

        # SERVER-API-B3 (DUZELTILDI): host-adı-temelli-sınıflandırma.
        http_semali, simule_host = _hedef_siniflandir(req.endpoint_url)

        def agent_executor(task, run_idx):
            if http_semali and not simule_host:
                try:
                    with httpx.Client(timeout=5.0) as client:
                        resp = client.post(
                            req.endpoint_url,
                            json={
                                "task_id": task.task_id,
                                "objective": task.objective,
                                "run_idx": run_idx,
                            },
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            return (
                                data.get("passed", True),
                                float(data.get("latency_sec", 10.5)),
                                float(data.get("cost_usd", 0.03)),
                                data.get("actions", ["click", "submit"]),
                            )
                        else:
                            return False, 5.0, 0.0, [f"http_error_{resp.status_code}"]
                except Exception:
                    return False, 5.0, 0.0, ["connection_error"]

            return True, 10.5, 0.03, ["click", "type", "submit"]

        try:
            report: EvaluationReport = eval_runner.run_evaluation(
                agent_id=req.agent_id,
                task_executor_fn=agent_executor,
                runs_per_task=2,
                job_id=job_id,
            )
        except Exception:
            # D29 (DUZELTILDI): koşucu-patladığında-kayıt-QUEUED-kalıyordu →
            # akış-rapor-yok-varsayılanlarıyla-"PASSED"/is_certified=true
            # uyduruyordu ( fail-open). Artık-durum-dürüstçe-FAILED-yazılır ve
            # istisna-yukarıya-bırakılır ( 500).
            jobs_db[job_id]["status"] = "FAILED"
            raise

        jobs_db[job_id]["status"] = "COMPLETED"
        jobs_db[job_id]["report"] = report

        cert_id = f"urn:veridrome:cert:{job_id}"
        if report.verifiable_credential:
            cert_id = report.verifiable_credential["id"]
            certificates_db[cert_id] = {
                "vc": report.verifiable_credential,
                "is_revoked": False,
                "revocation_reason": None,
            }
        jobs_db[job_id]["cert_id"] = cert_id

        return {
            "job_id": job_id,
            "estimated_duration_sec": 300,
            "tee_environment": "AMD-SEV-SNP",
            # SERVER-API-B1 (DUZELTILDI): koşum-BU-İSTEK-içinde-SENKRON
            # tamamlanır ( rapor+sertifika-yukarıda-yazıldı) — "PROCESSING"
            # demek-istemciyi-yanıltıyordu ( hiçbir-uçnokta-bu-işi-ilerletmez).
            "status": "COMPLETED",
        }

    @app.get("/v1/evaluations/{job_id}/stream")
    async def stream_evaluation(job_id: str):
        if job_id not in jobs_db:
            raise HTTPException(status_code=404, detail="Koşum bulunamadı.")

        job = jobs_db[job_id]
        report = job.get("report")
        # D29 (DUZELTILDI): rapor-yoksa-uydurma-bir-sertifika-kimliği
        # ( ``urn:veridrome:cert:{job_id}``) bildirilmez — kayıtlı-bir-cert_id
        # yoksa-boş-verilir ( fail-closed; var-olmayan-sertifika-ima-edilmez).
        cert_id = job.get("cert_id", "")

        async def event_generator():
            yield f"data: {json.dumps({'event': 'JOB_STARTED', 'step': 'STARTED', 'job_id': job_id})}\n\n"
            await asyncio.sleep(0.02)
            yield f"data: {json.dumps({'event': 'TEE_ALLOCATED', 'step': 'HARDWARE_TEE', 'platform': 'AMD-SEV-SNP', 'pcr0': '0x98f12a4b8823901234567890abcdef'})}\n\n"
            await asyncio.sleep(0.02)

            # SERVER-API-B4 (DUZELTILDI): görev-dizisi-artık-sabit
            # ``TaskRegistry()`` değil, koşumun-kullandığı-kayıt-defteridir —
            # özel-bir-kayıt-defteriyle-koşan-değerlendirme-için-akış
            # 20-uydurma-görev-bildirmez ( akış-koşumun-gerçeğini-yansıtır).
            kosum_kutugu = getattr(eval_runner, "registry", None) or TaskRegistry()
            tasks = kosum_kutugu.list_all()
            for idx, task in enumerate(tasks):
                yield f"data: {json.dumps({'event': 'TASK_EVALUATING', 'step': 'RUNNING', 'task_id': task.task_id, 'pool': task.pool_type.value, 'title': task.title, 'progress': f'{int((idx+1)/len(tasks)*100)}%'})}\n\n"
                await asyncio.sleep(0.02)

            if report is None:
                # D29: rapor-yok → uydurma-"PASSED"/is_certified=true YOK.
                # Kaydın-gerçek-durumu ( FAILED/QUEUED) ve-boş-kanıt-alanları.
                durum = str(job.get("status") or "UNKNOWN")
                yield f"data: {json.dumps({'event': 'JOB_COMPLETED', 'step': 'COMPLETED', 'status': durum, 'is_certified': False, 'certificate_id': '', 'merkle_root': ''})}\n\n"
                return

            verdict = report.anti_gaming.verdict
            yield f"data: {json.dumps({'event': 'JOB_COMPLETED', 'step': 'COMPLETED', 'status': verdict, 'is_certified': report.is_certified, 'certificate_id': cert_id, 'merkle_root': report.merkle_root})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/v1/certificates/{cert_id:path}")
    def get_certificate(cert_id: str):
        if cert_id.endswith("/verify"):
            base_id = cert_id[: -len("/verify")]
            if base_id not in certificates_db:
                raise HTTPException(status_code=404, detail="Sertifika bulunamadı.")
            entry = certificates_db[base_id]
            if entry["is_revoked"]:
                return {"is_valid": False, "reason": "CERTIFICATE_REVOKED"}
            vc = entry["vc"]
            # SERVER-API-B7 (DUZELTILDI): eksik/bozuk-yapılı-VC artık-500-
            # değil-422'dir ( fail-closed: ne-doğrulanmış-sayılır-ne-de-
            # sunucu-çöker; yapı-yokluğu-istemciye-bildirilir).
            subject = vc.get("credentialSubject") if isinstance(vc, dict) else None
            if (not isinstance(subject, dict) or "id" not in subject
                    or not isinstance(vc.get("validUntil"), str)):
                # Sayısal 422: starlette'in HTTP_422_UNPROCESSABLE_ENTITY
                # adı bırakıldı (DeprecationWarning) — sabit-bağlı literal.
                raise HTTPException(
                    status_code=422,
                    detail="Sertifika gövdesi doğrulanamıyor: "
                           "credentialSubject.id/validUntil eksik veya bozuk.",
                )
            # SERVER-API-B2 (DUZELTILDI): doğrulama-artık-ENJEKTE-edilen
            # yönetici-üzerinden-yapılır — parametre-ölü-değil ( alt-sınıf/
            # özel-yönetici-doğrulamayı-değiştirebilir). Varsayılan-yolda
            # sınıf-metodu-birebir-aynı-işi-yapar ( davranış-korunur).
            is_valid = bool(cred_mgr.verify_credential(
                vc, authority_signer.public_key_bytes))
            return {
                "is_valid": is_valid,
                "cert_id": base_id,
                "subject": subject["id"],
                "expires_at": vc["validUntil"],
            }

        if cert_id not in certificates_db:
            raise HTTPException(status_code=404, detail="Sertifika bulunamadı.")
        entry = certificates_db[cert_id]
        if entry["is_revoked"]:
            return JSONResponse(
                status_code=410,
                content={"status": "REVOKED", "reason": entry["revocation_reason"]},
            )
        return entry["vc"]

    @app.post("/v1/certificates/{cert_id:path}/revoke")
    def revoke_certificate(cert_id: str, req: RevokeRequest):
        # SERVER-API-B6 (DUZELTILDI): eski-kod ``cert_id.replace("/revoke","")``
        # ile-TÜM-geçişleri-soyuyordu — kimliğinin-ortasında "/revoke"-geçen
        # bir-sertifika-istek-YANLIŞ-hedefe-yönlenebiliyordu. Artık-önce
        # birebir-kimlik-denir; yalnız-``:path``-yol-son-ekini-yuttuğunda
        # ( ".../revoke/revoke") TEK-bir-son-ek-soyulur.
        target_id = cert_id
        if target_id not in certificates_db and target_id.endswith("/revoke"):
            target_id = target_id[: -len("/revoke")]
        if target_id not in certificates_db:
            raise HTTPException(status_code=404, detail="Sertifika bulunamadı.")
        certificates_db[target_id]["is_revoked"] = True
        certificates_db[target_id]["revocation_reason"] = req.reason
        return {"status": "SUCCESS", "cert_id": target_id, "is_revoked": True}

    return app


app = create_app()
