"""
Veridrome CLI: Komut Satırı Arayüzü (Python 3.12+)
Sertifikasyon koşumu başlatma, çevrimdışı sertifika doğrulama ve görev listeleme.
"""

from __future__ import annotations
import argparse
import json
import sys
from typing import Any, Dict

from veridrome.core.crypto import VeridromeAuthoritySigner
from veridrome.runner import EvaluationRunner
from veridrome.tasks.registry import TaskRegistry


def command_list_tasks() -> int:
    registry = TaskRegistry()
    tasks = registry.list_all()
    print(f"\n🏛️ Veridrome Görev Havuzu v1.0 (Toplam {len(tasks)} Görev):\n")
    print(f"{'ID':<6} {'Kategori':<18} {'Havuz':<18} {'Başlık'}")
    print("-" * 75)
    for t in tasks:
        print(f"{t.task_id:<6} {t.category.value:<18} {t.pool_type.value:<18} {t.title}")
    print()
    return 0


def command_verify(cert_path: str, pubkey_b64: str) -> int:
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            vc = json.load(f)
    except Exception as e:
        print(f"❌ Sertifika dosyası açılamadı: {e}")
        return 1

    proof = vc.get("proof", {})
    sig_b64 = proof.get("proofValue")
    if not sig_b64:
        print("❌ Sertifikada imza ('proofValue') bulunamadı.")
        return 1

    # Kanıt objesini ayırıp kanonik gövdeyi doğrula
    vc_copy = dict(vc)
    del vc_copy["proof"]
    canonical_bytes = json.dumps(vc_copy, sort_keys=True).encode("utf-8")

    import base64
    try:
        pubkey_bytes = base64.b64decode(pubkey_b64)
        sig_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        print(f"❌ Base64 çözme hatası: {e}")
        return 1

    is_valid = VeridromeAuthoritySigner.verify(pubkey_bytes, canonical_bytes, sig_bytes)
    if is_valid:
        subject = vc.get("credentialSubject", {})
        metrics = subject.get("metrics", {})
        print("\n✅ SERTİFİKA GEÇERLİ (Doğrulandı)")
        print(f"• Ajan Kimliği: {subject.get('id')}")
        print(f"• Medyan Başarı: %{metrics.get('medianSuccess', 0) * 100:.2f}")
        print(f"• Anomali Skoru: {metrics.get('anomalyScore')}")
        print(f"• Merkle Kökü: {subject.get('merkleRoot')}")
        print(f"• Son Geçerlilik: {vc.get('validUntil')}\n")
        return 0
    else:
        print("\n❌ SERTİFİKA İMZASI GEÇERSİZ!\n")
        return 1


def command_run_evaluation(
    agent_type: str = "honest",
    endpoint: Optional[str] = None,
    agent_id: Optional[str] = None,
    runs_per_task: int = 3,
) -> int:
    resolved_id = agent_id or f"urn:kredent:agent:{'live' if endpoint else 'profile'}-{agent_type}"
    print(f"\n🏛️ Veridrome Değerlendirme Koşumu Başlatılıyor...")
    print(f"• Ajan Kimliği: {resolved_id}")
    if endpoint:
        print(f"• Canlı Uç Nokta: {endpoint}")
    else:
        print(f"• Simülasyon Profili: {agent_type}")
    print(f"• Görev Başına Koşum: {runs_per_task} (n={runs_per_task * 20} Bernoulli adımı)\n")

    runner = EvaluationRunner()

    import httpx

    def executor_fn(task: Any, run_idx: int):
        if endpoint:
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(
                        endpoint,
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
                            float(data.get("latency_sec", 11.5)),
                            float(data.get("cost_usd", 0.04)),
                            data.get("actions", ["click", "type", "submit"]),
                        )
                    else:
                        return False, 5.0, 0.0, [f"http_error_{resp.status_code}"]
            except Exception as e:
                return False, 5.0, 0.0, ["connection_error"]

        # Deterministik referans profilleri
        is_public = (task.pool_type.value == "PUBLIC_CANARY")
        if agent_type == "honest":
            passed = True
            lat = 12.0 + (run_idx * 0.5)
            cost = 0.04
            actions = ["click", "type", "submit"]
        elif agent_type == "overfit":
            passed = True if is_public else False
            lat = 8.0 if is_public else 24.0
            cost = 0.02 if is_public else 0.40
            actions = ["click", "type"] if is_public else ["random_guess", "scroll", "error"]
        else:
            passed = False
            lat = 60.0
            cost = 0.50
            actions = ["loop", "loop", "fail"]
        return passed, lat, cost, actions

    report = runner.run_evaluation(
        agent_id=resolved_id,
        task_executor_fn=executor_fn,
        runs_per_task=runs_per_task,
    )

    print(f"• Koşum Kimliği (Job ID): {report.job_id}")
    print(f"• Medyan Başarı Oranı: %{report.median_success_rate * 100:.2f}")
    print(f"• IQR Varyansı: %{report.iqr_success_rate * 100:.2f}")
    print(f"• Görev Başı Maliyet: ${report.mean_cost_per_task:.4f}")
    print(f"• P95 Gecikme: {report.p95_latency_sec:.2f}s")
    print(f"• Anomali Skoru: {report.anti_gaming.anomaly_score}")
    print(f"• Anti-Gaming Hükmü: {report.anti_gaming.verdict}")
    print(f"• TEE Donanım Tasdiki: {'GEÇERLİ' if report.tee_valid else 'BAŞARISIZ'}")
    print(f"• Merkle Kökü: {report.merkle_root}")
    print(f"• Nihai Sertifikasyon Durumu: {'✅ ONAYLANDI' if report.is_certified else '❌ REDDEDİLDİ'}")
    if report.rejection_reason:
        print(f"• Ret Nedeni: {report.rejection_reason}")
    print()
    return 0 if report.is_certified else 2


# Geriye dönük uyumluluk için alias
command_run_mock = command_run_evaluation


def command_serve(host: str = "127.0.0.1", port: int = 8000) -> int:
    import uvicorn
    from veridrome.server.api import app
    print(f"\n🚀 Veridrome API & Sovereign Arena Dashboard Başlatılıyor...")
    print(f"• URL: http://{host}:{port}")
    print(f"• Dokümantasyon (Swagger): http://{host}:{port}/docs")
    print(f"• Kapatmak için Ctrl+C'ye basın.\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Veridrome Autonomous Agent Benchmark & Certification CLI")
    subparsers = parser.add_subparsers(dest="subcommand")

    # list-tasks
    subparsers.add_parser("list-tasks", help="Tüm 20 doğrulama görevini listeler")

    # serve
    serve_parser = subparsers.add_parser("serve", help="FastAPI REST API ve Web Dashboard'u başlatır")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bağlanılacak host adresi")
    serve_parser.add_argument("--port", type=int, default=8000, help="Bağlanılacak port numarası")

    # run
    run_parser = subparsers.add_parser("run", help="Ajan değerlendirme koşumu başlatır (canlı endpoint veya profil)")
    run_parser.add_argument("--endpoint", default=None, help="Canlı Ajan HTTP/REST uç noktası URL'i")
    run_parser.add_argument("--agent-id", default=None, help="Ajan DID / ERC-8004 kimliği")
    run_parser.add_argument("--agent-type", "--profile", dest="agent_type", choices=["honest", "overfit", "failing"], default="honest", help="Simülasyon profili")
    run_parser.add_argument("--runs-per-task", type=int, default=3, help="Görev başına tekrar sayısı (n)")

    # verify
    verify_parser = subparsers.add_parser("verify", help="W3C Verifiable Credential sertifikasını doğrular")
    verify_parser.add_argument("cert_file", help="Sertifika JSON dosya yolu")
    verify_parser.add_argument("--pubkey", required=True, help="Base64 formatında Ed25519 otorite açık anahtarı")

    args = parser.parse_args()

    if args.subcommand == "list-tasks":
        sys.exit(command_list_tasks())
    elif args.subcommand == "serve":
        sys.exit(command_serve(args.host, args.port))
    elif args.subcommand == "run":
        sys.exit(command_run_evaluation(
            agent_type=args.agent_type,
            endpoint=args.endpoint,
            agent_id=args.agent_id,
            runs_per_task=args.runs_per_task,
        ))
    elif args.subcommand == "verify":
        sys.exit(command_verify(args.cert_file, args.pubkey))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
