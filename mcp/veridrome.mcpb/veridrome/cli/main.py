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

from typing import Optional  # noqa: E402  ( tip-ekleri için)

from veridrome.certificate.core import (
    CertificateBuilder,
    verify_certificate,
    hash_files,
)
from veridrome.certificate.didkey import generate_keypair, keypair_from_seed
from veridrome.certificate.revocation import RevocationLedger, check_revoked


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


def command_verify(
    cert_path: str,
    pubkey_b64: Optional[str] = None,
    ledger_path: Optional[str] = None,
) -> int:
    """Sertifikayı bağımsız olarak doğrular.

    did:key-imzalı sertifikalar için --pubkey GEREKMEZ: doğrulama anahtarı
    sertifikanın ``issuer`` alanından kurtarılır ( self-resolving). Eski
    W3C-VC sertifikaları için --pubkey hâlâ kullanılabilir.
    """
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            vc = json.load(f)
    except Exception as e:
        print(f"❌ Sertifika dosyası açılamadı: {e}")
        return 1

    # --- yol-1: did:key-imzalı test-geçişi sertifikası ---------------------
    types = vc.get("type", [])
    if isinstance(types, list) and "VeridromeTestPassCertificate" in types:
        result = verify_certificate(vc)
        # İptal-defteri: --ledger verilmezse VERIDROME_HOME altındaki varsayılan
        # deftere düşer ( command_revoke tam-olarak-oraya yazar). defter-yoksa
        # iptal-denetimi yapılmaz ( None → revoked=False).
        ledger = None
        if ledger_path:
            ledger = RevocationLedger(ledger_path)
        else:
            import os as _os
            _home = _os.environ.get(
                "VERIDROME_HOME", _os.path.join(_os.path.expanduser("~"), ".veridrome")
            )
            _default_ledger = _os.path.join(_home, "revocations.jsonl")
            if _os.path.exists(_default_ledger):
                ledger = RevocationLedger(_default_ledger)
        rev = check_revoked(str(vc.get("cert_id", "")), ledger)
        if rev.get("revoked"):
            result.valid = False
            result.errors.append(
                f"sertifika iptal edilmiş: {rev.get('reason') or 'neden-belirtilmemiş'}"
            )
        subj = vc.get("credentialSubject", {})
        summ = subj.get("summary", {})
        if result.valid:
            print("\n✅ SERTİFİKA GEÇERLİ ( bağımsız doğrulama — did:key)")
            print(f"• Sertifika Kimliği: {vc.get('cert_id','')[:32]}…")
            print(f"• İmzalayan ( DID): {vc.get('issuer')}")
            print(f"• İmza Zamanı ( UTC): {vc.get('proof',{}).get('created')}")
            print(f"• Geçerlilik: {vc.get('validFrom')} → {vc.get('validUntil')}")
            print(f"• Repo Commit: {subj.get('repo',{}).get('commit')}")
            print(f"• Testler: {summ.get('passed')} passed / {summ.get('total')} "
                  f"( failed={summ.get('failed')}, skipped={summ.get('skipped')})")
            print(f"• Merkle Kökü: {subj.get('merkle_root')}")
            print(f"• Yaprak Sayısı: {subj.get('merkle_leaf_count')}")
            if result.warnings:
                for w in result.warnings:
                    print(f"⚠️  {w}")
            print()
            return 0
        print("\n❌ SERTİFİKA GEÇERSİZ")
        for e in result.errors:
            print(f"  • {e}")
        print()
        return 1

    # --- yol-2: eski W3C-VC ( --pubkey ile) --------------------------------
    if pubkey_b64 is None:
        print("❌ Bu sertifika did:key-imzalı değil — --pubkey zorunlu ( eski W3C-VC yolu)")
        return 1
    proof = vc.get("proof", {})
    sig_b64 = proof.get("proofValue")
    if not sig_b64:
        print("❌ Sertifikada imza ('proofValue') bulunamadı.")
        return 1

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


def _load_signing_seed() -> bytes:
    """İmzalama tohumunu yükler ( VERIDROME_HOME veya VERIDROME_SEED_HEX)."""
    import os
    hex_env = os.environ.get("VERIDROME_SEED_HEX", "").strip()
    if hex_env:
        try:
            seed = bytes.fromhex(hex_env)
            if len(seed) == 32:
                return seed
        except ValueError:
            pass
    home = os.environ.get(
        "VERIDROME_HOME", os.path.join(os.path.expanduser("~"), ".veridrome")
    )
    seed_path = os.path.join(home, "seed.hex")
    if os.path.exists(seed_path):
        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                seed = bytes.fromhex(f.read().strip())
            if len(seed) == 32:
                return seed
        except (OSError, ValueError):
            pass
    # yoksa-üret-ve-kaydet ( 0600)
    seed = generate_keypair()[0]
    try:
        os.makedirs(home, exist_ok=True)
        _fd = os.open(seed_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            f.write(seed.hex())
    except OSError:
        pass
    return seed


def command_certify(
    results_path: Optional[str],
    pytest_args: Optional[list],
    commit_sha: str,
    repo_url: Optional[str],
    job_id: Optional[str],
    agent_did: Optional[str],
    out_path: Optional[str],
    valid_days: int,
) -> int:
    """Test-sonuçlarından did:key-imzalı test-geçişi sertifikası üretir."""
    entries = None
    if results_path:
        from veridrome.certificate.pytest_parser import parse_pytest_json
        try:
            parsed = parse_pytest_json(results_path)
        except (FileNotFoundError, ValueError) as e:
            print(f"❌ Test-sonuçları okunamadı: {e}")
            return 1
        entries = parsed["entries"]
    else:
        from veridrome.certificate.pytest_parser import run_pytest_json
        args = pytest_args if pytest_args else ["tests/"]
        parsed = run_pytest_json(args)
        entries = parsed["entries"]
        if parsed.get("exit_code", 0) != 0:
            print(f"❌ pytest exit-code={parsed['exit_code']} — failing-testlerle sertifika yok ( fail-closed)")
            return 2

    if not entries:
        print("❌ Hiç test-sonucu bulunamadı — kanıtsız sertifika yok ( fail-closed)")
        return 2

    seed = _load_signing_seed()
    _, did, _ = keypair_from_seed(seed)
    builder = CertificateBuilder(seed, did)

    # test-dosyası-hash'leri: bulunabilen dosyalar için gerçek sha256
    import os
    test_files: dict = {}
    for e in entries:
        name = str(e.get("name", ""))
        path = name.split("::")[0] if "::" in name else ""
        if path and os.path.isfile(path) and path not in test_files:
            try:
                test_files.update(hash_files([path]))
            except OSError:
                pass

    try:
        cert = builder.build(
            test_results=entries,
            repo_url=repo_url,
            commit_sha=commit_sha,
            test_files=test_files or None,
            agent_did=agent_did,
            job_id=job_id,
            valid_days=valid_days,
        )
    except ValueError as e:
        print(f"❌ Sertifika üretilemedi: {e}")
        return 2

    payload = json.dumps(cert, ensure_ascii=False, indent=2)
    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(payload + "\n")
        except OSError as e:
            print(f"❌ Çıktı yazılamadı: {e}")
            return 1
        print(f"\n✅ Sertifika yazıldı: {out_path}")
    else:
        print(payload)

    summ = cert["credentialSubject"]["summary"]
    print(
        f"\n🏛️  did:key: {cert['issuer']}\n"
        f"    cert_id: {cert['cert_id']}\n"
        f"    testler: {summ['passed']} passed / {summ['total']}\n"
        f"    merkle:  {cert['credentialSubject']['merkle_root'][:24]}…\n",
        file=sys.stderr,
    )
    return 0


def command_keygen() -> int:
    """Yeni bir did:key imzalama anahtarı üretir ve gösterir ( PRIVATE_KEY YASAK-sakla)."""
    import os
    seed, did, _ = generate_keypair()
    home = os.environ.get(
        "VERIDROME_HOME", os.path.join(os.path.expanduser("~"), ".veridrome")
    )
    print(f"\n🔑 Yeni did:key imzalama anahtarı üretildi\n")
    print(f"  DID:           {did}")
    print(f"  İmzalama-yolu: {home}/seed.hex ( 0600-izin)\n")
    print("  NOT: tohum ASLA yazdırılmaz. ``veridrome certify`` otomatik "
          "kullanır;\n  taşıma için ``VERIDROME_SEED_HEX`` çevresel-değişkeni.\n")
    try:
        os.makedirs(home, exist_ok=True)
        _fd = os.open(os.path.join(home, "seed.hex"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(_fd, "w", encoding="utf-8") as f:
            f.write(seed.hex())
    except OSError as e:
        print(f"⚠️  Anahtar dosyaya yazılamadı ( {e}); tohum bellek-tutuldu.", file=sys.stderr)
    return 0


def command_revoke(cert_path: str, reason: str, ledger_path: Optional[str]) -> int:
    """Bir sertifikayı append-only hash-zincirli iptal-defterine ekler."""
    import os
    try:
        with open(cert_path, "r", encoding="utf-8") as f:
            cert = json.load(f)
    except Exception as e:
        print(f"❌ Sertifika dosyası açılamadı: {e}")
        return 1

    cert_id = cert.get("cert_id")
    if not isinstance(cert_id, str) or len(cert_id) != 64:
        print("❌ Bu dosya bir Veridrome test-geçişi sertifikası değil ( cert_id yok)")
        return 1

    seed = _load_signing_seed()
    _, did, _ = keypair_from_seed(seed)

    ledger = RevocationLedger(
        ledger_path or os.path.join(
            os.environ.get("VERIDROME_HOME", os.path.join(os.path.expanduser("~"), ".veridrome")),
            "revocations.jsonl",
        )
    )
    try:
        entry = ledger.revoke(cert_id, seed, did, reason)
    except (ValueError, RuntimeError) as e:
        print(f"❌ İptal-edilemedi ( fail-closed): {e}")
        return 1

    print(f"\n🚫 Sertifika iptal-edildi ( append-only)\n")
    print(f"  cert_id:    {cert_id}")
    print(f"  iptal-eden: {did}")
    print(f"  neden:      {reason}")
    print(f"  zaman:      {entry['timestamp']}")
    print(f"  defter-h:   {entry['h'][:32]}…\n")
    return 0


def command_mcp() -> int:
    """MCP sunucusunu stdio üzerinden başlatır ( AI ajanları için)."""
    from veridrome.mcp_server import serve_stdio
    serve_stdio()
    return 0


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

    # verify — did:key ile self-resolving ( --pubkey artık opsiyonel)
    verify_parser = subparsers.add_parser(
        "verify",
        help="Sertifikayı bağımsız olarak doğrular ( did:key self-resolving; --pubkey opsiyonel)",
    )
    verify_parser.add_argument("cert_file", help="Sertifika JSON dosya yolu")
    verify_parser.add_argument(
        "--pubkey",
        default=None,
        help="( eski W3C-VC sertifikaları için) Base64 Ed25519 otorite açık anahtarı",
    )
    verify_parser.add_argument(
        "--ledger",
        default=None,
        help="İptal-defteri yolu ( opsiyonel; VERIDROME_HOME altında varsayılan)",
    )

    # certify — test-sonuçlarından sertifika üret
    certify_parser = subparsers.add_parser(
        "certify",
        help="Test-sonuçlarından did:key-imzalı test-geçişi sertifikası üret",
    )
    certify_parser.add_argument(
        "--results",
        default=None,
        help="Test-sonuçları JSON dosyası ( yoksa pytest çalıştırılır)",
    )
    certify_parser.add_argument(
        "--pytest-args",
        nargs="*",
        default=None,
        help="pytest argümanları ( --results verilmezse; örn: tests/test_x.py)",
    )
    certify_parser.add_argument("--commit", required=True, help="Repo commit-hash'i ( zorunlu)")
    certify_parser.add_argument("--repo", default=None, help="Repo URL'i")
    certify_parser.add_argument("--job-id", default=None, help="CI job kimliği")
    certify_parser.add_argument("--agent-did", default=None, help="Ajan did:key'i")
    certify_parser.add_argument("--out", default=None, help="Çıktı dosyası ( varsayılan: stdout)")
    certify_parser.add_argument(
        "--valid-days", type=int, default=365, help="Geçerlilik süresi ( gün)",
    )

    # keygen — imzalama anahtarı üret
    subparsers.add_parser("keygen", help="Yeni bir did:key imzalama anahtarı üret ve göster")

    # revoke — sertifikayı iptal-defterine ekle
    revoke_parser = subparsers.add_parser("revoke", help="Bir sertifikayı append-only deftere iptal-girişi ekle")
    revoke_parser.add_argument("cert_file", help="İptal edilecek sertifika JSON dosyası")
    revoke_parser.add_argument("--reason", required=True, help="İptal-nedeni")

    # mcp — MCP sunucusunu stdio üzerinden başlat
    subparsers.add_parser("mcp", help="MCP sunucusunu stdio üzerinden başlat ( AI ajanları için)")

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
        sys.exit(command_verify(args.cert_file, pubkey_b64=args.pubkey, ledger_path=args.ledger))
    elif args.subcommand == "certify":
        sys.exit(command_certify(
            results_path=args.results,
            pytest_args=args.pytest_args,
            commit_sha=args.commit,
            repo_url=args.repo,
            job_id=args.job_id,
            agent_did=args.agent_did,
            out_path=args.out,
            valid_days=args.valid_days,
        ))
    elif args.subcommand == "keygen":
        sys.exit(command_keygen())
    elif args.subcommand == "revoke":
        sys.exit(command_revoke(args.cert_file, args.reason, ledger_path=None))
    elif args.subcommand == "mcp":
        sys.exit(command_mcp())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
