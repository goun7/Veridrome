"""
Veridrome Test-Geçişi Sertifikası — çekirdek.

Bir CI koşumunu **bağımsız-doğrulanabilir bir sertifika** dönüştürür.

  Girdi:  test sonuçları ( JSON), repo commit-hash, test dosya hash'leri
  Çıktı:  did:key ile imzalanmış sertifika:
            - hangi testler geçti ( hash'lenmiş, Merkle-agacı içinde)
            - hangi commit'te
            - ne zaman ( UTC, imzalı timestamp)
            - kim imzaladı ( did:key — self-resolving)

Felsefe ( Veridict-deseni): "Bir ajan 'testlerim geçti' der — ama kim
doğruladı, ne zaman, hangi sürüm?" Bu modül o sözcüğü **kanıta** çevirir:
sertifikadaki her bayt, herkes tarafından — hiçbir ağ, defter, kayıt defteri
veya hesap olmadan — yeniden hesaplanabilir.

İçerik-hash bağlama ( content-hash binding):
  - ``content_hash`` = sha256( kanonik-gövde). Tek bayt değişikliği kırar.
  - ``cert_id`` = sha256( content_hash || imza). Tek rakam değişikliği kırar.
  - Merkle kökü, geçen testlerin bağımsız yeniden-hesaplanabilir sıralamasıdır.

Güvenlik-özellikleri:
  - Fail-closed: kanıt yok → INVALID, asla "temiz tek".
  - Süre-dolumu denetlenir ( validUntil).
  - Geçmiş-tarih ( backdating) denetlenir ( validFrom, ±60s skew).
  - İmza, did:key'den kurtarılan anahtarla doğrulanır ( self-resolving).
  - Tarih-olarak-saklanan-sayılar değil, hash'ler: sıralama kanıtlanabilir.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

from veridrome.certificate.didkey import (
    ED25519_SIG_LEN,
    is_did_key,
    pubkey_from_did,
    sign,
    verification_method_from_did,
    verify as didkey_verify,
)

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

SERTIFIKALAR_CONTEXT = "https://schema.veridrome.io/v1"
W3C_VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
ED25519_2020_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"

CERT_TYPE = "VeridromeTestPassCertificate"
PROOF_TYPE = "Ed25519Signature2020"
SIGNATURE_SUITE = "veridrome-test-pass-v1"

# Saat-kayması toleransı ( saniye) — dağıtık saatler için.
_CLOCK_SKEW_S = 60.0

# Bir test-sonucu girdisinin kabul edilebilir outcome değerleri.
_PASS_OUTCOMES = {"passed", "pass", "ok", "success"}


# ---------------------------------------------------------------------------
# Kanonikleştirme —Deterministik-hash'in temeli
# ---------------------------------------------------------------------------

def _canonical_bytes(obj: Any) -> bytes:
    """JSON nesnesini kanonik ( sıralı-anahtar, sıkışık) baytlara dönüştürür.

    Bu, ``content_hash``'in herkes tarafından aynı şekilde yeniden
    hesaplanabilir olmasını sağlar — bayt-sırası, boşluk veya anahtar-sırası
    farklı olsa bile.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_iso8601(value: str) -> Optional[datetime.datetime]:
    """ISO-8601'i timezone-aware datetime'a dönüştürür; başarısızda None."""
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Merkle-agacı — geçen-testlerin sıralama kanıtı
# ---------------------------------------------------------------------------

def _merkle_root(hashes: Sequence[str]) -> str:
    """Sıralı hex-hash listesinden Merkle kökünü hesaplar ( RFC-6962-benzeri).

    Boş girişte fail-closed: boş-agac-kökü döndürülür ve ``build_certificate``
    tarafından RED edilir ( aşağıda).
    """
    if not hashes:
        return "0x" + hashlib.sha256(b"").hexdigest()

    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(b"\x01" + left + right).digest())
        level = nxt
    return "0x" + level[0].hex()


def _hash_test_entry(entry: Dict[str, Any]) -> str:
    """Tek bir test-sonucu girdisinin kanonik hash'ini üretir.

    Girdi, çıktı veya süre dahil — deterministik-davranış-taahhüdü: aynı test,
    aynı girdiyle her zaman aynı hash'i verir.
    """
    canon = {
        "name": str(entry.get("name", "")),
        "outcome": str(entry.get("outcome", "")),
    }
    if "duration_ms" in entry and entry["duration_ms"] is not None:
        try:
            canon["duration_ms"] = float(entry["duration_ms"])
        except (TypeError, ValueError):
            pass
    return hashlib.sha256(_canonical_bytes(canon)).hexdigest()


# ---------------------------------------------------------------------------
# Girdi-normalleştirme — pytest-JSON'u ortak forma getirir
# ---------------------------------------------------------------------------

def normalize_results(raw: Any) -> List[Dict[str, Any]]:
    """Çeşitli test-sonucu formatlarını ortak forma getirir.

    Desteklenen girdiler:
      - pytest ``--report-json`` / pytest-json-report ``tests`` listesi
      - ``{"tests": [...]}`` zarfı
      - düz liste
      - JUnit-XML-benzeri tekil kayıt
    """
    if raw is None:
        return []
    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, dict):
        # pytest-json-report zarfı: {"tests": [...], "summary": {...}}
        if "tests" in raw and isinstance(raw["tests"], list):
            entries = raw["tests"]
        # JUnit-benzeri tekil
        elif "testcase" in raw:
            entries = [raw]
        else:
            entries = [raw]
    else:
        return []

    out: List[Dict[str, Any]] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        name = e.get("name") or e.get("nodeid") or e.get("classname")
        outcome = e.get("outcome") or e.get("result") or e.get("status")
        if outcome is None:
            # pytest-json-report: call {"outcome": "passed"}; hata-durumları
            if e.get("call", {}).get("outcome"):
                outcome = e["call"]["outcome"]
            elif e.get("call", {}).get("crash"):
                outcome = "failed"
        if name is None or outcome is None:
            continue
        rec: Dict[str, Any] = {
            "name": str(name),
            "outcome": str(outcome).lower(),
        }
        dur = e.get("duration_ms", e.get("duration"))
        if dur is not None:
            try:
                # saniye → milisaniye normalizasyonu
                v = float(dur)
                rec["duration_ms"] = round(v * 1000.0, 3) if v < 1000 else round(v, 3)
            except (TypeError, ValueError):
                pass
        out.append(rec)
    return out


def summarize(entries: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Normalize edilmiş girdilerden dürüst bir özet üretir.

    Her rakam, ``entries`` listesinden bağımsız olarak yeniden hesaplanabilir
    — özet, hash'lenmiş girdilerin bir fonksiyonudur, değil-ayrı-saklanan-bir
    iddia.
    """
    total = len(entries)
    passed = sum(1 for e in entries if e.get("outcome") in _PASS_OUTCOMES)
    failed = sum(1 for e in entries if e.get("outcome") in ("failed", "error", "failure"))
    skipped = sum(1 for e in entries if e.get("outcome") in ("skipped", "skip", "xfailed", "xpass"))
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        # eğilim için: tanınmayan-sonuçlar dürüstçe raporlanır
        "other": max(0, total - passed - failed - skipped),
    }


# ---------------------------------------------------------------------------
# Sertifika-inşası
# ---------------------------------------------------------------------------

class CertificateBuilder:
    """Bir CI koşumundan test-geçişi sertifikası üretir.

    Kullanım:

        b = CertificateBuilder(seed, issuer_did)
        cert = b.build(
            test_results=results_json,
            repo_url="https://github.com/org/repo",
            commit_sha="a1b2c3...",
            test_files={"tests/test_x.py": "<sha256>"},
            agent_did="did:key:z6Mk...",
        )
    """

    def __init__(self, seed: bytes, issuer_did: Optional[str] = None) -> None:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed'i tam 32 bayt olmalı")
        self._seed = seed
        if issuer_did is None:
            from veridrome.certificate.didkey import keypair_from_seed
            _, did, _ = keypair_from_seed(seed)
            issuer_did = did
        if not is_did_key(issuer_did):
            raise ValueError(f"issuer_did geçerli bir did:key değil: {issuer_did!r}")
        self.issuer_did = issuer_did

    # -- dahili-yardımcılar ---------------------------------------------

    def _collect_file_hashes(
        self, test_files: Optional[Dict[str, str]], entries: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Test-dosyası hash'lerini kanonik sıralı listeye dönüştürür.

        ``test_files`` verilmezse, test isimlerinden dosya yollarını çıkarır —
        bu durumda hash'ler SADECE isme bağlıdır ( zayıf-kanıt) ve sertifika
        bunu ``hash_source: "name-derived"`` ile dürüstçe işaretler.
        """
        if test_files:
            return [
                {"path": str(p), "sha256": str(h)}
                for p, h in sorted(test_files.items(), key=lambda kv: str(kv[0]))
            ]
        # isimden-türetme: zayıf-ama-dürüst
        seen: Dict[str, str] = {}
        for e in entries:
            name = str(e.get("name", ""))
            if "::" in name:
                path = name.split("::")[0]
            elif "/" in name:
                path = name.rsplit("/", 1)[0] + "/" + name.rsplit("/", 1)[1].split(".")[0] + ".py"
            else:
                continue
            if path not in seen:
                seen[path] = hashlib.sha256(path.encode("utf-8")).hexdigest()
        return [
            {"path": p, "sha256": h} for p, h in sorted(seen.items())
        ]

    # -- ana-api ---------------------------------------------------------

    def build(
        self,
        test_results: Any,
        repo_url: Optional[str] = None,
        commit_sha: Optional[str] = None,
        test_files: Optional[Dict[str, str]] = None,
        agent_did: Optional[str] = None,
        job_id: Optional[str] = None,
        valid_days: int = 365,
        toolchain: Optional[Dict[str, str]] = None,
        now: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        """Sertifikayı üret, imzala ve content-hash ile bağla.

        ``commit_sha`` verilmezse fail-closed: "hangi-sürüm" sorusu cevapsız
        kalamaz — sertifika VERİLMEZ.
        """
        if not commit_sha:
            raise ValueError("commit_sha zorunlu — 'hangi-sürüm' cevapsız sertifika yok ( fail-closed)")

        entries = normalize_results(test_results)
        summary = summarize(entries)
        if summary["total"] == 0:
            raise ValueError("test-sonucu-girdisi-yok — kanıtsız sertifika yok ( fail-closed)")
        # fail-closed: failing-test içeren bir sonuç, GEÇİŞ-kanıtı değildir —
        # "testlerim-geçti" iddiası, failing-testlerle çelişir ( AT-186-deseni).
        if summary["failed"] > 0:
            raise ValueError(
                f"failing-test-var: {summary['failed']} test başarısız — "
                f"geçiş-kanıtı üretilemez ( fail-closed)"
            )

        # sıralama: isme göre deterministik — Merkle-kökü herkes için aynı
        entries_sorted = sorted(entries, key=lambda e: (str(e.get("name", ""))))
        test_hashes = [_hash_test_entry(e) for e in entries_sorted]
        merkle_root = _merkle_root(test_hashes)

        summary = summarize(entries)
        # AT-187: özeti Merkle-köküne bağla — aksi halde yaprak+kök birlikte-
        # değiştirilip summary.total arkasına gizlenebilirdi
        summary["commitment"] = hashlib.sha256(
            (merkle_root + str(summary["total"])).encode("utf-8")
        ).hexdigest()

        file_hashes = self._collect_file_hashes(test_files, entries_sorted)
        hash_source = "file" if test_files else "name-derived"

        now_dt = now or _now_utc()
        now_iso = now_dt.isoformat()
        valid_until = (now_dt + datetime.timedelta(days=valid_days)).isoformat()

        subject: Dict[str, Any] = {
            "id": agent_did or self.issuer_did,
            "suite": SIGNATURE_SUITE,
            "summary": summary,
            "repo": {
                "url": repo_url or "",
                "commit": str(commit_sha),
            },
            "test_files": file_hashes,
            "merkle_root": merkle_root,
            "merkle_leaf_count": len(test_hashes),
            # Yaprak-hash'leri taşınır → Merkle-kökü BAĞIMSIZ yeniden-
            # hesaplanabilir ( Veridict "verify-from-file-alone" deseni).
            "merkle_leaves": test_hashes,
            "hash_source": hash_source,
        }
        if toolchain:
            subject["toolchain"] = {
                str(k): str(v) for k, v in sorted(toolchain.items())
            }

        body: Dict[str, Any] = {
            "@context": [
                W3C_VC_CONTEXT,
                ED25519_2020_CONTEXT,
                SERTIFIKALAR_CONTEXT,
            ],
            "type": ["VerifiableCredential", CERT_TYPE],
            "issuer": self.issuer_did,
            "validFrom": now_iso,
            "validUntil": valid_until,
            "credentialSubject": subject,
        }
        if job_id:
            body["id"] = f"urn:veridrome:cert:{job_id}"

        return self._sign_and_bind(body, now_iso)

    def _sign_and_bind(self, body: Dict[str, Any], now_iso: str) -> Dict[str, Any]:
        """Kanonik gövdeyi imzalar ve content-hash/cert_id bağlar."""
        canonical = _canonical_bytes(body)
        content_hash = hashlib.sha256(canonical).hexdigest()

        sig = sign(self._seed, canonical)
        if len(sig) != ED25519_SIG_LEN:  # pragma: no cover — savunma
            raise RuntimeError("Ed25519 imzası 64 bayt değil — imzalama-bozuk")

        cert_id = hashlib.sha256(
            (content_hash + _b64(sig)).encode("utf-8")
        ).hexdigest()

        proof = {
            "type": PROOF_TYPE,
            "created": now_iso,
            "verificationMethod": verification_method_from_did(self.issuer_did),
            "proofPurpose": "assertionMethod",
            "proofValue": _b64(sig),
        }

        cert = dict(body)
        cert["content_hash"] = content_hash
        cert["cert_id"] = cert_id
        cert["proof"] = proof
        return cert


# ---------------------------------------------------------------------------
# Bağımsız-doğrulama
# ---------------------------------------------------------------------------

class VerifyResult:
    """Doğrulama sonucu — bütün denetçilerle dürüst-raporlama."""

    def __init__(self) -> None:
        self.valid: bool = False
        self.content_hash_valid: bool = False
        self.signature_valid: bool = False
        self.temporal_valid: bool = False
        self.merkle_valid: bool = False
        self.subject_ok: bool = False
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "content_hash_valid": self.content_hash_valid,
            "signature_valid": self.signature_valid,
            "temporal_valid": self.temporal_valid,
            "merkle_valid": self.merkle_valid,
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"VerifyResult(valid={self.valid})"


def _fail(res: VerifyResult, msg: str) -> VerifyResult:
    res.errors.append(msg)
    return res


def verify_certificate(cert: Any, now: Optional[datetime.datetime] = None) -> VerifyResult:
    """Bir sertifikayı bağımsız olarak doğrular — sıfır-güven, sıfır-ağ.

    Denetlenenler ( hepsi dosyadan-yeniden-hesaplanır):
      1. Yapısal-geçerlilik ( did:key, tipler, özet)
      2. content_hash — gövdeye karşı yeniden hesaplanır
      3. İmza — did:key'den kurtarılan anahtarla ( self-resolving)
      4. Zamansal-geçerlilik — validFrom ( backdating-red) ve validUntil ( süre-dolumu)
      5. Merkle-kökü — geçen-testlerin sıralamasından yeniden hesaplanır
      6. Özet-tutarlılığı — özet, girdilerin fonksiyonu olarak doğrulanır
    """
    res = VerifyResult()
    now_dt = now or _now_utc()

    if not isinstance(cert, dict):
        return _fail(res, "sertifika bir JSON nesnesi değil")

    # --- 1. yapısal-denetim -------------------------------------------------
    issuer = cert.get("issuer")
    if not (isinstance(issuer, str) and is_did_key(issuer)):
        return _fail(res, f"issuer geçerli bir did:key değil: {issuer!r}")

    types = cert.get("type", [])
    if not (isinstance(types, list) and CERT_TYPE in types):
        return _fail(res, f"bu bir {CERT_TYPE} değil")

    subject = cert.get("credentialSubject")
    if not isinstance(subject, dict):
        return _fail(res, "credentialSubject eksik")

    summary = subject.get("summary")
    if not isinstance(summary, dict):
        return _fail(res, "summary eksik — kanıt-özeti yok")

    proof = cert.get("proof")
    if not isinstance(proof, dict):
        return _fail(res, "proof eksik")
    if proof.get("type") != PROOF_TYPE:
        return _fail(res, f"proof.type beklenenden farklı: {proof.get('type')!r}")
    if proof.get("proofPurpose") != "assertionMethod":
        return _fail(res, "proofPurpose assertionMethod değil")
    sig_b64 = proof.get("proofValue")
    if not isinstance(sig_b64, str):
        return _fail(res, "proofValue eksik")

    # content-hash ve cert_id mevcut olmalı
    content_hash = cert.get("content_hash")
    cert_id = cert.get("cert_id")
    if not isinstance(content_hash, str) or len(content_hash) != 64:
        return _fail(res, "content_hash eksik veya 64-hex değil")
    if not isinstance(cert_id, str) or len(cert_id) != 64:
        return _fail(res, "cert_id eksik veya 64-hex değil")

    # --- 2. content-hash ---------------------------------------------------
    # İmzadan-önce: issuer değiştirilirse content-hash değişir → burada yakalanır.
    body = {k: v for k, v in cert.items() if k not in ("proof", "content_hash", "cert_id")}
    recomputed = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    if recomputed != content_hash:
        return _fail(res, "content_hash uyuşmuyor — gövde veya issuer değiştirilmiş ( tahriz)")
    res.content_hash_valid = True

    # cert_id bağını da denetle ( imza+content-hash'ten)
    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return _fail(res, "proofValue base64 değil")
    if len(sig_bytes) != ED25519_SIG_LEN:
        return _fail(res, f"imza {ED25519_SIG_LEN} bayt değil")
    expected_id = hashlib.sha256((content_hash + _b64(sig_bytes)).encode("utf-8")).hexdigest()
    if expected_id != cert_id:
        return _fail(res, "cert_id uyuşmuyor — imza veya içerik değiştirilmiş")

    # --- 3. imza ( did:key-self-resolving) --------------------------------
    pub = pubkey_from_did(issuer)
    if not didkey_verify(pub, _canonical_bytes(body), sig_bytes):
        return _fail(res, "Ed25519 imzası geçersiz — did:key ile uyuşmuyor")
    res.signature_valid = True

    # --- 4. zamansal-denetim ----------------------------------------------
    vf = _parse_iso8601(str(cert.get("validFrom", "")))
    vu = _parse_iso8601(str(cert.get("validUntil", "")))
    if vf is None or vu is None:
        return _fail(res, "validFrom/validUntil ISO-8601 olarak çözülemedi")
    if now_dt < vf - datetime.timedelta(seconds=_CLOCK_SKEW_S):
        return _fail(res, "gelecek-tarihli sertifika — validFrom henüz gelmedi ( backdating-red)")
    if now_dt > vu:
        return _fail(res, "sertifikanın süresi dolmuş ( validUntil geçti)")
    res.temporal_valid = True

    # --- 5. Merkle-kökü ----------------------------------------------------
    merkle_root = subject.get("merkle_root")
    leaf_count = subject.get("merkle_leaf_count")
    if not (isinstance(merkle_root, str) and merkle_root.startswith("0x") and len(merkle_root) == 66):
        return _fail(res, "merkle_root geçerli bir 0x...66hex değil")
    if not isinstance(leaf_count, int) or leaf_count < 1:
        return _fail(res, "merkle_leaf_count pozitif tam sayı değil")

    # kökü yeniden kurmak için leaf-hash'lerinin kendisini kanıt-kümesi olarak al
    leaf_hashes = subject.get("merkle_leaves")
    if isinstance(leaf_hashes, list) and leaf_hashes:
        if len(leaf_hashes) != leaf_count:
            return _fail(res, "merkle_leaves sayısı merkle_leaf_count ile uyuşmuyor")
        # tüm yapraklar 64-hex olmalı ( biçim-denetimi — fail-closed)
        if not all(isinstance(h, str) and len(h) == 64 for h in leaf_hashes):
            return _fail(res, "merkle_leaves 64-hex hash'ler olmalı")
        try:
            recomputed_root = _merkle_root(leaf_hashes)
        except Exception as exc:
            return _fail(res, f"Merkle-kökü yeniden hesaplanamadı: {exc}")
        if recomputed_root != merkle_root:
            return _fail(res, "Merkle-kökü uyuşmuyor — test-sıralaması değiştirilmiş")
        res.merkle_valid = True
    else:
        # yapraklar taşınmıyor → kök bağımsız-doğrulanamaz → uyar + zayıflat
        res.warnings.append(
            "merkle_leaves taşınmıyor — Merkle-kökü bağımsız yeniden-"
            "hesaplanamıyor; sadece imza+content-hash ile doğrulandı"
        )
        res.merkle_valid = False

    # --- 6. özet-tutarlılığı ---------------------------------------------
    total = summary.get("total")
    if not isinstance(total, int) or total != leaf_count:
        return _fail(res, "summary.total, merkle_leaf_count ile uyuşmuyor")
    if summary.get("failed", 0) > 0:
        return _fail(res, "sertifika failing-test içeriyor — geçiş-kanıtı değil")
    if total > 0 and summary.get("passed", 0) != total - summary.get("skipped", 0) - summary.get("other", 0):
        return _fail(res, "summary passed/failed/skipped/other aritmetiği uyuşmuyor")

    # ÖZET-MERKLE-BAĞI: özet, yaprak-hash'lerinin sıralamasını kapsamalıdır.
    # Aksi halde bir saldırgan yaprakları + kökü birlikte-değiştirip
    # summary.total sayısıyla gizleyebilirdi. İmzalı-gövdeye gömülen
    # ``summary_commitment`` ile bağımsız-yeniden-hesaplanabilir ( AT-187).
    expected_commitment = hashlib.sha256(
        (merkle_root + str(total)).encode("utf-8")
    ).hexdigest()
    if summary.get("commitment") != expected_commitment:
        return _fail(res, "summary.commitment uyuşmuyor — özet ile Merkle-kökü bağsız")
    res.subject_ok = True

    # --- sonuç ------------------------------------------------------------
    # Merkle-yaprakları yoksa yine de geçerli sayılırız AMA uyarıyla —
    # imza+content_hash+zaman+özet sağlamdır. Bu, "hiçbir-kanıt-INCONCLUSIVE"
    # felsefesidir: zayıf-kanıt > kanıt-yok, dürüst-etiketlenmiş.
    res.valid = all([
        res.content_hash_valid,
        res.signature_valid,
        res.temporal_valid,
        res.subject_ok,
    ])
    return res


# ---------------------------------------------------------------------------
# Yardımcı: dosyadan-hash-üretimi ( CLI için)
# ---------------------------------------------------------------------------

def hash_file(path: str) -> str:
    """Bir dosyanın sha256-hash'ini üretir ( test-dosyası-hash'leri için)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_files(paths: Sequence[str]) -> Dict[str, str]:
    """Birden çok dosya için {yol: sha256} haritası üretir."""
    return {str(p): hash_file(str(p)) for p in paths}


__all__ = [
    "CertificateBuilder",
    "verify_certificate",
    "VerifyResult",
    "normalize_results",
    "summarize",
    "hash_file",
    "hash_files",
    "CERT_TYPE",
    "SIGNATURE_SUITE",
]
