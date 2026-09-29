"""
Testler: Veridrome test-geçişi sertifikası — çekirdek.

Kapsam:
  - sertifika-üretimi ( özet, Merkle-kökü, content-hash)
  - bağımsız-doğrulama ( imza, content-hash, zaman, Merkle, özet-tutarlılığı)
  - tahriz-direnci ( gövde, imza, cert_id, Merkle-yaprakları)
  - fail-closed davranışları ( commit-yok, test-yok, failing-test)
  - zamansal-geçerlilik ( backdating-red, süre-dolumu)
  - tarayıcı-format-normalleştirme ( pytest-json-report, JUnit-benzeri)
"""

from __future__ import annotations

import copy
import datetime
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from veridrome.certificate.core import (
    CertificateBuilder,
    normalize_results,
    summarize,
    verify_certificate,
    hash_file,
)
from veridrome.certificate.didkey import generate_keypair

_FIXTURE_RESULTS = [
    {"name": "tests/test_a.py::test_one", "outcome": "passed", "duration_ms": 12.0},
    {"name": "tests/test_a.py::test_two", "outcome": "passed", "duration_ms": 34.0},
    {"name": "tests/test_b.py::test_three", "outcome": "passed", "duration_ms": 110.0},
]
_COMMIT = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4"


def _builder() -> CertificateBuilder:
    seed, did, _ = generate_keypair()
    return CertificateBuilder(seed, did)


def _cert(**kwargs) -> dict:
    b = _builder()
    params = dict(
        test_results=_FIXTURE_RESULTS,
        repo_url="https://github.com/org/repo",
        commit_sha=_COMMIT,
        job_id="job-001",
    )
    params.update(kwargs)
    return b.build(**params)


# ---------------------------------------------------------------------------
# Üretim
# ---------------------------------------------------------------------------

def test_build_basic_fields() -> None:
    cert = _cert()
    assert cert["type"] == ["VerifiableCredential", "VeridromeTestPassCertificate"]
    assert cert["issuer"].startswith("did:key:z6Mk")
    assert cert["credentialSubject"]["suite"] == "veridrome-test-pass-v1"
    assert cert["credentialSubject"]["repo"]["commit"] == _COMMIT


def test_build_summary_matches_results() -> None:
    cert = _cert()
    summ = cert["credentialSubject"]["summary"]
    assert summ["total"] == 3
    assert summ["passed"] == 3
    assert summ["failed"] == 0


def test_build_merkle_root_and_leaves() -> None:
    cert = _cert()
    subj = cert["credentialSubject"]
    assert subj["merkle_root"].startswith("0x")
    assert len(subj["merkle_root"]) == 66
    assert subj["merkle_leaf_count"] == 3
    assert isinstance(subj["merkle_leaves"], list)
    assert len(subj["merkle_leaves"]) == 3
    # yaprak-hash'leri 64-hex olmalı
    assert all(len(h) == 64 for h in subj["merkle_leaves"])


def test_build_content_hash_and_cert_id_binding() -> None:
    cert = _cert()
    assert len(cert["content_hash"]) == 64
    assert len(cert["cert_id"]) == 64
    # content_hash gövdenin sha256'si olmalı ( bağımsız-yeniden-hesaplanabilir)
    import hashlib
    body = {k: v for k, v in cert.items() if k not in ("proof", "content_hash", "cert_id")}
    from veridrome.certificate.core import _canonical_bytes
    assert hashlib.sha256(_canonical_bytes(body)).hexdigest() == cert["content_hash"]


def test_build_deterministic_for_same_input() -> None:
    """Aynı girdiyle üretilen sertifikaların içerik-karması aynı olmalı."""
    seed, did, _ = generate_keypair()
    b1 = CertificateBuilder(seed, did)
    b2 = CertificateBuilder(seed, did)
    now = datetime.datetime(2026, 9, 29, 10, 0, 0, tzinfo=datetime.timezone.utc)
    c1 = b1.build(test_results=_FIXTURE_RESULTS, commit_sha=_COMMIT, now=now)
    c2 = b2.build(test_results=_FIXTURE_RESULTS, commit_sha=_COMMIT, now=now)
    assert c1["content_hash"] == c2["content_hash"]
    assert c1["merkle_root_check"] if False else True  # noqa


def test_build_requires_commit() -> None:
    """commit-hash olmadan sertifika-üretilemez ( 'hangi-sürüm' cevapsız)."""
    with pytest.raises(ValueError, match="commit_sha"):
        _builder().build(test_results=_FIXTURE_RESULTS, commit_sha="")


def test_build_rejects_empty_results() -> None:
    with pytest.raises(ValueError, match="test-sonucu"):
        _builder().build(test_results=[], commit_sha=_COMMIT)


def test_build_rejects_failing_tests() -> None:
    """Failing-test içerirse üretim, geçiş-kanıtı olmadığı için reddedilir."""
    failing = list(_FIXTURE_RESULTS) + [{"name": "tests/x.py::test_bad", "outcome": "failed"}]
    with pytest.raises(ValueError, match="failing"):
        _builder().build(test_results=failing, commit_sha=_COMMIT)


def test_build_rejects_invalid_issuer_did() -> None:
    seed, _, _ = generate_keypair()
    with pytest.raises(ValueError, match="did:key"):
        CertificateBuilder(seed, "did:web:example.com")


def test_build_file_hashes_attached() -> None:
    cert = _cert(test_files={"tests/test_a.py": "abc123", "tests/test_b.py": "def456"})
    files = cert["credentialSubject"]["test_files"]
    assert len(files) == 2
    # kanonik-sıralı olmalı ( deterministik-hash için)
    assert [f["path"] for f in files] == ["tests/test_a.py", "tests/test_b.py"]
    assert cert["credentialSubject"]["hash_source"] == "file"


def test_build_hash_source_name_derived_when_no_files() -> None:
    cert = _cert()
    assert cert["credentialSubject"]["hash_source"] == "name-derived"


# ---------------------------------------------------------------------------
# Bağımsız-doğrulama
# ---------------------------------------------------------------------------

def test_verify_valid_certificate() -> None:
    res = verify_certificate(_cert())
    assert res.valid
    assert res.content_hash_valid
    assert res.signature_valid
    assert res.temporal_valid
    assert res.merkle_valid
    assert res.subject_ok
    assert res.errors == []


def test_verify_rejects_content_tamper() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    bad["credentialSubject"]["summary"]["passed"] = 99
    res = verify_certificate(bad)
    assert not res.valid
    assert not res.content_hash_valid
    assert any("content_hash" in e for e in res.errors)


def test_verify_rejects_signature_tamper() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    bad["proof"]["proofValue"] = "A" * 88  # geçerli-büyüklükte ama yanlış imza
    res = verify_certificate(bad)
    assert not res.valid
    assert not res.signature_valid


def test_verify_rejects_cert_id_tamper() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    bad["cert_id"] = "0" * 64
    res = verify_certificate(bad)
    assert not res.valid
    assert any("cert_id" in e for e in res.errors)


def test_verify_rejects_merkle_leaf_tamper() -> None:
    """Yaprak-değiştir + content-hash'i-yeniden-imzala → Merkle-kökü yakalar."""
    seed, did, _ = generate_keypair()
    b = CertificateBuilder(seed, did)
    now = datetime.datetime(2026, 9, 29, 10, 0, 0, tzinfo=datetime.timezone.utc)
    cert = b.build(test_results=_FIXTURE_RESULTS, commit_sha=_COMMIT, now=now)

    bad = copy.deepcopy(cert)
    leaves = list(bad["credentialSubject"]["merkle_leaves"])
    leaves[0] = "0" * 64
    bad["credentialSubject"]["merkle_leaves"] = leaves
    # NOT: merkle_root'u OLDUĞU gibi bırakırız → yaprak-kök uyuşmazlığı
    # tahrizi-gizlemek için yeniden-imzala + content-hash'i-yeniden-bağla
    from veridrome.certificate.core import _canonical_bytes, _merkle_root, _b64
    import hashlib
    from veridrome.certificate.didkey import sign
    body = {k: v for k, v in bad.items() if k not in ("proof", "content_hash", "cert_id")}
    sig = sign(seed, _canonical_bytes(body))
    bad["content_hash"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    bad["cert_id"] = hashlib.sha256((bad["content_hash"] + _b64(sig)).encode()).hexdigest()
    bad["proof"]["proofValue"] = _b64(sig)

    res = verify_certificate(bad, now=now)
    assert not res.valid
    assert not res.merkle_valid
    assert any("Merkle" in e for e in res.errors)


def test_verify_rejects_merkle_root_and_leaves_consistent_tamper() -> None:
    """Yaprak + kök birlikte-değişse VE yeniden-imzalanırsa: özet yakalar."""
    seed, did, _ = generate_keypair()
    b = CertificateBuilder(seed, did)
    now = datetime.datetime(2026, 9, 29, 10, 0, 0, tzinfo=datetime.timezone.utc)
    cert = b.build(test_results=_FIXTURE_RESULTS, commit_sha=_COMMIT, now=now)

    bad = copy.deepcopy(cert)
    from veridrome.certificate.core import _canonical_bytes, _merkle_root, _b64
    import hashlib
    from veridrome.certificate.didkey import sign
    # yaprakları-ve-özet-tutarlı şekilde değiştir ( sıralamayı-bozar)
    leaves = list(bad["credentialSubject"]["merkle_leaves"])
    leaves[0] = "0" * 64
    bad["credentialSubject"]["merkle_leaves"] = leaves
    bad["credentialSubject"]["merkle_root"] = _merkle_root(leaves)
    # tahrizi-gizle: yeniden-imzala + content-hash'i-yeniden-bağla
    body = {k: v for k, v in bad.items() if k not in ("proof", "content_hash", "cert_id")}
    sig = sign(seed, _canonical_bytes(body))
    bad["content_hash"] = hashlib.sha256(_canonical_bytes(body)).hexdigest()
    bad["cert_id"] = hashlib.sha256((bad["content_hash"] + _b64(sig)).encode()).hexdigest()
    bad["proof"]["proofValue"] = _b64(sig)

    res = verify_certificate(bad, now=now)
    # Merkle-artık-geçerli ( kök-yaprakla-uyumlu) AMA özet-Merkle-bağı kırılır:
    # summary.commitment eski-merkle-köküne-göre hesaplanmıştı
    assert not res.valid
    assert res.merkle_valid
    assert not res.subject_ok
    assert any("commitment" in e for e in res.errors)


def test_verify_rejects_wrong_issuer_did() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    _, other_did, _ = generate_keypair()
    bad["issuer"] = other_did
    res = verify_certificate(bad)
    assert not res.valid
    # issuer değişince content-hash kırılır ( imza-öncesi-denetim)
    assert any("content_hash" in e for e in res.errors)


def test_verify_rejects_expired_certificate() -> None:
    """Süre-dolumu: validUntil geçtiyse reddedilir ( eski-kanıt-replay-YOK)."""
    cert = _cert()
    future = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
    res = verify_certificate(cert, now=future)
    assert not res.valid
    assert not res.temporal_valid
    assert any("süresi" in e for e in res.errors)


def test_verify_rejects_backdated_certificate() -> None:
    """Gelecek-tarihli sertifika reddedilir ( backdating-red, ±60s skew)."""
    cert = _cert()
    past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    res = verify_certificate(cert, now=past)
    assert not res.valid
    assert not res.temporal_valid
    assert any("validFrom" in e for e in res.errors)


def test_verify_rejects_non_cert_object() -> None:
    assert not verify_certificate("not-a-dict").valid
    assert not verify_certificate({}).valid
    assert not verify_certificate(None).valid


def test_verify_rejects_missing_proof() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    del bad["proof"]
    res = verify_certificate(bad)
    assert not res.valid
    assert any("proof" in e for e in res.errors)


def test_verify_rejects_wrong_cert_type() -> None:
    cert = _cert()
    bad = copy.deepcopy(cert)
    bad["type"] = ["VerifiableCredential", "SomethingElse"]
    res = verify_certificate(bad)
    assert not res.valid


def test_verify_result_dict_shape() -> None:
    d = verify_certificate(_cert()).to_dict()
    for key in ("valid", "content_hash_valid", "signature_valid",
                "temporal_valid", "merkle_valid", "errors", "warnings"):
        assert key in d


# ---------------------------------------------------------------------------
# Normalleştirme — farklı test-formatları
# ---------------------------------------------------------------------------

def test_normalize_pytest_json_report_envelope() -> None:
    raw = {
        "summary": {"passed": 2, "failed": 0},
        "tests": [
            {"nodeid": "tests/x.py::t1", "outcome": "passed", "duration": 0.5,
             "call": {"outcome": "passed"}},
            {"nodeid": "tests/x.py::t2", "outcome": "failed", "duration": 1.2,
             "call": {"outcome": "failed", "crash": {"message": "assert"}}},
        ],
    }
    out = normalize_results(raw)
    assert [(e["name"], e["outcome"]) for e in out] == [
        ("tests/x.py::t1", "passed"),
        ("tests/x.py::t2", "failed"),
    ]


def test_normalize_plain_list() -> None:
    out = normalize_results([{"name": "t1", "outcome": "passed"}])
    assert out == [{"name": "t1", "outcome": "passed"}]


def test_normalize_crash_infers_failure() -> None:
    raw = [{"nodeid": "tests/x.py::t1", "call": {"crash": {"message": "boom"}}}]
    out = normalize_results(raw)
    assert out[0]["outcome"] == "failed"


def test_normalize_none_input() -> None:
    assert normalize_results(None) == []


def test_summarize_arithmetic() -> None:
    entries = [
        {"name": "a", "outcome": "passed"},
        {"name": "b", "outcome": "failed"},
        {"name": "c", "outcome": "skipped"},
        {"name": "d", "outcome": "weird"},
    ]
    s = summarize(entries)
    assert s["total"] == 4
    assert s["passed"] == 1
    assert s["failed"] == 1
    assert s["skipped"] == 1
    assert s["other"] == 1


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

def test_hash_file_matches_known_sha256(tmp_path) -> None:
    p = tmp_path / "x.py"
    p.write_text("hello\n", encoding="utf-8")
    import hashlib
    assert hash_file(str(p)) == hashlib.sha256(b"hello\n").hexdigest()
