"""
Veridrome Tests: CLI, TEE Attestation Signature & In-Memory Registry Verification
"""

import os
import json
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from veridrome.contracts.client import InMemoryVeridromeRegistryClient, MockVeridromeRegistryClient
from veridrome.core.tee_attestation import TEEAttestationVerifier
from veridrome.cli.main import command_run_evaluation, command_list_tasks


def test_in_memory_registry_client_full_cycle():
    client = InMemoryVeridromeRegistryClient()
    # Alias kontrolü
    assert MockVeridromeRegistryClient == InMemoryVeridromeRegistryClient

    pcr0 = b"\x12" * 32
    client.set_pcr0_validity(pcr0, True)

    agent_id = b"agent-001"
    merkle_root = b"\xaa" * 32
    cert_id = client.issue_certificate(
        agent_id=agent_id,
        pcr0_measurement=pcr0,
        merkle_root=merkle_root,
        score_median_bps=9500,
        score_iqr_bps=200,
        cost_per_task_cents=4,
        p95_latency_sec=12,
        anomaly_score_bps=120,
        vendor_address="0x1111111111111111111111111111111111111111",
    )
    assert len(cert_id) == 32
    assert client.verify_certificate(cert_id) is True

    # Teminat yatırma ve slashing
    client.deposit_collateral(cert_id, 5000)
    assert client.certificates[cert_id].collateral_staked == 5000

    remaining = client.slash_collateral(cert_id, "0xVictim", 2000)
    assert remaining == 3000

    # İptal etme (revocation)
    client.revoke_certificate(cert_id, "Exploit")
    assert client.verify_certificate(cert_id) is False


def test_tee_attestation_with_ecdsa_crypto_signature():
    # ECDSA P-384 anahtar çifti oluştur
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    expected_pcr0 = "0x98f12a4b8823901234567890abcdef1234567890abcdef1234567890abcdef"
    nonce = os.urandom(32)
    data_to_sign = f"{expected_pcr0}:{nonce.hex()}".encode("utf-8")
    sig = private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA384()))
    sig_b64 = base64.b64encode(sig).decode("utf-8")

    # 1. Geçerli imzalı tasdik
    payload_valid = {
        "measurement": expected_pcr0,
        "host_data": nonce.hex(),
        "policy": 0x30000,
        "signature": sig_b64,
        "public_key": public_key_pem,
    }
    res = TEEAttestationVerifier.verify_attestation(
        platform="AMD-SEV-SNP",
        attestation_payload=payload_valid,
        expected_pcr0=expected_pcr0,
        expected_nonce=nonce,
    )
    assert res.is_valid is True
    assert "Verified" in res.message

    # 2. Sahte imzalı tasdik
    payload_invalid_sig = dict(payload_valid)
    payload_invalid_sig["signature"] = base64.b64encode(b"invalid_signature_payload").decode("utf-8")
    res_bad = TEEAttestationVerifier.verify_attestation(
        platform="AMD-SEV-SNP",
        attestation_payload=payload_invalid_sig,
        expected_pcr0=expected_pcr0,
        expected_nonce=nonce,
    )
    assert res_bad.is_valid is False
    assert "İmzası Geçersiz" in res_bad.message


def test_cli_command_list_tasks():
    rc = command_list_tasks()
    assert rc == 0


def test_cli_command_run_evaluation_honest():
    rc = command_run_evaluation(agent_type="honest", runs_per_task=1)
    assert rc == 0


def test_cli_command_run_evaluation_overfit():
    rc = command_run_evaluation(agent_type="overfit", runs_per_task=1)
    assert rc == 2
