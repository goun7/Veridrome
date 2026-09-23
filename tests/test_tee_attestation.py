import os
import pytest
from veridrome.core.tee_attestation import TEEAttestationVerifier


def test_tee_attestation_sev_snp_verification():
    expected_pcr0 = "0x98f12a4b8823901234567890abcdef1234567890abcdef1234567890abcdef"
    nonce = os.urandom(32)

    valid_payload = {
        "measurement": expected_pcr0,
        "host_data": nonce.hex(),
        "policy": 0x30000,
    }

    res = TEEAttestationVerifier.verify_mock_or_real(
        platform="AMD-SEV-SNP",
        attestation_payload=valid_payload,
        expected_pcr0=expected_pcr0,
        expected_nonce=nonce,
    )
    assert res.is_valid is True
    assert res.platform == "AMD-SEV-SNP"
    assert res.nonce_matched is True


def test_tee_attestation_pcr0_mismatch():
    expected_pcr0 = "0x98f12a4b8823901234567890abcdef1234567890abcdef1234567890abcdef"
    tampered_pcr0 = "0x0000000000000000000000000000000000000000000000000000000000000000"
    nonce = os.urandom(32)

    invalid_payload = {
        "measurement": tampered_pcr0,
        "host_data": nonce.hex(),
    }

    res = TEEAttestationVerifier.verify_mock_or_real(
        platform="AMD-SEV-SNP",
        attestation_payload=invalid_payload,
        expected_pcr0=expected_pcr0,
        expected_nonce=nonce,
    )
    assert res.is_valid is False
    assert "Uyuşmazlığı" in res.message


def test_tee_attestation_aws_nitro_verification():
    expected_pcr0 = "0xaws_nitro_pcr0_hash_abcdef1234567890"
    nonce = os.urandom(32)

    valid_nitro = {
        "pcrs": {"0": expected_pcr0},
        "user_data": nonce.hex(),
    }

    res = TEEAttestationVerifier.verify_mock_or_real(
        platform="AWS-NITRO",
        attestation_payload=valid_nitro,
        expected_pcr0=expected_pcr0,
        expected_nonce=nonce,
    )
    assert res.is_valid is True
    assert res.platform == "AWS-NITRO"


def test_physical_tee_hardware_driver():
    from veridrome.core.tee_attestation import PhysicalTEEHardwareDriver

    nonce = os.urandom(32)
    hw_type = PhysicalTEEHardwareDriver.detect_hardware_tee()
    # Mevcut test ortamında SEV-SNP veya emülasyon olmalı
    attestation = PhysicalTEEHardwareDriver.fetch_hardware_attestation(nonce)
    assert "measurement" in attestation or "pcrs" in attestation
    assert "is_hardware_native" in attestation
    assert attestation["host_data"] == nonce.hex() or attestation.get("user_data") == nonce.hex()

