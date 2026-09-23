import os
import tempfile
import pytest
from veridrome.core.crypto import VeridromeAuthoritySigner
from veridrome.credentials.w3c_vc import VeridromeCredentialManager


def test_w3c_credential_issuance_and_verification():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        signer = VeridromeAuthoritySigner()
        manager = VeridromeCredentialManager(signer=signer, ct_log_path=log_path)

        vc, vapap_token = manager.issue_credential(
            job_id="job-9912",
            agent_id="urn:kredent:agent:0x1234",
            metrics={"medianSuccess": 0.945, "anomalyScore": 0.12},
            tee_platform="AMD-SEV-SNP",
            pcr0_measurement="0x98f12a",
            merkle_root="0xabcdef",
        )

        assert vc["id"] == "urn:veridrome:cert:job-9912"
        assert "proof" in vc
        assert len(vapap_token) > 20

        # İmzayı doğrula
        is_valid = VeridromeCredentialManager.verify_credential(vc, signer.public_key_bytes)
        assert is_valid is True

        # Tahrif edilmiş VC doğrulamadan geçmemeli
        vc_tampered = dict(vc)
        vc_tampered["credentialSubject"] = dict(vc["credentialSubject"])
        vc_tampered["credentialSubject"]["metrics"] = {"medianSuccess": 1.0}
        assert VeridromeCredentialManager.verify_credential(vc_tampered, signer.public_key_bytes) is False

        # CT log dosyasına yazıldığını kontrol et
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) == 1
            assert "job-9912" in lines[0]

    finally:
        if os.path.exists(log_path):
            os.remove(log_path)
