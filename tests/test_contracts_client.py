import pytest
from veridrome.contracts.client import MockVeridromeRegistryClient


def test_contracts_client_full_lifecycle():
    client = MockVeridromeRegistryClient()
    pcr0 = b"\x12\x34\x56" + b"\x00" * 29
    client.set_pcr0_validity(pcr0, True)

    agent_id = b"\xaa\xbb\xcc" + b"\x00" * 29
    merkle_root = b"\xdd\xee\xff" + b"\x00" * 29

    # 1. Başarılı sertifika basımı
    cert_id = client.issue_certificate(
        agent_id=agent_id,
        pcr0_measurement=pcr0,
        merkle_root=merkle_root,
        score_median_bps=9200,
        score_iqr_bps=300,
        cost_per_task_cents=4,
        p95_latency_sec=11,
        anomaly_score_bps=150,
        vendor_address="0xVendorAcme",
    )
    assert len(cert_id) == 32
    assert client.verify_certificate(cert_id) is True

    # 2. Teminat yatırma
    client.deposit_collateral(cert_id, 10_000_000)
    assert client.certificates[cert_id].collateral_staked == 10_000_000

    # 3. Slashing (Tazminat kesintisi)
    remaining = client.slash_collateral(cert_id, "0xVictim", 2_000_000)
    assert remaining == 8_000_000
    assert client.certificates[cert_id].collateral_staked == 8_000_000

    # 4. Sertifika iptali
    client.revoke_certificate(cert_id, "Ihlal")
    assert client.verify_certificate(cert_id) is False


def test_contracts_client_rejections():
    client = MockVeridromeRegistryClient()
    untrusted_pcr0 = b"\x99\x99\x99" + b"\x00" * 29

    # Geçersiz donanım profili reddedilmeli
    with pytest.raises(ValueError, match="Gecersiz TEE Donanim Profili"):
        client.issue_certificate(
            agent_id=b"\x01" * 32,
            pcr0_measurement=untrusted_pcr0,
            merkle_root=b"\x02" * 32,
            score_median_bps=9000,
            score_iqr_bps=200,
            cost_per_task_cents=5,
            p95_latency_sec=10,
            anomaly_score_bps=100,
            vendor_address="0xVendor",
        )

    # Anomali eşiği aşılırsa reddedilmeli
    trusted_pcr0 = b"\x77\x77\x77" + b"\x00" * 29
    client.set_pcr0_validity(trusted_pcr0, True)
    with pytest.raises(ValueError, match="Anomali Esigi Asildi"):
        client.issue_certificate(
            agent_id=b"\x01" * 32,
            pcr0_measurement=trusted_pcr0,
            merkle_root=b"\x02" * 32,
            score_median_bps=9000,
            score_iqr_bps=200,
            cost_per_task_cents=5,
            p95_latency_sec=10,
            anomaly_score_bps=5000,  # > 4500
            vendor_address="0xVendor",
        )
