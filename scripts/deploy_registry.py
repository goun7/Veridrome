"""
Veridrome Scripts: VeridromeRegistry.sol Dağıtım ve Başlatma Betiği
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from veridrome.contracts.client import MockVeridromeRegistryClient


def main():
    print("\n🏛️ Veridrome Akıllı Kontrat Dağıtım Süreci Başlatılıyor...")

    client = MockVeridromeRegistryClient()
    dummy_pcr0 = b"\x98\xf1\x2a" + b"\x00" * 29

    print("• Otorite Adresi:", client.authority_address)
    print("• TEE PCR0 Profili Tanımlanıyor:", dummy_pcr0.hex())
    client.set_pcr0_validity(dummy_pcr0, True)

    agent_id = b"\x44\x55\x66" + b"\x00" * 29
    merkle_root = b"\xaa\xbb\xcc" + b"\x00" * 29

    cert_id = client.issue_certificate(
        agent_id=agent_id,
        pcr0_measurement=dummy_pcr0,
        merkle_root=merkle_root,
        score_median_bps=9500,
        score_iqr_bps=200,
        cost_per_task_cents=5,
        p95_latency_sec=12,
        anomaly_score_bps=120,
        vendor_address="0xVendor1234567890",
    )

    print("✅ Sertifika On-Chain Basıldı (certId):", cert_id.hex())
    print("• Sertifika Doğrulaması:", "GEÇERLİ" if client.verify_certificate(cert_id) else "GEÇERSİZ")

    # Staking
    client.deposit_collateral(cert_id, 10_000_000_000)
    print("✅ $10.000 Staking Teminatı Kilitlendi.")
    print()


if __name__ == "__main__":
    main()
