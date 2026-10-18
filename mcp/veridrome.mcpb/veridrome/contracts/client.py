"""
Veridrome Contracts: Web3 Akıllı Kontrat İstemcisi (Python 3.12+)
VeridromeRegistry.sol akıllı kontratı ile etkileşim, on-chain sertifika basımı,
teminat kilitleme (staking) ve slashing işlemlerini yürütür.
"""

from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from eth_utils import keccak


@dataclass
class OnChainCertificate:
    cert_id: bytes
    agent_id: bytes
    vendor_address: str
    pcr0_measurement: bytes
    merkle_root: bytes
    issued_at: int
    expires_at: int
    is_revoked: bool
    score_median_bps: int
    anomaly_score_bps: int
    collateral_staked: int


class InMemoryVeridromeRegistryClient:
    """
    VeridromeRegistry.sol kontratının yerel veya Web3 RPC üzerinde
    tam durum ve kurallarla çalışan bellek-içi (in-memory) durum motoru istemcisi.
    """

    def __init__(self, authority_address: str = "0xAuthority0000000000000000000000000000000"):
        self.authority_address = authority_address
        self.valid_pcr0_profiles: Dict[bytes, bool] = {}
        self.certificates: Dict[bytes, OnChainCertificate] = {}

    def set_pcr0_validity(self, pcr0_hash: bytes, is_valid: bool) -> None:
        self.valid_pcr0_profiles[pcr0_hash] = is_valid

    def issue_certificate(
        self,
        agent_id: bytes,
        pcr0_measurement: bytes,
        merkle_root: bytes,
        score_median_bps: int,
        score_iqr_bps: int,
        cost_per_task_cents: int,
        p95_latency_sec: int,
        anomaly_score_bps: int,
        vendor_address: str,
    ) -> bytes:
        """Yeni bir sertifika kaydı oluşturur ve 32-baytlık certId döndürür."""
        if not self.valid_pcr0_profiles.get(pcr0_measurement, False):
            raise ValueError("Gecersiz TEE Donanim Profili: PCR0 kayitli degil.")

        if anomaly_score_bps > 4500:
            raise ValueError("Anomali Esigi Asildi: Overfit Reddi.")

        now = int(time.time())
        packed_data = agent_id + pcr0_measurement + merkle_root + now.to_bytes(32, "big")
        cert_id = keccak(packed_data)

        record = OnChainCertificate(
            cert_id=cert_id,
            agent_id=agent_id,
            vendor_address=vendor_address,
            pcr0_measurement=pcr0_measurement,
            merkle_root=merkle_root,
            issued_at=now,
            expires_at=now + (30 * 86400),
            is_revoked=False,
            score_median_bps=score_median_bps,
            anomaly_score_bps=anomaly_score_bps,
            collateral_staked=0,
        )

        self.certificates[cert_id] = record
        return cert_id

    def deposit_collateral(self, cert_id: bytes, amount_wei: int) -> None:
        """Sertifikaya garanti teminatı kilitler."""
        if cert_id not in self.certificates:
            raise KeyError("Sertifika bulunamadi.")
        cert = self.certificates[cert_id]
        if cert.is_revoked:
            raise ValueError("Iptal edilmis sertifikaya teminat yatirilamaz.")
        cert.collateral_staked += amount_wei

    def revoke_certificate(self, cert_id: bytes, reason: str) -> None:
        """Sertifikayı iptal eder."""
        if cert_id not in self.certificates:
            raise KeyError("Sertifika bulunamadi.")
        self.certificates[cert_id].is_revoked = True

    def slash_collateral(self, cert_id: bytes, victim_address: str, amount_wei: int) -> int:
        """Sertifika teminatından tazminat keser (slashing)."""
        if cert_id not in self.certificates:
            raise KeyError("Sertifika bulunamadi.")
        cert = self.certificates[cert_id]
        if cert.collateral_staked < amount_wei:
            raise ValueError("Yetersiz Teminat Bakiyesi.")
        cert.collateral_staked -= amount_wei
        return cert.collateral_staked

    def verify_certificate(self, cert_id: bytes) -> bool:
        """Sertifikanın geçerli olup olmadığını sorgular."""
        if cert_id not in self.certificates:
            return False
        cert = self.certificates[cert_id]
        now = int(time.time())
        if cert.is_revoked or now >= cert.expires_at or cert.issued_at == 0:
            return False
        return True


# Geriye dönük uyumluluk için alias
MockVeridromeRegistryClient = InMemoryVeridromeRegistryClient


class Web3VeridromeRegistryClient:
    """
    Ethereum JSON-RPC üzerinden gerçek VeridromeRegistry.sol akıllı kontratı
    ile etkileşime geçen Web3 istemcisi (Base Sepolia, Arbitrum Sepolia vb.).
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: Optional[str] = None,
    ):
        from web3 import Web3
        from veridrome.contracts.abi import VERIDROME_REGISTRY_ABI

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract_address = Web3.to_checksum_address(contract_address)
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=VERIDROME_REGISTRY_ABI,
        )
        self.private_key = private_key
        if private_key:
            self.account = self.w3.eth.account.from_key(private_key)
            self.authority_address = self.account.address
        else:
            self.account = None
            self.authority_address = "0x0000000000000000000000000000000000000000"

    def _send_transaction(self, func_call: Any, value: int = 0) -> str:
        if not self.account or not self.private_key:
            raise ValueError("İşlem imzalamak için 'private_key' tanımlanmalıdır.")

        nonce = self.w3.eth.get_transaction_count(self.account.address)
        tx = func_call.build_transaction({
            "from": self.account.address,
            "nonce": nonce,
            "value": value,
            "gas": 1_000_000,
            "gasPrice": self.w3.eth.gas_price,
        })
        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.get("status") != 1:
            raise RuntimeError(f"İşlem başarısız oldu: {tx_hash.hex()}")
        return tx_hash.hex()

    def set_pcr0_validity(self, pcr0_hash: bytes, is_valid: bool) -> str:
        func = self.contract.functions.setPcr0Validity(pcr0_hash, is_valid)
        return self._send_transaction(func)

    def issue_certificate(
        self,
        agent_id: bytes,
        pcr0_measurement: bytes,
        merkle_root: bytes,
        score_median_bps: int,
        score_iqr_bps: int,
        cost_per_task_cents: int,
        p95_latency_sec: int,
        anomaly_score_bps: int,
        vendor_address: str,
    ) -> bytes:
        from web3 import Web3
        metrics = (
            score_median_bps,
            score_iqr_bps,
            cost_per_task_cents,
            p95_latency_sec,
            anomaly_score_bps,
        )
        checksum_vendor = Web3.to_checksum_address(vendor_address)
        func = self.contract.functions.issueCertificate(
            agent_id,
            pcr0_measurement,
            merkle_root,
            metrics,
            checksum_vendor,
        )
        self._send_transaction(func)
        now = int(time.time())
        packed_data = agent_id + pcr0_measurement + merkle_root + now.to_bytes(32, "big")
        return keccak(packed_data)

    def deposit_collateral(self, cert_id: bytes, amount_wei: int) -> str:
        func = self.contract.functions.depositCollateral(cert_id)
        return self._send_transaction(func, value=amount_wei)

    def revoke_certificate(self, cert_id: bytes, reason: str) -> str:
        func = self.contract.functions.revokeCertificate(cert_id, reason)
        return self._send_transaction(func)

    def slash_collateral(
        self,
        cert_id: bytes,
        victim_address: str,
        amount_wei: int,
        justification: str = "SLOH Malicious Execution",
    ) -> str:
        from web3 import Web3
        checksum_victim = Web3.to_checksum_address(victim_address)
        func = self.contract.functions.slashCollateral(
            cert_id, checksum_victim, amount_wei, justification
        )
        return self._send_transaction(func)

    def verify_certificate(self, cert_id: bytes) -> bool:
        try:
            is_valid, _, _ = self.contract.functions.verifyCertificate(cert_id).call()
            return bool(is_valid)
        except Exception:
            return False

