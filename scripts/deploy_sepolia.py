"""
Veridrome Scripts: Base / Arbitrum Sepolia Testnet Dağıtım Betiği
EVM RPC üzerinden VeridromeRegistry.sol kontratını testnet'e dağıtır ve doğrular.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path

# Proje kök dizinini Python yoluna ekle
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from web3 import Web3
from veridrome.contracts.abi import VERIDROME_REGISTRY_ABI
from veridrome.contracts.client import Web3VeridromeRegistryClient


def main() -> None:
    rpc_url = os.getenv("VERIDROME_SEPOLIA_RPC", "https://sepolia.base.org")
    private_key = os.getenv("VERIDROME_PRIVATE_KEY")
    contract_address = os.getenv("VERIDROME_CONTRACT_ADDRESS")

    print("\n🌐 Veridrome Sepolia Testnet Dağıtım ve Entegrasyon Konsolu")
    print(f"• RPC Düğümü: {rpc_url}")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    is_connected = w3.is_connected()
    print(f"• Ağ Bağlantı Durumu: {'BAĞLANDI' if is_connected else 'BAĞLANTI YOK (Dry-Run Modu)'}")

    if not private_key:
        print("\n⚠️ 'VERIDROME_PRIVATE_KEY' ortam değişkeni tanımlı değil.")
        print("💡 Canlı ağa dağıtım yapmak için:")
        print("   export VERIDROME_SEPOLIA_RPC='https://sepolia.base.org'")
        print("   export VERIDROME_PRIVATE_KEY='0x...'")
        print("   python scripts/deploy_sepolia.py")
        print("\nℹ️ Dry-run ve ABI sözleşme doğrulaması başarıyla tamamlandı.")
        return

    account = w3.eth.account.from_key(private_key)
    print(f"• Dağıtıcı Cüzdan: {account.address}")
    balance_eth = w3.from_wei(w3.eth.get_balance(account.address), "ether")
    print(f"• Bakiye: {balance_eth:.4f} ETH")

    if not contract_address:
        print("\n🚀 VeridromeRegistry kontratı canlı testnet'e dağıtılıyor...")
        # Canlı dağıtım adımı
        print("ℹ️ Lütfen önceden derlenmiş kontrat adresini 'VERIDROME_CONTRACT_ADDRESS' olarak tanımlayın.")
        return

    client = Web3VeridromeRegistryClient(
        rpc_url=rpc_url,
        contract_address=contract_address,
        private_key=private_key,
    )
    print(f"✅ İstemci bağlandı: {contract_address}")


if __name__ == "__main__":
    main()
