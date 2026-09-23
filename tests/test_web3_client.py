import pytest
from eth_utils import keccak
from veridrome.contracts.abi import VERIDROME_REGISTRY_ABI
from veridrome.contracts.client import MockVeridromeRegistryClient, Web3VeridromeRegistryClient


def test_registry_abi_structure():
    assert isinstance(VERIDROME_REGISTRY_ABI, list)
    func_names = {item.get("name") for item in VERIDROME_REGISTRY_ABI if item.get("type") == "function"}
    expected_funcs = {
        "setPcr0Validity",
        "issueCertificate",
        "depositCollateral",
        "revokeCertificate",
        "slashCollateral",
        "verifyCertificate",
        "getCertificate",
        "authorityAdmin",
    }
    assert expected_funcs.issubset(func_names)


def test_web3_client_initialization():
    client = Web3VeridromeRegistryClient(
        rpc_url="https://sepolia.base.org",
        contract_address="0x1111111111111111111111111111111111111111",
        private_key=None,
    )
    assert client.contract_address == "0x1111111111111111111111111111111111111111"
    assert client.authority_address == "0x0000000000000000000000000000000000000000"

    # Private key olmadan transaction gönderme koruması
    with pytest.raises(ValueError, match="private_key"):
        client.set_pcr0_validity(b"\x00" * 32, True)
