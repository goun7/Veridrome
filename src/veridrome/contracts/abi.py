"""
Veridrome Contracts: VeridromeRegistry.sol ABI Tanımı
Ethereum Attestation Service (EAS) ve ERC-8004 uyumlu ABI veri yapısı.
"""

from typing import Any, List, Dict

VERIDROME_REGISTRY_ABI: List[Dict[str, Any]] = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"indexed": True, "internalType": "bytes32", "name": "agentId", "type": "bytes32"},
            {"indexed": False, "internalType": "uint32", "name": "scoreMedianBps", "type": "uint32"},
        ],
        "name": "CertificateIssued",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"indexed": False, "internalType": "string", "name": "reason", "type": "string"},
        ],
        "name": "CertificateRevoked",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "vendor", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
        ],
        "name": "CollateralDeposited",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "recipient", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "justification", "type": "string"},
        ],
        "name": "CollateralSlashed",
        "type": "event",
    },
    {
        "inputs": [],
        "name": "authorityAdmin",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "pcr0", "type": "bytes32"},
            {"internalType": "bool", "name": "isValid", "type": "bool"},
        ],
        "name": "setPcr0Validity",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "agentId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "pcr0Measurement", "type": "bytes32"},
            {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
            {
                "components": [
                    {"internalType": "uint32", "name": "scoreMedianBps", "type": "uint32"},
                    {"internalType": "uint32", "name": "scoreIqrBps", "type": "uint32"},
                    {"internalType": "uint32", "name": "costPerTaskCents", "type": "uint32"},
                    {"internalType": "uint32", "name": "p95LatencySec", "type": "uint32"},
                    {"internalType": "uint32", "name": "anomalyScoreBps", "type": "uint32"},
                ],
                "internalType": "struct VeridromeRegistry.EvaluationMetrics",
                "name": "metrics",
                "type": "tuple",
            },
            {"internalType": "address", "name": "vendorAddress", "type": "address"},
        ],
        "name": "issueCertificate",
        "outputs": [{"internalType": "bytes32", "name": "certId", "type": "bytes32"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "certId", "type": "bytes32"}],
        "name": "depositCollateral",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"internalType": "string", "name": "reason", "type": "string"},
        ],
        "name": "revokeCertificate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "certId", "type": "bytes32"},
            {"internalType": "address payable", "name": "recipient", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "string", "name": "justification", "type": "string"},
        ],
        "name": "slashCollateral",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "certId", "type": "bytes32"}],
        "name": "verifyCertificate",
        "outputs": [
            {"internalType": "bool", "name": "isValid", "type": "bool"},
            {"internalType": "uint32", "name": "scoreMedianBps", "type": "uint32"},
            {"internalType": "uint256", "name": "collateralStaked", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "certId", "type": "bytes32"}],
        "name": "getCertificate",
        "outputs": [
            {
                "components": [
                    {"internalType": "bytes32", "name": "certId", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "agentId", "type": "bytes32"},
                    {"internalType": "address", "name": "vendorAddress", "type": "address"},
                    {"internalType": "bytes32", "name": "pcr0Measurement", "type": "bytes32"},
                    {"internalType": "bytes32", "name": "merkleRoot", "type": "bytes32"},
                    {"internalType": "uint64", "name": "issuedAt", "type": "uint64"},
                    {"internalType": "uint64", "name": "expiresAt", "type": "uint64"},
                    {"internalType": "bool", "name": "isRevoked", "type": "bool"},
                    {
                        "components": [
                            {"internalType": "uint32", "name": "scoreMedianBps", "type": "uint32"},
                            {"internalType": "uint32", "name": "scoreIqrBps", "type": "uint32"},
                            {"internalType": "uint32", "name": "costPerTaskCents", "type": "uint32"},
                            {"internalType": "uint32", "name": "p95LatencySec", "type": "uint32"},
                            {"internalType": "uint32", "name": "anomalyScoreBps", "type": "uint32"},
                        ],
                        "internalType": "struct VeridromeRegistry.EvaluationMetrics",
                        "name": "metrics",
                        "type": "tuple",
                    },
                    {"internalType": "uint256", "name": "collateralStaked", "type": "uint256"},
                ],
                "internalType": "struct VeridromeRegistry.CertificateRecord",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]
