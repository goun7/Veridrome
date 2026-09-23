// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VeridromeRegistry
 * @notice Veridrome Ajan Değerlendirme, TEE Donanım Tasdiki ve Teminat (Staking) Kütüğü
 * @dev Ethereum Attestation Service (EAS) ve ERC-8004 ile tam uyumludur.
 */
contract VeridromeRegistry {
    struct EvaluationMetrics {
        uint32 scoreMedianBps;   // 10000 bazında medyan başarı (Örn: 9450 = %94.50)
        uint32 scoreIqrBps;      // Interquartile Range varyansı (Örn: 320 = %3.20)
        uint32 costPerTaskCents; // Görev başına ortalama harcama (Örn: 5 = $0.05)
        uint32 p95LatencySec;    // 95. persentil tamamlama süresi (Örn: 14 saniye)
        uint32 anomalyScoreBps;  // Anomali skoru (Örn: 1240 = 0.124)
    }

    struct CertificateRecord {
        bytes32 certId;          // Benzersiz sertifika hash'i
        bytes32 agentId;         // 68-Kredent / ERC-8004 Ajan Kimliği
        address vendorAddress;   // Satıcı yetkili cüzdanı
        bytes32 pcr0Measurement; // TEE Donanım PCR0 hash'i
        bytes32 merkleRoot;      // OTel yürütme izi Merkle kökü
        uint64 issuedAt;         // Blok zaman damgası
        uint64 expiresAt;        // Bitiş zaman damgası (maks 30 gün)
        bool isRevoked;          // İptal durumu bayrağı
        EvaluationMetrics metrics;
        uint256 collateralStaked;// Garanti havuzuna kilitlenen USDC/ETH miktarı
    }

    address public immutable authorityAdmin;
    mapping(bytes32 => CertificateRecord) public certificates;
    mapping(bytes32 => bool) public validPcr0Profiles;

    event CertificateIssued(bytes32 indexed certId, bytes32 indexed agentId, uint32 scoreMedianBps);
    event CertificateRevoked(bytes32 indexed certId, string reason);
    event CollateralDeposited(bytes32 indexed certId, address indexed vendor, uint256 amount);
    event CollateralSlashed(bytes32 indexed certId, address indexed recipient, uint256 amount, string justification);

    modifier onlyAuthority() {
        require(msg.sender == authorityAdmin, "Veridrome: Yalnizca Otorite Cagirabilir");
        _;
    }

    constructor() {
        authorityAdmin = msg.sender;
    }

    function setPcr0Validity(bytes32 pcr0, bool isValid) external onlyAuthority {
        validPcr0Profiles[pcr0] = isValid;
    }

    function issueCertificate(
        bytes32 agentId,
        bytes32 pcr0Measurement,
        bytes32 merkleRoot,
        EvaluationMetrics calldata metrics,
        address vendorAddress
    ) external onlyAuthority returns (bytes32 certId) {
        require(validPcr0Profiles[pcr0Measurement], "Gecersiz TEE Donanim Profili");
        require(metrics.anomalyScoreBps <= 4500, "Anomali Esigi Asildi: Overfit Reddi");

        certId = keccak256(abi.encodePacked(agentId, pcr0Measurement, merkleRoot, block.timestamp));
        certificates[certId] = CertificateRecord({
            certId: certId,
            agentId: agentId,
            vendorAddress: vendorAddress,
            pcr0Measurement: pcr0Measurement,
            merkleRoot: merkleRoot,
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 30 days),
            isRevoked: false,
            metrics: metrics,
            collateralStaked: 0
        });

        emit CertificateIssued(certId, agentId, metrics.scoreMedianBps);
        return certId;
    }

    function depositCollateral(bytes32 certId) external payable {
        CertificateRecord storage cert = certificates[certId];
        require(cert.issuedAt > 0 && !cert.isRevoked, "Gecersiz veya Iptal Edilmis Sertifika");
        require(block.timestamp < cert.expiresAt, "Sertifika Suresi Dolmus");
        cert.collateralStaked += msg.value;
        emit CollateralDeposited(certId, msg.sender, msg.value);
    }

    function revokeCertificate(bytes32 certId, string calldata reason) external onlyAuthority {
        CertificateRecord storage cert = certificates[certId];
        require(cert.issuedAt > 0, "Sertifika Bulunamadi");
        cert.isRevoked = true;
        emit CertificateRevoked(certId, reason);
    }

    function slashCollateral(
        bytes32 certId,
        address payable victim,
        uint256 amount,
        string calldata justification
    ) external onlyAuthority {
        CertificateRecord storage cert = certificates[certId];
        require(cert.collateralStaked >= amount, "Yetersiz Teminat Bakiyesi");
        cert.collateralStaked -= amount;
        victim.transfer(amount);
        emit CollateralSlashed(certId, victim, amount, justification);
    }

    function verifyCertificate(bytes32 certId) external view returns (bool isValid) {
        CertificateRecord memory cert = certificates[certId];
        if (cert.issuedAt == 0 || cert.isRevoked || block.timestamp >= cert.expiresAt) {
            return false;
        }
        return true;
    }
}
