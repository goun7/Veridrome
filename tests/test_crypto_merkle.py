import pytest
from veridrome.core.crypto import MerkleTreeAuditLog, VeridromeAuthoritySigner, generate_challenge_nonce


def test_ed25519_signer_and_verifier():
    signer = VeridromeAuthoritySigner()
    pubkey = signer.public_key_bytes

    msg = b"VERIDROME_CERTIFICATE_CLAIM_PAYLOAD_2026"
    sig = signer.sign(msg)

    # Doğru doğrulama
    assert VeridromeAuthoritySigner.verify(pubkey, msg, sig) is True

    # Tahrif edilmiş mesaj reddedilmeli
    tampered_msg = b"VERIDROME_CERTIFICATE_CLAIM_PAYLOAD_TAMPERED"
    assert VeridromeAuthoritySigner.verify(pubkey, tampered_msg, sig) is False


def test_merkle_tree_root_and_proof_verification():
    tree = MerkleTreeAuditLog()
    leaves_data = [
        b"step_01_navigate_to_cart",
        b"step_02_type_coupon_code",
        b"step_03_click_apply_btn",
        b"step_04_assert_total_amount",
    ]

    for d in leaves_data:
        tree.add_leaf(d)

    root = tree.get_root()
    assert len(root) == 32
    assert tree.get_root_hex().startswith("0x")

    # Tüm yaprakların denetim kanıtını doğrula
    for idx, d in enumerate(leaves_data):
        proof = tree.generate_proof(idx)
        is_valid = MerkleTreeAuditLog.verify_proof(d, proof, root)
        assert is_valid is True

    # Sahte veri denetim kanıtını geçemez
    fake_data = b"step_fake_injected"
    proof0 = tree.generate_proof(0)
    assert MerkleTreeAuditLog.verify_proof(fake_data, proof0, root) is False


def test_challenge_nonce_generation():
    nonce1 = generate_challenge_nonce(32)
    nonce2 = generate_challenge_nonce(32)
    assert len(nonce1) == 32
    assert len(nonce2) == 32
    assert nonce1 != nonce2
