"""
Veridrome Core: Kriptografi & Merkle Defter Motoru (Python 3.12+)
Ed25519 Otorite İmzası, RFC 6962 Merkle Tree Yürütme İzi (CT Log) ve Güvenli Nonce Üretimi.
"""

from __future__ import annotations
import base64
import hashlib
import os
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class VeridromeAuthoritySigner:
    """Veridrome otorite imzalayıcısı ve anahtar yöneticisi."""

    def __init__(self, private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        self._private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def sign_base64(self, message: bytes) -> str:
        return base64.b64encode(self.sign(message)).decode("ascii")

    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
        except Exception:
            return False


class MerkleTreeAuditLog:
    """
    RFC 6962 uyumlu Merkle Tree Defteri.
    Her DOM olayı, HTTP çağrısı ve LLM token adımı yaprak olarak eklenir.
    Prefix 0x00: Yaprak düğümler (Leaf)
    Prefix 0x01: İç düğümler (Interior Nodes)
    """

    def __init__(self, leaves_data: Optional[List[bytes]] = None):
        self.leaves: List[bytes] = []
        if leaves_data:
            for data in leaves_data:
                self.add_leaf(data)

    @staticmethod
    def hash_leaf(data: bytes) -> bytes:
        """RFC 6962: SHA256(0x00 || data)"""
        return hashlib.sha256(b"\x00" + data).digest()

    @staticmethod
    def hash_children(left: bytes, right: bytes) -> bytes:
        """RFC 6962: SHA256(0x01 || left || right)"""
        return hashlib.sha256(b"\x01" + left + right).digest()

    def add_leaf(self, data: bytes) -> bytes:
        h = self.hash_leaf(data)
        self.leaves.append(h)
        return h

    def get_root(self) -> bytes:
        """Ağacın 32-baytlık kök (root) özetini hesaplar."""
        if not self.leaves:
            return hashlib.sha256(b"").digest()

        current_level = list(self.leaves)
        while len(current_level) > 1:
            next_level: List[bytes] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # Tek kalan yaprak kopyalanır
                next_level.append(self.hash_children(left, right))
            current_level = next_level

        return current_level[0]

    def get_root_hex(self) -> str:
        return "0x" + self.get_root().hex()

    def generate_proof(self, index: int) -> List[Tuple[str, bytes]]:
        """Verilen indeksteki yaprak için denetim kanıtı (audit path) üretir."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Geçersiz yaprak indeksi.")

        proof: List[Tuple[str, bytes]] = []
        current_level = list(self.leaves)
        curr_idx = index

        while len(current_level) > 1:
            next_level: List[bytes] = []
            is_right_sibling = (curr_idx % 2 == 0)

            if is_right_sibling:
                if curr_idx + 1 < len(current_level):
                    sibling = current_level[curr_idx + 1]
                else:
                    sibling = current_level[curr_idx]
                proof.append(("right", sibling))
            else:
                sibling = current_level[curr_idx - 1]
                proof.append(("left", sibling))

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self.hash_children(left, right))

            curr_idx = curr_idx // 2
            current_level = next_level

        return proof

    @classmethod
    def verify_proof(cls, leaf_data: bytes, proof: List[Tuple[str, bytes]], expected_root: bytes) -> bool:
        """Denetim kanıtını bağımsız olarak doğrular."""
        current_hash = cls.hash_leaf(leaf_data)
        for direction, sibling_hash in proof:
            if direction == "right":
                current_hash = cls.hash_children(current_hash, sibling_hash)
            else:
                current_hash = cls.hash_children(sibling_hash, current_hash)
        return current_hash == expected_root


def generate_challenge_nonce(length: int = 32) -> bytes:
    """Kriptografik güvenli rastgele meydan okuma (challenge) nonce'u."""
    return os.urandom(length)
