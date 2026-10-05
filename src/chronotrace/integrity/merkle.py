"""Merkle tree calculation for compact cryptographic attestation."""

from __future__ import annotations
import hashlib
from typing import List, Sequence


class MerkleTree:
    """Calculates a deterministic Merkle root over a sequence of leaf hashes."""

    @staticmethod
    def compute_root(leaf_hashes: Sequence[str]) -> str:
        """
        Compute root hash over a list of leaf hex digests.
        Empty set produces standard zero hash.
        """
        if not leaf_hashes:
            return "0" * 64

        # Deterministic sort of leaf hashes
        sorted_leaves = sorted(leaf_hashes)
        current_layer = [bytes.fromhex(h) for h in sorted_leaves]

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                if i + 1 < len(current_layer):
                    right = current_layer[i + 1]
                else:
                    right = left  # duplicate odd leaf
                combined = hashlib.sha256(left + right).digest()
                next_layer.append(combined)
            current_layer = next_layer

        return current_layer[0].hex()
