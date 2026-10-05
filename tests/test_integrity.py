"""Tests for cryptographic hashing, custody ledger, and Merkle root integrity."""

from pathlib import Path
from chronotrace.acquire.hasher import Hasher
from chronotrace.integrity.ledger import CustodyLedger, GENESIS_HASH
from chronotrace.integrity.merkle import MerkleTree


def test_streaming_hasher(tmp_path: Path):
    test_file = tmp_path / "sample.bin"
    content = b"CHRONOTRACE_INTEGRITY_VERIFICATION" * 1000
    test_file.write_bytes(content)

    hasher = Hasher()
    hashes, size = hasher.hash_file(test_file)

    assert size == len(content)
    assert "sha256" in hashes
    assert len(hashes["sha256"]) == 64
    assert hashes["sha256"] == Hasher.sha256_bytes(content)


def test_custody_ledger_hash_chain(tmp_path: Path):
    ledger_file = tmp_path / "ledger.jsonl"
    ledger = CustodyLedger(ledger_file)

    e1 = ledger.append_event(
        event_type="case_created",
        actor="Examiner Alice",
        payload={"case_id": "CASE-001"},
    )
    assert e1["seq"] == 1
    assert e1["prev_hash"] == GENESIS_HASH

    e2 = ledger.append_event(
        event_type="evidence_acquired",
        actor="Examiner Alice",
        payload={"evidence_id": "EV-001"},
    )
    assert e2["seq"] == 2
    assert e2["prev_hash"] == e1["entry_hash"]

    # Verify ledger integrity passes
    valid, count, errors = ledger.verify_ledger()
    assert valid is True
    assert count == 2
    assert len(errors) == 0


def test_custody_ledger_tamper_detection(tmp_path: Path):
    ledger_file = tmp_path / "tampered_ledger.jsonl"
    ledger = CustodyLedger(ledger_file)

    ledger.append_event("event_1", "Actor A", {"data": 1})
    ledger.append_event("event_2", "Actor A", {"data": 2})

    # Tamper with the ledger file
    lines = ledger_file.read_text(encoding="utf-8").splitlines()
    # Modify payload in line 1
    tampered_line1 = lines[0].replace('"data": 1', '"data": 999')
    ledger_file.write_text(f"{tampered_line1}\n{lines[1]}\n", encoding="utf-8")

    valid, count, errors = ledger.verify_ledger()
    assert valid is False
    assert len(errors) > 0


def test_merkle_tree_calculation():
    h1 = "a" * 64
    h2 = "b" * 64
    h3 = "c" * 64

    root1 = MerkleTree.compute_root([h1, h2, h3])
    root2 = MerkleTree.compute_root([h3, h1, h2])  # Order-independent sort
    assert root1 == root2
    assert len(root1) == 64
