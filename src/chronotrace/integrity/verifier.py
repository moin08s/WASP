"""Integrity verifier checking evidence, ledger, derived files, and Merkle root."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
from chronotrace.core.case import Case
from chronotrace.acquire.hasher import Hasher
from chronotrace.integrity.merkle import MerkleTree


class IntegrityVerifier:
    """Verifies SHA-256 evidence hashes, derived file digests, and custody ledger replay."""

    def __init__(self, case: Case):
        self.case = case

    def verify(self, rehash_evidence: bool = True, ledger_only: bool = False) -> Dict[str, Any]:
        """
        Execute comprehensive integrity verification.
        Returns detailed verification status report.
        """
        report: Dict[str, Any] = {
            "case_id": self.case.case_id,
            "overall_status": "PASS",
            "ledger_status": "PASS",
            "evidence_status": "PASS",
            "derived_status": "PASS",
            "merkle_status": "PASS",
            "errors": [],
            "warnings": [],
            "checked_items": {
                "ledger_entries": 0,
                "evidence_files": 0,
                "derived_files": 0,
            },
        }

        # 1. Replay and verify Custody Ledger
        if self.case.ledger:
            valid, count, errors = self.case.ledger.verify_ledger()
            report["checked_items"]["ledger_entries"] = count
            if not valid:
                report["overall_status"] = "FAIL"
                report["ledger_status"] = "FAIL"
                report["errors"].extend([f"Custody Ledger: {e}" for e in errors])

        if ledger_only:
            return report

        # 2. Check Manifest
        if not self.case.manifest_path.exists():
            report["overall_status"] = "FAIL"
            report["errors"].append("Missing manifest.json in case root")
            return report

        manifest_data = self.case.manifest.data if self.case.manifest else {}

        # 3. Verify Evidence Hashes
        if rehash_evidence:
            hasher = Hasher()
            for ev_entry in manifest_data.get("evidence", []):
                ev_id = ev_entry.get("evidence_id")
                rel_path = ev_entry.get("path")
                expected_sha256 = ev_entry.get("hashes", {}).get("sha256")
                full_path = self.case.root / rel_path

                report["checked_items"]["evidence_files"] += 1
                if not full_path.exists():
                    report["overall_status"] = "FAIL"
                    report["evidence_status"] = "FAIL"
                    report["errors"].append(f"Evidence file missing: {rel_path} ({ev_id})")
                    continue

                actual_hashes, _ = hasher.hash_file(full_path)
                actual_sha256 = actual_hashes.get("sha256")
                if actual_sha256 != expected_sha256:
                    report["overall_status"] = "FAIL"
                    report["evidence_status"] = "FAIL"
                    report["errors"].append(
                        f"Evidence SHA-256 mismatch for {rel_path}: expected {expected_sha256}, got {actual_sha256}"
                    )

        # 4. Verify Derived & Index Files
        derived_hashes = []
        for d_entry in manifest_data.get("derived", []):
            rel_path = d_entry.get("path")
            expected_sha256 = d_entry.get("sha256")
            full_path = self.case.root / rel_path

            report["checked_items"]["derived_files"] += 1
            if full_path.exists():
                actual_sha256 = Hasher.sha256_file(full_path)
                derived_hashes.append(actual_sha256)
                if actual_sha256 != expected_sha256:
                    report["overall_status"] = "FAIL"
                    report["derived_status"] = "FAIL"
                    report["errors"].append(
                        f"Derived file SHA-256 mismatch for {rel_path}: expected {expected_sha256}, got {actual_sha256}"
                    )
            else:
                report["warnings"].append(f"Derived file missing: {rel_path}")

        for i_entry in manifest_data.get("index", []):
            rel_path = i_entry.get("path")
            expected_sha256 = i_entry.get("sha256")
            full_path = self.case.root / rel_path
            if full_path.exists():
                actual_sha256 = Hasher.sha256_file(full_path)
                derived_hashes.append(actual_sha256)
                if actual_sha256 != expected_sha256:
                    report["overall_status"] = "FAIL"
                    report["derived_status"] = "FAIL"
                    report["errors"].append(
                        f"Index file SHA-256 mismatch for {rel_path}: expected {expected_sha256}, got {actual_sha256}"
                    )

        # 5. Verify Merkle Root
        expected_merkle = manifest_data.get("merkle_root")
        if expected_merkle:
            computed_merkle = MerkleTree.compute_root(derived_hashes)
            if computed_merkle != expected_merkle:
                report["merkle_status"] = "FAIL"
                report["warnings"].append(
                    f"Merkle root mismatch: expected {expected_merkle}, computed {computed_merkle}"
                )

        return report
