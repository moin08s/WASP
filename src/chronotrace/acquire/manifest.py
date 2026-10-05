"""Manifest generator and validator for case integrity tracking."""

from __future__ import annotations
import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from chronotrace.integrity.merkle import MerkleTree
from chronotrace.acquire.hasher import Hasher


class CaseManifest:
    """Manages the case manifest.json cryptographic inventory."""

    def __init__(self, manifest_path: str | Path, case_id: str = "CASE-DEFAULT"):
        self.path = Path(manifest_path)
        self.case_id = case_id
        self.data: Dict[str, Any] = {
            "manifest_version": "1.1.0",
            "case_id": case_id,
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tool": {"name": "wasp", "version": "1.4.0"},
            "schema_version": "2.0.0",
            "evidence": [],
            "derived": [],
            "index": [],
            "reports": [],
            "config": None,
            "merkle_root": None,
        }
        if self.path.exists():
            self.load()

    def load(self) -> None:
        """Load manifest from disk."""
        with open(self.path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
            self.case_id = self.data.get("case_id", self.case_id)

    def save(self) -> None:
        """Calculate Merkle root and write canonical manifest.json."""
        # Calculate Merkle root across derived and index files
        derived_hashes = [d["sha256"] for d in self.data.get("derived", []) if "sha256" in d]
        index_hashes = [i["sha256"] for i in self.data.get("index", []) if "sha256" in i]
        all_hashes = derived_hashes + index_hashes
        self.data["merkle_root"] = MerkleTree.compute_root(all_hashes)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)

    def add_evidence(
        self,
        evidence_id: str,
        rel_path: str,
        container: str,
        size_bytes: int,
        hashes: Dict[str, str],
        source: Optional[str] = None,
        verification_result: str = "match",
    ) -> None:
        """Register an acquired evidence container or file."""
        # Remove any existing entry for this evidence_id
        self.data["evidence"] = [
            e for e in self.data["evidence"] if e.get("evidence_id") != evidence_id
        ]
        entry = {
            "evidence_id": evidence_id,
            "path": rel_path.replace("\\", "/"),
            "container": container,
            "size_bytes": size_bytes,
            "acquired_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": source or rel_path,
            "read_errors": 0,
            "hashes": hashes,
            "verification": {
                "method": "readback",
                "verified_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "result": verification_result,
            },
        }
        self.data["evidence"].append(entry)

    def add_derived_file(
        self,
        rel_path: str,
        size_bytes: int,
        sha256: str,
        plugin: str = "core",
        plugin_version: str = "1.0.0",
    ) -> None:
        """Register a derived artefact file."""
        norm_path = rel_path.replace("\\", "/")
        self.data["derived"] = [
            d for d in self.data["derived"] if d.get("path") != norm_path
        ]
        self.data["derived"].append({
            "path": norm_path,
            "size_bytes": size_bytes,
            "sha256": sha256,
            "plugin": plugin,
            "plugin_version": plugin_version,
        })

    def add_index_file(self, rel_path: str, size_bytes: int, sha256: str) -> None:
        """Register an index store file."""
        norm_path = rel_path.replace("\\", "/")
        self.data["index"] = [
            i for i in self.data["index"] if i.get("path") != norm_path
        ]
        self.data["index"].append({
            "path": norm_path,
            "size_bytes": size_bytes,
            "sha256": sha256,
        })

    def add_report_file(self, rel_path: str, sha256: str) -> None:
        """Register an investigation report file."""
        norm_path = rel_path.replace("\\", "/")
        self.data["reports"] = [
            r for r in self.data["reports"] if r.get("path") != norm_path
        ]
        self.data["reports"].append({
            "path": norm_path,
            "sha256": sha256,
        })

    def set_config(self, rel_path: str, sha256: str) -> None:
        """Register case config hash."""
        self.data["config"] = {
            "path": rel_path.replace("\\", "/"),
            "sha256": sha256,
        }
