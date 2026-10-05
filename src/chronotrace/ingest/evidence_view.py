"""EvidenceView: read-only abstraction provided to parsers and plugins."""

from __future__ import annotations
import os
from pathlib import Path
from typing import BinaryIO, Iterator, List, Optional
from chronotrace.core.writeguard import guarded_open


class EvidenceFile:
    """Represents an evidence file accessible in read-only mode."""

    def __init__(self, physical_path: Path, virtual_path: str, evidence_id: str, sha256: str):
        self.physical_path = physical_path
        self.virtual_path = virtual_path.replace("\\", "/")
        self.evidence_id = evidence_id
        self.sha256 = sha256

    def open_read(self) -> BinaryIO:
        """Open the evidence file in strictly read-only binary mode."""
        return guarded_open(self.physical_path, "rb")

    def read_bytes(self, offset: int = 0, length: Optional[int] = None) -> bytes:
        """Read a slice of bytes from the evidence file."""
        with self.open_read() as f:
            if offset > 0:
                f.seek(offset)
            if length is not None:
                return f.read(length)
            return f.read()

    @property
    def size(self) -> int:
        return self.physical_path.stat().st_size

    def stat(self) -> os.stat_result:
        return self.physical_path.stat()


class EvidenceView:
    """Read-only view over registered case evidence files and containers."""

    def __init__(self, case_root: Path, evidence_entries: List[dict]):
        self.case_root = case_root
        self.entries = evidence_entries
        self._files: List[EvidenceFile] = []
        self._scan_evidence()

    def _scan_evidence(self) -> None:
        """Scan physical files in evidence directory."""
        for entry in self.entries:
            ev_id = entry.get("evidence_id", "EV-UNKNOWN")
            sha = entry.get("hashes", {}).get("sha256", "")
            rel_path = entry.get("path", "")
            full_path = self.case_root / rel_path

            if full_path.is_file():
                self._files.append(EvidenceFile(full_path, rel_path, ev_id, sha))
            elif full_path.is_dir():
                for root, _, files in os.walk(full_path):
                    for fname in sorted(files):
                        p = Path(root) / fname
                        vpath = str(p.relative_to(self.case_root)).replace("\\", "/")
                        self._files.append(EvidenceFile(p, vpath, ev_id, sha))

    def files(self, pattern: Optional[str] = None) -> Iterator[EvidenceFile]:
        """Iterate over available evidence files, optionally filtering with glob pattern."""
        import fnmatch
        for ef in self._files:
            if pattern is None or fnmatch.fnmatch(ef.virtual_path, pattern) or fnmatch.fnmatch(ef.physical_path.name, pattern):
                yield ef

    def get_file(self, virtual_path: str) -> Optional[EvidenceFile]:
        """Retrieve a specific evidence file by its virtual path."""
        norm = virtual_path.replace("\\", "/")
        for ef in self._files:
            if ef.virtual_path == norm or ef.virtual_path.endswith(norm):
                return ef
        return None
