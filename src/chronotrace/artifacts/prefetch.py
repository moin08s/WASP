"""Windows Prefetch (.pf) execution artefact parser."""

from __future__ import annotations
import struct
from typing import Iterator
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import filetime_to_datetime


@register_plugin
class PrefetchPlugin(ArtifactPlugin):
    """Parses Windows Prefetch (.pf) files to extract execution timestamps and run counts."""

    name: str = "prefetch"
    version: str = "1.2.0"
    capabilities: list[str] = ["timeline", "execution"]
    applies_to: list[str] = ["windows"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            if ef.virtual_path.lower().endswith(".pf"):
                yield from self._parse_prefetch_file(ef)

    def _parse_prefetch_file(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse binary prefetch header and execution timestamps."""
        data = ef.read_bytes(0, min(ef.size, 8192))
        if len(data) < 84:
            return

        # Check for uncompressed SCCA signature at offset 4
        magic = data[4:8]
        if magic != b"SCCA":
            # If MAM compressed or other format, extract basic filename from path
            exec_name = ef.physical_path.name.split("-")[0].upper()
            st = ef.stat()
            dt = filetime_to_datetime(int(st.st_mtime * 10000000 + 116444736000000000))
            if dt:
                yield create_event(
                    timestamp_utc=dt,
                    action="PROCESS_START",
                    action_class="process",
                    timestamp_type="executed",
                    artifact="Windows:Prefetch",
                    plugin=self.name,
                    evidence_id=ef.evidence_id,
                    evidence_sha256=ef.sha256,
                    object_path=exec_name,
                    confidence=0.88,
                    rationale=f"Prefetch file modification time for {exec_name}",
                    tags=["execution"],
                    raw_data={"prefetch_file": ef.virtual_path},
                )
            return

        version = struct.unpack_from("<I", data, 0)[0]
        # Executable name: 60 bytes UTF-16LE at offset 0x10
        raw_name = data[0x10 : 0x10 + 60]
        exec_name = raw_name.decode("utf-16le", errors="ignore").split("\x00")[0]
        if not exec_name:
            exec_name = ef.physical_path.name.split("-")[0].upper()

        # Run count and last execution timestamps based on version
        timestamps = []
        run_count = 0

        if version in (30, 31):  # Windows 10 / 11
            # Run count at offset 0xD0 (or 0xC8)
            if len(data) >= 0xD4:
                run_count = struct.unpack_from("<I", data, 0xD0)[0]
            # 8 execution times starting at 0x80
            for i in range(8):
                offset = 0x80 + (i * 8)
                if len(data) >= offset + 8:
                    ft = struct.unpack_from("<Q", data, offset)[0]
                    dt = filetime_to_datetime(ft)
                    if dt and dt.year >= 2000 and dt.year <= 2040:
                        timestamps.append((dt, ft))

        elif version in (23, 26):  # Windows 7 / 8
            if len(data) >= 0x94:
                run_count = struct.unpack_from("<I", data, 0x90)[0]
            # Single or up to 8 timestamps starting at 0x80
            for i in range(8):
                offset = 0x80 + (i * 8)
                if len(data) >= offset + 8:
                    ft = struct.unpack_from("<Q", data, offset)[0]
                    dt = filetime_to_datetime(ft)
                    if dt and dt.year >= 2000 and dt.year <= 2040:
                        timestamps.append((dt, ft))

        for idx, (dt, ft) in enumerate(timestamps):
            yield create_event(
                timestamp_utc=dt,
                action="PROCESS_START",
                action_class="process",
                timestamp_type="executed",
                artifact="Windows:Prefetch",
                plugin=self.name,
                evidence_id=ef.evidence_id,
                evidence_sha256=ef.sha256,
                object_path=exec_name,
                confidence=0.99,
                rationale=f"Prefetch verified execution timestamp (run {idx+1}/{len(timestamps)})",
                tags=["execution", "prefetch"],
                raw_data={"executable": exec_name, "run_count": run_count, "raw_filetime": ft},
            )
