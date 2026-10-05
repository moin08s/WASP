"""Windows Registry hive parser extracting key LastWriteTime timestamps and configuration."""

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
class RegistryPlugin(ArtifactPlugin):
    """Parses Windows Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT) for LastWriteTime events."""

    name: str = "registry"
    version: str = "1.9.3"
    capabilities: list[str] = ["timeline", "config", "persistence"]
    applies_to: list[str] = ["windows"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            path_lower = ef.virtual_path.lower()
            if any(h in path_lower for h in ["system", "software", "sam", "security", "ntuser.dat", "usrclass.dat"]):
                yield from self._parse_hive(ef)

    def _parse_hive(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse raw regf registry hive header and scan for nk key nodes."""
        header = ef.read_bytes(0, 4)
        if header != b"regf":
            return

        file_size = ef.size
        # Read hive in chunks to locate 'nk' cells
        chunk_size = 65536
        num_chunks = file_size // chunk_size

        for chunk_idx in range(min(num_chunks, 500)):
            offset = 4096 + (chunk_idx * chunk_size)
            chunk_data = ef.read_bytes(offset, chunk_size)
            pos = 0

            while pos < len(chunk_data) - 80:
                # Look for 'nk' cell signature: b"nk"
                idx = chunk_data.find(b"nk", pos)
                if idx == -1 or idx + 80 > len(chunk_data):
                    break

                # LastWriteTime at offset +4 in nk structure (after signature)
                ft = struct.unpack_from("<Q", chunk_data, idx + 4)[0]
                dt = filetime_to_datetime(ft)

                name_len = struct.unpack_from("<H", chunk_data, idx + 0x48)[0]
                if 0 < name_len < 256 and idx + 0x4C + name_len <= len(chunk_data):
                    try:
                        key_name = chunk_data[idx + 0x4C : idx + 0x4C + name_len].decode("ascii", errors="ignore")
                    except Exception:
                        key_name = "Key"
                else:
                    key_name = "Key"

                if dt and 2000 <= dt.year <= 2040:
                    action = "REGISTRY_SET"
                    tags = ["config"]
                    if any(p in key_name.lower() for p in ["run", "runonce", "services", "startup"]):
                        tags.append("persistence")

                    yield create_event(
                        timestamp_utc=dt,
                        action=action,
                        action_class="config",
                        timestamp_type="last_write",
                        artifact=f"Registry:{ef.virtual_path}",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=f"{ef.virtual_path}\\{key_name}",
                        confidence=0.92,
                        rationale=f"Registry key '{key_name}' LastWriteTime",
                        record_offset=offset + idx,
                        tags=tags,
                        raw_data={"key_name": key_name, "raw_filetime": ft},
                    )

                pos = idx + 2
