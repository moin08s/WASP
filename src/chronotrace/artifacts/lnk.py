"""Windows Shortcut (.lnk) Shell Link parser."""

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
class LnkPlugin(ArtifactPlugin):
    """Parses Windows Shell Link (.lnk) shortcut files for target access timestamps."""

    name: str = "lnk"
    version: str = "1.1.0"
    capabilities: list[str] = ["timeline", "file"]
    applies_to: list[str] = ["windows"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            if ef.virtual_path.lower().endswith(".lnk"):
                yield from self._parse_lnk(ef)

    def _parse_lnk(self, ef: EvidenceFile) -> Iterator[Event]:
        data = ef.read_bytes(0, min(ef.size, 4096))
        if len(data) < 76:
            return

        header_size = struct.unpack_from("<I", data, 0)[0]
        if header_size != 76:
            return

        clsid = data[4:20]
        # Check standard Shell Link CLSID
        if clsid != bytes.fromhex("0114020000000000c000000000000046"):
            return

        c_time = struct.unpack_from("<Q", data, 0x1C)[0]
        a_time = struct.unpack_from("<Q", data, 0x24)[0]
        w_time = struct.unpack_from("<Q", data, 0x2C)[0]

        target_name = ef.physical_path.stem

        # Yield access time
        dt_access = filetime_to_datetime(a_time)
        if dt_access and 2000 <= dt_access.year <= 2040:
            yield create_event(
                timestamp_utc=dt_access,
                action="FILE_ACCESS",
                action_class="file",
                timestamp_type="accessed",
                artifact="Windows:LNK",
                plugin=self.name,
                evidence_id=ef.evidence_id,
                evidence_sha256=ef.sha256,
                object_path=f"{ef.virtual_path} -> {target_name}",
                confidence=0.96,
                rationale="LNK target last accessed FILETIME",
                tags=["user_activity", "lnk"],
                raw_data={"target_name": target_name, "raw_access": a_time},
            )

        # Yield write/modified time
        dt_write = filetime_to_datetime(w_time)
        if dt_write and 2000 <= dt_write.year <= 2040:
            yield create_event(
                timestamp_utc=dt_write,
                action="FILE_WRITE",
                action_class="file",
                timestamp_type="modified",
                artifact="Windows:LNK",
                plugin=self.name,
                evidence_id=ef.evidence_id,
                evidence_sha256=ef.sha256,
                object_path=f"{ef.virtual_path} -> {target_name}",
                confidence=0.96,
                rationale="LNK target last modified FILETIME",
                tags=["user_activity", "lnk"],
                raw_data={"target_name": target_name, "raw_write": w_time},
            )
