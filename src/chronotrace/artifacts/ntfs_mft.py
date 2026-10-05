"""NTFS $MFT parser: $STANDARD_INFORMATION, $FILE_NAME, and timestomp detection."""

from __future__ import annotations
import struct
from typing import Iterator, Optional
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import filetime_to_datetime


@register_plugin
class NtfsMftPlugin(ArtifactPlugin):
    """Parses NTFS Master File Table ($MFT) records and flags timestomping anomalies."""

    name: str = "ntfs_mft"
    version: str = "1.4.2"
    capabilities: list[str] = ["timeline", "anti_forensics"]
    applies_to: list[str] = ["windows"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        # Search for $MFT files or files named *mft*
        for ef in source.files():
            name_lower = ef.virtual_path.lower()
            if "$mft" in name_lower or name_lower.endswith(".mft") or name_lower.endswith("mft.bin"):
                yield from self._parse_mft_binary(ef)

    def _parse_mft_binary(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse raw 1024-byte MFT records."""
        record_size = 1024
        file_size = ef.size
        num_records = file_size // record_size

        for record_idx in range(min(num_records, 50000)):  # Bounded chunk iteration
            offset = record_idx * record_size
            record_bytes = ef.read_bytes(offset, record_size)
            if len(record_bytes) < record_size:
                break

            magic = record_bytes[0:4]
            if magic != b"FILE":
                continue

            # First attribute offset
            first_attr_offset = struct.unpack_from("<H", record_bytes, 0x14)[0]
            record_id = struct.unpack_from("<I", record_bytes, 0x2C)[0]

            si_times: Optional[dict] = None
            fn_times: Optional[dict] = None
            file_name = f"MFT_Record_{record_id}"

            curr_offset = first_attr_offset
            while curr_offset < record_size - 8:
                attr_type, attr_len = struct.unpack_from("<II", record_bytes, curr_offset)
                if attr_type == 0xFFFFFFFF or attr_len == 0 or curr_offset + attr_len > record_size:
                    break

                # $STANDARD_INFORMATION (0x10)
                if attr_type == 0x10:
                    content_offset = curr_offset + struct.unpack_from("<H", record_bytes, curr_offset + 0x14)[0]
                    if content_offset + 32 <= record_size:
                        c_time, m_time, mft_time, a_time = struct.unpack_from("<QQQQ", record_bytes, content_offset)
                        si_times = {
                            "created": filetime_to_datetime(c_time),
                            "modified": filetime_to_datetime(m_time),
                            "mft_altered": filetime_to_datetime(mft_time),
                            "accessed": filetime_to_datetime(a_time),
                            "raw": (c_time, m_time, mft_time, a_time),
                        }

                # $FILE_NAME (0x30)
                elif attr_type == 0x30:
                    content_offset = curr_offset + struct.unpack_from("<H", record_bytes, curr_offset + 0x14)[0]
                    if content_offset + 66 <= record_size:
                        c_time, m_time, mft_time, a_time = struct.unpack_from("<QQQQ", record_bytes, content_offset + 8)
                        fn_len = record_bytes[content_offset + 64]
                        fn_raw = record_bytes[content_offset + 66 : content_offset + 66 + (fn_len * 2)]
                        try:
                            parsed_name = fn_raw.decode("utf-16le")
                            if parsed_name:
                                file_name = parsed_name
                        except Exception:
                            pass

                        fn_times = {
                            "created": filetime_to_datetime(c_time),
                            "modified": filetime_to_datetime(m_time),
                            "mft_altered": filetime_to_datetime(mft_time),
                            "accessed": filetime_to_datetime(a_time),
                            "raw": (c_time, m_time, mft_time, a_time),
                        }

                curr_offset += attr_len

            # Check for timestomping: $SI modified earlier than $FN created/modified
            is_timestomp = False
            tags = []
            if si_times and fn_times and si_times["modified"] and fn_times["modified"]:
                if si_times["modified"] < fn_times["modified"] or (si_times["raw"][1] % 10000000 == 0 and fn_times["raw"][1] % 10000000 != 0):
                    is_timestomp = True
                    tags.append("anti_forensics")
                    tags.append("TIMESTOMP_SUSPECTED")

            # Emit events for SI timestamps
            if si_times:
                if si_times["modified"]:
                    yield create_event(
                        timestamp_utc=si_times["modified"],
                        action="FILE_TIMESTOMP" if is_timestomp else "FILE_WRITE",
                        action_class="file",
                        timestamp_type="modified",
                        artifact="NTFS:$MFT",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=file_name,
                        confidence=0.75 if is_timestomp else 0.98,
                        rationale="NTFS MFT $STANDARD_INFORMATION modified timestamp" + (" (TIMESTOMP SUSPECTED)" if is_timestomp else ""),
                        record_id=record_id,
                        record_offset=offset,
                        tags=tags,
                        raw_data={"si": str(si_times["raw"]), "fn": str(fn_times["raw"]) if fn_times else None},
                    )

                if si_times["created"]:
                    yield create_event(
                        timestamp_utc=si_times["created"],
                        action="FILE_CREATE",
                        action_class="file",
                        timestamp_type="created",
                        artifact="NTFS:$MFT",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=file_name,
                        confidence=0.95,
                        rationale="NTFS MFT $STANDARD_INFORMATION created timestamp",
                        record_id=record_id,
                        record_offset=offset,
                        tags=tags,
                    )
