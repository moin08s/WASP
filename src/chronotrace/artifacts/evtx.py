"""Windows Event Log (EVTX) parser extracting authentication, execution, and service events."""

from __future__ import annotations
import datetime
import json
import re
import struct
from typing import Iterator
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import filetime_to_datetime, parse_iso_timestamp


@register_plugin
class EvtxPlugin(ArtifactPlugin):
    """Parses Windows Event Log (.evtx and exported JSON/XML) records."""

    name: str = "evtx"
    version: str = "2.1.0"
    capabilities: list[str] = ["timeline", "auth", "execution"]
    applies_to: list[str] = ["windows"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            path_lower = ef.virtual_path.lower()
            if path_lower.endswith(".evtx"):
                yield from self._parse_binary_evtx(ef)
            elif "winevt" in path_lower or ("event" in path_lower and path_lower.endswith((".json", ".jsonl"))):
                yield from self._parse_json_logs(ef)

    def _parse_binary_evtx(self, ef: EvidenceFile) -> Iterator[Event]:
        """Scan EVTX binary records for SystemTime and EventID."""
        header = ef.read_bytes(0, 16)
        if not header.startswith(b"ElfFile\x00"):
            return

        file_size = ef.size
        chunk_size = 65536  # 64 KiB EVTX chunk size
        num_chunks = file_size // chunk_size

        for chunk_idx in range(min(num_chunks, 1000)):
            chunk_offset = 4096 + (chunk_idx * chunk_size)
            chunk_data = ef.read_bytes(chunk_offset, chunk_size)
            if not chunk_data.startswith(b"ElfChnk\x00"):
                continue

            # Scan for record signatures within chunk: 0x2a 0x2a 0x00 0x00
            for match in re.finditer(rb"\x2a\x2a\x00\x00([\s\S]{20,512})", chunk_data):
                rec_slice = match.group(0)
                if len(rec_slice) < 28:
                    continue
                record_id = struct.unpack_from("<Q", rec_slice, 8)[0]
                # FILETIME is often stored at offset 16 in the record header
                ft = struct.unpack_from("<Q", rec_slice, 16)[0]
                dt = filetime_to_datetime(ft)
                if not dt or dt.year < 2000 or dt.year > 2040:
                    continue

                # Basic heuristic extraction for event ID
                event_id = 0
                eid_match = re.search(rb"<EventID[^>]*>(\d+)</EventID>", rec_slice)
                if eid_match:
                    try:
                        event_id = int(eid_match.group(1).decode("ascii"))
                    except Exception:
                        pass

                action, action_class, tags = self._map_event_id(event_id)

                yield create_event(
                    timestamp_utc=dt,
                    action=action,
                    action_class=action_class,
                    timestamp_type="logged",
                    artifact=f"EVTX:{ef.virtual_path}",
                    plugin=self.name,
                    evidence_id=ef.evidence_id,
                    evidence_sha256=ef.sha256,
                    object_path=ef.virtual_path,
                    confidence=0.99,
                    rationale=f"Windows EVTX SystemTime for Event ID {event_id}",
                    record_id=record_id,
                    tags=tags,
                    raw_data={"event_id": event_id, "chunk": chunk_idx},
                )

    def _parse_json_logs(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse exported Event Log JSON/JSONL dumps."""
        try:
            with ef.open_read() as f:
                for line in f:
                    line_str = line.decode("utf-8", errors="ignore").strip()
                    if not line_str or not line_str.startswith("{"):
                        continue
                    try:
                        data = json.loads(line_str)
                    except Exception:
                        continue

                    # Extract timestamp
                    ts_raw = data.get("SystemTime") or data.get("TimeCreated") or data.get("timestamp")
                    if not ts_raw:
                        continue

                    dt, _ = parse_iso_timestamp(str(ts_raw))
                    if not dt:
                        continue

                    eid = int(data.get("EventID") or data.get("event_id") or 0)
                    action, action_class, tags = self._map_event_id(eid)
                    user = data.get("TargetUserName") or data.get("user") or "UNKNOWN"
                    host = data.get("Computer") or data.get("host") or "UNKNOWN"

                    yield create_event(
                        timestamp_utc=dt,
                        action=action,
                        action_class=action_class,
                        timestamp_type="logged",
                        artifact=f"EVTX:{ef.virtual_path}",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        host=host,
                        user=user,
                        confidence=0.99,
                        rationale=f"Windows Event Log JSON entry for Event ID {eid}",
                        tags=tags,
                        raw_data=data,
                    )
        except Exception:
            pass

    def _map_event_id(self, event_id: int) -> tuple[str, str, list[str]]:
        """Map Windows Event ID to controlled action and forensic tags."""
        tags = []
        if event_id == 4624:
            return "AUTH_LOGIN", "auth", ["logon"]
        elif event_id == 4625:
            return "AUTH_FAIL", "auth", ["failed_logon"]
        elif event_id == 4688:
            return "PROCESS_START", "process", ["execution", "process_create"]
        elif event_id == 7045:
            return "SERVICE_INSTALL", "process", ["persistence", "service"]
        elif event_id == 1102:
            return "LOG_CLEARED", "system", ["anti_forensics", "log_cleared"]
        elif event_id == 4104:
            return "PROCESS_START", "process", ["powershell", "execution"]
        return "FILE_ACCESS", "system", []
