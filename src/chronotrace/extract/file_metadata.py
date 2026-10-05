"""File metadata extractor: filesystem timestamps, EXIF, PDF, and OOXML core properties."""

from __future__ import annotations
import datetime
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from typing import Iterator
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import parse_iso_timestamp, unix_to_datetime


@register_plugin
class FileMetadataPlugin(ArtifactPlugin):
    """Extracts filesystem metadata, document properties (OOXML, PDF), and archive timestamps."""

    name: str = "file_metadata"
    version: str = "1.3.0"
    capabilities: list[str] = ["metadata", "timeline"]
    applies_to: list[str] = ["all"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            try:
                # 1. Filesystem Stat metadata
                st = ef.stat()

                # Modified time
                mtime_dt = unix_to_datetime(st.st_mtime)
                if mtime_dt:
                    yield create_event(
                        timestamp_utc=mtime_dt,
                        action="FILE_WRITE",
                        action_class="file",
                        timestamp_type="modified",
                        artifact="filesystem:stat",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=ef.virtual_path,
                        confidence=0.95,
                        rationale="Filesystem stat modification time (mtime)",
                        raw_data={"mtime": st.st_mtime, "size": st.st_size, "mode": oct(st.st_mode)},
                    )

                # Creation / Metadata change time (ctime / birthtime)
                ctime_val = getattr(st, "st_birthtime", st.st_ctime)
                ctime_dt = unix_to_datetime(ctime_val)
                if ctime_dt:
                    yield create_event(
                        timestamp_utc=ctime_dt,
                        action="FILE_CREATE",
                        action_class="file",
                        timestamp_type="created",
                        artifact="filesystem:stat",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=ef.virtual_path,
                        confidence=0.90,
                        rationale="Filesystem stat creation/change time (ctime/birthtime)",
                        raw_data={"ctime": ctime_val, "size": st.st_size},
                    )

                # 2. OOXML Document Metadata (.docx, .xlsx, .pptx)
                if ef.virtual_path.lower().endswith((".docx", ".xlsx", ".pptx")):
                    yield from self._parse_ooxml(ef)

                # 3. PDF Metadata (.pdf)
                elif ef.virtual_path.lower().endswith(".pdf"):
                    yield from self._parse_pdf(ef)

                # 4. Zip archive entry timestamps (.zip)
                elif ef.virtual_path.lower().endswith(".zip"):
                    yield from self._parse_zip_entries(ef)

            except Exception:
                # Suppress parse warnings on damaged files, continue stream
                continue

    def _parse_ooxml(self, ef: EvidenceFile) -> Iterator[Event]:
        """Extract core.xml document properties from OOXML container."""
        try:
            with ef.open_read() as f:
                with zipfile.ZipFile(f, "r") as z:
                    if "docProps/core.xml" in z.namelist():
                        xml_bytes = z.read("docProps/core.xml")
                        root = ET.fromstring(xml_bytes)
                        # Namespaces
                        ns = {
                            "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                            "dc": "http://purl.org/dc/elements/1.1/",
                            "dcterms": "http://purl.org/dc/terms/",
                        }
                        creator = root.findtext("dc:creator", namespaces=ns) or "UNKNOWN"
                        modified_by = root.findtext("cp:lastModifiedBy", namespaces=ns) or "UNKNOWN"

                        created_str = root.findtext("dcterms:created", namespaces=ns)
                        if created_str:
                            c_dt, c_rfc = parse_iso_timestamp(created_str)
                            if c_dt:
                                yield create_event(
                                    timestamp_utc=c_dt,
                                    action="FILE_CREATE",
                                    action_class="file",
                                    timestamp_type="created",
                                    artifact="ooxml:core_properties",
                                    plugin=self.name,
                                    evidence_id=ef.evidence_id,
                                    evidence_sha256=ef.sha256,
                                    object_path=ef.virtual_path,
                                    user=creator,
                                    confidence=0.98,
                                    rationale="OOXML dcterms:created metadata",
                                    raw_data={"creator": creator, "created_raw": created_str},
                                )

                        modified_str = root.findtext("dcterms:modified", namespaces=ns)
                        if modified_str:
                            m_dt, m_rfc = parse_iso_timestamp(modified_str)
                            if m_dt:
                                yield create_event(
                                    timestamp_utc=m_dt,
                                    action="FILE_WRITE",
                                    action_class="file",
                                    timestamp_type="modified",
                                    artifact="ooxml:core_properties",
                                    plugin=self.name,
                                    evidence_id=ef.evidence_id,
                                    evidence_sha256=ef.sha256,
                                    object_path=ef.virtual_path,
                                    user=modified_by,
                                    confidence=0.98,
                                    rationale="OOXML dcterms:modified metadata",
                                    raw_data={"modified_by": modified_by, "modified_raw": modified_str},
                                )
        except Exception:
            pass

    def _parse_pdf(self, ef: EvidenceFile) -> Iterator[Event]:
        """Extract metadata dates from PDF trailer dictionary."""
        try:
            content = ef.read_bytes(0, min(ef.size, 1024 * 1024))
            # Search for /CreationDate and /ModDate (e.g. D:20240311142200Z or D:20240311142200-04'00')
            date_regex = re.compile(rb"/(\w+Date)\s*\(D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})")
            for match in date_regex.finditer(content):
                date_type = match.group(1).decode("ascii", errors="ignore")
                year, month, day, hour, minute, second = [int(g) for g in match.groups()[1:7]]
                dt = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
                action = "FILE_CREATE" if "Creation" in date_type else "FILE_WRITE"
                ts_type = "created" if "Creation" in date_type else "modified"

                yield create_event(
                    timestamp_utc=dt,
                    action=action,
                    action_class="file",
                    timestamp_type=ts_type,
                    artifact="pdf:trailer_info",
                    plugin=self.name,
                    evidence_id=ef.evidence_id,
                    evidence_sha256=ef.sha256,
                    object_path=ef.virtual_path,
                    confidence=0.92,
                    rationale=f"PDF {date_type} trailer property",
                    raw_data={"field": date_type, "raw_match": match.group(0).decode("ascii", errors="ignore")},
                )
        except Exception:
            pass

    def _parse_zip_entries(self, ef: EvidenceFile) -> Iterator[Event]:
        """Extract timestamps of individual files contained inside a zip archive."""
        try:
            with ef.open_read() as f:
                with zipfile.ZipFile(f, "r") as z:
                    for info in z.infolist():
                        if not info.is_dir():
                            dt = datetime.datetime(*info.date_time, tzinfo=datetime.timezone.utc)
                            yield create_event(
                                timestamp_utc=dt,
                                action="FILE_WRITE",
                                action_class="file",
                                timestamp_type="modified",
                                artifact="zip:entry_central_dir",
                                plugin=self.name,
                                evidence_id=ef.evidence_id,
                                evidence_sha256=ef.sha256,
                                object_path=f"{ef.virtual_path}::{info.filename}",
                                confidence=0.85,
                                rationale="ZIP entry central directory DOS timestamp",
                                raw_data={"zip_file": ef.virtual_path, "entry_name": info.filename, "file_size": info.file_size},
                            )
        except Exception:
            pass
