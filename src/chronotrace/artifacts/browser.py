"""Web Browser activity parser for Chromium, Edge, and Firefox SQLite databases."""

from __future__ import annotations
import sqlite3
import tempfile
from typing import Iterator
from chronotrace.extract.base import ArtifactPlugin
from chronotrace.extract.registry import register_plugin
from chronotrace.core.models import Event
from chronotrace.ingest.evidence_view import EvidenceFile, EvidenceView
from chronotrace.normalize.normalizer import create_event
from chronotrace.normalize.timezone import chrome_time_to_datetime, unix_to_datetime


@register_plugin
class BrowserPlugin(ArtifactPlugin):
    """Parses Chromium, Edge, and Firefox browsing history databases."""

    name: str = "browser"
    version: str = "1.3.0"
    capabilities: list[str] = ["timeline", "network", "web"]
    applies_to: list[str] = ["all"]
    parallel_safe: bool = True

    def parse(self, source: EvidenceView) -> Iterator[Event]:
        for ef in source.files():
            path_lower = ef.virtual_path.lower()
            if path_lower.endswith("history") or "history" in path_lower:
                yield from self._parse_chromium(ef)
            elif path_lower.endswith("places.sqlite"):
                yield from self._parse_firefox(ef)

    def _parse_chromium(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse Chromium / Edge 'History' SQLite database in memory."""
        data = ef.read_bytes()
        if not data.startswith(b"SQLite format 3\x00"):
            return

        try:
            conn = sqlite3.connect(":memory:")
            conn.deserialize(data)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls WHERE last_visit_time > 0 ORDER BY last_visit_time ASC LIMIT 5000"
            )
            for row in cursor.fetchall():
                url, title, visit_count, last_visit = row
                dt = chrome_time_to_datetime(last_visit)
                if dt and 2000 <= dt.year <= 2040:
                    yield create_event(
                        timestamp_utc=dt,
                        action="WEB_VISIT",
                        action_class="network",
                        timestamp_type="accessed",
                        artifact=f"Browser:Chromium:{ef.virtual_path}",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=url,
                        object_type="url",
                        confidence=0.97,
                        rationale="Chromium last_visit_time WebKit timestamp",
                        tags=["web", "browser_history"],
                        raw_data={"url": url, "title": title, "visit_count": visit_count, "raw_time": last_visit},
                    )
            conn.close()
        except Exception:
            pass

    def _parse_firefox(self, ef: EvidenceFile) -> Iterator[Event]:
        """Parse Firefox places.sqlite database in memory."""
        data = ef.read_bytes()
        if not data.startswith(b"SQLite format 3\x00"):
            return

        try:
            conn = sqlite3.connect(":memory:")
            conn.deserialize(data)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date > 0 ORDER BY last_visit_date ASC LIMIT 5000"
            )
            for row in cursor.fetchall():
                url, title, last_visit = row
                # Firefox uses microseconds since Unix epoch
                dt = unix_to_datetime(last_visit / 1000000.0)
                if dt and 2000 <= dt.year <= 2040:
                    yield create_event(
                        timestamp_utc=dt,
                        action="WEB_VISIT",
                        action_class="network",
                        timestamp_type="accessed",
                        artifact=f"Browser:Firefox:{ef.virtual_path}",
                        plugin=self.name,
                        evidence_id=ef.evidence_id,
                        evidence_sha256=ef.sha256,
                        object_path=url,
                        object_type="url",
                        confidence=0.97,
                        rationale="Firefox moz_places last_visit_date microsecond timestamp",
                        tags=["web", "browser_history"],
                        raw_data={"url": url, "title": title, "raw_time": last_visit},
                    )
            conn.close()
        except Exception:
            pass
