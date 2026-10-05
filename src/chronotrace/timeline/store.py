"""Timeline storage engine writing both columnar Parquet and indexed SQLite stores."""

from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
import pyarrow as pa
import pyarrow.parquet as pq
from chronotrace.core.models import Event


class TimelineStore:
    """Manages Parquet and SQLite persistence for reconstructed chronological timelines."""

    def __init__(self, index_dir: str | Path):
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.parquet_path = self.index_dir / "events.parquet"
        self.sqlite_path = self.index_dir / "events.sqlite"

    def write_timeline(self, events: List[Event]) -> tuple[str, str]:
        """
        Write sorted events to both events.parquet and events.sqlite.
        Returns: (parquet_sha256, sqlite_sha256)
        """
        from chronotrace.acquire.hasher import Hasher

        # 1. Write Columnar Parquet
        self._write_parquet(events)

        # 2. Write SQLite with indexes & FTS5
        self._write_sqlite(events)

        p_hash = Hasher.sha256_file(self.parquet_path)
        s_hash = Hasher.sha256_file(self.sqlite_path)
        return p_hash, s_hash

    def _write_parquet(self, events: List[Event]) -> None:
        """Write events to compressed Apache Parquet table."""
        records = []
        for e in events:
            records.append({
                "event_id": e.event_id,
                "timestamp_utc": e.timestamp_utc,
                "timestamp_raw": e.timestamp_raw or "",
                "timestamp_type": e.timestamp_type,
                "action": e.action,
                "action_class": e.action_class,
                "host": e.host,
                "user": e.user,
                "object_type": e.object.type,
                "object_path": e.object.path or "",
                "object_path_norm": e.object.path_norm or "",
                "artifact": e.source.artifact,
                "plugin": e.source.plugin,
                "evidence_id": e.evidence.evidence_id,
                "evidence_sha256": e.evidence.sha256,
                "confidence": float(e.confidence),
                "rationale": e.rationale,
                "tags": ",".join(e.tags),
                "corroborated_by": ",".join(e.corroborated_by),
                "warnings": "; ".join(e.warnings),
                "raw_json": json.dumps(e.raw),
            })

        if not records:
            # Create empty table schema
            fields = [
                pa.field("event_id", pa.string()),
                pa.field("timestamp_utc", pa.string()),
                pa.field("action", pa.string()),
                pa.field("object_path", pa.string()),
                pa.field("corroborated_by", pa.string()),
                pa.field("warnings", pa.string()),
            ]
            table = pa.Table.from_arrays([pa.array([]), pa.array([]), pa.array([]), pa.array([]), pa.array([]), pa.array([])], schema=pa.schema(fields))
        else:
            table = pa.Table.from_pylist(records)

        pq.write_table(table, self.parquet_path, compression="zstd")

    def _write_sqlite(self, events: List[Event]) -> None:
        """Write events to SQLite database with B-Tree indexes and FTS5 full-text search."""
        if self.sqlite_path.exists():
            self.sqlite_path.unlink()

        conn = sqlite3.connect(self.sqlite_path)
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                timestamp_utc TEXT,
                timestamp_raw TEXT,
                timestamp_type TEXT,
                action TEXT,
                action_class TEXT,
                host TEXT,
                user TEXT,
                object_path TEXT,
                artifact TEXT,
                plugin TEXT,
                evidence_id TEXT,
                evidence_sha256 TEXT,
                confidence REAL,
                rationale TEXT,
                tags TEXT,
                corroborated_by TEXT,
                warnings TEXT,
                raw_json TEXT
            )
        """)

        cur.execute("CREATE INDEX idx_events_ts ON events(timestamp_utc)")
        cur.execute("CREATE INDEX idx_events_action ON events(action)")
        cur.execute("CREATE INDEX idx_events_user ON events(user)")
        cur.execute("CREATE INDEX idx_events_object ON events(object_path)")

        # Create FTS5 virtual table if supported
        try:
            cur.execute("""
                CREATE VIRTUAL TABLE events_fts USING fts5(
                    event_id,
                    object_path,
                    rationale,
                    user,
                    action,
                    tags,
                    corroborated_by,
                    warnings,
                    content='events',
                    content_rowid='rowid'
                )
            """)
            has_fts = True
        except Exception:
            has_fts = False

        rows = []
        for e in events:
            rows.append((
                e.event_id,
                e.timestamp_utc,
                e.timestamp_raw,
                e.timestamp_type,
                e.action,
                e.action_class,
                e.host,
                e.user,
                e.object.path or "",
                e.source.artifact,
                e.source.plugin,
                e.evidence.evidence_id,
                e.evidence.sha256,
                e.confidence,
                e.rationale,
                ",".join(e.tags),
                ",".join(e.corroborated_by),
                "; ".join(e.warnings),
                json.dumps(e.raw),
            ))

        cur.executemany("""
            INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)

        if has_fts:
            cur.execute("""
                INSERT INTO events_fts(events_fts) VALUES('rebuild')
            """)

        conn.commit()
        conn.close()
