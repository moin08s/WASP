"""Timeline query and filter interface."""

from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource


class TimelineQuery:
    """Queries reconstructed timeline events stored in SQLite/Parquet."""

    def __init__(self, index_dir: str | Path):
        self.sqlite_path = Path(index_dir) / "events.sqlite"

    def execute_sql(self, sql_query: str) -> List[Dict[str, Any]]:
        """Run arbitrary read-only SQL query against SQLite index."""
        if not self.sqlite_path.exists():
            return []
        conn = sqlite3.connect(f"file:{self.sqlite_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(sql_query)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows

    def filter_events(
        self,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        user: Optional[str] = None,
        host: Optional[str] = None,
        action: Optional[str] = None,
        action_class: Optional[str] = None,
        search_term: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Filter events with parameter criteria."""
        if not self.sqlite_path.exists():
            return []

        conditions = []
        params: List[Any] = []

        if from_ts:
            conditions.append("timestamp_utc >= ?")
            params.append(from_ts)
        if to_ts:
            conditions.append("timestamp_utc <= ?")
            params.append(to_ts)
        if user:
            conditions.append("user LIKE ?")
            params.append(f"%{user}%")
        if host:
            conditions.append("host LIKE ?")
            params.append(f"%{host}%")
        if action:
            conditions.append("action = ?")
            params.append(action)
        if action_class:
            conditions.append("action_class = ?")
            params.append(action_class)
        if search_term:
            conditions.append("(object_path LIKE ? OR rationale LIKE ? OR tags LIKE ? OR corroborated_by LIKE ? OR warnings LIKE ?)")
            term = f"%{search_term}%"
            params.extend([term, term, term, term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"SELECT * FROM events {where_clause} ORDER BY timestamp_utc ASC LIMIT {limit}"

        conn = sqlite3.connect(f"file:{self.sqlite_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, params)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
