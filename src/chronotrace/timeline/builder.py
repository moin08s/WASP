"""Reconstructs single chronologically sorted activity super-timeline."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable, List, Optional
from chronotrace.core.models import Event
from chronotrace.timeline.store import TimelineStore


class TimelineBuilder:
    """Merges events from all sources and reconstructs a deterministic chronological timeline."""

    def __init__(self, index_dir: str | Path, derived_dir: Optional[str | Path] = None):
        self.store = TimelineStore(index_dir)
        self.derived_dir = Path(derived_dir) if derived_dir else None
        self._events: List[Event] = []

    def add_event(self, event: Event) -> None:
        self._events.append(event)

    def add_events(self, events: Iterable[Event]) -> None:
        self._events.extend(events)

    def build(self, deduplicate: bool = True) -> List[Event]:
        """
        Sort events stably by (timestamp_utc, event_id) and persist to Parquet and SQLite.
        """
        # Deduplicate identical events by event_id if required
        if deduplicate:
            seen_ids = set()
            unique_events = []
            for ev in self._events:
                if ev.event_id not in seen_ids:
                    seen_ids.add(ev.event_id)
                    unique_events.append(ev)
            self._events = unique_events

        # Deterministic stable sort: primary key timestamp_utc, secondary key event_id
        self._events.sort(key=lambda e: (e.timestamp_utc, e.event_id))

        # Persist to Parquet and SQLite stores
        self.store.write_timeline(self._events)

        # Also write canonical jsonl if derived directory provided
        if self.derived_dir:
            self.derived_dir.mkdir(parents=True, exist_ok=True)
            jsonl_path = self.derived_dir / "timeline.jsonl"
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for ev in self._events:
                    f.write(json.dumps(ev.to_canonical_dict(), sort_keys=True) + "\n")

        return self._events
