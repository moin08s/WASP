"""Tests for chronological timeline reconstruction and queries."""

from pathlib import Path
from chronotrace.normalize.normalizer import create_event
from chronotrace.timeline.builder import TimelineBuilder
from chronotrace.timeline.query import TimelineQuery


def test_timeline_reconstruction_and_query(tmp_path: Path):
    index_dir = tmp_path / "index"
    derived_dir = tmp_path / "derived"
    builder = TimelineBuilder(index_dir, derived_dir)

    # Add events out of chronological order
    e_later = create_event(
        timestamp_utc="2024-03-11T12:00:00Z",
        action="FILE_WRITE",
        artifact="NTFS",
        plugin="test",
        evidence_id="EV-1",
        evidence_sha256="hash1",
        object_path="C:\\file2.txt",
        user="bob",
    )
    e_earlier = create_event(
        timestamp_utc="2024-03-11T09:00:00Z",
        action="PROCESS_START",
        artifact="Prefetch",
        plugin="test",
        evidence_id="EV-1",
        evidence_sha256="hash1",
        object_path="malware.exe",
        user="alice",
    )

    builder.add_event(e_later)
    builder.add_event(e_earlier)

    events = builder.build()
    assert len(events) == 2
    # Verify sorted order
    assert events[0].timestamp_utc == "2024-03-11T09:00:00Z"
    assert events[1].timestamp_utc == "2024-03-11T12:00:00Z"

    # Verify Parquet and SQLite files created
    assert (index_dir / "events.parquet").exists()
    assert (index_dir / "events.sqlite").exists()
    assert (derived_dir / "timeline.jsonl").exists()

    # Query tests
    tq = TimelineQuery(index_dir)
    alice_events = tq.filter_events(user="alice")
    assert len(alice_events) == 1
    assert alice_events[0]["user"] == "alice"

    # SQL query test
    sql_rows = tq.execute_sql("SELECT count(*) as cnt FROM events")
    assert sql_rows[0]["cnt"] == 2
