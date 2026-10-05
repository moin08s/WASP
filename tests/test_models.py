"""Tests for Unified Event Model Schema 2.0.0 and determinism."""

import datetime
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource
from chronotrace.normalize.normalizer import create_event


def test_event_deterministic_id():
    """Verify that identical event fields produce the exact same UUIDv5."""
    e1 = create_event(
        timestamp_utc="2024-03-11T02:14:07.123456Z",
        action="FILE_WRITE",
        artifact="NTFS:$MFT",
        plugin="ntfs_mft",
        evidence_id="EV-0001",
        evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        object_path="C:\\Windows\\System32\\cmd.exe",
        host="WS-01",
        user="CORP\\alice",
        record_id=118472,
        record_offset=121315328,
    )

    e2 = create_event(
        timestamp_utc="2024-03-11T02:14:07.123456Z",
        action="FILE_WRITE",
        artifact="NTFS:$MFT",
        plugin="ntfs_mft",
        evidence_id="EV-0001",
        evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        object_path="C:\\Windows\\System32\\cmd.exe",
        host="WS-01",
        user="CORP\\alice",
        record_id=118472,
        record_offset=121315328,
    )

    assert e1.event_id == e2.event_id
    assert len(e1.event_id) == 36
    assert e1.schema_version == "2.0.0"


def test_event_vocabularies():
    """Verify fallback and mapping for action classes and timestamp types."""
    e = create_event(
        timestamp_utc=datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
        action="PROCESS_START",
        artifact="Prefetch",
        plugin="prefetch",
        evidence_id="EV-0001",
        evidence_sha256="abcdef",
        timestamp_type="executed",
    )
    assert e.action_class == "process"
    assert e.timestamp_type == "executed"
    assert e.confidence == 1.0
