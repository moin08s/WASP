"""Tests for Cross-Source Corroboration and Anti-Forensic Conflict Detection."""

from chronotrace.analysis.corroborator import CorroborationEngine
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource


def _make_test_event(event_id, ts, plugin, action, path, ts_type="modified"):
    return Event(
        event_id=event_id,
        timestamp_utc=ts,
        timestamp_type=ts_type,
        action=action,
        host="WORKSTATION-01",
        user="john.doe",
        object=EventObject(path=path),
        source=EventSource(
            artifact=plugin.upper(),
            plugin=plugin,
            evidence_id="EVID-001",
        ),
        evidence=EventEvidence(evidence_id="EVID-001", sha256="a" * 64),
        confidence=0.8,
    )


def test_cross_source_corroboration_match():
    """Verify that events from different plugins within time window are linked and boosted."""
    # Event 1: Prefetch execution of mimikatz.exe at 10:00:00
    ev1 = _make_test_event("ev-001", "2024-03-15T10:00:00+00:00", "prefetch", "PROCESS_EXECUTE", "C:\\Users\\John\\mimikatz.exe")
    # Event 2: EVTX 4688 process creation of mimikatz.exe at 10:00:15 (15 seconds later)
    ev2 = _make_test_event("ev-002", "2024-03-15T10:00:15+00:00", "evtx", "PROCESS_CREATION", "C:\\Users\\John\\mimikatz.exe")

    engine = CorroborationEngine(time_window_seconds=120)
    result = engine.analyze([ev1, ev2])

    assert result.corroborated_count == 2
    assert len(result.clusters) == 1
    assert "CORROBORATED" in ev1.tags
    assert "CORROBORATED" in ev2.tags
    assert any("evtx" in ref for ref in ev1.corroborated_by)
    assert any("prefetch" in ref for ref in ev2.corroborated_by)
    # Confidence should be boosted
    assert ev1.confidence > 0.8
    assert ev2.confidence > 0.8


def test_anti_forensics_timestomp_conflict():
    """Verify that execution preceding file creation is flagged as an anti-forensic conflict."""
    # Executed at 09:00:00
    ev_exec = _make_test_event("ev-exec", "2024-03-15T09:00:00+00:00", "prefetch", "PROCESS_EXECUTE", "C:\\malware.exe")
    # File created at 10:00:00 (1 hour later than execution!)
    ev_create = _make_test_event("ev-create", "2024-03-15T10:00:00+00:00", "ntfs_mft", "FILE_CREATE", "C:\\malware.exe", ts_type="created")

    engine = CorroborationEngine()
    result = engine.analyze([ev_exec, ev_create])

    assert result.conflict_count >= 1
    assert "CONFLICT" in ev_exec.tags
    assert "TIMESTOMP_SUSPECT" in ev_exec.tags
    assert len(ev_exec.warnings) > 0
    assert any(c["conflict_type"] == "EXECUTION_PRE_CREATION" for c in result.conflicts)
