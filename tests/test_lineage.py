import pytest
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource
from chronotrace.analysis.lineage import ProcessLineageReconstructor, ProcessNode


def _make_event(action: str, path: str, user: str, ts: str, raw: dict) -> Event:
    return Event(
        timestamp_utc=ts,
        source=EventSource(artifact="EVTX", plugin="evtx", evidence_id="EVID-1"),
        evidence=EventEvidence(evidence_id="EVID-1", sha256="a" * 64),
        action=action,
        object=EventObject(path=path),
        user=user,
        raw=raw,
    )


def test_process_lineage_reconstruction():
    events = [
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\explorer.exe",
            user="victim_user",
            ts="2026-10-05T02:00:00Z",
            raw={"ProcessId": "1000", "ParentProcessId": "500", "NewProcessName": "explorer.exe"},
        ),
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\System32\\cmd.exe",
            user="victim_user",
            ts="2026-10-05T02:00:05Z",
            raw={"ProcessId": "2000", "ParentProcessId": "1000", "NewProcessName": "cmd.exe", "CommandLine": "cmd.exe /c whoami"},
        ),
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\System32\\whoami.exe",
            user="victim_user",
            ts="2026-10-05T02:00:10Z",
            raw={"ProcessId": "3000", "ParentProcessId": "2000", "NewProcessName": "whoami.exe"},
        ),
    ]

    reconstructor = ProcessLineageReconstructor(events)
    roots = reconstructor.build_trees()

    assert len(roots) == 1
    root = roots[0]
    assert root.process_name == "explorer.exe"
    assert len(root.children) == 1
    cmd_child = root.children[0]
    assert cmd_child.process_name == "cmd.exe"
    assert len(cmd_child.children) == 1
    whoami_child = cmd_child.children[0]
    assert whoami_child.process_name == "whoami.exe"

    ascii_tree = reconstructor.render_ascii_tree(roots)
    assert "explorer.exe" in ascii_tree
    assert "cmd.exe" in ascii_tree
    assert "whoami.exe" in ascii_tree


def test_suspicious_spawn_detection():
    events = [
        _make_event(
            action="PROCESS_START",
            path="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            user="victim_user",
            ts="2026-10-05T03:00:00Z",
            raw={"ProcessId": "1100", "ParentProcessId": "800", "NewProcessName": "winword.exe"},
        ),
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\System32\\cmd.exe",
            user="victim_user",
            ts="2026-10-05T03:00:02Z",
            raw={"ProcessId": "2200", "ParentProcessId": "1100", "NewProcessName": "cmd.exe"},
        ),
    ]

    reconstructor = ProcessLineageReconstructor(events)
    roots = reconstructor.build_trees()
    assert len(roots) == 1
    child = roots[0].children[0]
    assert any("Office macro spawning" in alert for alert in child.threat_alerts)
