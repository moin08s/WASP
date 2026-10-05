import pytest
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource
from chronotrace.analysis.sigma import SigmaRuleEngine


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


def test_sigma_rule_builtin_matching():
    events = [
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\System32\\cmd.exe",
            user="attacker",
            ts="2026-10-05T03:00:00Z",
            raw={"CommandLine": "vssadmin delete shadows /all /quiet", "EventID": 4688},
        ),
        _make_event(
            action="PROCESS_START",
            path="C:\\Tools\\mimikatz.exe",
            user="attacker",
            ts="2026-10-05T03:01:00Z",
            raw={"CommandLine": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"", "EventID": 4688},
        ),
        _make_event(
            action="PROCESS_START",
            path="C:\\Windows\\notepad.exe",
            user="legit_user",
            ts="2026-10-05T03:02:00Z",
            raw={"CommandLine": "notepad.exe report.txt", "EventID": 4688},
        ),
    ]

    engine = SigmaRuleEngine()
    matches = engine.scan_events(events)

    assert len(matches) == 2
    rule_ids = [m.rule_id for m in matches]
    assert "sigma-proc-002" in rule_ids  # VSS shadow deletion
    assert "sigma-proc-001" in rule_ids  # Mimikatz
