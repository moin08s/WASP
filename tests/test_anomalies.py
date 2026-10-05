import pytest
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource
from chronotrace.analysis.anomalies import AnomalyDetector


def _make_event(action: str, path: str, user: str, ts: str, raw: dict = None) -> Event:
    return Event(
        timestamp_utc=ts,
        source=EventSource(artifact="EVTX", plugin="evtx", evidence_id="EVID-1"),
        evidence=EventEvidence(evidence_id="EVID-1", sha256="a" * 64),
        action=action,
        object=EventObject(path=path),
        user=user,
        raw=raw or {},
    )


def test_off_hours_logon_detection():
    # 03:30 AM UTC logon (off-hours)
    events = [
        _make_event(
            action="USER_LOGON",
            path="C:\\Windows\\System32\\winlogon.exe",
            user="Administrator",
            ts="2026-10-05T03:30:00Z",
            raw={"EventID": 4624, "TargetUserName": "Administrator"},
        ),
        # 14:00 PM UTC logon (business hours)
        _make_event(
            action="USER_LOGON",
            path="C:\\Windows\\System32\\winlogon.exe",
            user="standard_user",
            ts="2026-10-05T14:00:00Z",
            raw={"EventID": 4624, "TargetUserName": "standard_user"},
        ),
    ]

    detector = AnomalyDetector(events, off_hours_start=22, off_hours_end=6)
    findings = detector.detect_off_hours_logons()

    assert len(findings) == 1
    assert findings[0].anomaly_type == "OFF_HOURS_LOGON"
    assert "Administrator" in findings[0].affected_users


def test_ransomware_mass_file_modification():
    events = []
    # Generate 15 file modifications within 20 seconds
    for i in range(15):
        events.append(
            _make_event(
                action="FILE_MODIFY",
                path=f"C:\\Users\\Victim\\Documents\\file_{i}.docx.locked",
                user="attacker",
                ts=f"2026-10-05T04:00:{i:02d}Z",
            )
        )

    detector = AnomalyDetector(events)
    findings = detector.detect_rapid_file_modifications(threshold_count=10, window_seconds=60)

    assert len(findings) == 1
    assert findings[0].anomaly_type == "RANSOMWARE_ENCRYPTION_SPIKE"
    assert findings[0].metric_value == 15.0


def test_statistical_activity_burst():
    events = []
    # Normal baseline across multiple 15m windows: 1-2 events per window
    for h in range(4):
        for m in (5, 20, 35, 50):
            events.append(_make_event(action="READ", path=f"normal_{h}_{m}", user="u1", ts=f"2026-10-05T0{h}:{m:02d}:00Z"))

    # Huge burst in window 04:15 - 04:30 (50 events)
    for i in range(50):
        events.append(_make_event(action="READ", path=f"burst_{i}", user="u1", ts=f"2026-10-05T04:20:{i:02d}Z"))

    detector = AnomalyDetector(events, window_minutes=15, z_threshold=2.0)
    findings = detector.detect_activity_bursts()

    assert len(findings) >= 1
    burst = findings[0]
    assert burst.anomaly_type == "BURST_ACTIVITY"
    assert burst.metric_value >= 50.0
