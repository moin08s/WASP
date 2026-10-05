"""Tests for YARA and Threat Pattern Rule Engine."""

from chronotrace.analysis.rules import RuleEngine
from chronotrace.core.models import Event, EventEvidence, EventObject, EventSource


def test_threat_rule_pattern_matching(tmp_path):
    """Verify YARA/pattern matching against suspicious files and command strings."""
    engine = RuleEngine()

    # 1. Test text scanning (mimikatz credential access)
    findings = engine.scan_text("User ran mimikatz sekurlsa::logonpasswords to dump creds")
    assert len(findings) >= 1
    assert any("Mimikatz" in f.rule_name for f in findings)
    assert any(f.severity == "CRITICAL" for f in findings)

    # 2. Test LOLBin command line
    findings_lolbin = engine.scan_text("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=")
    assert len(findings_lolbin) >= 1
    assert any("LOLBin" in f.rule_name for f in findings_lolbin)

    # 3. Test File Scanning
    suspicious_file = tmp_path / "forensic_artifact.txt"
    suspicious_file.write_text("Detected certutil -urlcache download or mshta http://server/test.hta\n", encoding="utf-8")
    file_findings = engine.scan_file(suspicious_file)
    assert len(file_findings) >= 1
    assert any("LOLBin" in f.rule_name for f in file_findings)


def test_threat_rule_event_tagging():
    """Verify that scan_events mutates matching events with ALERT and THREAT tags."""
    engine = RuleEngine()

    ev = Event(
        event_id="ev-alert-001",
        timestamp_utc="2024-03-15T12:00:00+00:00",
        action="PROCESS_EXECUTE",
        host="CORP-DC01",
        user="SYSTEM",
        object=EventObject(path="C:\\Windows\\System32\\vssadmin.exe"),
        source=EventSource(artifact="PREFETCH", plugin="prefetch", evidence_id="EVID-1"),
        evidence=EventEvidence(evidence_id="EVID-1", sha256="b" * 64),
        raw={"command_line": "vssadmin delete shadows /all /quiet"},
    )

    findings = engine.scan_events([ev])
    assert len(findings) >= 1
    assert "ALERT" in ev.tags
    assert any("THREAT:" in t for t in ev.tags)
    assert len(ev.warnings) >= 1
