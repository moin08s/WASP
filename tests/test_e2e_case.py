"""End-to-end test verifying complete forensic analysis workflow."""

import json
from pathlib import Path
from chronotrace.core.case import Case
from chronotrace.acquire.hasher import Hasher


def test_complete_forensic_pipeline(tmp_path: Path):
    case_dir = tmp_path / "CASE-2024-TEST"

    # 1. Create Case
    case = Case.create(
        case_id="CASE-2024-TEST",
        out_dir=case_dir,
        examiner="Analyst Lead",
        organization="Incident Response Team",
        authorization_ref="WARRANT-TEST-99",
    )
    assert case.case_json_path.exists()
    assert (case_dir / "custody" / "ledger.jsonl").exists()
    assert (case_dir / "manifest.json").exists()

    # 2. Prepare mock forensic evidence
    src_dir = tmp_path / "raw_evidence"
    src_dir.mkdir()

    # Create mock auth.log
    auth_log = src_dir / "auth.log"
    auth_log.write_text(
        "Mar 11 02:14:07 test-host sshd[123]: Accepted password for alice from 192.168.1.100 port 22 ssh2\n"
        "Mar 11 02:15:20 test-host sudo: alice : TTY=pts/0 ; COMMAND=/usr/bin/cat /etc/shadow\n",
        encoding="utf-8",
    )

    # Create mock EVTX JSON dump
    evtx_dump = src_dir / "Security_events.jsonl"
    evtx_dump.write_text(
        json.dumps({
            "TimeCreated": "2024-03-11T02:14:07.123456Z",
            "EventID": 4624,
            "TargetUserName": "alice",
            "Computer": "WS-01",
        }) + "\n" +
        json.dumps({
            "TimeCreated": "2024-03-11T02:16:30.000000Z",
            "EventID": 4688,
            "TargetUserName": "alice",
            "Computer": "WS-01",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        }) + "\n",
        encoding="utf-8",
    )

    # 3. Acquire Evidence into Case
    ev1 = case.acquire(auth_log, output_filename="auth.log", evidence_id="EV-0001", notes="Extracted auth log")
    assert ev1["verification"] == "match"
    assert (case.evidence_dir / "auth.log.sha256").exists()

    ev2 = case.acquire(evtx_dump, output_filename="Security_events.jsonl", evidence_id="EV-0002", notes="Extracted EVTX dump")
    assert ev2["verification"] == "match"
    assert (case.evidence_dir / "Security_events.jsonl.sha256").exists()

    # 4. Extract Artefacts
    events = case.extract(profile="all")
    assert len(events) >= 4

    # 5. Build Timeline
    timeline_events = case.build_timeline()
    assert len(timeline_events) >= 4
    assert (case.index_dir / "events.parquet").exists()
    assert (case.index_dir / "events.sqlite").exists()

    # 6. Verify Integrity
    verify_result = case.verify()
    assert verify_result["overall_status"] == "PASS"
    assert verify_result["ledger_status"] == "PASS"
    assert verify_result["evidence_status"] == "PASS"
    assert verify_result["derived_status"] == "PASS"

    # 7. Generate Investigation Reports
    reports = case.report(template="full", formats=("html", "json", "csv", "md"), redact=("usernames", "ips"))
    assert "html" in reports
    assert "json" in reports
    assert "csv" in reports
    assert "md" in reports

    assert Path(reports["html"]).exists()
    assert Path(reports["json"]).exists()
    assert Path(reports["csv"]).exists()
    assert Path(reports["md"]).exists()

    # Verify that redaction took place in the reports
    html_content = Path(reports["html"]).read_text(encoding="utf-8")
    assert "CASE-2024-TEST" in html_content
    assert "WASP Investigation Report" in html_content
