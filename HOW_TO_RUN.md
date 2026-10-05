# 🚀 WASP — Execution & Run Guide
**WASP: Wide-scope Artifact & Super-timeline Platform**  
*Deterministic Digital Forensics, Timestamp Normalization, Cross-Source Corroboration, Threat Scanning & Integrity Attestation*

---

## ⚡ 1. Quick Start (Run in 30 Seconds)

WASP can be executed in three primary ways:

### A. Launch Desktop GUI (Recommended)
```powershell
python launch_gui.py
```
*Or via CLI launcher:*
```powershell
python wasp.py gui
```

### B. Run Complete Automated Forensic Demonstration
Executes sample evidence acquisition, artifact extraction, super-timeline reconstruction, cross-source corroboration, YARA scanning, integrity verification, and multi-format report generation:
```powershell
python run_demo.py
```

### C. Run Built-in Diagnostic Doctor
Verifies your Python environment, active plugins, write-guard protection, and database engines:
```powershell
python wasp.py doctor
```

---

## 💻 2. System Prerequisites

* **Operating System**: Windows 10/11, Windows Server, Linux (Ubuntu/Debian/RHEL), or macOS.
* **Python Runtime**: Python 3.11, 3.12, or 3.13+.
* **Core Dependencies**: Installed via pip:
  ```powershell
  python -m pip install jinja2 pyarrow pydantic rich tomli-w typer yara-python pytest
  ```

> [!NOTE]
> All root launchers (`wasp.py`, `launch_gui.py`, `run_demo.py`, and `chronotrace.py`) automatically add `./src` to your `sys.path`. No manual environment path configuration is required.

---

## 🖥️ 3. Using the Desktop Graphical User Interface (GUI)

Launch the GUI:
```powershell
python launch_gui.py
```

### GUI Features & Navigation Tabs:
1. **📂 Case Dashboard**:
   * Create a new forensic workspace (`+ New Case...`) or load an existing one (`Open Case...`).
   * Displays case metadata, lead examiner, authorization reference, registered evidence count, and active write-guard status.
   * Quick action button: `⚡ Run Full Automated Pipeline` runs all stages in one click.

2. **🔌 External Devices & Acquire**:
   * **Real-Time Hotplug Monitoring**: Background watcher alerts the examiner whenever an external USB drive, HDD, or SD card is inserted.
   * Scans and displays physical drives, interface types (USB/SCSI), drive letters, filesystems, and capacities.
   * One-click bit-stream / directory forensic acquisition with readback verification and mandatory streaming SHA-256 hash calculation.

3. **⚙️ Artefacts & Ingest**:
   * Select analysis profiles (`all`, `windows`, `linux`).
   * Executes all 8 built-in plugins (NTFS MFT, Windows Event Logs, Prefetch, Registry hives, Chromium/Firefox SQLite, LNK shortcuts, Linux logs, and generic file metadata).
   * Live streaming log display.

4. **⏱️ Activity Timeline**:
   * Chronologically sorted super-timeline treeview.
   * Live search filter by keyword, user, or action.
   * **🔗 Cross-Source Corroborate**: Links independent artifact events across time windows ($\le 120\text{s}$) and flags anti-forensic timestomp conflicts.
   * **🛡️ Scan YARA Threats**: Scans timeline events and raw evidence against curated DFIR threat rules (Mimikatz, Ransomware, LOLBins, Log wiping).

5. **🛡️ Integrity & Custody**:
   * **Verify Integrity**: Replays the SHA-256 hash-chained custody ledger (`ledger.jsonl`), re-hashes evidence files, and validates the Merkle tree root.
   * Audit treeview displaying every immutable custody action and entry hash.

6. **📄 Investigation Reports**:
   * Export reports in **HTML**, **Markdown**, **JSON**, and **CSV**.
   * Toggle privacy redaction (anonymizes usernames and IP addresses with reversible deterministic pseudonyms).
   * Click **Open HTML Report** to view the report directly in your default web browser.

---

## ⌨️ 4. Command-Line Interface (CLI) Reference

WASP provides a command-line tool accessible via `python wasp.py`:

```powershell
python wasp.py --help
```

### Complete CLI Command Cheat Sheet:

| Task | Command |
|---|---|
| **Show Version** | `python wasp.py --version` |
| **System Diagnostics** | `python wasp.py doctor` |
| **List Artifact Plugins** | `python wasp.py plugin list` |
| **List Storage Devices** | `python wasp.py device list` |
| **Real-time USB Watcher** | `python wasp.py device watch [--interval 1.5] [--timeout 60]` |
| **Create Forensic Case** | `python wasp.py case create --id CASE-001 --out ./cases/case001 --examiner "Alex Mercer" --org "DFIR Unit"` |
| **View Case Info** | `python wasp.py case info --case ./cases/case001` |
| **Acquire File Evidence** | `python wasp.py acquire --case ./cases/case001 --source ./evidence/sample.evtx` |
| **Acquire External USB** | `python wasp.py acquire --case ./cases/case001 --device E: --output usb_disk.tar` |
| **Extract Artifacts** | `python wasp.py extract --case ./cases/case001 --profile all` |
| **Reconstruct Timeline** | `python wasp.py timeline --case ./cases/case001` |
| **Cross-Source Corroboration** | `python wasp.py corroborate --case ./cases/case001 --window 120` |
| **YARA Threat Scan** | `python wasp.py scan --case ./cases/case001 [--rules custom.yar]` |
| **Verify Integrity** | `python wasp.py verify --case ./cases/case001` |
| **Generate Reports** | `python wasp.py report --case ./cases/case001 --format html,md,json,csv --redact usernames,ips` |

---

## 🧪 5. Running Automated Tests

WASP includes a comprehensive test suite covering all data models, write-guard protection, streaming hashers, hash chains, Merkle trees, device acquisition, hotplug detection, cross-source corroboration, and YARA threat scanning:

```powershell
python -m pytest -v
```

### Running Specific Test Modules:
```powershell
# Cross-Source Corroboration & Timestomp Conflict Detection
python -m pytest tests/test_corroborator.py -v

# Real-Time USB Hotplug Watcher
python -m pytest tests/test_hotplug.py -v

# YARA & Threat Pattern Rule Scanner
python -m pytest tests/test_rules.py -v

# End-to-End Complete Forensic Pipeline
python -m pytest tests/test_e2e_case.py -v

# Write-Guard Forensic Read-Only Enforcement
python -m pytest tests/test_writeguard.py -v
```

---

## 📂 6. Generated Case Workspace Structure

When WASP manages a forensic case, it creates an isolated directory structure:

```
<case_root>/
├── case.json               # Case metadata, examiner, authorization, and timestamps
├── config.toml             # Case-specific configuration overrides
├── manifest.json           # Canonical Merkle tree manifest tracking all files & SHA-256 hashes
├── custody/
│   └── ledger.jsonl        # Cryptographically hash-chained append-only custody ledger
├── evidence/               # Acquired evidence files (Read-Only guarded)
│   ├── image.raw
│   └── image.raw.sha256    # Accompanying SHA-256 sidecar digest
├── derived/                # Normalized JSONL event streams produced by plugins
│   ├── evtx.jsonl
│   ├── prefetch.jsonl
│   ├── corroboration.json  # Multi-source corroboration chains & conflict records
│   ├── threat_alerts.json  # YARA and threat pattern detection findings
│   └── timeline.jsonl      # Unified chronological super-timeline
├── index/
│   ├── events.parquet      # Columnar compressed (zstd) database for analytical queries
│   └── events.sqlite       # Indexed SQLite database with FTS5 full-text search
└── reports/
    ├── <case_id>_full.html    # Standalone HTML report
    ├── <case_id>_summary.md   # Markdown summary
    ├── <case_id>_full.json    # Machine-readable JSON export
    └── <case_id>_full.csv     # Tabular CSV export
```

---

## 🛠️ 7. Troubleshooting & FAQ

### Issue: `UnicodeEncodeError` in Windows PowerShell / CMD
* **Cause**: Older Windows consoles using code page 1252 (cp1252).
* **Fix**: WASP is natively configured with ASCII-safe status indicators (`[+]`, `[-]`, `*`). You can also switch your console to UTF-8:
  ```powershell
  chcp 65001
  ```

### Issue: Cannot access USB device on Windows
* **Fix**: Ensure your PowerShell or terminal window has Administrator privileges if you are capturing raw physical disk handles (`\\.\PhysicalDriveX`). Mounted volume capture (`E:\`) works in normal user mode.

### Issue: ModuleNotFoundError for `chronotrace`
* **Fix**: Always use the root launchers (`python wasp.py`, `python launch_gui.py`, `python run_demo.py`) which inject `src/` into Python's module path automatically, or set the environment variable:
  ```powershell
  $env:PYTHONPATH="src"
  ```
