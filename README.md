# 🐝 WASP
### Wide-scope Artifact & Super-timeline Platform
*Automated Digital Forensics, Timestamp Normalization, Cross-Source Corroboration, YARA Threat Scanning & Integrity Attestation*

---

## 📖 Overview
**WASP** is an automated digital forensics investigation tool designed to acquire digital evidence, parse multi-source system artifacts, normalize multi-epoch timestamps to UTC, reconstruct a chronological activity super-timeline, cross-corroborate events across independent sources, scan for threat signatures with YARA rules, verify cryptographic SHA-256 integrity, and generate comprehensive multi-format reports.

## 🚀 How to Run
For detailed instructions, step-by-step CLI commands, GUI documentation, and testing, see:

👉 **[HOW_TO_RUN.md](file:///D:/Download/chronotrace/HOW_TO_RUN.md)**

### Quick Launch Commands:
```powershell
# 1. Launch the Desktop GUI
python launch_gui.py

# 2. Run the Command-Line Interface (CLI)
python wasp.py --help

# 3. Run the Full Automated Live Forensic Demonstration
python run_demo.py

# 4. Run the Automated Test Suite (19 tests)
python -m pytest -v
```

## ✨ Core Features
1. **Desktop Graphical User Interface (GUI)**: Modern 6-tab dark-mode forensic workbench (`tkinter/ttk`) with real-time progress updates and background threading.
2. **External Storage & USB Evidence Acquisition**: Auto-detects physical drives and mounted volumes with streaming SHA-256 computation and readback verification.
3. **Real-Time USB Hotplug Watcher**: Background thread alerts examiners when USB media or storage devices are connected.
4. **8 Forensic Artifact Plugins**: NTFS MFT, Windows Event Logs (EVTX), Prefetch, Registry hives, Chromium/Firefox SQLite, LNK shortcuts, Linux logs, and generic file metadata.
5. **Deterministic Super-Timeline Reconstruction**: Dual-store persistence in Apache Parquet (`zstd` compressed) and SQLite with FTS5 full-text indexing.
6. **Cross-Source Corroboration Engine**: Links events across multiple sources and flags anti-forensic timestomp anomalies.
7. **YARA & Threat Pattern Rule Engine**: Scans raw evidence and timeline events against curated DFIR rules (Mimikatz, Ransomware, LOLBins, Log wiping).
8. **Cryptographic Integrity & Chain of Custody**: Enforces read-only write-guards, append-only hash-chained ledger (`ledger.jsonl`), and Merkle tree root verification.
9. **Structured Multi-Format Reporting**: Exports HTML, Markdown, JSON, and CSV reports with deterministic privacy redaction.
