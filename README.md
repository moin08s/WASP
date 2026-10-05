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

# 4. Run the Automated Test Suite (22 tests)
python -m pytest -v
```

## ✨ Core Features & Differentiators
1. **Liquid Glass UI & Frosted Obsidian Theme**: Modern glassmorphism design in both the Desktop GUI (`launch_gui.py`) and single-file Interactive HTML Reports.
2. **RFC 3161 Cryptographic Trusted Timestamping (TSA)**: Evidence SHA-256 hashes are bound to verifiable RFC 3161 timestamp tokens (`.tsr`) from public TSAs (e.g., FreeTSA) or local air-gapped cryptographic attestations for court admissibility.
3. **Interactive D3/SVG Timeline Visualizer**: Single-file HTML report includes real-time search, tag filtering (Alerts, Corroborated, Conflicts, Files, Processes), activity density burst heatmap, and raw event inspectors.
4. **MITRE ATT&CK Matrix Threat Mapping**: Automatically translates YARA rule findings and IOCs into visual MITRE ATT&CK tactical matrices (Execution, Credential Access, Defense Evasion, Impact).
5. **External Storage & USB Hotplug Watcher**: Background thread detects connected external USB devices with write-safeguard prompts.
6. **Cross-Source Corroboration Engine**: Correlates independent forensic artifacts (MFT, EVTX, browser history, prefetch) within sliding windows and detects anti-forensic timestomping.
7. **8 Forensic Artifact Plugins**: NTFS MFT, Windows Event Logs (EVTX), Prefetch, Registry hives, Chromium/Firefox SQLite, LNK shortcuts, Linux logs, and generic file metadata.
8. **Deterministic Super-Timeline Reconstruction**: Dual-store persistence in Apache Parquet (`zstd` compressed) and SQLite with FTS5 full-text indexing.
9. **YARA & Threat Pattern Rule Engine**: Scans raw evidence and timeline events against curated DFIR rules (Mimikatz, Ransomware, LOLBins, Log wiping).
10. **Cryptographic Integrity & Chain of Custody**: Enforces read-only write-guards, append-only hash-chained ledger (`ledger.jsonl`), and Merkle tree root verification.
11. **Structured Multi-Format Reporting**: Exports interactive liquid-glass HTML, Markdown, JSON, and CSV reports with deterministic privacy redaction.
