# ChronoTrace

**An automated digital forensics tool that extracts file metadata and system artefacts from digital evidence, reconstructs a chronological activity timeline, generates SHA-256 hashes for evidence integrity, and produces structured investigation reports.**

[![CI](https://img.shields.io/badge/ci-passing-brightgreen)](#testing)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#installation)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE.md)
[![DFIR](https://img.shields.io/badge/domain-DFIR-informational)](#)

---

## What it does

ChronoTrace ingests digital evidence (disk images, mounted volumes, live directories, or
pre-extracted artefact dumps) and automates the full forensic analysis pipeline across six
core objectives:

| # | Objective | Module |
|---|---|---|
| 1 | **File metadata extraction** — filesystem stats, EXIF, XMP, PDF, OOXML, archive entry metadata, media container timestamps | `chronotrace.extract` |
| 2 | **System artefact extraction** — MFT, USN journal, registry, EVTX, LNK, Prefetch, Amcache, SRUM, ShimCache, ShellBags, browser history, Linux/macOS logs | `chronotrace.artifacts` |
| 3 | **Timestamp extraction & normalization** — per-artefact timestamp decoding, timezone resolution, confidence scoring, raw value preservation | `chronotrace.normalize` |
| 4 | **Chronological activity timeline reconstruction** — normalized super-timeline sorted by `(timestamp_utc, event_id)`, stored in Parquet + SQLite | `chronotrace.timeline` |
| 5 | **SHA-256 evidence integrity** — mandatory streaming hash for every evidence object and derived file, hash-chained chain-of-custody ledger, Merkle root attestation | `chronotrace.integrity` |
| 6 | **Structured investigation reports** — JSON, CSV, HTML, PDF, Markdown output from versioned Jinja2 templates with redaction and provenance sections | `chronotrace.report` |

Every byte of evidence is hashed with SHA-256, every derived record is traceable back to its
source offset, and every case produces a structured, reproducible investigation report.

---

## Design principles

1. **Read-only by construction.** Evidence sources are opened with read-only handles; the
   tool never writes to the evidence path. A write-guard raises `EvidenceWriteAttempt`
   if any plugin attempts to open an evidence file in a writable mode.
2. **Automated end-to-end pipeline.** A single invocation (`ingest → extract → timeline → report`)
   drives all six objectives — metadata extraction, artefact parsing, timestamp extraction,
   timeline reconstruction, SHA-256 hashing, and report generation — without manual
   intervention between stages.
3. **Deterministic output.** Identical evidence + identical config ⇒ byte-identical
   timeline and report (modulo volatile report metadata, which is excluded via
   `--deterministic`).
4. **Provenance for every record.** Every timeline event carries the source artefact, the
   parser version, the record offset/ID, and the evidence hash it was derived from.
5. **Plugin-first.** All artefact parsers are entry-point plugins with a versioned
   contract. Adding a format does not require touching the core.
6. **Explainable confidence.** Each event carries a `confidence` score and, where
   applicable, a human-readable `rationale` string explaining the basis for the
   timestamp or finding.

---

## Quickstart

```bash
# 0. Install
pip install chronotrace            # or: pipx install chronotrace

# 1. Create a case
chronotrace case create --id CASE-2024-0117 --examiner "A. Analyst" --out ./CASE-2024-0117

# 2. Register evidence and compute SHA-256
chronotrace acquire \
  --case ./CASE-2024-0117 \
  --source /dev/sdb \
  --output ./CASE-2024-0117/evidence/disk0.E01 \
  --format ewf --hash sha256

# 3. Ingest + extract artefacts
chronotrace ingest --case ./CASE-2024-0117 --profile windows --jobs 8

# 4. Reconstruct the timeline
chronotrace timeline \
  --case ./CASE-2024-0117 \
  --from 2024-01-01T00:00:00Z --to 2024-03-31T23:59:59Z \
  --tz UTC --format parquet

# 5. Verify integrity
chronotrace verify --case ./CASE-2024-0117

# 6. Produce reports
chronotrace report --case ./CASE-2024-0117 --template full --format html,pdf,json
````

svgsvg

Output:

text

```
./CASE-2024-0117/
├── case.json
├── evidence/
│   ├── disk0.E01
│   └── disk0.E01.sha256
├── custody/
│   └── ledger.jsonl          # append-only hash-chained chain of custody
├── index/
│   ├── events.parquet
│   └── events.sqlite
├── derived/
│   ├── mft.csv
│   ├── evtx.jsonl
│   ├── registry.jsonl
│   └── ...
└── reports/
    ├── CASE-2024-0117_full.html
    ├── CASE-2024-0117_full.pdf
    ├── CASE-2024-0117_full.json
    └── CASE-2024-0117_summary.md
```

svgsvg

---

## Unified event model (excerpt)

json

```
{
  "event_id": "9f1c0a1e-6a1f-5a4f-9c2f-1b2c3d4e5f60",
  "timestamp_utc": "2024-03-11T02:14:07.123456Z",
  "timestamp_raw": "2024-03-10 22:14:07.123456 -04:00",
  "timestamp_type": "modified",
  "action": "FILE_WRITE",
  "host": "WS-01",
  "user": "CORP\\alice",
  "object": { "type": "file", "path": "C:\\Windows\\System32\\cmd.exe" },
  "source": {
    "artifact": "NTFS:$MFT",
    "plugin": "ntfs_mft",
    "plugin_version": "1.4.2",
    "record_id": 118472,
    "record_offset": 121315328
  },
  "evidence": {
    "evidence_id": "EV-0001",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "confidence": 0.98,
  "tags": ["execution"],
  "rationale": "NTFS MFT $STANDARD_INFORMATION modified timestamp"
}
```

svgsvg

See [docs/TIMELINE_MODEL.md](https://docs/TIMELINE_MODEL.md).

---

## Supported evidence & artefacts

**Evidence containers:** raw/dd, E01/EWF, VHDX, VMDK, QCOW2, ISO, directory trees, tar/zip archives.
**Filesystems:** NTFS, FAT12/16/32, exFAT, ext2/3/4, XFS, Btrfs, APFS (read-only), HFS+.
**Windows artefacts:** `MFT,`UsnJrnl, $LogFile, Registry (SAM/SECURITY/SOFTWARE/SYSTEM/NTUSER), EVTX, Prefetch, Amcache, SRUM, ShimCache, LNK, Jump Lists, ShellBags, USN, Recycle Bin, WMI repository, IIS logs, PowerShell history/transcripts, Scheduled Tasks.
**Linux artefacts:** auth.log, syslog, journald, wtmp/btmp/lastlog, bash/zsh history, cron/at, systemd units, auditd, package manager logs, /etc/passwd & shadow metadata.
**macOS artefacts:** unified logs, FSEvents, quarantine events, plists, launchd, Spotlight metadata.
**Cross-cutting:** EXIF, XMP, IPTC, PDF XMP/Info dict, OOXML/ODF core properties, ZIP/gzip/tar entry metadata, media container timestamps (MP4/`mvhd`), email headers.

Full list: [docs/ARTIFACT_REFERENCE.md](https://docs/ARTIFACT_REFERENCE.md).

---

## Integrity guarantees

- SHA-256 (and optional BLAKE3 / SHA-1 for legacy cross-check) for every evidence object.
- Per-artefact and per-derived-file hashes recorded in `manifest.json`.
- Append-only, hash-chained **chain-of-custody ledger** (`custody/ledger.jsonl`), optionally
  HMAC-SHA256 signed with an examiner key.
- `chronotrace verify` re-hashes evidence and replays the ledger, reporting any divergence.
- Merkle root over the derived artefact set for compact report attestation.

Details: [docs/HASHING_AND_INTEGRITY.md](https://docs/HASHING_AND_INTEGRITY.md).

---

## Reporting

bash

```
chronotrace report --case ./CASE-2024-0117 \
  --template full \
  --format html,pdf,json,csv,md \
  --include-integrity --include-custody \
  --redact usernames,paths
```

svgsvg

Templates: `summary`, `timeline`, `artefact`, `integrity`, `executive`, `full`, `custom` (Jinja2).
See [docs/REPORTING.md](https://docs/REPORTING.md).

---

## Library usage

python

```
from chronotrace import Case, Timeline

case = Case.open("./CASE-2024-0117")
with case.ingest(profile="windows", jobs=8) as ingest:
    ingest.run()

tl = Timeline.from_case(case)
for event in tl.between("2024-03-10T00:00:00Z", "2024-03-12T00:00:00Z"):
    print(event.timestamp_utc, event.action, event.object.path)
```

svgsvg

See [docs/API_REFERENCE.md](https://docs/API_REFERENCE.md).

---

## Legal & ethical use

ChronoTrace is intended **only** for lawful digital forensics, incident response, and
research on systems you are authorized to examine. See
[docs/LEGAL_AND_ETHICS.md](https://docs/LEGAL_AND_ETHICS.md). Misuse may be a criminal offence.

---

## Documentation index

| **Document**                                                           | **Purpose**                         |
| :--------------------------------------------------------------------- | :---------------------------------- |
| [docs/ARCHITECTURE.md](https://docs/ARCHITECTURE.md)                   | Pipeline, modules, data flow        |
| [docs/INSTALLATION.md](https://docs/INSTALLATION.md)                   | Install, dependencies, containers   |
| [docs/CLI_REFERENCE.md](https://docs/CLI_REFERENCE.md)                 | Every command and flag              |
| [docs/CONFIGURATION.md](https://docs/CONFIGURATION.md)                 | Config file schema                  |
| [docs/USAGE.md](https://docs/USAGE.md)                                 | Workflows and recipes               |
| [docs/ARTIFACT_REFERENCE.md](https://docs/ARTIFACT_REFERENCE.md)       | Supported artefacts & parsing notes |
| [docs/TIMELINE_MODEL.md](https://docs/TIMELINE_MODEL.md)               | Event schema & normalization rules  |
| [docs/HASHING_AND_INTEGRITY.md](https://docs/HASHING_AND_INTEGRITY.md) | Hashing, ledger, verification       |
| [docs/REPORTING.md](https://docs/REPORTING.md)                         | Templates and output formats        |
| [docs/PLUGIN_DEVELOPMENT.md](https://docs/PLUGIN_DEVELOPMENT.md)       | Writing an artefact plugin          |
| [docs/API_REFERENCE.md](https://docs/API_REFERENCE.md)                 | Python API                          |
| [docs/EVIDENCE_HANDLING.md](https://docs/EVIDENCE_HANDLING.md)         | Chain of custody procedures         |
| [docs/TESTING.md](https://docs/TESTING.md)                             | Test strategy, fixtures, CI         |
| [docs/TROUBLESHOOTING.md](https://docs/TROUBLESHOOTING.md)             | Common failures                     |
| [docs/GLOSSARY.md](https://docs/GLOSSARY.md)                           | Terminology                         |
| [docs/ROADMAP.md](https://docs/ROADMAP.md)                             | Planned work                        |
| [docs/LEGAL_AND_ETHICS.md](https://docs/LEGAL_AND_ETHICS.md)           | Authorized-use policy               |

---

## Contributing

See [CONTRIBUTING.md](https://contributing.md/) and the [Code of Conduct](https://code_of_conduct.md/).

## License

Apache-2.0 — see [LICENSE.md](https://license.md/).

text
