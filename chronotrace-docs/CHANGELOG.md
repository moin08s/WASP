# Changelog

All notable changes to ChronoTrace are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

ChronoTrace automates six core forensic objectives from the project specification: file
metadata extraction, system artefact extraction, timestamp extraction, chronological
activity timeline reconstruction, SHA-256 evidence integrity, and structured
investigation reports. The unified event schema and the ledger format are versioned
independently (see `docs/TIMELINE_MODEL.md` and `docs/HASHING_AND_INTEGRITY.md`).
Schema-breaking changes bump the schema major version and are listed under **BREAKING**.

---

## [Unreleased]

### Added
- macOS unified log (`*.tracev3`) parser plugin.
  *(PS: system artefact extraction — macOS coverage)*
- `--deterministic` flag: strips volatile metadata (wall-clock report generation time,
  hostname of the analysis machine, absolute temp paths) so two runs over identical
  evidence produce byte-identical outputs.
  *(PS: structured investigation reports — reproducible output)*
- Merkle root attestation block in JSON reports.
  *(PS: SHA-256 evidence integrity — compact commitment to all derived files)*
- `chronotrace verify --ledger-only` for replaying chain of custody without re-hashing
  evidence (fast audit mode).
  *(PS: SHA-256 evidence integrity — efficient custody audit)*
- Report section mapping to project specification objectives: each structured report now
  includes a methodology section explicitly cross-referencing all six PS objectives and
  the evidence that satisfies each.
  *(PS: structured investigation reports)*

### Changed
- Timeline sort is now a stable sort keyed on `(timestamp_utc, event_id)` to guarantee
  reproducibility across thread counts.
  *(PS: chronological activity timeline reconstruction — deterministic ordering)*
- Confidence scoring for registry `LastWriteTime` lowered to 0.85 when hive
  transaction-log replay is disabled.
  *(PS: timestamp extraction — more accurate confidence values)*

### Fixed
- USN Journal (`$UsnJrnl:$J`) parser no longer emits phantom records when a sparse
  region crosses a 4 KiB page boundary.
- EVTX parser correctly handles `BinXml` template instances with >64 substitutions.
- Timezone resolution no longer falls back to the analysis host's local zone when a
  registry `TimeZoneInformation` key is present but malformed; it now records
  `tz_confidence: 0.0` and defaults to UTC with a warning.
  *(PS: timestamp extraction — correct timezone resolution)*

### Security
- Write-guard now intercepts `os.open`, `open`, `mmap`, and `io.open` on evidence paths.
- Ledger HMAC keys are zeroized after use and never written to logs.

---


## [1.3.0] — 2024-09-12

### Added
- Plugin API v2 with manifest validation and capability declaration.
- SRUM parser (`SRUDB.dat`) with ESE database support.
- Browser history parsers: Chrome/Edge (SQLite), Firefox (`places.sqlite`), Safari
  (`History.db`).
- `chronotrace report --template executive` (non-technical summary).
- Btrfs and XFS filesystem support.
- Parallel artefact extraction with a bounded worker pool (`--jobs`).

### Changed
- **BREAKING (schema 2.0.0):** `source.artifact` renamed from `source.artefact`
  (US spelling) for consistency; a migration shim maps old values on read.
- Timeline store default changed from SQLite-only to Parquet + SQLite index.
- SHA-256 is now the default and mandatory hash; `--hash` may add but not remove it.

### Fixed
- Corrected FAT32 timestamp decoding for dates after 2038.
- LNK parser handles `LinkTargetIDList` with multiple `RootFolder` shells.

---

## [1.2.1] — 2024-06-30

### Fixed
- Registry hive parser: fixed an off-by-one in `nk` cell size validation that rejected
  valid hives produced by Windows 11 22H2.
- PDF report: images no longer overflow page width.

---

## [1.2.0] — 2024-05-02

### Added
- Chain-of-custody ledger with SHA-256 hash chaining and optional HMAC signing.
- `chronotrace verify` command.
- APFS read-only support (snapshot-aware).
- Redaction profiles for reports (`--redact usernames,paths,ips`).

### Changed
- `acquire` now writes a `.sha256` sidecar in `sha256sum`-compatible format.

---

## [1.1.0] — 2024-02-14

### Added
- Prefetch, Amcache, ShimCache parsers.
- EXIF/XMP extraction for images.
- CSV report format.

---

## [1.0.0] — 2023-11-01

### Added
- Initial public release: NTFS `$MFT`, registry, EVTX, LNK, shellbags, timeline
  reconstruction, SHA-256 integrity, HTML/JSON reporting.
