# Glossary

## Core project specification objectives

- **File metadata extraction:** Automated collection of filesystem statistics (size, permissions, timestamps), embedded document properties (EXIF, XMP, IPTC, PDF Info, OOXML core properties), archive entry metadata, and media container timestamps from digital evidence.
- **System artefact extraction:** Automated parsing of operating-system structures that record user and system activity — including NTFS MFT, USN journal, Windows registry, event logs (EVTX), execution artefacts (Prefetch, Amcache, SRUM, ShimCache), user-activity artefacts (LNK, Jump Lists, ShellBags), browser history databases, and Linux/macOS authentication and audit logs.
- **Timestamp extraction:** Per-artefact decoding of all available timestamp fields, timezone resolution (registry → embedded offset → UTC fallback), raw value preservation, and confidence scoring for each resolved UTC timestamp.
- **Chronological activity timeline reconstruction:** Automated merging of normalized events from all artefact sources into a single super-timeline, stable-sorted by `(timestamp_utc, event_id)`, stored in Parquet and SQLite for querying.
- **SHA-256 evidence integrity:** Mandatory streaming SHA-256 hashing of every evidence object during acquisition and every derived file after extraction, recorded in a signed manifest and an append-only hash-chained chain-of-custody ledger.
- **Structured investigation reports:** Multi-format (JSON, CSV, HTML, PDF, Markdown) reports generated from versioned Jinja2 templates, containing case metadata, evidence inventory with hashes, file metadata findings, system artefact findings, the chronological timeline, timestamp provenance, integrity attestation, and chain-of-custody summary.

## General terminology

- **Artefact:** A file, database, log, metadata structure, or filesystem record containing potentially useful forensic information.
- **Case:** The controlled workspace containing evidence references, configuration, derived data, indexes, reports, and custody records.
- **Chain of custody:** An auditable record of who handled evidence and what actions were performed, implemented as a hash-chained ledger (`custody/ledger.jsonl`).
- **Confidence:** A normalized ($0.0–1.0$) indication of how strongly the parser supports an event or inferred field.
- **Derived data:** Information produced from evidence by ChronoTrace parsers rather than the original evidence itself.
- **Evidence ID:** Stable identifier assigned to an acquired evidence object, referenced in every derived event.
- **EvidenceView:** Read-only interface presented to plugins for examining evidence; no write operations are exposed.
- **Event:** A normalized chronological record representing an observable or inferred action/state, conforming to the Unified Event Schema.
- **Event ID:** Deterministic UUIDv5 identifying a normalized event, computed as `uuid5(NS, sha256(canonical_fields))`.
- **Hash chain:** A sequence where each record includes the hash of its predecessor, making undetected modification of any record impossible.
- **Manifest:** Machine-readable inventory of evidence, derived files, reports, SHA-256 hashes, plugins, and configuration (`manifest.json`).
- **Merkle root:** Compact cryptographic commitment to a collection of derived files, included in report attestation blocks.
- **Plugin:** Versioned parser or processor discovered through the ChronoTrace plugin registry; implements the `ArtifactPlugin` contract.
- **Provenance:** Information linking a derived event to its evidence source, record location (byte offset or record ID), and parser version.
- **Super-timeline:** The combined chronological view produced by merging normalized events from all artefact plugins across all evidence sources.
- **Timestamp normalization:** Conversion of source timestamps into the unified UTC representation while retaining `timestamp_raw` and recording timezone confidence.
- **Timestomping:** Manipulation of NTFS `$STANDARD_INFORMATION` timestamps intended to obscure activity; detected by comparing against `$FILE_NAME` timestamps.
- **Unified Event Schema:** ChronoTrace's normalized event representation (schema version `2.0.0`) used by the timeline and reporting layers.
