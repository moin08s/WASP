# Roadmap

The roadmap is organized around the six project specification objectives and the quality
principles that underpin them: correctness, reproducibility, integrity, and
analyst-friendly reporting.

## Near term

**File metadata extraction**
- Expand EXIF/XMP coverage for RAW image formats and video containers.
- Improve PDF metadata parsing for encrypted and linearized PDFs.

**System artefact extraction**
- Expand Windows artefact coverage (WMI repository, IIS logs, PowerShell transcripts).
- Improve parser regression corpora and fuzzing for binary formats.

**Timestamp extraction**
- Extend provenance validation and deterministic-output tests for timestamp decoding.
- Handle additional timezone edge cases (DST transition ambiguity, historical offsets).

**SHA-256 evidence integrity**
- Improve container and filesystem compatibility where safe.
- Expand the `chronotrace verify --provenance` full-chain replay.

**Structured investigation reports**
- Improve report templates and disclosure/redaction workflows.
- Add `executive` template that explicitly summarises all six PS objectives.

## Medium term

**System artefact extraction**
- Additional macOS (unified logs, Spotlight) and Linux (auditd, systemd) artefacts.
- Stronger sandboxing for untrusted parser workloads.

**Chronological activity timeline reconstruction**
- More structured SQL/DataFrame query capabilities over Parquet/SQLite.
- Richer cross-source corroboration and burst-detection algorithms.

**SHA-256 evidence integrity**
- Optional external timestamping (RFC 3161) and attestation integrations.
- Performance improvements for multi-terabyte evidence sets.

## Long term

- Stable ecosystem for third-party plugins across all six PS objectives.
- Expanded schema migration tooling and compatibility guarantees.
- Reproducible, signed analysis bundles suitable for independent verification.

## Prioritization

Correctness and integrity take priority over parser breadth. A feature that cannot
preserve read-only evidence handling, deterministic output, provenance, and defensible
reporting should not be prioritized ahead of those guarantees.
