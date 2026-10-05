# Reporting

ChronoTrace fulfils the **structured investigation reports** objective of the project
specification by rendering normalized events, file metadata findings, system artefact
discoveries, timestamp evidence, integrity hashes, and chain-of-custody information into
reproducible, machine-readable and human-readable investigation reports.

## Formats

- JSON / JSONL — machine-readable evidence and event export.
- CSV — spreadsheet and timeline analysis.
- Markdown — portable narrative output.
- HTML — interactive human-readable report.
- PDF — fixed-layout disclosure copy rendered from HTML.

## Templates

Built-in templates are `summary`, `timeline`, `artefact`, `integrity`, `executive`, `full`, and `custom`.

```bash
chronotrace report --case ./CASE-2024-0117 \
  --template full \
  --format html,pdf,json,csv,md \
  --include-integrity --include-custody
```

Custom templates use Jinja2. Templates receive normalized events and report metadata, but redaction is applied before rendering.

## Redaction

Use a redaction profile for usernames, paths, IP addresses, hostnames, or configured patterns. Redacted values must not reach the template engine. Controlled de-redaction mappings belong in `reports/.redaction_map.json` with restrictive permissions.

## Report sections

Structured investigation reports produced by ChronoTrace contain the following sections,
directly corresponding to the six PS objectives:

1. **Case metadata** — examiner, organization, case ID, authorization reference.
2. **Evidence inventory with SHA-256 hashes** *(PS: SHA-256 evidence integrity)* — per-object hashes, acquisition timestamps, source serial numbers, read errors.
3. **File metadata findings** *(PS: file metadata extraction)* — filesystem stats, EXIF/XMP/PDF/OOXML properties, archive entry metadata, media container timestamps.
4. **System artefact findings** *(PS: system artefact extraction)* — MFT records, registry keys, EVTX events, Prefetch/Amcache execution evidence, SRUM, LNK, ShellBags, browser history.
5. **Chronological timeline** *(PS: timeline reconstruction)* — merged, sorted super-timeline with confidence scores, rationale, and corroboration links.
6. **Timestamp provenance** *(PS: timestamp extraction)* — raw timestamps, timezone resolution chain, `timestamp_type` breakdown per artefact.
7. **Extraction and plugin inventory** — plugins run, versions, parse warnings, records emitted.
8. **Integrity manifest and Merkle root** *(PS: SHA-256 integrity)* — hashes for every derived file, ledger replay result, attestation block.
9. **Chain-of-custody ledger summary** — sequenced, hash-chained custody log.
10. **Redaction and methodology notes** — what was redacted, with which profile, and the examiner's methodology statement.

## Determinism

When deterministic mode is enabled, generation timestamps, analysis-host names, temporary
paths, and other volatile metadata are excluded. Identical inputs and configuration should
produce identical report content, making reports directly comparable across re-runs.

