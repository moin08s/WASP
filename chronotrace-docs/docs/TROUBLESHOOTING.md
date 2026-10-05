# Troubleshooting

This document covers common failures grouped by the project specification objective they
affect.

## Installation failures

**Native library not found:** install the platform packages for `libewf`, `libtsk`, `libvhdi`, `libvmdk`, `libqcow`, `libesedb`, and PDF-rendering dependencies, or use the supported container/WSL2 environment.

**Python dependency conflict:** create a fresh virtual environment and install the pinned project dependencies.

## Evidence problems *(PS: SHA-256 evidence integrity)*

**`EvidenceCorruptError`:** note the failing offset, preserve the original source, and inspect acquisition/read errors. Do not attempt to repair the original evidence in place.

**Hash mismatch on verify:** stop analysis, preserve the manifest and ledger, and determine whether the source, evidence copy, or storage medium changed. Do not continue analysis until the discrepancy is resolved and documented.

## Parsing problems *(PS: file metadata extraction + system artefact extraction)*

**Plugin warnings:** inspect `derived/<plugin>.warnings.jsonl`. Run with `--strict` when validating a parser or preparing a controlled examination.

**Missing artefact:** confirm the correct profile, filesystem, path, plugin availability, and whether the artefact exists in the acquired evidence. A missing parser result is not proof that the artefact never existed.

## Performance

- Put `CHRONOTRACE_TMPDIR` on fast local storage.
- Use a bounded `--jobs` value appropriate to physical CPU cores and RAM.
- For very large images, extract high-value plugins in separate passes.
- Keep the evidence image outside the temporary workspace.

## Timeline discrepancies *(PS: timestamp extraction + chronological timeline reconstruction)*

Check timezone metadata, raw timestamps, parser version, confidence/rationale, deduplication settings, and schema version. Compare the event's provenance back to the source record before treating a discrepancy as a parser defect.

## Reports *(PS: structured investigation reports)*

If PDF rendering fails, generate HTML/JSON first to separate data-generation problems from rendering problems. For disclosure, verify the final report hash against the manifest and include the integrity section in any submitted report.

