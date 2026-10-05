# Testing

Testing prioritizes forensic correctness, reproducibility, and resistance to malformed
evidence, in direct support of the six project specification objectives: file metadata
extraction, system artefact extraction, timestamp extraction, chronological timeline
reconstruction, SHA-256 evidence integrity, and structured investigation reports.

## Test layers

| Layer | Purpose |
|---|---|
| Unit | Timestamp decoding, parsers, normalization, hashing, redaction |
| Integration | Complete ingest/extract/timeline flows on fixtures |
| Regression | Prevent changes to known-good event output |
| Property | Validate invariants such as deterministic IDs and canonical serialization |
| Fuzz | Exercise binary parsers with malformed and adversarial input |
| Security | Path traversal, write-guard, report injection, resource exhaustion |

## Required checks

```bash
pytest -q
ruff check chronotrace
ruff format --check chronotrace
mypy --strict chronotrace
bandit -r chronotrace
```

## Fixtures

Do not commit real case evidence. Use public forensic corpora, synthetic generators, or donated samples with written permission. Each fixture should include `PROVENANCE.md` describing source, license, generation method, and expected results.

## Determinism test

Run the same case twice with deterministic mode and compare the output trees. Event ordering must be stable across worker counts, and deterministic `event_id` values must not depend on runtime UUID randomness.

## Failure expectations

Malformed records normally produce `ParseWarning` records and continue processing. Strict
mode converts parse warnings into failures. Tests must verify that corrupted inputs never
cause evidence writes or uncontrolled output paths.

## PS objective test coverage

| PS Objective | Test focus |
|---|---|
| File metadata extraction | EXIF/XMP/PDF/OOXML field accuracy; archive entry metadata; media container timestamp correctness |
| System artefact extraction | Per-plugin format correctness; regression fixtures; malformed-input fuzz harnesses |
| Timestamp extraction | Timezone resolution correctness; raw value preservation; DST/ambiguous-time handling; `tz_confidence` accuracy |
| Chronological timeline reconstruction | Stable sort order across thread counts; deterministic `event_id` values; deduplication idempotency |
| SHA-256 evidence integrity | Hash correctness for all evidence containers; ledger chain integrity; manifest completeness; Merkle root accuracy |
| Structured investigation reports | Report content completeness; redaction correctness; deterministic rendering; PDF/HTML rendering integrity |

