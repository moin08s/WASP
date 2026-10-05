# Evidence Handling

ChronoTrace is designed for forensic examination where evidence must remain unchanged and
every derived result must be traceable to its source. Evidence handling procedures
directly support the **SHA-256 evidence integrity** objective of the project
specification: every evidence object is hashed during acquisition, every derived file is
hashed after extraction, and the chain of custody is recorded in a cryptographically
linked ledger.

## Acquisition

1. Record examiner, case ID, authorization reference, source details, and acquisition time.
2. Prefer a physical device or source image opened read-only.
3. Acquire to an evidence object before analysis.
4. Compute mandatory SHA-256 while acquiring.
5. Perform read-back verification where supported.
6. Record read errors and bad-sector information rather than silently substituting data.

## Read-only analysis

Analysis plugins consume `EvidenceView`, which exposes reads and metadata but no write operation. The write-guard protects evidence paths against common file and memory-mapping APIs.

## Chain of custody

Every significant action is recorded in `custody/ledger.jsonl`. Records contain a sequence number, UTC timestamp, actor, event type, payload, previous-record hash, and current hash. Optional HMAC signing provides authenticity in addition to hash-chain integrity.

## Transfers and storage

Document every physical or logical custody transfer. Store manifests and ledger copies separately from working data when practical, preferably on controlled or write-once media. Preserve original evidence and never use derived output as a substitute for the source.

## Verification

Use `chronotrace verify` to re-hash evidence, replay the ledger, verify derived-file hashes, and optionally validate provenance. Seal completed cases only after all required reports and integrity checks are complete.
