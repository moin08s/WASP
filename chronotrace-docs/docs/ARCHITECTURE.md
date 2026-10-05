# Architecture

## 1. Overview

ChronoTrace automates six core forensic objectives — **file metadata extraction**,
**system artefact extraction**, **timestamp extraction**, **chronological activity
timeline reconstruction**, **SHA-256 evidence integrity**, and **structured
investigation reporting** — through a staged, plugin-driven pipeline. Each stage reads
from a content-addressed store and writes to it; stages are independently re-runnable and
idempotent. The pipeline ensures that any derived record can be traced back to the exact
bytes of evidence that produced it.

```

svgsvg

┌──────────────────────────────────────────────────────┐
│ CASE │
│ case.json · config.toml · custody/ledger.jsonl │
└──────────────────────────────────────────────────────┘
│
┌───────────┐ ┌───────────┐ ┌──────▼──────┐ ┌───────────────┐
│ ACQUIRE │───▶│ INGEST │───▶│ EXTRACT │───▶│ NORMALIZE │
│ │ │ │ │ │ │ │
│ hash │ │ open RO │ │ plugins: │ │ unify event │
│ copy/E01 │ │ partition │ │ mft, evtx, │ │ schema, tz │
│ write │ │ mount RO │ │ registry, │ │ normalization │
│ manifest │ │ fs detect │ │ lnk, ... │ │ confidence │
└───────────┘ └───────────┘ └─────────────┘ └───────┬───────┘
│
┌───────────────────────────────────────────────────────▼────────┐
│ TIMELINE STORE │
│ events.parquet · events.sqlite (index) · derived/*.jsonl │*
*└───────────────────────────────┬────────────────────────────────┘*
*│*
*┌───────────────────────────────▼────────────────────────────────┐*
*│ INTEGRITY VERIFY REPORT │*
*│ manifest.json re-hash templates/*.j2 │
│ ledger.jsonl replay ledger JSON/CSV/HTML/PDF/MD │
│ merkle_root diff attestation block │
└────────────────────────────────────────────────────────────────┘

text

```
## 2. Layers

### 2.1 Core (`chronotrace.core`)

| Module | Responsibility |
|---|---|
| `case.py` | Case lifecycle, `case.json`, paths, locking |
| `evidence.py` | `EvidenceSource` abstraction; read-only handle enforcement |
| `writeguard.py` | Intercepts `open`, `os.open`, `mmap`, `io.open` on evidence paths |
| `store.py` | Content-addressed blob store for derived artefacts |
| `registry.py` | Plugin discovery and manifest validation |
| `config.py` | Config loading, merging, schema validation |
| `logging.py` | Structured JSON logging with PII scrubbing |
| `errors.py` | Exception hierarchy |

### 2.2 Acquire (`chronotrace.acquire`)

* `Imager` — raw/E01/VHDX writers with resumable chunking.
* `Hasher` — streaming SHA-256 (mandatory), optional BLAKE3/SHA-1/MD5 (legacy
  cross-check only; never the sole hash).
* `Verifier` — read-back verification pass.
* `Manifest` — `manifest.json` with per-object hashes, sizes, and acquisition metadata.

### 2.3 Ingest (`chronotrace.ingest`)

* `ContainerReader` — EWF/VHDX/VMDK/QCOW2/ISO via `libewf`, `libvhdi`, `libvmdk`, `libqcow`.
* `VolumeReader` — partition table parsing (MBR/GPT/APM), volume assembly, LVM/LUKS
  detection (metadata only; no key recovery).
* `FilesystemReader` — `pytsk3`-backed and native readers; provides `stat`, `read`,
  `readdir`, `walk`, and per-filesystem metadata records.
* `EvidenceView` — the read-only interface plugins consume. Exposes byte ranges,
  record iteration, and filesystem metadata, but no write path.

### 2.4 Extract (`chronotrace.extract`)

* **File metadata extractors:** EXIF, XMP, IPTC, PDF, OOXML/ODF, archive entry metadata,
  media containers.
* **Artefact plugins:** see [ARTIFACT_REFERENCE.md](ARTIFACT_REFERENCE.md).
* Plugin execution is parallel across artefacts and bounded by `--jobs` and a memory
  budget. Each plugin runs against a read-only `EvidenceView` slice.

### 2.5 Normalize (`chronotrace.normalize`)

* Maps plugin-specific records to the unified `Event` model.
* Resolves timezones: explicit offset > registry `TimeZoneInformation` > artefact-embedded
  zone > UTC (with `tz_confidence` recorded).
* Assigns `action` from a controlled vocabulary.
* Computes deterministic `event_id` = `uuid5(NS, sha256(canonical_fields))`.
* Assigns `confidence` and `rationale`.
* Deduplicates equivalent events from multiple sources (configurable; keeps the highest
  confidence and records `corroborated_by`).

### 2.6 Timeline (`chronotrace.timeline`)

* `TimelineBuilder` — merges normalized events, stable-sorts by
  `(timestamp_utc, event_id)`.
* `TimeRangeFilter` — inclusive/exclusive ranges, gap detection.
* `Aggregator` — per-hour/day counts, burst detection, first/last-seen.
* `Query` — SQL over the SQLite index; predicate pushdown to Parquet via `pyarrow.dataset`.
* Storage: Parquet (columnar, compressed, sorted by time) + SQLite (indexes and FTS5 over
  paths/usernames/commands).

### 2.7 Integrity (`chronotrace.integrity`)

* `Hasher`, `ManifestWriter`, `Ledger` (append-only hash chain), `MerkleTree`,
  `Verifier`, `Attestor` (optional RFC 3161 timestamp / external notarization hook).

### 2.8 Report (`chronotrace.report`)

* Jinja2 templates → HTML → PDF (WeasyPrint), plus native JSON/CSV/Markdown writers.
* Redaction engine applied to the event stream *before* rendering.
* Report hash appended to the ledger.

### 2.9 CLI (`chronotrace.cli`)

Typer-based CLI. Commands: `case`, `acquire`, `ingest`, `extract`, `timeline`, `verify`,
`report`, `plugin`, `config`, `doctor`. See [CLI_REFERENCE.md](CLI_REFERENCE.md).

## 3. Data flow and provenance

Every `Event` carries:

```

svgsvg

evidence_id ──▶ evidence sha256 ──▶ source artefact ──▶ record offset/ID ──▶ parser version

text

```
This chain is written into the event itself and into `derived/<plugin>.provenance.jsonl`.
`chronotrace verify --provenance` walks the chain for a sampled or full set of events and
re-derives them from the evidence, reporting any mismatch.

## 4. Determinism

Sources of nondeterminism and their mitigations:

| Source | Mitigation |
|---|---|
| Thread scheduling | Stable sort on `(timestamp_utc, event_id)`; results merged in a deterministic order |
| Dict ordering | Canonical JSON serialization with sorted keys |
| Wall clock | Excluded from `--deterministic` outputs; otherwise isolated in `report.generated_at` |
| Filesystem iteration order | `walk()` sorts entries by `(parent_id, name)` |
| Locale/timezone | All internal times are UTC `datetime` with `tzinfo=UTC`; locale-independent formatting |
| Random UUIDs | `event_id` is a UUIDv5, derived from content |
| Floating point | Confidence stored as `Decimal` quantized to 3 places |
| Parallel plugin output | Per-plugin output buffered and appended in plugin-name order |

Verify determinism in CI: run the same case twice and `diff -r` the output trees.

## 5. Extension points

| Point | Mechanism |
|---|---|
| Artefact parsers | `chronotrace.plugins` entry point, `ArtifactPlugin` subclass |
| Report templates | Jinja2 templates in `templates/` or `--template-dir` |
| Filesystems | `FilesystemProvider` registration |
| Evidence containers | `ContainerProvider` registration |
| Redaction rules | `redaction/*.toml` profiles |
| Post-processing hooks | `chronotrace.hooks` entry point |

## 6. Performance characteristics

Baseline on a 4 vCPU / 16 GB analysis host, 500 GB NTFS image, `--jobs 4`:

| Stage | Time | Notes |
|---|---|---|
| Acquire (hash + E01) | ~45 min | I/O bound; ~110 MB/s with SHA-256 |
| Ingest (fs index) | ~12 min | Metadata only |
| Extract ($MFT + registry + EVTX) | ~25 min | ~180M events |
| Normalize | ~8 min | |
| Timeline write (Parquet) | ~3 min | |
| Report (full HTML+PDF) | ~2 min | |

Memory is bounded by streaming parsers and a configurable `--memory-budget`. The tool never
loads a full image into RAM.

## 7. Concurrency model

* A bounded `ProcessPoolExecutor` for CPU-bound parsers (plugins declare
  `parallel_safe = True` to opt in).
* `asyncio` for I/O-bound container reads.
* A single writer process owns the timeline store; workers ship serialized events back
  over a queue, which preserves deterministic merge order.

## 8. Failure handling

* Parse failures never abort the run by default; they emit `ParseWarning` records and
  increment `warnings` counters in the manifest.
* `--strict` turns warnings into errors (recommended for validation runs).
* Corrupt evidence surfaces as `EvidenceCorruptError` with the failing offset; acquisition
  is resumable from the last verified chunk.

## 9. Pipeline objectives mapping

The table below maps each pipeline stage to the six core objectives stated in the project
specification.

| PS Objective | Stage(s) | Key outputs |
|---|---|---|
| **File metadata extraction** | `extract` | EXIF/XMP/PDF/OOXML fields → `derived/metadata.jsonl` |
| **System artefact extraction** | `ingest` + `extract` | MFT, registry, EVTX, Prefetch, SRUM, LNK, ShellBags → `derived/*.jsonl` |
| **Timestamp extraction** | `extract` + `normalize` | Per-artefact decoded timestamps, timezone resolution, `timestamp_raw` + `timestamp_utc` |
| **Chronological activity timeline reconstruction** | `timeline` | `index/events.parquet`, `index/events.sqlite`, stable-sorted by `(timestamp_utc, event_id)` |
| **SHA-256 evidence integrity** | `acquire` + `integrity` | `manifest.json`, `evidence/*.sha256`, `custody/ledger.jsonl`, Merkle root |
| **Structured investigation reports** | `report` | `reports/*.html`, `reports/*.pdf`, `reports/*.json`, `reports/*.csv`, `reports/*.md` |

