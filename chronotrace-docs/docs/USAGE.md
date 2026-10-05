# Usage

ChronoTrace automates the complete forensic pipeline across six objectives derived from
the project specification: **file metadata extraction**, **system artefact extraction**,
**timestamp extraction**, **chronological activity timeline reconstruction**,
**SHA-256 evidence integrity**, and **structured investigation report generation**.

This document covers end-to-end workflows. For flag-by-flag details see
[CLI_REFERENCE.md](CLI_REFERENCE.md).

---

## 1. Standard workflow (Windows disk image)

Each step below is annotated with the project specification objective it satisfies.

```bash
# --- Setup -----------------------------------------------------------------
chronotrace case create \
  --id CASE-2024-0117 \
  --examiner "A. Analyst" \
  --organization "Example DFIR Unit" \
  --authorization-ref "WARRANT-2024-0117" \
  --out ./CASE-2024-0117

# --- Acquire [PS: SHA-256 evidence integrity] --------------------------------
# Streams SHA-256 hash during imaging; writes evidence/*.sha256 and manifest.json
chronotrace acquire \
  --case ./CASE-2024-0117 \
  --source /dev/sdb \
  --output ./CASE-2024-0117/evidence/disk0.E01 \
  --format ewf --hash sha256 --hash-extra blake3 \
  --verify readback \
  --notes "Seized 2024-01-17 09:12, office desktop, powered off"

# --- Ingest [PS: system artefact extraction + file metadata extraction] -----
# Opens evidence read-only; indexes filesystem; sets up for plugin extraction
chronotrace ingest \
  --case ./CASE-2024-0117 \
  --profile windows --jobs 8 \
  --exclude-glob "C:/Windows/WinSxS/**"

# --- Extract artefacts [PS: system artefact extraction + file metadata + timestamps] ---
# Runs all artefact plugins (MFT, registry, EVTX, Prefetch, SRUM, LNK,
# ShellBags, browser history, EXIF, XMP, PDF metadata, OOXML properties, ...)
chronotrace extract --case ./CASE-2024-0117 --all --jobs 8

# --- Build timeline [PS: chronological activity timeline reconstruction] ----
# Merges all extracted events; stable-sorts by (timestamp_utc, event_id);
# writes events.parquet + events.sqlite
chronotrace timeline \
  --case ./CASE-2024-0117 \
  --from 2024-01-01T00:00:00Z --to 2024-03-31T23:59:59Z \
  --tz UTC --format parquet,sqlite --dedupe strict

# --- Verify [PS: SHA-256 evidence integrity] --------------------------------
# Replays hash-chained ledger and re-hashes evidence + derived files
chronotrace verify --case ./CASE-2024-0117 --ledger-only
chronotrace verify --case ./CASE-2024-0117 --rehash --provenance-sample 5000

# --- Report [PS: structured investigation reports] -------------------------
# Produces multi-format structured reports covering all six PS objectives
chronotrace report \
  --case ./CASE-2024-0117 \
  --template full --format html,pdf,json,md \
  --include-integrity --include-custody \
  --redact usernames
```

---

## 2. Triage workflow (fast, metadata-only)

For a quick look before committing to a full extraction:

bash

```
chronotrace ingest --case ./CASE-2024-0117 --profile minimal --jobs 16
chronotrace extract --case ./CASE-2024-0117 --plugins mft,usn,evtx,prefetch --jobs 16
chronotrace timeline --case ./CASE-2024-0117 \
  --from -7d --min-confidence 0.7 \
  --aggregate hour --format csv --out ./triage.csv
```

svgsvg

Then pivot on interesting hours:

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --from 2024-03-11T01:00:00Z --to 2024-03-11T04:00:00Z \
  --format csv --out ./incident_window.csv
```

svgsvg

---

## 3. Building an execution-focused timeline

Questions like "what ran on this host?" are best answered with a filtered view:

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --filter "action in (PROCESS_START, EXECUTION, SERVICE_INSTALL, SCHEDULED_TASK_CREATE)" \
  --from 2024-01-01T00:00:00Z \
  --format csv --out ./executions.csv
```

svgsvg

Relevant actions come from Prefetch, Amcache, ShimCache, SRUM, EVTX 4688/4104/7045,
Scheduled Tasks, and WMI persistence artefacts.

---

## 4. Building a file-activity timeline for a user

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --user "CORP\\alice" \
  --filter "object.type == 'file'" \
  --format csv --out ./alice_files.csv
```

svgsvg

Correlate with USB and network activity:

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --filter "action in (USB_CONNECT, NETWORK_CONNECT, FILE_COPY_TO_REMOVABLE)" \
  --from 2024-03-01T00:00:00Z --to 2024-03-31T23:59:59Z \
  --format csv --out ./exfil_candidates.csv
```

svgsvg

---

## 5. Anti-forensics detection

Look for timestomping (NTFS `$SI` vs `$FN` mismatch) and log clearing:

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --filter "tag in (TIMESTOMP_SUSPECTED, LOG_CLEARED, USN_GAP, SHADOW_COPY_DELETED)" \
  --format csv --out ./anti_forensics.csv
```

svgsvg

`TIMESTOMP_SUSPECTED` is emitted by the `mft` plugin when
`$STANDARD_INFORMATION.modified < $FILE_NAME.modified` and sub-second precision is zeroed
— a classic indicator.

---

## 6. Comparing two acquisitions

bash

```
chronotrace timeline diff \
  --case ./CASE-2024-0117 \
  --against ./CASE-2024-0117-pre-incident \
  --out ./diff
```

svgsvg

Produces `added.jsonl`, `removed.jsonl`, `changed.jsonl` and a summary count table.

---

## 7. Working with a directory (not an image)

bash

```
chronotrace acquire \
  --case ./CASE-2024-0117 \
  --source /mnt/exported_host \
  --output ./CASE-2024-0117/evidence/host_dir.tar.zst \
  --format tar --hash sha256
```

svgsvg

Or point directly at a directory if you have already acquired it and just need hashing:

bash

```
chronotrace ingest --case ./CASE-2024-0117 --evidence-dir /mnt/exported_host
```

svgsvg

---

## 8. Batch processing many cases

bash

```
for case in /cases/*/; do
  chronotrace verify --case "$case" --ledger-only || echo "FAILED: $case"
  chronotrace report --case "$case" --template summary --format md
done
```

svgsvg

With the container:

bash

```
docker run --rm --network none \
  -v /cases:/cases:ro -v /out:/out \
  ghcr.io/chronotrace/chronotrace:1.3.0 \
  bash -c 'for c in /cases/*/; do chronotrace report --case "$c" --template summary --format md --out /out; done'
```

svgsvg

---

## 9. Library usage

python

```
from chronotrace import Case
from chronotrace.timeline import Timeline
from chronotrace.report import ReportBuilder

case = Case.open("./CASE-2024-0117", key_env="CHRONOTRACE_CASE_KEY")

# Run the pipeline
case.ingest(profile="windows", jobs=8).run()
case.extract(plugins="all", jobs=8).run()
case.build_timeline(from_="2024-01-01T00:00:00Z", to="2024-04-01T00:00:00Z")

# Query
tl = Timeline.from_case(case)
execs = tl.filter(action="PROCESS_START").filter(confidence_min=0.8)
for e in execs.iter_events():
    print(e.timestamp_utc.isoformat(), e.object.get("path"), e.confidence)

# Report
ReportBuilder(case).template("full").formats("html", "json").build()
```

svgsvg

---

## 10. Recipes

### 10.1 Find all files touched within 10 minutes of a known event

python

```
import datetime as dt
from chronotrace.timeline import Timeline

tl = Timeline.from_case(case)
anchor = dt.datetime(2024, 3, 11, 2, 14, 7, tzinfo=dt.timezone.utc)
window = tl.between(anchor - dt.timedelta(minutes=10), anchor + dt.timedelta(minutes=10))
for e in window.filter(object_type="file"):
    print(e.timestamp_utc, e.action, e.object["path"])
```

svgsvg

### 10.2 First and last activity per user

bash

```
chronotrace timeline query --case ./CASE-2024-0117 --sql "
  SELECT user, min(timestamp_utc) AS first_seen, max(timestamp_utc) AS last_seen, count(*) AS n
  FROM events GROUP BY user ORDER BY n DESC"
```

svgsvg

### 10.3 Detect activity outside business hours

bash

```
chronotrace timeline query --case ./CASE-2024-0117 --sql "
  SELECT * FROM events
  WHERE cast(strftime('%H', timestamp_utc) AS INTEGER) NOT BETWEEN 8 AND 18
     OR strftime('%w', timestamp_utc) IN ('0','6')
  ORDER BY timestamp_utc"
```

svgsvg

### 10.4 Correlate a USB device with file writes

bash

```
chronotrace timeline --case ./CASE-2024-0117 \
  --filter "action in (USB_CONNECT, FILE_WRITE) and (object.path like '%E:\\%' or tag == 'usb')" \
  --format csv
```

svgsvg

### 10.5 Export a timeline for ingestion into another tool

bash

```
chronotrace timeline --case ./CASE-2024-0117 --format jsonl --out ./timeline.jsonl
# or a mactime-style body file
chronotrace timeline --case ./CASE-2024-0117 --format bodyfile --out ./timeline.body
```

svgsvg

---

## 11. Operational tips

- Set `CHRONOTRACE_TMPDIR` to fast local storage; extraction is I/O heavy.
- Use `--jobs` equal to physical cores, not hyperthreads.
- For very large images, extract in passes (`--plugins mft` then `--plugins evtx`) to
  bound memory.
- Keep `--deterministic` on for anything that may be disclosed or compared across runs.
- Never delete `custody/ledger.jsonl` or `manifest.json` — they are the integrity
  backbone and are required for verification.

text
