# CLI Reference

````

svgsvg

chronotrace [GLOBAL OPTIONS] COMMAND [ARGS]

text

````
Global options must precede the subcommand.

## Global options

| Flag | Default | Description |
|---|---|---|
| `--version` | | Print version and exit |
| `--config PATH` | `~/.config/chronotrace/config.toml` | Global config file |
| `--log-level LEVEL` | `info` | `trace\|debug\|info\|warn\|error` |
| `--log-format FMT` | `text` | `text\|json` |
| `--log-file PATH` | | Append structured logs to a file |
| `--no-color` | | Disable ANSI colour |
| `--deterministic` | off | Strip volatile metadata from all outputs |
| `--no-network` | env `CHRONOTRACE_NO_NETWORK` | Hard-fail on any network attempt |
| `--strict` | off | Treat parse warnings as fatal |
| `--dry-run` | off | Plan actions without executing |
| `-v, --verbose` | | Repeatable verbosity |

---

## `chronotrace case`

Manage cases.

### `case create`

```bash
chronotrace case create \
  --id CASE-2024-0117 \
  --examiner "A. Analyst" \
  --organization "Example DFIR Unit" \
  --out ./CASE-2024-0117 \
  [--description "..." ] \
  [--authorization-ref "WARRANT-2024-0117"] \
  [--no-encrypt]
````

svgsvg

Creates the case directory, `case.json`, `custody/ledger.jsonl`, and an empty manifest.
`--encrypt` (default) protects the derived store with an age/X25519 key you supply via
`CHRONOTRACE_CASE_KEY`.

### `case info`

bash

```
chronotrace case info --case ./CASE-2024-0117 [--json]
```

svgsvg

### `case migrate`

bash

```
chronotrace case migrate --case ./CASE-2024-0117 [--to 2.0.0] [--dry-run]
```

svgsvg

### `case export`

bash

```
chronotrace case export --case ./CASE-2024-0117 --out bundle.tar.zst \
  [--include-evidence] [--include-derived] [--sign KEYID]
```

svgsvg

---

## `chronotrace acquire`

Acquire evidence with integrity hashing.

bash

```
chronotrace acquire \
  --case ./CASE-2024-0117 \
  --source /dev/sdb \
  --output ./CASE-2024-0117/evidence/disk0.E01 \
  --format ewf \
  --hash sha256 \
  [--hash-extra blake3,sha1] \
  [--compress zlib:6] \
  [--segment-size 2G] \
  [--read-retries 3] \
  [--verify readback] \
  [--notes "Seized from office desktop"]
```

svgsvg

| **Flag**                  | **Description**                                           |
| :------------------------ | :-------------------------------------------------------- |
| `--source PATH\|DEVICE`   | Input device, image, or directory                         |
| `--output PATH`           | Destination image path                                    |
| `--format`                | `raw\|ewf\|vhdxi\|vmdk\|qcow\|dir\|tar\|zip`              |
| `--hash`                  | Primary hash algorithm (SHA-256 always computed)          |
| `--hash-extra`            | Additional hashes for cross-checking                      |
| `--segment-size`          | Split output size (E01/raw)                               |
| `--read-retries N`        | Retries on read errors; bad sectors are logged, not fatal |
| `--bad-sector-map PATH`   | Write a bad-sector map file                               |
| `--verify readback\|none` | Post-acquisition verification strategy                    |
| `--notes TEXT`            | Free-text custody note (recorded in ledger)               |

**Exit codes:** `0` success · `2` completed with read errors · `3` hash mismatch · `4` I/O failure.

### `acquire resume`

bash

```
chronotrace acquire resume --case ./CASE-2024-0117 --from-chunk 4096
```

svgsvg

---

## `chronotrace ingest`

Open evidence, enumerate filesystems, build the file index.

bash

```
chronotrace ingest \
  --case ./CASE-2024-0117 \
  --profile windows \
  [--evidence EV-0001] \
  [--jobs 8] \
  [--memory-budget 8G] \
  [--include-glob "C:/Users/**"] \
  [--exclude-glob "C:/Windows/WinSxS/**"] \
  [--hash-files "C:/Users/**/*.exe,C:/Users/**/*.dll"] \
  [--no-carve]
```

svgsvg

| **Flag**                            | **Description**                                             |
| :---------------------------------- | :---------------------------------------------------------- |
| `--profile`                         | Preset artefact set: `windows\|linux\|macos\|minimal\|full` |
| `--evidence`                        | Restrict to a specific evidence ID                          |
| `--jobs`                            | Worker processes                                            |
| `--include-glob` / `--exclude-glob` | Filesystem path filters (repeatable)                        |
| `--hash-files GLOBS`                | Also hash matching file *contents* (slow; off by default)   |
| `--no-carve`                        | Disable file carving of unallocated space                   |

---

## `chronotrace extract`

Run artefact plugins.

bash

```
chronotrace extract \
  --case ./CASE-2024-0117 \
  [--plugins mft,usn,evtx,registry,lnk,prefetch,browser,srum] \
  [--all] \
  [--exclude-plugins amcache] \
  [--jobs 8] \
  [--timeout-per-artifact 900] \
  [--continue-on-error] \
  [--output-format jsonl|parquet|csv]
```

svgsvg

bash

```
chronotrace extract --list        # list available plugins
```

svgsvg

---

## `chronotrace timeline`

Reconstruct the chronological timeline.

bash

```
chronotrace timeline \
  --case ./CASE-2024-0117 \
  [--from 2024-01-01T00:00:00Z] \
  [--to 2024-03-31T23:59:59Z] \
  [--tz UTC|local|<IANA>] \
  [--format parquet,csv,jsonl,sqlite] \
  [--filter "action in (FILE_WRITE,PROCESS_START)"] \
  [--user "CORP\\alice"] \
  [--host WS-01] \
  [--dedupe strict|loose|off] \
  [--min-confidence 0.5] \
  [--sort asc|desc] \
  [--aggregate hour|day|none] \
  [--limit N] \
  [--out PATH]
```

svgsvg

| **Flag**           | **Description**                                                                                               |
| :----------------- | :------------------------------------------------------------------------------------------------------------ |
| `--from` / `--to`  | Inclusive UTC bounds; accepts ISO-8601 and relative (`-7d`)                                                   |
| `--tz`             | Output timezone; internal processing is always UTC                                                            |
| `--filter`         | Expression over event fields (see [TIMELINE_MODEL.md](https://timeline_model.md/))                            |
| `--dedupe`         | `strict` merges same timestamp+object+action; `loose` also merges near-duplicates within 1 s; `off` keeps all |
| `--min-confidence` | Drop events below this confidence                                                                             |
| `--aggregate`      | Emit per-bucket counts alongside events                                                                       |

### `timeline query` (ad-hoc)

bash

```
chronotrace timeline query --case ./CASE-2024-0117 \
  --sql "SELECT action, count(*) FROM events WHERE timestamp_utc > '2024-03-01' GROUP BY 1 ORDER BY 2 DESC"
```

svgsvg

### `timeline diff`

bash

```
chronotrace timeline diff --case ./CASE-2024-0117 --against ./CASE-2024-0117-baseline
```

svgsvg

---

## `chronotrace verify`

Verify integrity.

bash

```
chronotrace verify \
  --case ./CASE-2024-0117 \
  [--evidence EV-0001] \
  [--rehash] \
  [--ledger-only] \
  [--provenance-sample 1000] \
  [--provenance-full] \
  [--report ./CASE-2024-0117/reports/verification.json]
```

svgsvg

| **Flag**                | **Description**                                              |
| :---------------------- | :----------------------------------------------------------- |
| `--rehash`              | Re-read evidence and recompute SHA-256 (slow, definitive)    |
| `--ledger-only`         | Replay the hash chain without touching evidence (fast audit) |
| `--provenance-sample N` | Re-derive N random events from evidence and compare          |
| `--provenance-full`     | Re-derive all events (very slow)                             |

**Exit codes:** `0` verified · `5` hash mismatch · `6` ledger chain broken · `7` provenance mismatch.

---

## `chronotrace report`

Generate investigation reports.

bash

```
chronotrace report \
  --case ./CASE-2024-0117 \
  --template full \
  --format html,pdf,json,csv,md \
  [--out ./CASE-2024-0117/reports] \
  [--title "Investigation into ..."] \
  [--from ...] [--to ...] \
  [--include-integrity] \
  [--include-custody] \
  [--include-provenance] \
  [--redact usernames,paths,ips,hashes] \
  [--redaction-profile ./redaction/court.toml] \
  [--max-events 100000] \
  [--template-dir ./templates] \
  [--watermark DRAFT] \
  [--sign KEYID]
```

svgsvg

| **Template** | **Purpose**                                     |
| :----------- | :---------------------------------------------- |
| `summary`    | One-page overview with counts and top artefacts |
| `executive`  | Non-technical narrative for stakeholders        |
| `timeline`   | Chronological event listing with filters        |
| `artefact`   | Per-artefact findings with provenance           |
| `integrity`  | Hash manifest, ledger, verification results     |
| `full`       | All of the above, combined                      |
| `custom`     | Your Jinja2 template via `--template-dir`       |

---

## `chronotrace plugin`

bash

```
chronotrace plugin list [--json] [--verbose]
chronotrace plugin info ntfs_mft
chronotrace plugin validate ./my_plugin/
chronotrace plugin scaffold --name my_artifact --out ./plugins/
```

svgsvg

---

## `chronotrace config`

bash

```
chronotrace config show [--effective] [--json]
chronotrace config validate ./config.toml
chronotrace config schema            # print JSON Schema
```

svgsvg

---

## `chronotrace doctor`

Diagnose the environment.

bash

```
chronotrace doctor [--fix-permissions] [--json]
```

svgsvg

---

## Exit codes (global)

| **Code** | **Meaning**                         |
| :------- | :---------------------------------- |
| 0        | Success                             |
| 1        | Generic error                       |
| 2        | Completed with warnings/read errors |
| 3        | Hash mismatch during acquisition    |
| 4        | I/O failure                         |
| 5        | Verification hash mismatch          |
| 6        | Ledger chain broken                 |
| 7        | Provenance mismatch                 |
| 8        | Configuration error                 |
| 9        | Plugin load/validation failure      |
| 10       | Evidence write attempt blocked      |
| 130      | Interrupted (SIGINT)                |

## Environment variables

| **Variable**                  | **Purpose**                                                |
| :---------------------------- | :--------------------------------------------------------- |
| `CHRONOTRACE_HOME`            | Config/cache root                                          |
| `CHRONOTRACE_CASE_KEY`        | Case encryption key (age/X25519)                           |
| `CHRONOTRACE_LEDGER_HMAC_KEY` | Ledger HMAC signing key (or `..._KEY_FILE`, `..._KMS_URI`) |
| `CHRONOTRACE_NO_NETWORK`      | Enforce offline mode                                       |
| `CHRONOTRACE_TMPDIR`          | Scratch space for extraction                               |
| `CHRONOTRACE_PLUGIN_PATH`     | Extra plugin directories                                   |
| `CHRONOTRACE_MAX_MEMORY`      | Global memory ceiling                                      |

## Shell completion

bash

```
chronotrace --install-completion bash   # or zsh, fish, powershell
```

svgsvg

text
