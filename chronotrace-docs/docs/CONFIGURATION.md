# Configuration

ChronoTrace reads configuration from (in increasing precedence):

1. Built-in defaults
2. `~/.config/chronotrace/config.toml` (or `$CHRONOTRACE_HOME/config.toml`)
3. Case-level `<case>/config.toml`
4. `--config PATH` on the command line
5. Environment variables (`CHRONOTRACE_*`)
6. Command-line flags

The effective merged config is recorded in `<case>/config.effective.toml` for
reproducibility, and its SHA-256 is written to the manifest.

Validate with `chronotrace config validate <file>`; print the JSON Schema with
`chronotrace config schema`.

---

## Full reference

```toml
#:schema https://chronotrace.example/schema/config-1.3.json

[general]
case_id            = "CASE-2024-0117"
examiner           = "A. Analyst"
organization       = "Example DFIR Unit"
description        = "Unauthorized access investigation"
authorization_ref  = "WARRANT-2024-0117"
deterministic      = true          # strip volatile metadata from outputs
strict             = false         # treat parse warnings as fatal
no_network         = true          # hard-fail on network attempts
locale             = "C.UTF-8"     # never rely on host locale

[paths]
workdir            = "./work"
tmpdir             = "/var/tmp/chronotrace"
evidence_dir       = "./evidence"
derived_dir        = "./derived"
index_dir          = "./index"
report_dir         = "./reports"
custody_dir        = "./custody"

[logging]
level              = "info"        # trace|debug|info|warn|error
format             = "json"        # text|json
file               = "./logs/chronotrace.log"
scrub_pii          = true          # scrub usernames/paths from log messages
rotate             = "50MB"
retain             = 10

[acquire]
format             = "ewf"
hash               = "sha256"      # SHA-256 always computed
hash_extra         = ["blake3"]    # ["sha1"] only for legacy cross-check
compress           = "zlib:6"      # none|zlib:1-9|lz4|zstd:1-19
segment_size       = "2G"
read_retries       = 3
verify             = "readback"    # none|readback
bad_sector_policy  = "log"         # log|fail|zero-fill
notes              = ""

[ingest]
profile            = "windows"     # windows|linux|macos|minimal|full
jobs               = 8
memory_budget      = "8G"
carve              = true
carve_min_size     = "4K"
include_globs      = []
exclude_globs      = ["**/WinSxS/**", "**/node_modules/**"]
hash_files_globs   = []            # e.g. ["**/*.exe", "**/*.dll"]
follow_symlinks    = false
max_path_depth     = 64

[extract]
plugins            = ["mft", "usn", "registry", "evtx", "lnk", "prefetch",
                      "amcache", "shimcache", "srum", "browser", "shellbags",
                      "jumplists", "recyclebin", "scheduled_tasks",
                      "powershell", "wmiprov"]
exclude_plugins    = []
jobs               = 8
timeout_per_artifact = 900         # seconds; 0 = unlimited
continue_on_error  = true
output_format      = "parquet"     # jsonl|parquet|csv
max_records_per_plugin = 0         # 0 = unlimited

[extract.plugin_options.registry]
replay_transaction_logs = true     # replay .LOG1/.LOG2 for accuracy
include_deleted_keys    = true

[extract.plugin_options.evtx]
resolve_strings   = true
include_correlated = true

[extract.plugin_options.mft]
include_deleted   = true
include_slack     = false
timestamps        = ["si", "fn"]   # $STANDARD_INFORMATION + $FILE_NAME

[normalize]
tz_default        = "UTC"
tz_source_priority = ["explicit_offset", "registry", "artifact_embedded", "utc"]
dedupe            = "strict"       # strict|loose|off
dedupe_window_s   = 1
min_confidence    = 0.0
confidence_overrides = { registry_lastwrite_no_log = 0.85 }

[timeline]
sort              = "asc"          # asc|desc
store             = "parquet+sqlite"
compression       = "zstd:9"
partition_by      = "none"         # none|day|month
index_columns     = ["timestamp_utc", "action", "user", "host", "object.path"]

[integrity]
hash              = "sha256"
ledger            = true
ledger_hmac_key_file = ""          # or use CHRONOTRACE_LEDGER_HMAC_KEY
merkle            = true
merkle_leaf_order = "sorted_path"  # sorted_path|insertion
rfc3161_tsa_url   = ""             # optional external timestamping
verify_on_open    = "manifest"     # none|manifest|rehash

[report]
default_template  = "full"
formats           = ["html", "json", "md"]
title             = ""
watermark         = ""
max_events        = 100000
include_integrity = true
include_custody   = true
include_provenance = false
redaction_profile = "none"         # none|default|court|custom
page_size         = "A4"
logo              = ""

[report.redaction]
usernames = false
paths     = false
ips       = false
hashes    = false
hostnames = false
emails    = false

[security]
sandbox_plugins    = false         # Linux only (nsjail/seccomp)
allow_symlinks     = false
allow_network      = false
max_decompression_ratio = 200      # zip-bomb protection
max_nested_archives = 3
plugin_signature_policy = "warn"   # off|warn|enforce

[performance]
io_threads         = 4
cpu_threads        = 0             # 0 = auto
read_ahead         = "16M"
cache_size         = "2G"
````

svgsvg

---

## Environment variables

| **Variable**                       | **Overrides**                            |
| :--------------------------------- | :--------------------------------------- |
| `CHRONOTRACE_HOME`                 | Config root                              |
| `CHRONOTRACE_CONFIG`               | `--config`                               |
| `CHRONOTRACE_LOG_LEVEL`            | `[logging].level`                        |
| `CHRONOTRACE_NO_NETWORK`           | `[general].no_network`                   |
| `CHRONOTRACE_TMPDIR`               | `[paths].tmpdir`                         |
| `CHRONOTRACE_CASE_KEY`             | Case encryption key                      |
| `CHRONOTRACE_LEDGER_HMAC_KEY`      | Ledger signing key (inline)              |
| `CHRONOTRACE_LEDGER_HMAC_KEY_FILE` | Ledger signing key (file)                |
| `CHRONOTRACE_LEDGER_HMAC_KMS_URI`  | Ledger signing key (KMS/HSM URI)         |
| `CHRONOTRACE_PLUGIN_PATH`          | Extra plugin search path (`:`-separated) |
| `CHRONOTRACE_MAX_MEMORY`           | `[ingest].memory_budget`                 |

---

## Profiles

Profiles are named bundles of `[extract].plugins` plus per-plugin options. Built-ins:

| **Profile** | **Plugins enabled**                                                                                                                                |
| :---------- | :------------------------------------------------------------------------------------------------------------------------------------------------- |
| `windows`   | mft, usn, registry, evtx, lnk, prefetch, amcache, shimcache, srum, browser, shellbags, jumplists, recyclebin, scheduled_tasks, powershell, wmiprov |
| `linux`     | ext_metadata, authlogs, journald, wtmp, shell_history, cron, systemd, auditd, pkglogs                                                              |
| `macos`     | apfs_metadata, unifiedlog, fsevents, quarantine, plists, launchd, spotlight                                                                        |
| `minimal`   | mft, ext_metadata, apfs_metadata (filesystem metadata only, fastest)                                                                               |
| `full`      | everything                                                                                                                                         |

Define your own in `[profiles.<name>]`:

toml

```
[profiles.triage]
plugins = ["mft", "usn", "evtx", "prefetch"]
[profiles.triage.plugin_options.mft]
include_deleted = true
```

svgsvg

---

## Redaction profiles

toml

```
# redaction/court.toml
[redact]
usernames = true
paths     = true
ips       = true
hostnames = true

[redact.patterns]
credit_card = '\b(?:\d[ -]*?){13,19}\b'
national_id = '\b\d{3}-\d{2}-\d{4}\b'

[redact.replace]
usernames = "USER_{n}"
paths     = "PATH_{n}"
ips       = "IP_{n}"
```

svgsvg

Redaction is applied to the event stream before rendering, so redacted values never reach
the template engine. Mappings are stored in `reports/.redaction_map.json` (mode 0600) so
an examiner can de-redact in a controlled environment if legally required.

---

## Determinism checklist

If `[general].deterministic = true`, the following are stripped from outputs:

- `report.generated_at`, `report.generated_by_host`
- Absolute paths outside the case directory
- Temporary directory names
- Tool invocation timestamps and durations
- Any `dict` iteration order dependence

To verify:

bash

```
chronotrace timeline --case ./C1 --deterministic --out ./out1
chronotrace timeline --case ./C1 --deterministic --out ./out2
diff -r ./out1 ./out2   # must be empty
```

svgsvg

text
