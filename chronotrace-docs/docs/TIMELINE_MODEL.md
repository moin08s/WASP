# Timeline Model

## 1. Purpose

This document describes the unified event model that fulfils the **chronological activity
timeline reconstruction** objective of the project specification. The model exists so that
artefacts from radically different sources (file metadata, filesystem metadata, binary
logs, registry hives, SQLite databases, text logs) can be merged, sorted, filtered, and
reasoned about uniformly — while never losing the provenance needed to defend a finding
in court.

ChronoTrace's timeline reconstruction is:
- **Automated** — all artefact sources feed a single normalized pipeline without manual merging.
- **Chronological** — events are stable-sorted by `(timestamp_utc, event_id)` so ordering is reproducible.
- **Comprehensive** — timestamps from filesystem metadata, system artefacts, and file metadata are all included.
- **Traceable** — every event carries the SHA-256 of the evidence it was derived from.

**Schema version:** `2.0.0`
**Canonical serialization:** JSON Lines, UTF-8, keys sorted, times as RFC 3339 UTC.

---

## 2. The `Event` object

```json
{
  "event_id": "9f1c0a1e-6a1f-5a4f-9c2f-1b2c3d4e5f60",
  "schema_version": "2.0.0",

  "timestamp_utc": "2024-03-11T02:14:07.123456Z",
  "timestamp_raw": "2024-03-10 22:14:07.123456 -04:00",
  "timestamp_type": "modified",
  "timestamp_confidence": 0.98,

  "action": "FILE_WRITE",
  "action_class": "file",

  "host": "WS-01",
  "user": "CORP\\alice",
  "user_sid": "S-1-5-21-1111-2222-3333-1001",

  "object": {
    "type": "file",
    "path": "C:\\Users\\alice\\Documents\\report.docx",
    "path_norm": "c:/users/alice/documents/report.docx",
    "size": 45213,
    "inode": 118472,
    "extension": "docx",
    "md5": null,
    "sha256": null
  },

  "source": {
    "artifact": "NTFS:$MFT",
    "plugin": "ntfs_mft",
    "plugin_version": "1.4.2",
    "evidence_id": "EV-0001",
    "record_id": 118472,
    "record_offset": 121315328,
    "record_type": "FILE"
  },

  "evidence": {
    "evidence_id": "EV-0001",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "container": "disk0.E01"
  },

  "confidence": 0.98,
  "rationale": "NTFS MFT $STANDARD_INFORMATION modified timestamp",

  "tags": ["execution"],
  "corroborated_by": [
    "3b2f...@Prefetch",
    "7c9a...@SRUM"
  ],

  "tz": {
    "source": "registry",
    "name": "America/New_York",
    "offset": "-04:00",
    "confidence": 0.92
  },

  "raw": {
    "si_modified": "2024-03-11T02:14:07.123456Z",
    "fn_modified": "2024-03-11T02:14:07.123456Z",
    "flags": "FILE_ATTRIBUTE_ARCHIVE"
  },

  "warnings": []
}
````

svgsvg

### 2.1 Field reference

| **Field**               | **Type**      | **Required** | **Description**                                                                      |
| :---------------------- | :------------ | :----------- | :----------------------------------------------------------------------------------- |
| `event_id`              | UUIDv5 string | ✅            | Deterministic; `uuid5(NS_URL, sha256(canonical_fields))`                             |
| `schema_version`        | semver        | ✅            | Model version that produced this event                                               |
| `timestamp_utc`         | RFC 3339      | ✅            | Normalized to UTC, microsecond precision where available                             |
| `timestamp_raw`         | string        |              | Original value exactly as parsed                                                     |
| `timestamp_type`        | enum          | ✅            | See §3                                                                               |
| `timestamp_confidence`  | float 0–1     |              | Confidence specific to the time value                                                |
| `action`                | enum          | ✅            | Controlled vocabulary, see §4                                                        |
| `action_class`          | enum          |              | Grouping: `file`, `process`, `network`, `auth`, `config`, `system`, `media`, `other` |
| `host`                  | string        |              | Hostname where the activity occurred                                                 |
| `user`                  | string        |              | `DOMAIN\user` or `user@host`                                                         |
| `user_sid` / `user_uid` | string/int    |              | Platform identifier                                                                  |
| `object`                | object        | ✅            | The thing acted upon; schema varies by `object.type`                                 |
| `source`                | object        | ✅            | Provenance: artefact, plugin, version, offsets                                       |
| `evidence`              | object        | ✅            | Evidence ID and its SHA-256                                                          |
| `confidence`            | float 0–1     | ✅            | Overall event confidence                                                             |
| `rationale`             | string        |              | Human-readable justification                                                         |
| `tags`                  | string[]      |              | Analytical tags (`execution`, `persistence`, `exfil`, `anti_forensics`)              |
| `corroborated_by`       | string[]      |              | `event_id@plugin` of corroborating events                                            |
| `tz`                    | object        |              | Timezone resolution details                                                          |
| `raw`                   | object        |              | Plugin-specific original fields (never discarded)                                    |
| `warnings`              | string[]      |              | Non-fatal parse issues for this record                                               |

**Rule:** `raw` must always be retained. Downstream consumers may ignore it, but the tool
never discards original parsed values, so a finding can be re-examined without re-parsing.

---

## 3. `timestamp_type` vocabulary

| **Value**           | **Meaning**                    | **Typical sources**                                     |
| :------------------ | :----------------------------- | :------------------------------------------------------ |
| `created`           | Object creation / birth time   | NTFS `$SI`/`$FN` created, ext4 `crtime`, APFS `created` |
| `modified`          | Content modification           | NTFS `$SI` modified, mtime                              |
| `accessed`          | Last access                    | NTFS `$SI` accessed, atime                              |
| `changed`           | Metadata change                | NTFS entry-modified, ext4 `ctime`                       |
| `deleted`           | Deletion                       | ext4 `dtime`, Recycle Bin `$I`                          |
| `executed`          | Program execution              | Prefetch last-run, SRUM                                 |
| `logged`            | Event logged                   | EVTX `SystemTime`, syslog line                          |
| `connected`         | Device/session connect         | USBSTOR, NetworkList                                    |
| `disconnected`      | Device/session disconnect      | udev, wtmp logout                                       |
| `created_key`       | Registry key creation          | Registry transaction logs                               |
| `last_write`        | Registry key last write        | Registry `nk` header                                    |
| `installed`         | Software install               | Package logs, Amcache                                   |
| `sent` / `received` | Network transfer               | Email headers, firewall logs                            |
| `boot` / `shutdown` | System power events            | EVTX 6005/6006, wtmp                                    |
| `inferred`          | Derived, not directly recorded | Filename parsing, sequence gaps                         |

A single artefact may produce multiple events with different `timestamp_type` values. That
is expected and desirable: NTFS `$MFT` alone yields four time types per record.

---

## 4. `action` vocabulary (controlled)

Grouped by `action_class`.

### file

`FILE_CREATE`, `FILE_WRITE`, `FILE_MODIFY`, `FILE_READ`, `FILE_ACCESS`, `FILE_DELETE`,
`FILE_RENAME`, `FILE_COPY`, `FILE_MOVE`, `FILE_COPY_TO_REMOVABLE`, `FILE_DOWNLOAD`,
`FILE_EXECUTE`, `FILE_TIMESTOMP`, `FILE_RECOVERED`, `FILE_ADS_CREATE`, `FILE_PERMISSION_CHANGE`

### process

`PROCESS_START`, `PROCESS_STOP`, `PROCESS_INJECT`, `PROCESS_ELEVATE`, `EXECUTION`,
`SCRIPT_BLOCK`, `SERVICE_INSTALL`, `SERVICE_START`, `SERVICE_STOP`, `DRIVER_LOAD`,
`SCHEDULED_TASK_CREATE`, `SCHEDULED_TASK_RUN`, `SCHEDULED_TASK_DELETE`

### network

`NETWORK_CONNECT`, `NETWORK_DISCONNECT`, `NETWORK_LISTEN`, `DNS_QUERY`, `HTTP_REQUEST`,
`SMB_CONNECT`, `RDP_CONNECT`, `VPN_CONNECT`, `FIREWALL_BLOCK`, `FIREWALL_ALLOW`

### auth

`LOGON_SUCCESS`, `LOGON_FAILURE`, `LOGOFF`, `ACCOUNT_CREATE`, `ACCOUNT_DELETE`,
`ACCOUNT_ENABLE`, `ACCOUNT_DISABLE`, `PASSWORD_CHANGE`, `PRIVILEGE_ESCALATION`,
`EXPLICIT_CREDENTIAL_USE`, `SESSION_LOCK`, `SESSION_UNLOCK`

### config

`REGISTRY_KEY_CREATE`, `REGISTRY_VALUE_SET`, `REGISTRY_KEY_DELETE`, `CONFIG_CHANGE`,
`POLICY_CHANGE`, `PERSISTENCE_INSTALL`, `PERSISTENCE_REMOVE`, `AUTOSTART_ADD`,
`AUTOSTART_REMOVE`

### system

`SYSTEM_BOOT`, `SYSTEM_SHUTDOWN`, `SYSTEM_SLEEP`, `SYSTEM_WAKE`, `LOG_CLEAR`,
`LOG_ROTATE`, `SHADOW_COPY_CREATE`, `SHADOW_COPY_DELETE`, `UPDATE_INSTALL`,
`TIME_CHANGE`, `TIMEZONE_CHANGE`, `AUDIT_POLICY_CHANGE`

### media

`USB_CONNECT`, `USB_DISCONNECT`, `DEVICE_MOUNT`, `DEVICE_UNMOUNT`, `MEDIA_INSERT`,
`MEDIA_EJECT`, `MOUNTED_VOLUME_CREATE`

### other

`ARTIFACT_PARSED`, `PARSE_WARNING`, `CORRELATION`, `NOTE`

Custom actions may be introduced by plugins but must be namespaced:
`X_MYPLUGIN_MYACTION`, and must declare `action_class = "other"` unless the core
maintainers promote them.

---

## 5. Object schemas

`object.type` determines the sub-schema.

### `file`

json

```
{
  "type": "file",
  "path": "C:\\Users\\alice\\report.docx",
  "path_norm": "c:/users/alice/report.docx",
  "size": 45213,
  "inode": 118472,
  "extension": "docx",
  "sha256": "…",
  "md5": "…",
  "volume": "C:",
  "volume_serial": "A1B2-C3D4",
  "zone_id": "3",
  "origin_url": "https://example.com/report.docx"
}
```

svgsvg

### `process`

json

```
{
  "type": "process",
  "path": "C:\\Windows\\System32\\cmd.exe",
  "pid": 4812,
  "ppid": 1204,
  "command_line": "cmd.exe /c whoami",
  "integrity": "Medium",
  "hashes": { "sha256": "…" },
  "signature": { "signed": true, "signer": "Microsoft Windows" }
}
```

svgsvg

### `registry_key`

json

```
{ "type": "registry_key", "hive": "SYSTEM", "path": "ControlSet001\\Services\\Foo", "value_name": "ImagePath", "value_data": "C:\\temp\\foo.exe" }
```

svgsvg

### `network_endpoint`

json

```
{ "type": "network_endpoint", "src_ip": "10.0.0.5", "src_port": 49812, "dst_ip": "203.0.113.9", "dst_port": 443, "protocol": "tcp", "hostname": "example.com" }
```

svgsvg

### `user_account`

json

```
{ "type": "user_account", "name": "alice", "sid": "S-1-5-21-…", "domain": "CORP", "logon_type": 10 }
```

svgsvg

### `device`

json

```
{ "type": "device", "vendor": "SanDisk", "product": "Cruzer", "serial": "4C530001…", "vid_pid": "0781:5567", "volume_serial": "…", "drive_letter": "E:" }
```

svgsvg

### `event_log_record`

json

```
{ "type": "event_log_record", "channel": "Security", "event_id": 4688, "provider": "Microsoft-Windows-Security-Auditing", "record_id": 991234 }
```

svgsvg

---

## 6. Deterministic `event_id`

python

```
CANONICAL_FIELDS = (
    "timestamp_utc", "timestamp_type", "action", "host", "user",
    "object.path", "source.artifact", "source.record_id", "source.record_offset",
)

def event_id(ev) -> uuid.UUID:
    payload = "\x1f".join(str(get_field(ev, f) or "") for f in CANONICAL_FIELDS)
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    return uuid.uuid5(NAMESPACE_CHRONOTRACE, digest.hex())
```

svgsvg

This guarantees:

- The same record parsed twice yields the same ID.
- IDs are stable across tool versions unless the canonical field set changes (which is a
  schema-major change).
- `corroborated_by` references remain valid over time.

---

## 7. Timezone normalization

Resolution order (configurable via `[normalize].tz_source_priority`):

1. **Explicit offset** in the source (`+02:00`, `Z`, epoch with known zone). Confidence 0.98.
2. **Registry** `TimeZoneInformation` from the source system's `SYSTEM` hive, combined
   with the artefact's absolute time to account for DST at that date. Confidence 0.92.
3. **Artefact-embedded zone** (e.g. EVTX `TimeCreated` with `TimeZoneInformation`,
   exFAT stored offset, email `Received` with offset). Confidence 0.90.
4. **UTC assumption.** Confidence 0.70, and a `TZ_ASSUMED_UTC` warning is attached.

Ambiguity handling:

- Non-existent local times (DST spring-forward gap) → shift forward by the gap and record
  `tz.ambiguous = "nonexistent"`.
- Ambiguous local times (fall-back overlap) → choose the **first** (pre-transition) offset
  and record `tz.ambiguous = "repeated"` with both candidates in `tz.candidates`.

Every event's `tz` block is preserved in output even when the output `--tz` differs, so a
reader can reconstruct the original local time.

---

## 8. Deduplication

Different artefacts frequently record the same activity (e.g. a file copy appears in
`$MFT`, `$UsnJrnl`, and a Shellbag). Deduplication modes:

| **Mode**           | **Rule**                                                                                                                                         |
| :----------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- |
| `off`              | Keep every event                                                                                                                                 |
| `strict` (default) | Merge events with identical `(timestamp_utc, action, object.path_norm, user)`; keep highest confidence; union `tags`; populate `corroborated_by` |
| `loose`            | As `strict`, but timestamps within `dedupe_window_s` (default 1 s) also merge                                                                    |

Deduplication **never discards provenance**: merged events list all contributing
`source` records in `corroborated_by`, and the discarded duplicates are written to
`derived/dedupe.jsonl` for audit.

---

## 9. Sorting and stability

The canonical sort key is `(timestamp_utc, event_id)` ascending. Because `event_id` is
content-derived, the sort is total and stable regardless of thread count, plugin order, or
filesystem iteration order. Descending output reverses the key but keeps the tiebreaker
consistent.

---

## 10. Filter expression language

`--filter` accepts a small, safe expression language (no `eval`).

text

```
action in (FILE_WRITE, FILE_DELETE)
  and user == "CORP\\alice"
  and object.path like "C:/Users/%"
  and timestamp_utc between "2024-03-01T00:00:00Z" and "2024-04-01T00:00:00Z"
  and confidence >= 0.7
  and "usb" in tags
```

svgsvg

Supported operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`, `like` (SQL `%`/`_`),
`between`, `and`, `or`, `not`, parentheses. Fields are the dotted paths of the event
schema. String comparison is case-sensitive; use `lower()` for case-insensitive matching.

---

## 11. SQL access

The SQLite index exposes a single `events` table with generated columns for the most
common fields plus a JSON column for the rest:

sql

```
CREATE TABLE events (
  event_id          TEXT PRIMARY KEY,
  timestamp_utc     TEXT NOT NULL,
  action            TEXT NOT NULL,
  action_class      TEXT,
  host              TEXT,
  user              TEXT,
  object_type       TEXT,
  object_path       TEXT,
  confidence        REAL,
  evidence_id       TEXT,
  plugin            TEXT,
  tags              TEXT,   -- JSON array
  event_json        TEXT NOT NULL
);
CREATE INDEX idx_events_ts      ON events(timestamp_utc);
CREATE INDEX idx_events_action  ON events(action);
CREATE INDEX idx_events_user    ON events(user);
CREATE INDEX idx_events_path    ON events(object_path);
CREATE VIRTUAL TABLE events_fts USING fts5(object_path, user, host, content='events', content_rowid='rowid');
```

svgsvg

Query with `chronotrace timeline query --sql "…"` or open `index/events.sqlite`
read-only in any SQLite client.

---

## 12. Schema versioning policy

- **Major** — field removed/renamed/retyped, `event_id` inputs changed, vocabulary
  values removed.
- **Minor** — new optional fields, new vocabulary values, new object types.
- **Patch** — documentation and confidence-default changes that do not alter structure.

Migration is handled by `chronotrace case migrate`. Old events are converted on read via
a registered migration function; the original JSON is preserved in
`derived/legacy/<schema_version>/`.

text
