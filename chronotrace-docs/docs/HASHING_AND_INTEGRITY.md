# Hashing and Integrity

## 1. Goals

ChronoTrace fulfils the **SHA-256 evidence integrity** objective of the project
specification through the following guarantees:

1. Prove that the evidence examined is the evidence acquired — every evidence object
   receives a mandatory SHA-256 hash computed during acquisition.
2. Prove that derived artefacts and reports have not been altered since generation —
   every file in `derived/`, `index/`, and `reports/` is individually hashed.
3. Provide a defensible, auditable chain of custody — an append-only, hash-chained
   ledger records every significant case action.
4. Detect tool bugs and hardware faults that corrupt data silently — `chronotrace verify`
   re-hashes and replays the entire ledger on demand.

---

## 2. Hash algorithms

| Algorithm | Role | Notes |
|---|---|---|
| **SHA-256** | Primary, mandatory | Computed for every evidence object and every derived artefact. Cannot be disabled. |
| BLAKE3 | Optional, secondary | Faster; used for internal dedupe and integrity checks; not a substitute for SHA-256. |
| SHA-1 | Optional, legacy | Only for cross-checking against historical manifests (e.g. old `sha1sum` files). Marked `legacy: true` in output. |
| MD5 | Optional, legacy | Same caveat; included only when explicitly requested for compatibility with an existing case. |

**SHA-256 is always computed.** `--hash sha1` does not replace SHA-256; it adds SHA-1.
Reports clearly distinguish `primary` from `legacy` hashes.

Hashing is streaming (constant memory) with a 8 MiB buffer, `O_DIRECT` where supported.

---

## 3. What gets hashed

| Object | Hash recorded in | Purpose |
|---|---|---|
| Evidence image (whole) | `manifest.json`, `evidence/<name>.sha256`, ledger | Prove evidence integrity |
| Each evidence segment (E01 split) | `manifest.json` | Detect single-segment corruption |
| Bad-sector map | `manifest.json` | Document read errors |
| Each derived artefact file (`derived/*.jsonl`, `derived/*.parquet`) | `manifest.json` | Prove extracted data integrity |
| Timeline store (`index/events.parquet`, `index/events.sqlite`) | `manifest.json` | Prove timeline integrity |
| Each report file | `manifest.json`, ledger | Prove report integrity |
| Case config (`config.effective.toml`) | `manifest.json` | Reproducibility: prove the exact settings used |
| Plugin set + versions | `manifest.json` | Reproducibility: prove which parsers ran |
| Selected file *contents* (opt-in via `--hash-files`) | `derived/file_hashes.jsonl` | Known-file / NSRL matching, malware identification |

`manifest.json` is itself hashed and its hash is entered into the ledger.

---

## 4. `manifest.json`

```json
{
  "manifest_version": "1.1.0",
  "case_id": "CASE-2024-0117",
  "created_utc": "2024-01-17T14:02:11Z",
  "tool": { "name": "chronotrace", "version": "1.3.0" },
  "schema_version": "2.0.0",

  "evidence": [
    {
      "evidence_id": "EV-0001",
      "path": "evidence/disk0.E01",
      "container": "ewf",
      "size_bytes": 500107862016,
      "acquired_utc": "2024-01-17T13:10:02Z",
      "source": "/dev/sdb",
      "source_model": "Samsung SSD 870 EVO 1TB",
      "source_serial": "S5Y2NG0R123456",
      "read_errors": 0,
      "bad_sector_map": null,
      "hashes": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "blake3": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "sha1":   { "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "legacy": true }
      },
      "segments": [
        { "path": "evidence/disk0.E01", "sha256": "…" },
        { "path": "evidence/disk0.E02", "sha256": "…" }
      ],
      "verification": { "method": "readback", "verified_utc": "2024-01-17T14:01:58Z", "result": "match" }
    }
  ],

  "derived": [
    { "path": "derived/mft.jsonl",     "size_bytes": 8123456789, "sha256": "…", "plugin": "ntfs_mft",  "plugin_version": "1.4.2" },
    { "path": "derived/evtx.jsonl",    "size_bytes": 1234567890, "sha256": "…", "plugin": "evtx",      "plugin_version": "2.1.0" },
    { "path": "derived/registry.jsonl","size_bytes":  987654321, "sha256": "…", "plugin": "registry",  "plugin_version": "1.9.3" }
  ],

  "index": [
    { "path": "index/events.parquet", "size_bytes": 4567890123, "sha256": "…" },
    { "path": "index/events.sqlite",  "size_bytes":  789012345, "sha256": "…" }
  ],

  "reports": [
    { "path": "reports/CASE-2024-0117_full.html", "sha256": "…" },
    { "path": "reports/CASE-2024-0117_full.pdf",  "sha256": "…" }
  ],

  "config": {
    "path": "config.effective.toml",
    "sha256": "…"
  },

  "plugins": [
    { "name": "ntfs_mft", "version": "1.4.2", "sha256": "…" },
    { "name": "evtx",     "version": "2.1.0", "sha256": "…" }
  ],

  "merkle_root": {
    "algorithm": "sha256",
    "leaf_order": "sorted_path",
    "root": "5f2c…",
    "leaf_count": 42
  },

  "manifest_sha256": "9a1b…"
}
````

svgsvg

`manifest_sha256` is the SHA-256 of the manifest with the `manifest_sha256` field set to
`null`. This self-hash is what gets chained into the ledger.

---

## 5. Chain-of-custody ledger

`custody/ledger.jsonl` is an append-only, hash-chained log. Each line is one JSON object;
each object contains the hash of the previous line, forming a tamper-evident chain.

json

```
{"seq":0,"ts_utc":"2024-01-17T13:05:00Z","actor":"A. Analyst","event":"CASE_CREATED","case_id":"CASE-2024-0117","prev_hash":null,"payload":{...},"hash":"1a2b…"}
{"seq":1,"ts_utc":"2024-01-17T13:10:02Z","actor":"A. Analyst","event":"EVIDENCE_ACQUIRED","evidence_id":"EV-0001","prev_hash":"1a2b…","payload":{"sha256":"e3b0…","size_bytes":500107862016},"hash":"3c4d…"}
{"seq":2,"ts_utc":"2024-01-17T14:02:11Z","actor":"A. Analyst","event":"MANIFEST_WRITTEN","prev_hash":"3c4d…","payload":{"manifest_sha256":"9a1b…"},"hash":"5e6f…"}
```

svgsvg

### 5.1 Record fields

| **Field**   | **Description**                                                                                                                                                                                                                                |
| :---------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seq`       | Monotonically increasing integer starting at 0                                                                                                                                                                                                 |
| `ts_utc`    | UTC time the action was recorded                                                                                                                                                                                                               |
| `actor`     | Examiner identity from the case file or `--actor`                                                                                                                                                                                              |
| `event`     | One of: `CASE_CREATED`, `CASE_OPENED`, `EVIDENCE_ACQUIRED`, `EVIDENCE_VERIFIED`, `INGEST_COMPLETE`, `EXTRACT_COMPLETE`, `TIMELINE_BUILT`, `MANIFEST_WRITTEN`, `REPORT_GENERATED`, `CASE_EXPORTED`, `NOTE`, `CUSTODY_TRANSFER`, `LEDGER_SEALED` |
| `prev_hash` | `hash` of the previous record; `null` for seq 0                                                                                                                                                                                                |
| `payload`   | Event-specific data                                                                                                                                                                                                                            |
| `hash`      | `sha256(canonical_json(record_without_hash))`                                                                                                                                                                                                  |
| `hmac`      | Optional HMAC-SHA256 over `hash` using the examiner key                                                                                                                                                                                        |

### 5.2 Hash computation

python

```
def record_hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k not in ("hash", "hmac")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
```

svgsvg

### 5.3 HMAC signing

If `CHRONOTRACE_LEDGER_HMAC_KEY`, `..._KEY_FILE`, or `..._KMS_URI` is set, each record's
`hash` is HMAC-SHA256'd and stored as `hmac`. This provides authenticity (the examiner
produced it) in addition to integrity (nobody altered it). Without a key, the chain is
tamper-*evident* but not tamper-*proof*: an attacker who rewrites the whole chain can
produce a self-consistent ledger, which is why external timestamping is recommended.

### 5.4 External timestamping

`[integrity].rfc3161_tsa_url` enables RFC 3161 timestamping of each ledger `hash` (or of
the Merkle root at seal time). The returned TSR is stored in `custody/timestamps/`. This
anchors the ledger to a trusted clock.

### 5.5 Sealing

bash

```
chronotrace verify --case ./CASE-2024-0117 --seal --note "Examination complete"
```

svgsvg

Sealing appends a `LEDGER_SEALED` record containing the Merkle root of all derived
artefacts and the current chain head. After sealing, no further records may be appended
without breaking the seal; a new seal must be created with an explanatory note.

---

## 6. Merkle tree over derived artefacts

A Merkle tree provides a compact, verifiable commitment to the entire derived dataset.

- **Leaves:** `sha256(path || "\0" || file_sha256)` for each file under `derived/`,
  `index/`, and `reports/`.
- **Leaf order:** lexicographic by case-relative path (`sorted_path`), or insertion order
  (`insertion`) if configured.
- **Internal nodes:** `sha256(left || right)`.
- **Odd leaf:** promoted unchanged (Bitcoin-style) or hashed with itself (RFC 6962-style);
  ChronoTrace uses RFC 6962 domain separation:

text

```
leaf_hash = sha256(0x00 || data)
node_hash = sha256(0x01 || left || right)
