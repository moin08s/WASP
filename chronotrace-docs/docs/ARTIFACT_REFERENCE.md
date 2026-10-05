# Artefact Reference

This document lists all supported artefacts, the plugin that parses them, the timestamps
available, and forensic notes. It documents ChronoTrace's coverage of two core project
specification objectives:

- **File metadata extraction** — filesystem metadata, embedded document properties (EXIF,
  XMP, PDF, OOXML/ODF), archive entry metadata, and media container timestamps.
- **System artefact extraction** — operating-system structures (MFT, registry, event logs,
  execution artefacts, browser databases, authentication logs, and more) that record
  system activity on Windows, Linux, and macOS.

All timestamps from every listed artefact feed directly into the **chronological
activity timeline reconstruction** stage.

Confidence values are defaults; they may be adjusted by config.

Legend for **Timestamp quality**:
`★★★` authoritative (explicit UTC/offset or monotonic sequence) ·
`★★` reliable with caveats ·
`★` inferred or easily manipulated.

---

## 1. Evidence containers

| Format | Plugin | Notes |
|---|---|---|
| Raw / dd | `container_raw` | No metadata; optional sidecar `.sha256` |
| E01 / EWF | `container_ewf` | Uses `libewf`; supports compression, segments, bad-sector maps |
| VHDX / VHD | `container_vhdx` | Uses `libvhdi` |
| VMDK | `container_vmdk` | Uses `libvmdk`; snapshot chain flattened read-only |
| QCOW2 | `container_qcow` | Uses `libqcow` |
| ISO 9660 / UDF | `container_iso` | Rock Ridge / Joliet extensions read |
| tar / zip / 7z | `container_archive` | Entry mtimes; zip-bomb limits enforced |
| Directory | `container_dir` | Direct filesystem walk; hashes computed per file |

---

## 2. Filesystem metadata

### 2.1 NTFS

| Artefact | Plugin | Timestamps | Notes |
|---|---|---|---|
| `$MFT` | `ntfs_mft` | SI: created/modified/accessed/entry-modified; FN: same | ★★ — `$SI` is user-settable (timestomping); `$FN` requires kernel-mode change and is more trustworthy. Plugin flags mismatches as `TIMESTOMP_SUSPECTED`. |
| `$UsnJrnl:$J` | `ntfs_usn` | USN reason timestamp | ★★★ — monotonic; gaps indicate journal deletion or wrapping. |
| `$LogFile` | `ntfs_logfile` | Transaction times | ★★★ — helps detect `$MFT` tampering. |
| `$Bitmap` | `ntfs_bitmap` | — | Allocation state for deleted-file analysis. |
| `$Secure:$SDS` | `ntfs_secure` | — | ACLs / ownership. |
| `$Extend/$ObjId` | `ntfs_objid` | — | Stable object identifiers for correlation. |
| `$Extend/$Reparse` | `ntfs_reparse` | — | Symlinks, junctions, mount points. |
| Alternate Data Streams | `ntfs_ads` | Per-stream SI/FN | Zone.Identifier reveals download origin. |
| Deleted file records | `ntfs_mft` | SI/FN | Recovery only if record not overwritten; confidence reduced. |

### 2.2 FAT / exFAT

| Artefact | Plugin | Timestamps | Notes |
|---|---|---|---|
| Directory entries | `fat_meta` | created / modified / accessed | ★ — 2-second precision on FAT; no timezone; DST bugs common. |
| exFAT entries | `exfat_meta` | created / modified / accessed | ★★ — 10 ms precision, UTC offset stored. |

### 2.3 ext2/3/4

| Artefact | Plugin | Timestamps | Notes |
|---|---|---|---|
| Inode table | `ext_inode` | atime / mtime / ctime / crtime / dtime | ★★★ — `ctime` is metadata-change time; `dtime` is deletion time. |
| ext4 journal | `ext_journal` | transaction times | ★★★ — can reveal pre-deletion metadata. |
| Extents | `ext_extents` | — | File layout and fragmentation. |

### 2.4 XFS / Btrfs / APFS / HFS+

| Artefact | Plugin | Notes |
|---|---|---|
| XFS inodes + log | `xfs_meta` | ★★; log replay is read-only and offline |
| Btrfs subvolumes + snapshots | `btrfs_meta` | Snapshot creation times are strong evidence |
| APFS inodes + snapshots | `apfs_meta` | ★★★ for snapshot `created` times |
| HFS+ catalog | `hfs_meta` | ★★; CNID-based provenance |

---

## 3. Windows artefacts

| Artefact | Typical path | Plugin | Timestamps | Quality | Forensic value |
|---|---|---|---|---|---|
| Registry hive | `Windows/System32/config/SYSTEM` etc. | `registry` | LastWriteTime per key | ★★ (with transaction log replay ★★★) | Configuration, persistence, USB history |
| `NTUSER.DAT` | `Users/<u>/NTUSER.DAT` | `registry` | LastWriteTime | ★★ | Per-user activity, TypedPaths, RunMRU |
| `UsrClass.dat` | `Users/<u>/AppData/Local/Microsoft/Windows/UsrClass.dat` | `registry` | LastWriteTime | ★★ | Shellbags, file dialog history |
| EVTX | `Windows/System32/winevt/Logs/*.evtx` | `evtx` | `SystemTime`, `TimeCreated` | ★★★ | Logons, process creation, service installs, log clearing |
| Prefetch | `Windows/Prefetch/*.pf` | `prefetch` | Last run times (up to 8) | ★★★ | Execution evidence |
| Amcache | `Windows/AppCompat/Programs/Amcache.hve` | `amcache` | Install/execute times | ★★ | Execution and first-seen |
| ShimCache / AppCompatCache | `SYSTEM` hive | `shimcache` | Last modified (Win8+) | ★★ | Execution (presence ≠ execution on older Windows) |
| SRUM | `Windows/System32/sru/SRUDB.dat` | `srum` | Hourly buckets | ★★ | Network/energy/app usage per process per hour |
| LNK | `Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` | `lnk` | Target created/accessed/modified; LNK file times | ★★ | File access, removable media, network shares |
| Jump Lists | `.../Recent/AutomaticDestinations/*.automaticDestinations-ms` | `jumplists` | DestList entry times | ★★ | Per-application recent files |
| Shellbags | `UsrClass.dat`, `NTUSER.DAT` | `shellbags` | BagMRU/Bags LastWriteTime | ★★ | Folder navigation, including deleted folders |
| Recycle Bin | `$Recycle.Bin/<SID>/$I*` | `recyclebin` | Deletion time | ★★★ | File deletion and original path |
| Scheduled Tasks | `Windows/System32/Tasks/**`, `Windows/System32/Tasks/*.job` | `scheduled_tasks` | Task creation, last run, next run | ★★★ | Persistence |
| PowerShell history | `Users/<u>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` | `powershell` | File mtime; no per-command time | ★ | Command history (unordered timing) |
| PowerShell transcripts | `Users/<u>/Documents/PowerShell_transcript*.txt` | `powershell` | Per-block start/end | ★★★ | Full command output with timing |
| PowerShell Operational log | EVTX `Microsoft-Windows-PowerShell/Operational` | `evtx` | Event time | ★★★ | Script block logging (4104) |
| WMI persistence | `Windows/System32/wbem/Repository/OBJECTS.DATA` | `wmiprov` | Class instance times | ★★ | Fileless persistence |
| BITS jobs | `ProgramData/Microsoft/Network/Downloader/qmgr*.dat` | `bits` | Job created/modified | ★★ | Download activity |
| Windows Search | `ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb` | `windows_search` | Index times | ★★ | File existence and access |
| Thumbcache | `Users/<u>/AppData/Local/Microsoft/Windows/Explorer/thumbcache_*.db` | `thumbcache` | Cache entry times | ★★ | Images viewed |
| IconCache | `Users/<u>/AppData/Local/IconCache.db` | `iconcache` | — | ★ | Application presence |
| ADS Zone.Identifier | any NTFS stream | `ntfs_ads` | — | ★★ | Mark-of-the-Web, download source |
| `$MFT` slack | | `ntfs_mft` | | ★ | Residual metadata (opt-in, slow) |
| Volume Shadow Copies | `System Volume Information/**` | `vss` | Snapshot creation | ★★★ | Historical filesystem states |
| Windows Defender logs | EVTX `Microsoft-Windows-Windows Defender/Operational` | `evtx` | Event time | ★★★ | Detections and quarantines |
| WER reports | `ProgramData/Microsoft/Windows/WER/**` | `wer` | Report time | ★★ | Crash and application data |
| RDP cache / bitmap | `Users/<u>/AppData/Local/Microsoft/Terminal Server Client/Cache` | `rdp_cache` | File times | ★★ | RDP session remnants |

### Registry keys of particular interest

| Key | Reveals |
|---|---|
| `SYSTEM\...\USBSTOR` | USB mass-storage devices ever connected |
| `SYSTEM\...\MountedDevices` | Drive letter ↔ volume mapping |
| `SYSTEM\...\Services` | Service installs and image paths |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Run*` | Autostart entries |
| `NTUSER.DAT\...\Explorer\RunMRU` | Run dialog history |
| `NTUSER.DAT\...\Explorer\TypedPaths` | Explorer address-bar history |
| `NTUSER.DAT\...\Explorer\RecentDocs` | Recently opened documents |
| `NTUSER.DAT\...\Explorer\UserAssist` | GUI program execution (ROT13-encoded) |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList` | Network profiles, first/last connected |
| `SYSTEM\...\TimeZoneInformation` | Host timezone at last boot (timezone resolution) |
| `SAM\...\Users` | Local accounts, last logon, password policy metadata |
| `SECURITY\...\AuditPolicy` | Audit configuration (relevant to log availability) |

---

## 4. Linux artefacts

| Artefact | Typical path | Plugin | Timestamps | Quality |
|---|---|---|---|---|
| `auth.log` / `secure` | `/var/log/auth.log`, `/var/log/secure` | `authlogs` | Per-line with offset | ★★★ |
| `syslog` / `messages` | `/var/log/syslog`, `/var/log/messages` | `syslogs` | Per-line | ★★★ |
| `journald` | `/var/log/journal/**/*.journal` | `journald` | Realtime + monotonic | ★★★ |
| `wtmp` / `btmp` / `lastlog` | `/var/log/wtmp` etc. | `wtmp` | Login/logout/boot records | ★★★ |
| Shell history | `~/.bash_history`, `~/.zsh_history` | `shell_history` | Optional per-command epoch (extended history) | ★★ |
| cron / at | `/etc/crontab`, `/var/spool/cron/**`, `/var/spool/at/**` | `cron` | File mtime; job times parsed | ★★ |
| systemd units | `/etc/systemd/system/**`, `/lib/systemd/system/**` | `systemd` | Unit file times; journal correlates | ★★ |
| auditd | `/var/log/audit/audit.log` | `auditd` | Per-record with sequence | ★★★ |
| Package logs | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`, `/var/log/dnf.log` | `pkglogs` | Per-transaction | ★★★ |
| `utmp` | `/var/run/utmp` | `utmp` | Active sessions | ★★ |
| `sudo` log | `/var/log/sudo.log` | `authlogs` | Per-invocation | ★★★ |
| `/etc/passwd`, `/etc/shadow` metadata | | `passwd_meta` | File mtime; password change epoch (shadow) | ★★ |
| SELinux / AppArmor logs | `/var/log/audit/**`, `/var/log/kern.log` | `auditd` | Per-record | ★★★ |
| Docker / container logs | `/var/lib/docker/containers/**/*-json.log` | `containerlogs` | Per-line | ★★★ |

---

## 5. macOS artefacts

| Artefact | Path | Plugin | Notes |
|---|---|---|---|
| Unified log | `/var/db/diagnostics/**/*.tracev3` | `unifiedlog` | ★★★; requires `timesync` for absolute times |
| `timesync` | `/var/db/diagnostics/timesync/*.timesync` | `unifiedlog` | Boot/sleep/wake clock correlation |
| FSEvents | `/.fseventsd/**` | `fsevents` | ★★; coarse-grained, aggregated |
| Quarantine events | `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` | `quarantine` | ★★★; download source URL |
| Plists | `~/Library/Preferences/**/*.plist` | `plists` | ★★; binary and XML plists |
| launchd | `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `~/Library/LaunchAgents` | `launchd` | ★★; persistence |
| Spotlight metadata | `.Spotlight-V100/**` | `spotlight` | ★; file existence |
| Keychain metadata | `~/Library/Keychains/**` | `keychain_meta` | Metadata only; no secret extraction |
| Safari history | `~/Library/Safari/History.db` | `browser` | ★★★ |
| KnowledgeC | `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` | `knowledgec` | ★★★; app/device usage |
| Unified logs for auth | `com.apple.securityd`, `authd` subsystems | `unifiedlog` | ★★★ |

---

## 6. Cross-cutting file metadata

| Type | Plugin | Extracted |
|---|---|---|
| JPEG/TIFF/RAW | `exif` | `DateTimeOriginal`, `CreateDate`, `ModifyDate`, GPS, camera make/model, serial |
| PNG | `png_meta` | `tEXt`/`iTXt`/`zTXt` chunks, `tIME` |
| PDF | `pdf_meta` | `Info` dict (`CreationDate`, `ModDate`, `Author`, `Producer`), XMP, incremental-update history |
| OOXML (docx/xlsx/pptx) | `ooxml_meta` | `docProps/core.xml` (`created`, `modified`, `lastModifiedBy`), `app.xml` |
| ODF | `odf_meta` | `meta.xml` (`creation-date`, `date`, `editing-cycles`) |
| MP4 / MOV | `mp4_meta` | `mvhd` creation/modification, `udta` |
| AVI / MKV | `av_meta` | Container creation date |
| ZIP / GZIP / TAR | `archive_meta` | Entry mtimes, original paths, comment fields |
| Email (EML/MSG) | `email_meta` | `Date`, `Received` chain, `Message-ID`, attachments |
| SQLite databases | `sqlite_meta` | Table-level timestamps, WAL/freelist remnants |
| ESE databases | `ese_meta` | Page-level metadata, long values |
| Windows shortcut internals | `lnk` | MAC times of target, volume serial, NetBIOS name |

---

## 7. Confidence model

| Situation | Default confidence |
|---|---|
| Explicit UTC timestamp in a structured record | 0.99 |
| Timestamp with explicit offset, converted to UTC | 0.98 |
| Timestamp localized via registry `TimeZoneInformation` | 0.92 |
| Timestamp localized via artifact-embedded zone | 0.90 |
| Timestamp assumed UTC (no zone info anywhere) | 0.70 |
| FAT timestamp (2 s precision, no zone) | 0.60 |
| Registry `LastWriteTime` without transaction log replay | 0.85 |
| Registry `LastWriteTime` with transaction log replay | 0.97 |
| Inferred timestamp (e.g. log line without a year) | 0.50 |
| Carved / deleted record with possible overwrite | 0.40–0.70 |
| Filename-derived timestamp (e.g. `20240311_021407.jpg`) | 0.30 |

Confidence is stored per event and surfaced in reports. Investigators should treat
`confidence < 0.7` events as corroborative, not primary, evidence.

---

## 8. Unsupported / out of scope

* Live memory acquisition and memory forensics (a separate, complementary discipline).
* Full-disk encryption key recovery or brute force.
* Network packet capture analysis.
* Mobile device filesystems (iOS/Android) — partially supported via extracted
  filesystem images only; no native acquisition.
* Cloud-native audit logs — adapters exist in the `[cloud]` extra but are not part of the
  core artefact set.
* Steganography detection.
