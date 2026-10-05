"""Unit tests for individual artefact plugins."""

import datetime
import io
import sqlite3
import struct
import zipfile
from pathlib import Path
from chronotrace.artifacts.browser import BrowserPlugin
from chronotrace.artifacts.evtx import EvtxPlugin
from chronotrace.artifacts.lnk import LnkPlugin
from chronotrace.artifacts.logs import LogsPlugin
from chronotrace.artifacts.ntfs_mft import NtfsMftPlugin
from chronotrace.artifacts.prefetch import PrefetchPlugin
from chronotrace.artifacts.registry import RegistryPlugin
from chronotrace.extract.file_metadata import FileMetadataPlugin
from chronotrace.ingest.evidence_view import EvidenceView


def test_file_metadata_plugin_zip(tmp_path: Path):
    """Verify zip entry extraction by FileMetadataPlugin."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    zip_path = case_dir / "test.zip"

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("secret.txt", "confidential content")

    manifest_evidence = [{
        "evidence_id": "EV-01",
        "path": "test.zip",
        "hashes": {"sha256": "dummy"},
    }]
    ev_view = EvidenceView(case_dir, manifest_evidence)
    plugin = FileMetadataPlugin()
    events = list(plugin.parse(ev_view))

    assert len(events) >= 1
    zip_entries = [e for e in events if "secret.txt" in (e.object.path or "")]
    assert len(zip_entries) == 1
    assert zip_entries[0].action == "FILE_WRITE"


def test_ntfs_mft_timestomp_detection(tmp_path: Path):
    """Verify timestomp detection logic in NtfsMftPlugin."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    mft_path = case_dir / "sample.mft"

    # Construct synthetic 1024-byte MFT record with FILE magic
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    # Offset of first attribute = 0x38 (56)
    struct.pack_into("<H", rec, 0x14, 56)
    # Record number = 100
    struct.pack_into("<I", rec, 0x2C, 100)

    # Attribute 1: $STANDARD_INFORMATION (0x10), len 96
    # offset 56: attr_type=0x10, attr_len=96, content_offset=24
    struct.pack_into("<II", rec, 56, 0x10, 96)
    struct.pack_into("<H", rec, 56 + 0x14, 24)
    # Standard info timestamps: modified is backdated (1000)
    # offset 56 + 24 = 80: c, m, mft, a
    # 100-ns FILETIMEs: m = 116444736000000000 (1970), fn_m = 133500000000000000 (2024)
    struct.pack_into("<QQQQ", rec, 80, 133500000000000000, 116444736000000000, 133500000000000000, 133500000000000000)

    # Attribute 2: $FILE_NAME (0x30), offset 152, len 120, content_offset=24
    struct.pack_into("<II", rec, 152, 0x30, 120)
    struct.pack_into("<H", rec, 152 + 0x14, 24)
    # offset 152 + 24 = 176: parent_ref(8), c, m, mft, a, ...
    struct.pack_into("<QQQQ", rec, 176 + 8, 133500000000000000, 133500000000000000, 133500000000000000, 133500000000000000)
    # filename length at 176 + 64 = 240: 8 chars
    rec[176 + 64] = 8
    test_fn = "cmd.exe\x00".encode("utf-16le")
    rec[176 + 66 : 176 + 66 + len(test_fn)] = test_fn

    # End marker attribute
    struct.pack_into("<I", rec, 152 + 120, 0xFFFFFFFF)

    mft_path.write_bytes(rec)

    manifest_evidence = [{
        "evidence_id": "EV-01",
        "path": "sample.mft",
        "hashes": {"sha256": "dummy"},
    }]
    ev_view = EvidenceView(case_dir, manifest_evidence)
    plugin = NtfsMftPlugin()
    events = list(plugin.parse(ev_view))

    # Should detect TIMESTOMP_SUSPECTED
    timestomp_events = [e for e in events if "TIMESTOMP_SUSPECTED" in e.tags]
    assert len(timestomp_events) >= 1
    assert timestomp_events[0].action == "FILE_TIMESTOMP"


def test_browser_plugin_sqlite(tmp_path: Path):
    """Verify Chromium history extraction."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    db_path = case_dir / "History"

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)")
    # Chromium epoch time for 2024-01-01
    cur.execute("INSERT INTO urls VALUES (1, 'https://example.com/login', 'Example Login', 3, 13348579200000000)")
    conn.commit()
    conn.close()

    manifest_evidence = [{
        "evidence_id": "EV-01",
        "path": "History",
        "hashes": {"sha256": "dummy"},
    }]
    ev_view = EvidenceView(case_dir, manifest_evidence)
    plugin = BrowserPlugin()
    events = list(plugin.parse(ev_view))

    assert len(events) == 1
    assert events[0].action == "WEB_VISIT"
    assert events[0].object.path == "https://example.com/login"
