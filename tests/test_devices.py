"""Unit tests for external device discovery and acquisition."""

from pathlib import Path
from chronotrace.acquire.devices import DeviceManager, StorageDevice
from chronotrace.core.case import Case


def test_device_discovery():
    """Verify device enumeration returns valid StorageDevice instances."""
    devices = DeviceManager.list_devices()
    assert isinstance(devices, list)
    assert len(devices) > 0

    for dev in devices:
        assert isinstance(dev, StorageDevice)
        assert dev.device_id
        assert dev.size_display


def test_device_acquisition(tmp_path: Path):
    """Verify acquiring from a mounted storage device/volume."""
    case_dir = tmp_path / "CASE-DEVICE-TEST"
    case = Case.create(
        case_id="CASE-DEVICE-TEST",
        out_dir=case_dir,
        examiner="Analyst Device",
    )

    # Mock an external USB drive mount
    mock_usb = tmp_path / "mock_usb_drive"
    mock_usb.mkdir()
    (mock_usb / "evidence.txt").write_text("CONFIDENTIAL EXFILTRATED DATA", encoding="utf-8")

    device = StorageDevice(
        device_id="E:",
        model="SanDisk Ultra USB 3.0",
        mount_point=str(mock_usb),
        is_removable=True,
        serial_number="USB_SERIAL_123456",
    )

    res = DeviceManager.acquire_device(
        device=device,
        case=case,
        output_filename="usb_dump.tar",
        notes="Seized USB thumb drive",
    )

    assert res["verification"] == "match"
    assert "sha256" in res["hashes"]
    assert (case.evidence_dir / "usb_dump.tar").exists()
    assert (case.evidence_dir / "usb_dump.tar.sha256").exists()

    # Verify custody ledger entry
    entries = case.ledger.get_entries()
    acq_entry = [e for e in entries if e["event_type"] == "evidence_acquired"][0]
    assert "SanDisk Ultra USB" in acq_entry["payload"]["notes"]
