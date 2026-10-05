"""Tests for Real-time USB / External Storage Hotplug Watcher."""

import time
from unittest.mock import patch
from chronotrace.acquire.devices import StorageDevice
from chronotrace.acquire.hotplug import HotplugWatcher


def test_hotplug_detection_callbacks():
    """Verify that connect and disconnect events invoke registered callbacks."""
    dev1 = StorageDevice(device_id="E:", model="SanDisk Ultra USB", mount_point="E:\\", serial_number="SN123")
    dev2 = StorageDevice(device_id="F:", model="Kingston DataTraveler", mount_point="F:\\", serial_number="SN456")

    connected = []
    disconnected = []

    watcher = HotplugWatcher(
        poll_interval=0.05,
        on_connected=lambda d: connected.append(d),
        on_disconnected=lambda d: disconnected.append(d),
    )

    # Initial state: dev1 plugged in
    with patch("chronotrace.acquire.hotplug.DeviceManager.list_devices", return_value=[dev1]):
        watcher.start()
        time.sleep(0.1)

    assert watcher.is_running

    # State 2: dev2 plugged in as well
    with patch("chronotrace.acquire.hotplug.DeviceManager.list_devices", return_value=[dev1, dev2]):
        time.sleep(0.15)

    assert len(connected) == 1
    assert connected[0].serial_number == "SN456"

    # State 3: dev1 unplugged
    with patch("chronotrace.acquire.hotplug.DeviceManager.list_devices", return_value=[dev2]):
        time.sleep(0.15)

    assert len(disconnected) == 1
    assert disconnected[0].serial_number == "SN123"

    watcher.stop()
    assert not watcher.is_running
