"""Real-time USB and external storage device hotplug monitoring engine."""

from __future__ import annotations
import platform
import threading
import time
from typing import Callable, Dict, Generator, List, Optional, Set
from chronotrace.acquire.devices import DeviceManager, StorageDevice


class HotplugWatcher:
    """
    Monitors external and removable storage device connections/disconnections
    in real-time and triggers forensic callbacks.
    """

    def __init__(
        self,
        poll_interval: float = 1.5,
        on_connected: Optional[Callable[[StorageDevice], None]] = None,
        on_disconnected: Optional[Callable[[StorageDevice], None]] = None,
    ):
        self.poll_interval = poll_interval
        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._known_devices: Dict[str, StorageDevice] = {}

    @property
    def is_running(self) -> bool:
        return self._running

    def _device_key(self, dev: StorageDevice) -> str:
        """Derive a stable unique key for comparing devices."""
        return dev.serial_number or dev.mount_point or dev.device_id

    def snapshot(self) -> Dict[str, StorageDevice]:
        """Fetch current devices mapped by unique key."""
        devices = DeviceManager.list_devices()
        return {self._device_key(d): d for d in devices}

    def start(self) -> None:
        """Start the background hotplug monitoring thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            # Establish baseline snapshot
            try:
                self._known_devices = self.snapshot()
            except Exception:
                self._known_devices = {}

            self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ChronoTrace-HotplugWatcher")
            self._thread.start()

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _monitor_loop(self) -> None:
        """Internal polling loop checking for device delta."""
        while self._running:
            time.sleep(self.poll_interval)
            if not self._running:
                break

            try:
                current_devices = self.snapshot()
                old_keys = set(self._known_devices.keys())
                new_keys = set(current_devices.keys())

                # Check connected devices
                added_keys = new_keys - old_keys
                for k in added_keys:
                    dev = current_devices[k]
                    if self.on_connected:
                        try:
                            self.on_connected(dev)
                        except Exception:
                            pass

                # Check disconnected devices
                removed_keys = old_keys - new_keys
                for k in removed_keys:
                    dev = self._known_devices[k]
                    if self.on_disconnected:
                        try:
                            self.on_disconnected(dev)
                        except Exception:
                            pass

                self._known_devices = current_devices
            except Exception:
                pass

    def watch(
        self, timeout: Optional[float] = None, interval: float = 1.5
    ) -> Generator[tuple[str, StorageDevice], None, None]:
        """
        Synchronous generator yielding ('connected'|'disconnected', StorageDevice) tuples.
        Useful for CLI real-time monitoring.
        """
        known = self.snapshot()
        start_time = time.time()

        while True:
            if timeout is not None and (time.time() - start_time) >= timeout:
                break
            time.sleep(interval)
            try:
                current = self.snapshot()
                old_keys = set(known.keys())
                new_keys = set(current.keys())

                for k in new_keys - old_keys:
                    yield ("connected", current[k])
                for k in old_keys - new_keys:
                    yield ("disconnected", known[k])

                known = current
            except Exception:
                pass
