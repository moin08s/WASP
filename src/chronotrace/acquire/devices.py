"""External storage device discovery and forensic acquisition."""

from __future__ import annotations
import ctypes
import json
import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from chronotrace.acquire.hasher import Hasher
from chronotrace.core.case import Case
from chronotrace.core.errors import EvidenceCorruptError


class StorageDevice(BaseModel):
    """Represents a physical or removable storage device."""
    device_id: str                      # e.g. "\\\\.\\PHYSICALDRIVE1" or "E:" or "/dev/sdb"
    model: str = "Unknown Storage Device"
    interface_type: str = "Unknown"     # e.g. "USB", "SCSI", "NVMe"
    media_type: str = "Removable"       # e.g. "Removable Media", "Fixed hard disk"
    size_bytes: int = 0
    size_display: str = "0 MB"
    serial_number: Optional[str] = None
    mount_point: Optional[str] = None   # e.g. "E:\\" or "/media/usb"
    file_system: Optional[str] = None   # e.g. "NTFS", "FAT32", "exFAT"
    volume_name: Optional[str] = None
    is_removable: bool = True
    is_system_drive: bool = False


class DeviceManager:
    """Discovers external/removable storage devices and drives across platforms."""

    @staticmethod
    def list_devices() -> List[StorageDevice]:
        """Enumerate connected external, removable, and secondary storage drives."""
        system = platform.system().lower()
        if "windows" in system:
            return DeviceManager._list_windows_devices()
        elif "linux" in system:
            return DeviceManager._list_linux_devices()
        elif "darwin" in system:
            return DeviceManager._list_macos_devices()
        return DeviceManager._fallback_list_drives()

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format bytes into human-readable string."""
        if size_bytes <= 0:
            return "0 B"
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0 or unit == "TB":
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    @staticmethod
    def _list_windows_devices() -> List[StorageDevice]:
        """Query connected disks and logical drives on Windows using CIM/PowerShell & ctypes."""
        devices: List[StorageDevice] = []
        system_drive = os.environ.get("SystemDrive", "C:").upper()

        # 1. Query logical drives
        logical_map: Dict[str, Dict[str, Any]] = {}
        try:
            ps_cmd = (
                "Get-CimInstance Win32_LogicalDisk | "
                "Select-Object DeviceID, DriveType, VolumeName, FileSystem, Size, FreeSpace, VolumeSerialNumber | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for ld in data:
                    did = ld.get("DeviceID", "").upper()
                    logical_map[did] = ld
        except Exception:
            pass

        # 2. Query physical disk drives (to identify USB/external drives and models)
        try:
            ps_cmd = (
                "Get-CimInstance Win32_DiskDrive | "
                "Select-Object DeviceID, Model, InterfaceType, MediaType, Size, SerialNumber | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                if isinstance(data, dict):
                    data = [data]
                for dd in data:
                    dev_id = dd.get("DeviceID", "")
                    size = int(dd.get("Size") or 0)
                    model = (dd.get("Model") or "Generic Disk").strip()
                    iface = (dd.get("InterfaceType") or "USB").strip()
                    mtype = (dd.get("MediaType") or "External").strip()
                    sn = (dd.get("SerialNumber") or "").strip() or None

                    is_removable = (
                        "usb" in iface.lower()
                        or "removable" in mtype.lower()
                        or "external" in mtype.lower()
                    )

                    devices.append(
                        StorageDevice(
                            device_id=dev_id,
                            model=model,
                            interface_type=iface,
                            media_type=mtype,
                            size_bytes=size,
                            size_display=DeviceManager._format_size(size),
                            serial_number=sn,
                            is_removable=is_removable,
                            is_system_drive=False,
                        )
                    )
        except Exception:
            pass

        # 3. Add logical volumes with drive letters (e.g. D:, E:, F:)
        for drive_letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            root_path = f"{drive_letter}:\\"
            if os.path.exists(root_path):
                # DriveType: 2 = DRIVE_REMOVABLE, 3 = DRIVE_FIXED, 4 = DRIVE_REMOTE, 5 = DRIVE_CDROM
                drive_type_val = 3
                if hasattr(ctypes, "windll"):
                    try:
                        drive_type_val = ctypes.windll.kernel32.GetDriveTypeW(root_path)
                    except Exception:
                        pass

                is_sys = (f"{drive_letter}:" == system_drive)
                is_removable = (drive_type_val == 2) or (not is_sys and drive_type_val in (2, 5))

                ld_info = logical_map.get(f"{drive_letter}:", {})
                size = int(ld_info.get("Size") or 0)
                vol_name = ld_info.get("VolumeName") or f"Volume ({drive_letter}:)"
                fs_name = ld_info.get("FileSystem") or "Unknown"
                sn = ld_info.get("VolumeSerialNumber")

                type_desc = "Removable USB Drive" if drive_type_val == 2 else ("CD/DVD Drive" if drive_type_val == 5 else "Fixed Disk Volume")

                devices.append(
                    StorageDevice(
                        device_id=f"{drive_letter}:",
                        model=f"{vol_name} [{drive_letter}:]",
                        interface_type="Logical Volume",
                        media_type=type_desc,
                        size_bytes=size,
                        size_display=DeviceManager._format_size(size),
                        serial_number=sn,
                        mount_point=root_path,
                        file_system=fs_name,
                        volume_name=vol_name,
                        is_removable=is_removable,
                        is_system_drive=is_sys,
                    )
                )

        return devices

    @staticmethod
    def _list_linux_devices() -> List[StorageDevice]:
        """Query storage devices on Linux via lsblk."""
        devices: List[StorageDevice] = []
        try:
            res = subprocess.run(
                ["lsblk", "-J", "-b", "-o", "NAME,MODEL,SIZE,TRAN,RM,MOUNTPOINTS,FSTYPE,SERIAL"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                data = json.loads(res.stdout)
                for blk in data.get("blockdevices", []):
                    name = f"/dev/{blk.get('NAME')}"
                    size = int(blk.get("SIZE") or 0)
                    model = blk.get("MODEL") or "Linux Block Device"
                    tran = blk.get("TRAN") or "SCSI"
                    rm = bool(blk.get("RM"))
                    sn = blk.get("SERIAL")
                    mounts = blk.get("MOUNTPOINTS", [])
                    mp = mounts[0] if mounts else None

                    devices.append(
                        StorageDevice(
                            device_id=name,
                            model=model,
                            interface_type=tran.upper(),
                            media_type="Removable" if rm or tran == "usb" else "Fixed Disk",
                            size_bytes=size,
                            size_display=DeviceManager._format_size(size),
                            serial_number=sn,
                            mount_point=mp,
                            file_system=blk.get("FSTYPE"),
                            is_removable=rm or (tran == "usb"),
                            is_system_drive=(mp == "/" or mp == "/boot"),
                        )
                    )
        except Exception:
            pass
        return devices

    @staticmethod
    def _list_macos_devices() -> List[StorageDevice]:
        """Query storage devices on macOS via diskutil."""
        devices: List[StorageDevice] = []
        try:
            res = subprocess.run(["diskutil", "list"], capture_output=True, text=True, timeout=5)
            for line in res.stdout.splitlines():
                if line.startswith("/dev/disk"):
                    parts = line.split()
                    dev_id = parts[0]
                    devices.append(
                        StorageDevice(
                            device_id=dev_id,
                            model=f"macOS Disk {dev_id}",
                            interface_type="External",
                            media_type="Disk",
                            size_bytes=0,
                            size_display="External",
                            is_removable=True,
                        )
                    )
        except Exception:
            pass
        return devices

    @staticmethod
    def _fallback_list_drives() -> List[StorageDevice]:
        """Fallback drive scanner."""
        devices: List[StorageDevice] = []
        for d in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            p = f"{d}:\\"
            if os.path.exists(p):
                devices.append(
                    StorageDevice(
                        device_id=f"{d}:",
                        model=f"Drive {d}:",
                        mount_point=p,
                        is_removable=(d not in ("C", "D")),
                        is_system_drive=(d == "C"),
                    )
                )
        return devices

    @staticmethod
    def acquire_device(
        device: StorageDevice,
        case: Case,
        output_filename: Optional[str] = None,
        notes: str = "",
        evidence_id: Optional[str] = None,
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Acquire forensic evidence from an external device or mounted drive.
        Computes streaming SHA-256 and writes sidecar hash and custody entry.
        """
        ev_id = evidence_id or f"EV-DEV-{device.device_id.replace(':', '').replace('/', '_').replace('\\', '')[:8].upper()}"
        out_name = output_filename or f"device_{device.device_id.replace(':', '').replace('/', '_').replace('\\', '')}.raw"

        # If device has a mount point (e.g. E:\), we can acquire directory or files
        if device.mount_point and os.path.exists(device.mount_point):
            mount_path = Path(device.mount_point)
            # If output is specified as archive .tar
            if out_name.endswith(".tar"):
                return case.acquire(
                    source=mount_path,
                    archive_name=out_name,
                    evidence_id=ev_id,
                    notes=f"Forensic acquisition of device {device.model} ({device.device_id}) [SN: {device.serial_number}]. {notes}",
                )
            else:
                # Direct folder or file acquisition
                archive_name = out_name if out_name.endswith((".tar", ".zip")) else f"{out_name}.tar"
                return case.acquire(
                    source=mount_path,
                    archive_name=archive_name,
                    evidence_id=ev_id,
                    notes=f"Forensic acquisition of external drive {device.model} ({device.device_id}) [SN: {device.serial_number}]. {notes}",
                )
        else:
            # Physical drive acquisition or path
            target_path = Path(device.device_id)
            if target_path.exists():
                return case.acquire(
                    source=target_path,
                    output_filename=out_name,
                    evidence_id=ev_id,
                    notes=f"Physical device acquisition of {device.device_id}. {notes}",
                )
            else:
                raise FileNotFoundError(f"Device target not accessible: {device.device_id}")
