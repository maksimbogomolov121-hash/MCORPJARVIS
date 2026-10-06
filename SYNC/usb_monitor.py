# -*- coding: utf-8 -*-

"""
JARVIS V11
USB Monitor v1.1

Назначение:
    Автоматически обнаруживать подключение именно JARVIS USB
    и запускать синхронизацию PC <-> USB.

Идентификация JARVIS USB:

    1. Ищется JARVIS_USB_DEVICE.json.
    2. Проверяется device_type.
    3. Проверяется device_id.
    4. Проверяется manifest.json.
    5. Проверяется product.name.
    6. Проверяется структура накопителя.

Обычные USB-накопители игнорируются.

Security:
    НЕ используется.
"""

from __future__ import annotations

import json
import os
import string
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, List


# ============================================================
# CONSTANTS
# ============================================================

MODULE_NAME = "usb_monitor"
MODULE_VERSION = "1.1.0"

JARVIS_USB_TYPE = "JARVIS_USB"

DEVICE_MARKER_FILENAME = "JARVIS_USB_DEVICE.json"
MANIFEST_FILENAME = "manifest.json"

DEFAULT_SCAN_INTERVAL = 1.5

ENV_USB_ROOT = "JARVIS_USB_ROOT"
ENV_JARVIS_ROOT = "JARVIS_ROOT"

EXPECTED_PATHS = (
    "JARVIS_USB.exe",
    "CONFIG",
    "DATA",
    "MODELS",
    "RUNTIME",
    "JARVIS",
)

MIN_STRUCTURE_MATCHES = 3


# ============================================================
# DATA
# ============================================================

@dataclass
class USBDevice:
    root_path: str
    device_id: str
    device_type: str
    name: str
    is_jarvis_usb: bool

    def to_dict(self) -> dict:
        return {
            "root_path": self.root_path,
            "device_id": self.device_id,
            "device_type": self.device_type,
            "name": self.name,
            "is_jarvis_usb": self.is_jarvis_usb,
        }


# ============================================================
# USB MONITOR
# ============================================================

class USBMonitor:

    def __init__(
        self,
        project_root: Optional[str | Path] = None,
        scan_interval: float = DEFAULT_SCAN_INTERVAL,
        auto_sync: bool = True,
    ):

        self.project_root = self._resolve_project_root(
            project_root
        )

        self.scan_interval = max(
            0.5,
            float(scan_interval)
        )

        self.auto_sync = bool(
            auto_sync
        )

        self.running = False

        self.thread: Optional[
            threading.Thread
        ] = None

        self.lock = threading.RLock()

        self.connected_devices: Dict[
            str,
            USBDevice
        ] = {}

        self.last_jarvis_usb_path: Optional[
            Path
        ] = None

        self.last_sync_result = None

        self._sync_in_progress = False

        self.device_manager = None
        self.sync_manager = None
        self.logger = None

        self._load_components()

        self._log(
            "info",
            f"USBMonitor v{MODULE_VERSION} initialized."
        )

    # ========================================================
    # PROJECT ROOT
    # ========================================================

    @staticmethod
    def _resolve_project_root(
        project_root: Optional[str | Path]
    ) -> Path:

        env_root = os.environ.get(
            ENV_JARVIS_ROOT
        )

        if project_root:

            return Path(
                project_root
            ).resolve()

        if env_root:

            return Path(
                env_root
            ).resolve()

        return (
            Path(__file__)
            .resolve()
            .parent
            .parent
        )

    # ========================================================
    # COMPONENTS
    # ========================================================

    def _load_components(self) -> None:

        # ----------------------------------------------------
        # LOGGER
        # ----------------------------------------------------

        try:


            from .sync_logger import SyncLogger

            self.logger = SyncLogger(
                self.project_root
            )

        except Exception:

            try:

                from sync_logger import SyncLogger

                self.logger = SyncLogger(
                    self.project_root
                )

            except Exception:

                self.logger = None

        # ----------------------------------------------------
        # DEVICE MANAGER
        # ----------------------------------------------------

        try:

            from .device_manager import DeviceManager

            self.device_manager = DeviceManager(
                self.project_root
            )

        except Exception:

            try:

                from device_manager import DeviceManager

                self.device_manager = DeviceManager(
                    self.project_root
                )

            except Exception as exc:

                self._log(
                    "warning",
                    f"DeviceManager unavailable: {exc}"
                )

        # ----------------------------------------------------
        # SYNC MANAGER
        # ----------------------------------------------------

        try:

            from .sync_manager import SyncManager

            self.sync_manager = SyncManager(
                self.project_root
            )

        except Exception:

            try:

                from sync_manager import SyncManager

                self.sync_manager = SyncManager(
                    self.project_root
                )

            except Exception as exc:

                self._log(
                    "warning",
                    f"SyncManager unavailable: {exc}"
                )

    # ========================================================
    # LOG
    # ========================================================

    def _log(
        self,
        level: str,
        message: str
    ) -> None:

        try:

            if self.logger:

                method = getattr(
                    self.logger,
                    level,
                    None
                )

                if method:

                    method(message)

                    return

        except Exception:
            pass

        print(
            f"[USBMonitor][{level.upper()}] {message}"
        )

    # ========================================================
    # WINDOWS DRIVES
    # ========================================================

    def _get_windows_drives(
        self
    ) -> List[Path]:

        if os.name != "nt":

            return []

        drives: List[Path] = []

        for letter in string.ascii_uppercase:

            drive = Path(
                f"{letter}:\\"
            )

            try:

                if (
                    drive.exists()
                    and drive.is_dir()
                ):

                    drives.append(
                        drive.resolve()
                    )

            except Exception:

                continue

        return drives

    # ========================================================
    # LOAD JSON
    # ========================================================

    @staticmethod
    def _load_json(
        path: Path
    ) -> Optional[dict]:

        if not path.is_file():

            return None

        try:

            with path.open(
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if isinstance(
                data,
                dict
            ):

                return data

        except Exception:
            return None

        return None

    # ========================================================
    # DEVICE MARKER
    # ========================================================

    def _load_device_marker(
        self,
        root: Path
    ) -> Optional[dict]:

        marker_path = (
            root
            / DEVICE_MARKER_FILENAME
        )

        return self._load_json(
            marker_path
        )

    # ========================================================
    # MANIFEST
    # ========================================================

    def _load_manifest(
        self,
        root: Path
    ) -> Optional[dict]:

        manifest_path = (
            root
            / MANIFEST_FILENAME
        )

        return self._load_json(
            manifest_path
        )

    # ========================================================
    # DEVICE ID
    # ========================================================

    @staticmethod
    def _get_marker_device_id(
        marker: dict
    ) -> Optional[str]:

        value = marker.get(
            "device_id"
        )

        if isinstance(
            value,
            str
        ):

            value = value.strip()

            if value:
                return value

        return None

    # ========================================================
    # DEVICE TYPE
    # ========================================================

    @staticmethod
    def _get_marker_device_type(
        marker: dict
    ) -> Optional[str]:

        value = marker.get(
            "device_type"
        )

        if isinstance(
            value,
            str
        ):

            value = value.strip().upper()

            if value:
                return value

        return None

    # ========================================================
    # STRUCTURE CHECK
    # ========================================================

    def _check_structure(
        self,
        root: Path
    ) -> bool:

        matches = 0

        for relative_path in EXPECTED_PATHS:

            path = (
                root
                / relative_path
            )

            try:

                if path.exists():

                    matches += 1

            except Exception:
                pass

        return (
            matches
            >= MIN_STRUCTURE_MATCHES
        )

    # ========================================================
    # PRODUCT CHECK
    # ========================================================

    def _check_product(
        self,
        manifest: dict
    ) -> bool:

        product = manifest.get(
            "product"
        )

        if not isinstance(
            product,
            dict
        ):

            return False

        name = str(
            product.get(
                "name",
                ""
            )
        ).strip().upper()

        return (
            name == "JARVIS USB"
        )

    # ========================================================
    # MANIFEST DEVICE CHECK
    # ========================================================

    def _check_manifest_identity(
        self,
        manifest: dict,
        marker_device_id: str
    ) -> bool:

        # ----------------------------------------------------
        # New sync_device block
        # ----------------------------------------------------

        sync_device = manifest.get(
            "sync_device"
        )

        if isinstance(
            sync_device,
            dict
        ):

            manifest_id = str(
                sync_device.get(
                    "device_id",
                    ""
                )
            ).strip()

            manifest_type = str(
                sync_device.get(
                    "device_type",
                    ""
                )
            ).strip().upper()

            if (
                manifest_id == marker_device_id
                and manifest_type == JARVIS_USB_TYPE
            ):

                return True

        # ----------------------------------------------------
        # Legacy direct device_id
        # ----------------------------------------------------

        manifest_id = manifest.get(
            "device_id"
        )

        manifest_type = manifest.get(
            "device_type"
        )

        if (
            str(
                manifest_id or ""
            ).strip()
            == marker_device_id
            and str(
                manifest_type or ""
            ).strip().upper()
            == JARVIS_USB_TYPE
        ):

            return True

        # ----------------------------------------------------
        # Product-only fallback.
        #
        # Marker file + correct product + correct structure
        # уже достаточно надёжны для обнаружения.
        # ----------------------------------------------------

        return self._check_product(
            manifest
        )

    # ========================================================
    # REGISTERED DEVICE CHECK
    # ========================================================

    def _is_registered(
        self,
        device_id: str
    ) -> bool:

        if not self.device_manager:

            # В новой версии marker-файл является
            # первичным идентификатором.
            #
            # Поэтому отсутствие DeviceManager
            # не мешает обнаружению устройства.
            #
            # Но синхронизация всё равно потребует
            # SyncManager.

            return True

        try:

            getter = getattr(
                self.device_manager,
                "get_device",
                None
            )

            if not getter:

                return True

            device = getter(
                device_id
            )

            if device:

                return True

        except Exception as exc:

            self._log(
                "debug",
                (
                    "DeviceManager lookup failed: "
                    f"{exc}"
                )
            )

        # ----------------------------------------------------
        # ВАЖНО:
        #
        # Не блокируем обнаружение новой физической флешки.
        # Она будет зарегистрирована при первом sync.
        # ----------------------------------------------------

        return True

    # ========================================================
    # IDENTIFY JARVIS USB
    # ========================================================

    def _identify_jarvis_usb(
        self,
        root: Path
    ) -> Optional[USBDevice]:

        try:

            root = root.resolve()

        except Exception:

            return None

        # ----------------------------------------------------
        # 1. DEVICE MARKER
        # ----------------------------------------------------

        marker = self._load_device_marker(
            root
        )

        if not marker:

            return None

        marker_type = (
            self._get_marker_device_type(
                marker
            )
        )

        marker_id = (
            self._get_marker_device_id(
                marker
            )
        )

        if marker_type != JARVIS_USB_TYPE:

            return None

        if not marker_id:

            self._log(
                "warning",
                (
                    f"JARVIS USB marker at {root} "
                    "has no device_id."
                )
            )

            return None

        # ----------------------------------------------------
        # 2. MANIFEST
        # ----------------------------------------------------

        manifest = self._load_manifest(
            root
        )

        if not manifest:

            return None

        # ----------------------------------------------------
        # 3. MANIFEST / PRODUCT
        # ----------------------------------------------------

        if not self._check_product(
            manifest
        ):

            return None

        if not self._check_manifest_identity(
            manifest,
            marker_id
        ):

            return None

        # ----------------------------------------------------
        # 4. STRUCTURE
        # ----------------------------------------------------

        if not self._check_structure(
            root
        ):

            self._log(
                "debug",
                (
                    f"Structure check failed "
                    f"for {root}"
                )
            )

            return None

        # ----------------------------------------------------
        # 5. REGISTERED DEVICE
        # ----------------------------------------------------

        if not self._is_registered(
            marker_id
        ):

            return None

        # ----------------------------------------------------
        # NAME
        # ----------------------------------------------------

        name = str(
            marker.get(
                "name",
                "JARVIS USB"
            )
        ).strip()

        if not name:

            name = "JARVIS USB"

        # ----------------------------------------------------
        # DEVICE
        # ----------------------------------------------------

        return USBDevice(
            root_path=str(root),
            device_id=marker_id,
            device_type=JARVIS_USB_TYPE,
            name=name,
            is_jarvis_usb=True,
        )

    # ========================================================
    # SCAN
    # ========================================================

    def scan(
        self
    ) -> List[USBDevice]:

        candidates: Dict[
            str,
            USBDevice
        ] = {}

        # ----------------------------------------------------
        # Portable root
        # ----------------------------------------------------

        env_root = os.environ.get(
            ENV_USB_ROOT
        )

        if env_root:

            root = Path(
                env_root
            )

            try:

                if root.exists():

                    device = (
                        self._identify_jarvis_usb(
                            root
                        )
                    )

                    if device:

                        candidates[
                            device.device_id
                        ] = device

            except Exception:
                pass

        # ----------------------------------------------------
        # Windows drives
        # ----------------------------------------------------

        for drive in self._get_windows_drives():

            try:

                # Avoid duplicate portable root.
                if env_root:

                    if (
                        drive.resolve()
                        == Path(
                            env_root
                        ).resolve()
                    ):

                        continue

                device = (
                    self._identify_jarvis_usb(
                        drive
                    )
                )

                if device:

                    candidates[
                        device.device_id
                    ] = device

            except Exception:
                continue

        return list(
            candidates.values()
        )

    # ========================================================
    # CONNECTION
    # ========================================================

    def _handle_connected(
        self,
        device: USBDevice
    ) -> None:

        with self.lock:

            if device.device_id in (
                self.connected_devices
            ):

                return

            self.connected_devices[
                device.device_id
            ] = device

            self.last_jarvis_usb_path = Path(
                device.root_path
            )

        self._log(
            "info",
            (
                "JARVIS USB connected: "
                f"{device.name} "
                f"[{device.device_id}] "
                f"at {device.root_path}"
            )
        )

        if self.auto_sync:

            self._start_sync(
                device
            )

    # ========================================================
    # DISCONNECTION
    # ========================================================

    def _handle_disconnected(
        self,
        device_id: str
    ) -> None:

        with self.lock:

            device = (
                self.connected_devices.pop(
                    device_id,
                    None
                )
            )

        if device:

            self._log(
                "info",
                (
                    "JARVIS USB disconnected: "
                    f"{device.name} "
                    f"[{device.device_id}]"
                )
            )

            if (
                self.last_jarvis_usb_path
                and not self.last_jarvis_usb_path.exists()
            ):

                self.last_jarvis_usb_path = None

    # ========================================================
    # START SYNC
    # ========================================================

    def _start_sync(
        self,
        device: USBDevice
    ) -> None:

        with self.lock:

            if self._sync_in_progress:

                self._log(
                    "warning",
                    "Sync already in progress."
                )

                return

            self._sync_in_progress = True

        thread = threading.Thread(
            target=self._sync_worker,
            args=(device,),
            daemon=True,
            name="JARVIS-USBSync",
        )

        thread.start()

    # ========================================================
    # SYNC WORKER
    # ========================================================

    def _sync_worker(
        self,
        device: USBDevice
    ) -> None:

        try:

            if not self.sync_manager:

                self._log(
                    "error",
                    "SyncManager is unavailable."
                )

                return

            usb_root = Path(
                device.root_path
            )

            if not usb_root.exists():

                self._log(
                    "warning",
                    (
                        "JARVIS USB disappeared "
                        "before sync."
                    )
                )

                return

            self._log(
                "info",
                (
                    "Starting automatic "
                    f"PC -> JARVIS USB sync: {usb_root}"
                )
            )

            # ------------------------------------------------
            # Current SyncManager API
            # ------------------------------------------------

            method = getattr(
                self.sync_manager,
                "sync_pc_to_usb",
                None
            )

            if method is None:

                self._log(
                    "error",
                    (
                        "SyncManager does not provide "
                        "sync_pc_to_usb()."
                    )
                )

                return

            # ------------------------------------------------
            # IMPORTANT:
            #
            # Some implementations accept usb_root,
            # some use positional argument.
            # ------------------------------------------------

            try:

                result = method(
                    usb_root=str(
                        usb_root
                    )
                )

            except TypeError:

                result = method(
                    str(
                        usb_root
                    )
                )

            self.last_sync_result = result

            # ------------------------------------------------
            # RESULT
            # ------------------------------------------------

            success = False

            if isinstance(

result,
                bool
            ):

                success = result

            elif isinstance(
                result,
                dict
            ):

                success = bool(
                    result.get(
                        "success",
                        result.get(
                            "status"
                        ) == "completed"
                    )
                )

            else:

                success = bool(
                    getattr(
                        result,
                        "success",
                        False
                    )
                )

            if success:

                self._log(
                    "info",
                    (
                        "Automatic JARVIS USB "
                        "sync completed."
                    )
                )

            else:

                self._log(
                    "warning",
                    (
                        "Automatic JARVIS USB "
                        "sync finished with warnings."
                    )
                )

        except Exception as exc:

            self._log(
                "error",
                (
                    "Automatic USB sync failed: "
                    f"{exc}"
                )
            )

        finally:

            with self.lock:

                self._sync_in_progress = False

    # ========================================================
    # MONITOR LOOP
    # ========================================================

    def _monitor_loop(
        self
    ) -> None:

        self._log(
            "info",
            "USB monitor started."
        )

        previous_ids: set[str] = set()

        while self.running:

            try:

                devices = self.scan()

                current_ids = {
                    device.device_id
                    for device in devices
                }

                # ------------------------------------------------
                # CONNECTED
                # ------------------------------------------------

                for device in devices:

                    if (
                        device.device_id
                        not in previous_ids
                    ):

                        self._handle_connected(
                            device
                        )

                # ------------------------------------------------
                # DISCONNECTED
                # ------------------------------------------------

                disconnected = (
                    previous_ids
                    - current_ids
                )

                for device_id in disconnected:

                    self._handle_disconnected(
                        device_id
                    )

                previous_ids = current_ids

                time.sleep(
                    self.scan_interval
                )

            except Exception as exc:

                self._log(
                    "error",
                    (
                        "USB monitor loop error: "
                        f"{exc}"
                    )
                )

                time.sleep(
                    self.scan_interval
                )

        self._log(
            "info",
            "USB monitor stopped."
        )

    # ========================================================
    # START
    # ========================================================

    def start(
        self
    ) -> bool:

        with self.lock:

            if self.running:

                return False

            self.running = True

            self.thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="JARVIS-USBMonitor",
            )

            self.thread.start()

        return True

    # ========================================================
    # STOP
    # ========================================================

    def stop(
        self,
        timeout: float = 5.0
    ) -> bool:

        with self.lock:

            if not self.running:

                return False

            self.running = False

            thread = self.thread

        if (
            thread
            and thread.is_alive()
        ):

            thread.join(
                timeout=max(
                    0.1,
                    timeout
                )
            )

        with self.lock:

            self.thread = None

            self.connected_devices.clear()

        return True

    # ========================================================
    # STATUS
    # ========================================================

    def status(
        self
    ) -> dict:

        with self.lock:

            return {
                "module": MODULE_NAME,
                "version": MODULE_VERSION,
                "running": self.running,
                "auto_sync": self.auto_sync,
                "scan_interval": self.scan_interval,
                "project_root": str(
                    self.project_root
                ),
                "connected_devices": [
                    device.to_dict()
                    for device
                    in self.connected_devices.values()
                ],
                "last_jarvis_usb_path": (
                    str(
                        self.last_jarvis_usb_path
                    )
                    if self.last_jarvis_usb_path
                    else None
                ),
                "sync_in_progress": (
                    self._sync_in_progress
                ),
            }

    # ========================================================
    # MANUAL SCAN
    # ========================================================

    def scan_now(
        self
    ) -> List[dict]:

        devices = self.scan()

        return [
            device.to_dict()
            for device in devices
        ]

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(
        self
    ) -> bool:

        try:

            if not self.project_root.exists():
                return False

            if not self.project_root.is_dir():
                return False

            if self.scan_interval <= 0:
                return False

            self._get_windows_drives()

            if self.sync_manager is None:

                self._log(
                    "warning",
                    (
                        "SyncManager unavailable "
                        "during self-test."
                    )
                )

                return False

            self._log(
                "info",
                "Self-test: OK"
            )

            return True

        except Exception as exc:

            self._log(
                "error",
                f"Self-test failed: {exc}"
            )

            return False


# ============================================================
# GLOBAL API
# ============================================================

_monitor: Optional[
    USBMonitor
] = None


def get_usb_monitor(
    project_root: Optional[str | Path] = None
) -> USBMonitor:

    global _monitor

    if _monitor is None:

        _monitor = USBMonitor(
            project_root=project_root
        )

    return _monitor


def start_usb_monitor(
    project_root: Optional[str | Path] = None
) -> USBMonitor:

    monitor = get_usb_monitor(
        project_root
    )

    monitor.start()

    return monitor


def stop_usb_monitor() -> bool:

    global _monitor

    if _monitor is None:

        return False

    return _monitor.stop()


def usb_monitor_status() -> dict:

    if _monitor is None:

        return {
            "running": False,
            "initialized": False,
        }

    status = _monitor.status()
    status["initialized"] = True

    return status


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print("=" * 64)
    print(
        "JARVIS V11 - USB Monitor"
    )
    print(
        f"Version: {MODULE_VERSION}"
    )
    print("=" * 64)

    monitor = USBMonitor()

    print()
    print(
        "Project root:"
    )

    print(
        monitor.project_root
    )

    print()
    print(
        "Self-test..."
    )

    if monitor.self_test():

        print(
            "[+] USB Monitor: OK"
        )

    else:

        print(
            "[-] USB Monitor: FAILED"
        )

    print()
    print(
        "Current JARVIS USB devices:"
    )

    devices = monitor.scan_now()

    if not devices:

        print(
            "  No JARVIS USB detected."
        )

    else:

        for device in devices:

            print(
                f"  [+] {device['name']}"
            )

            print(
                f"      ID: {device['device_id']}"
            )

            print(
                f"      Path: {device['root_path']}"
            )

    print()
    print(
        "Starting monitor..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    monitor.start()

    try:

        while monitor.running:

            time.sleep(1)

    except KeyboardInterrupt:

        print()

        print(
            "Stopping..."
        )

        monitor.stop()

        print(
            "Stopped."
        )