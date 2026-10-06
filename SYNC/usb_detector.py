"""
JARVIS V11 - USB Detector
Version: 1.4.1

Назначение:
    Обнаружение JARVIS USB при подключении/отключении
    через Windows WM_DEVICECHANGE.

Поддерживаемая структура:

    D:\
    ├── JARVIS USB\
    │   ├── JARVIS_USB.exe
    │   ├── manifest.json
    │   ├── JARVIS_USB_DEVICE.json
    │   ├── CONFIG\
    │   ├── DATA\
    │   ├── MODELS\
    │   ├── RUNTIME\
    │   └── JARVIS\
    │
    └── Музыка\

ВАЖНО:
    Этот модуль пока только обнаруживает USB.
    Автоматическую синхронизацию НЕ запускает.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import json
import string
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


# ============================================================
# VERSION
# ============================================================

MODULE_NAME = "USBDetector"
MODULE_VERSION = "1.4.1"


# ============================================================
# WINDOWS CONSTANTS
# ============================================================

WM_DEVICECHANGE = 0x0219
WM_QUIT = 0x0012
WM_DESTROY = 0x0002

DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004

DBT_DEVTYP_VOLUME = 0x00000002
DBT_DEVNODES_CHANGED = 0x0007

CS_HREDRAW = 0x0002
CS_VREDRAW = 0x0001

WS_OVERLAPPED = 0x00000000

# Обычное скрытое top-level окно. Оно получает broadcast WM_DEVICECHANGE.
HWND_MESSAGE = None

ERROR_CLASS_ALREADY_EXISTS = 1410


# ============================================================
# WINDOWS DLL
# ============================================================

user32 = ctypes.WinDLL(
    "user32",
    use_last_error=True
)

kernel32 = ctypes.WinDLL(
    "kernel32",
    use_last_error=True
)


# ============================================================
# WINDOWS STRUCTURES
# ============================================================

class POINT(ctypes.Structure):
    _fields_ = [
        ("x", wintypes.LONG),
        ("y", wintypes.LONG),
    ]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("message", wintypes.UINT),
        ("wParam", wintypes.WPARAM),
        ("lParam", wintypes.LPARAM),
        ("time", wintypes.DWORD),
        ("pt", POINT),
        ("lPrivate", wintypes.DWORD),
    ]


WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class DEV_BROADCAST_HDR(ctypes.Structure):
    _fields_ = [
        ("dbch_size", wintypes.DWORD),
        ("dbch_devicetype", wintypes.DWORD),
        ("dbch_reserved", wintypes.DWORD),
    ]


class DEV_BROADCAST_VOLUME(ctypes.Structure):
    _fields_ = [
        ("dbcv_size", wintypes.DWORD),
        ("dbcv_devicetype", wintypes.DWORD),
        ("dbcv_reserved", wintypes.DWORD),
        ("dbcv_unitmask", wintypes.DWORD),
        ("dbcv_flags", wintypes.WORD),
    ]


# ============================================================
# WINDOWS API SIGNATURES
# ============================================================

user32.RegisterClassW.argtypes = [
    ctypes.POINTER(WNDCLASSW)
]
user32.RegisterClassW.restype = wintypes.ATOM


user32.UnregisterClassW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.HINSTANCE,
]
user32.UnregisterClassW.restype = wintypes.BOOL


user32.CreateWindowExW.argtypes = [
    wintypes.DWORD,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int,
    wintypes.HWND,
    wintypes.HMENU,
    wintypes.HINSTANCE,
    wintypes.LPVOID,
]

user32.CreateWindowExW.restype = wintypes.HWND


user32.DestroyWindow.argtypes = [
    wintypes.HWND
]
user32.DestroyWindow.restype = wintypes.BOOL


user32.DefWindowProcW.argtypes = [
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
]
user32.DefWindowProcW.restype = ctypes.c_ssize_t


user32.GetMessageW.argtypes = [
    ctypes.POINTER(MSG),
    wintypes.HWND,
    wintypes.UINT,
    wintypes.UINT,
]
user32.GetMessageW.restype = ctypes.c_int


user32.TranslateMessage.argtypes = [
    ctypes.POINTER(MSG)
]
user32.TranslateMessage.restype = wintypes.BOOL


user32.DispatchMessageW.argtypes = [
    ctypes.POINTER(MSG)
]
user32.DispatchMessageW.restype = ctypes.c_ssize_t


user32.PostThreadMessageW.argtypes = [
    wintypes.DWORD,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
]
user32.PostThreadMessageW.restype = wintypes.BOOL


kernel32.GetModuleHandleW.argtypes = [
    wintypes.LPCWSTR
]
kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE


kernel32.GetCurrentThreadId.argtypes = []
kernel32.GetCurrentThreadId.restype = wintypes.DWORD


kernel32.GetLogicalDrives.argtypes = []
kernel32.GetLogicalDrives.restype = wintypes.DWORD


kernel32.GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
kernel32.GetVolumeInformationW.restype = wintypes.BOOL


# ============================================================
# DATA CLASS
# ============================================================

@dataclass
class USBDevice:
    drive: str
    jarvis_root: str
    volume_serial: str
    label: str
    is_jarvis_usb: bool

    marker_found: bool = False
    manifest_found: bool = False

    product_name: str = ""
    product_version: str = ""

    structure_matches: int = 0
    identification_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "drive": self.drive,
            "jarvis_root": self.jarvis_root,
            "volume_serial": self.volume_serial,
            "label": self.label,
            "is_jarvis_usb": self.is_jarvis_usb,
            "marker_found": self.marker_found,
            "manifest_found": self.manifest_found,
            "product_name": self.product_name,
            "product_version": self.product_version,
            "structure_matches": self.structure_matches,
            "identification_reason": self.identification_reason,
        }


# ============================================================
# USB DETECTOR
# ============================================================

class USBDetector:

    MARKER_FILENAME = "JARVIS_USB_DEVICE.json"
    MANIFEST_FILENAME = "manifest.json"

    # Минимальная структура JARVIS USB
    EXPECTED_STRUCTURE = (
        "JARVIS_USB.exe",
        "CONFIG",
        "DATA",
        "MODELS",
        "RUNTIME",
        "JARVIS",
    )

    # Максимальная глубина поиска.
    #
    # 0 = только корень диска
    # 1 = корень + папки первого уровня
    #
    # Нам нужен именно 1, чтобы не сканировать всю музыку
    # и остальные пользовательские папки.
    MAX_SEARCH_DEPTH = 1

    def __init__(
        self,
        poll_interval: float = 1.5,
        on_connected: Optional[
            Callable[[USBDevice], None]
        ] = None,
        on_disconnected: Optional[
            Callable[[USBDevice], None]
        ] = None,
    ):

        self.poll_interval = poll_interval

        self.on_connected = on_connected
        self.on_disconnected = on_disconnected

        self._running = False

        self._thread: Optional[
            threading.Thread
        ] = None

        self._message_thread_id: Optional[int] = None

        self._hwnd = None

        self._class_name = (
            f"JARVIS_USB_DETECTOR_{uuid.uuid4().hex}"
        )

        self._wnd_proc = WNDPROC(
            self._window_proc
        )

        self._registered_class = False

        self._known_devices: dict[
            str,
            USBDevice
        ] = {}

        self._lock = threading.RLock()

    # ========================================================
    # LOG
    # ========================================================

    @staticmethod
    def _log(message: str) -> None:
        print(
            f"[USBDetector] {message}"
        )

    # ========================================================
    # LOGICAL DRIVES
    # ========================================================

    @staticmethod
    def get_logical_drives() -> list[str]:

        mask = kernel32.GetLogicalDrives()

        if not mask:
            return []

        drives = []

        for index, letter in enumerate(
            string.ascii_uppercase
        ):

            if mask & (1 << index):

                drives.append(
                    f"{letter}:\\"
                )

        return drives

    # ========================================================
    # DRIVE TYPE
    # ========================================================

    @staticmethod
    def get_drive_type(root: str) -> int:

        kernel32.GetDriveTypeW.argtypes = [
            wintypes.LPCWSTR
        ]

        kernel32.GetDriveTypeW.restype = (
            wintypes.UINT
        )

        return int(
            kernel32.GetDriveTypeW(root)
        )

    # ========================================================
    # VOLUME INFO
    # ========================================================

    @staticmethod
    def get_volume_information(
        root: str
    ) -> tuple[str, str]:

        volume_name = ctypes.create_unicode_buffer(
            261
        )

        file_system_name = (
            ctypes.create_unicode_buffer(261)
        )

        serial_number = wintypes.DWORD()
        max_component_length = wintypes.DWORD()
        file_system_flags = wintypes.DWORD()

        success = kernel32.GetVolumeInformationW(
            root,
            volume_name,
            len(volume_name),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_length),
            ctypes.byref(file_system_flags),
            file_system_name,
            len(file_system_name),
        )

        if not success:

            return "", ""

        serial = (
            f"{serial_number.value:08X}"
        )

        return (
            serial,
            volume_name.value
        )

    # ========================================================
    # READ JSON
    # ========================================================

    @staticmethod
    def _read_json(
        path: Path
    ) -> Optional[dict]:

        try:

            if not path.is_file():
                return None

            with path.open(
                "r",
                encoding="utf-8-sig"
            ) as file:

                data = json.load(file)

            if isinstance(data, dict):
                return data

        except Exception as exc:

            USBDetector._log(
                f"JSON error {path}: {exc}"
            )

        return None

    # ========================================================
    # CHECK JARVIS ROOT
    # ========================================================

    def _inspect_jarvis_root(
        self,
        drive: str,
        root: Path,
        serial: str,
        label: str,
    ) -> Optional[USBDevice]:

        marker_path = (
            root / self.MARKER_FILENAME
        )

        manifest_path = (
            root / self.MANIFEST_FILENAME
        )

        marker_found = (
            marker_path.is_file()
        )

        manifest_found = (
            manifest_path.is_file()
        )

        marker = self._read_json(
            marker_path
        )

        manifest = self._read_json(
            manifest_path
        )

        product_name = ""
        product_version = ""

        if isinstance(manifest, dict):

            product = manifest.get(
                "product",
                {}
            )

            if isinstance(product, dict):

                product_name = str(
                    product.get(
                        "name",
                        ""
                    )
                )

                product_version = str(
                    product.get(
                        "version",
                        ""
                    )
                )

        structure_matches = 0

        for item in self.EXPECTED_STRUCTURE:

            if (root / item).exists():

                structure_matches += 1

        reasons = []

        is_jarvis = False

        # ----------------------------------------------------
        # MARKER
        # ----------------------------------------------------

        if marker_found:

            reasons.append(
                "marker найден"
            )

            if isinstance(marker, dict):

                device_type = str(
                    marker.get(
                        "device_type",
                        ""
                    )
                ).upper()

                if device_type == "JARVIS_USB":

                    is_jarvis = True

                    reasons.append(
                        "device_type=JARVIS_USB"
                    )

        # ----------------------------------------------------
        # MANIFEST
        # ----------------------------------------------------

        if manifest_found:

            reasons.append(
                "manifest найден"
            )

        if product_name:

            reasons.append(
                f"product.name={product_name}"
            )

            if (
                "JARVIS USB"
                in product_name.upper()
            ):

                is_jarvis = True

                reasons.append(
                    "manifest подтверждает JARVIS USB"
                )

        # ----------------------------------------------------
        # STRUCTURE
        # ----------------------------------------------------

        reasons.append(
            "структура="
            f"{structure_matches}/"
            f"{len(self.EXPECTED_STRUCTURE)}"
        )

        # Если есть достаточно структуры,
        # тоже считаем устройство JARVIS USB.
        if structure_matches >= 4:

            is_jarvis = True

            reasons.append(
                "структура подтверждает JARVIS USB"
            )

        # ----------------------------------------------------
        # Если вообще нет признаков JARVIS —
        # возвращаем None.
        # ----------------------------------------------------

        if not is_jarvis:

            return None

        return USBDevice(
            drive=drive,
            jarvis_root=str(root),
            volume_serial=serial,
            label=label,
            is_jarvis_usb=True,

            marker_found=marker_found,
            manifest_found=manifest_found,

            product_name=product_name,
            product_version=product_version,

            structure_matches=structure_matches,

            identification_reason="; ".join(
                reasons
            ),
        )

    # ========================================================
    # INSPECT DRIVE
    # ========================================================

    def inspect_drive(
        self,
        root: str
    ) -> tuple[
        Optional[USBDevice],
        dict
    ]:

        drive_path = Path(root)

        serial, label = (
            self.get_volume_information(root)
        )

        diagnostic = {
            "drive": root,
            "label": label,
            "serial": serial,

            "root_marker": False,
            "root_manifest": False,

            "candidate_folders": [],
            "found": False,
        }

        # ----------------------------------------------------
        # 1. Проверяем сам корень D:\
        # ----------------------------------------------------

        candidate_roots = [
            drive_path
        ]

        # ----------------------------------------------------
        # 2. Ищем папки первого уровня.
        #
        # Например:
        #
        # D:\JARVIS USB\
        # D:\Music\
        # D:\Photos\
        #
        # Но внутрь Music/Photos не идём.
        # ----------------------------------------------------

        try:

            for item in drive_path.iterdir():

                try:

                    if item.is_dir():

                        candidate_roots.append(
                            item
                        )

                        diagnostic[
                            "candidate_folders"
                        ].append(
                            item.name
                        )

                except (
                    PermissionError,
                    OSError,
                ):

                    continue

        except (
            PermissionError,
            OSError,
        ) as exc:

            diagnostic["scan_error"] = str(
                exc
            )

        # ----------------------------------------------------
        # 3. Проверяем кандидатов.
        # ----------------------------------------------------

        for candidate in candidate_roots:

            try:

                device = self._inspect_jarvis_root(
                    drive=root,
                    root=candidate,
                    serial=serial,
                    label=label,
                )

            except Exception as exc:

                self._log(
                    f"Ошибка проверки кандидата "
                    f"{candidate}: {exc}"
                )
                continue

            if device:

                diagnostic[
                    "found"
                ] = True

                diagnostic[
                    "jarvis_root"
                ] = str(candidate)

                diagnostic[
                    "candidate"
                ] = candidate.name

                return (
                    device,
                    diagnostic
                )

        return (
            None,
            diagnostic
        )

    # ========================================================
    # SCAN
    # ========================================================

    def scan(
        self
    ) -> list[USBDevice]:

        devices = []

        for drive in (
            self.get_logical_drives()
        ):

            try:

                device, diagnostic = (
                    self.inspect_drive(
                        drive
                    )
                )

                if device:

                    devices.append(
                        device
                    )

            except Exception as exc:

                self._log(
                    f"Ошибка проверки "
                    f"{drive}: {exc}"
                )

        return devices

    # ========================================================
    # FULL DIAGNOSTIC
    # ========================================================

    def print_scan(self) -> None:

        print()
        print("=" * 70)
        print(
            "JARVIS USB - диагностика v1.4.1"
        )
        print("=" * 70)

        for drive in (
            self.get_logical_drives()
        ):

            print()
            print(
                f"Диск: {drive}"
            )

            drive_type = (
                self.get_drive_type(drive)
            )

            print(
                f"Тип Windows: "
                f"{drive_type}"
            )

            serial, label = (
                self.get_volume_information(
                    drive
                )
)

            print(
                f"Метка: "
                f"{label or '(нет)'}"
            )

            print(
                f"Serial: "
                f"{serial or '(нет)'}"
            )

            try:

                device, diagnostic = (
                    self.inspect_drive(
                        drive
                    )
                )

                folders = diagnostic.get(
                    "candidate_folders",
                    []
                )

                if folders:

                    print(
                        "Папки первого уровня:"
                    )

                    for folder in folders:

                        print(
                            f"  - {folder}"
                        )

                else:

                    print(
                        "Папки первого уровня: нет"
                    )

                if device:

                    print()
                    print(
                        ">>> JARVIS USB НАЙДЕН!"
                    )

                    print(
                        f"JARVIS root: "
                        f"{device.jarvis_root}"
                    )

                    print(
                        f"Product: "
                        f"{device.product_name or '(нет)'}"
                    )

                    print(
                        f"Version: "
                        f"{device.product_version or '(нет)'}"
                    )

                    print(
                        f"Marker: "
                        f"{'YES' if device.marker_found else 'NO'}"
                    )

                    print(
                        f"Manifest: "
                        f"{'YES' if device.manifest_found else 'NO'}"
                    )

                    print(
                        f"Structure: "
                        f"{device.structure_matches}/"
                        f"{len(self.EXPECTED_STRUCTURE)}"
                    )

                    print(
                        f"Reason: "
                        f"{device.identification_reason}"
                    )

                else:

                    print()
                    print(
                        "JARVIS USB не найден."
                    )

                    if folders:

                        print(
                            "Проверены папки:"
                        )

                        for folder in folders:

                            print(
                                f"  - {folder}"
                            )

            except Exception as exc:

                print(
                    f"Ошибка диагностики: "
                    f"{exc}"
                )

        print()
        print("=" * 70)
        print()

    # ========================================================
    # DEVICE KEY
    # ========================================================

    @staticmethod
    def _device_key(
        device: USBDevice
    ) -> str:

        if device.volume_serial:

            return (
                device.volume_serial.upper()
            )

        return device.drive.upper()

    # ========================================================
    # ARRIVAL
    # ========================================================

    def _handle_arrival(
        self,
        drive: str
    ) -> None:

        self._log(
            f"Обнаружено изменение: "
            f"{drive}"
        )

        # Windows может прислать событие чуть раньше,
        # чем том полностью смонтируется. Повторяем проверку.
        device = None
        diagnostic = {}

        for attempt in range(5):

            device, diagnostic = self.inspect_drive(
                drive
            )

            if device:
                break

            if attempt < 4:
                time.sleep(0.5)

        if not device:

            self._log(
                f"{drive}: "
                f"JARVIS USB не найден."
            )

            return

        key = self._device_key(
            device
        )

        with self._lock:

            already_known = (
                key in self._known_devices
            )

        self._known_devices[key] = (
                device
            )

        if already_known:

            return

        print()
        print("+" * 70)
        print(
            "JARVIS USB CONNECTED"
        )
        print("+" * 70)

        print(
            f"Drive: {device.drive}"
        )

        print(
            f"JARVIS root: "
            f"{device.jarvis_root}"
        )

        print(
            f"Serial: "
            f"{device.volume_serial}"
        )

        print(
            f"Product: "
            f"{device.product_name}"
        )

        print(
            f"Version: "
            f"{device.product_version}"
        )

        print(
            "SYNC: not started"
        )

        print("+" * 70)
        print()

        if self.on_connected:

            try:

                self.on_connected(
                    device
                )

            except Exception as exc:

                self._log(
                    f"Callback error: {exc}"
                )

    # ========================================================
    # REMOVAL
    # ========================================================

    def _handle_removal(
        self,
        drive: str
    ) -> None:

        drive_upper = (
            drive.upper()
        )

        removed = []

        with self._lock:

            for key, device in list(
                self._known_devices.items()
            ):

                if (
                    device.drive.upper()
                    == drive_upper
                ):

                    removed.append(
                        device
                    )

                    del (
                        self._known_devices[key]
                    )

        for device in removed:

            self._log(
                "JARVIS USB отключена: "
                f"{device.drive}"
            )

            if self.on_disconnected:

                try:

                    self.on_disconnected(
                        device
                    )

                except Exception as exc:

                    self._log(
                        f"Callback error: "
                        f"{exc}"
                    )

    # ========================================================
    # FALLBACK RESCAN
    # ========================================================

    def _rescan_after_device_change(self) -> None:

        time.sleep(0.8)

        current_devices = {
            self._device_key(device): device
            for device in self.scan()
        }

        with self._lock:
            known_devices = dict(self._known_devices)

        # Подключившиеся устройства.
        for key, device in current_devices.items():

            if key not in known_devices:

                with self._lock:
                    self._known_devices[key] = device

                print()
                print("+" * 70)
                print("JARVIS USB CONNECTED")
                print("+" * 70)
                print(f"Drive: {device.drive}")
                print(f"JARVIS root: {device.jarvis_root}")
                print(f"Serial: {device.volume_serial}")
                print(f"Product: {device.product_name}")
                print(f"Version: {device.product_version}")
                print("SYNC: not started")
                print("+" * 70)
                print()

                if self.on_connected:

                    try:
                        self.on_connected(device)
                    except Exception as exc:
                        self._log(
                            f"Callback error: {exc}"
                        )

        # Отключившиеся устройства.
        for key, device in known_devices.items():

            if key not in current_devices:

                with self._lock:
                    self._known_devices.pop(key, None)

                self._log(
                    "JARVIS USB отключена: "
                    f"{device.drive}"
                )

                if self.on_disconnected:

                    try:
                        self.on_disconnected(device)
                    except Exception as exc:
                        self._log(
                            f"Callback error: {exc}"
                        )


    # ========================================================
    # WINDOWS CALLBACK
    # ========================================================

    def _window_proc(
        self,
        hwnd,
        message,
        wparam,
        lparam,
    ):

        if message == WM_DEVICECHANGE:

            if wparam == DBT_DEVNODES_CHANGED:

                # Windows иногда сообщает об изменении дерева устройств
                # без готового volume lParam. Делаем фоновый rescan.
                threading.Thread(
                    target=self._rescan_after_device_change,
                    daemon=True,
                    name="JARVIS-USB-Rescan",
                ).start()

            if wparam in (
                DBT_DEVICEARRIVAL,
                DBT_DEVICEREMOVECOMPLETE,
            ):

                if lparam:

                    try:

                        header = ctypes.cast(
                            lparam,
                            ctypes.POINTER(
                                DEV_BROADCAST_HDR
                            ),
                        ).contents

                        if (
                            header.dbch_devicetype
                            == DBT_DEVTYP_VOLUME
                        ):

                            volume = ctypes.cast(
                                lparam,
                                ctypes.POINTER(
                                    DEV_BROADCAST_VOLUME
                                ),
                            ).contents

                            mask = (
                                volume.dbcv_unitmask
                            )

                            for index, letter in enumerate(
                                string.ascii_uppercase
                            ):

                                if mask & (
                                    1 << index
                                ):

                                    drive = (
                                        f"{letter}:\\"
                                    )

                                    if (
                                        wparam

== DBT_DEVICEARRIVAL
                                    ):

                                        threading.Thread(
                                            target=(
                                                self._handle_arrival
                                            ),
                                            args=(
                                                drive,
                                            ),
                                            daemon=True,
                                            name=(
                                                "JARVIS-USB-Event"
                                            ),
                                        ).start()

                                    else:

                                        threading.Thread(
                                            target=(
                                                self._handle_removal
                                            ),
                                            args=(
                                                drive,
                                            ),
                                            daemon=True,
                                            name=(
                                                "JARVIS-USB-Removal"
                                            ),
                                        ).start()

                    except Exception as exc:

                        self._log(
                            "Ошибка "
                            f"WM_DEVICECHANGE: {exc}"
                        )

        if message == WM_DESTROY:

            return 0

        return user32.DefWindowProcW(
            hwnd,
            message,
            wparam,
            lparam,
        )

    # ========================================================
    # MESSAGE LOOP
    # ========================================================

    def _message_loop(self) -> None:

        self._message_thread_id = (
            kernel32.GetCurrentThreadId()
        )

        h_instance = (
            kernel32.GetModuleHandleW(None)
        )

        wnd_class = WNDCLASSW()

        wnd_class.style = (
            CS_HREDRAW | CS_VREDRAW
        )

        wnd_class.lpfnWndProc = (
            self._wnd_proc
        )

        wnd_class.cbClsExtra = 0
        wnd_class.cbWndExtra = 0

        wnd_class.hInstance = h_instance
        wnd_class.hIcon = None
        wnd_class.hCursor = None
        wnd_class.hbrBackground = None
        wnd_class.lpszMenuName = None
        wnd_class.lpszClassName = (
            self._class_name
        )

        atom = user32.RegisterClassW(
            ctypes.byref(wnd_class)
        )

        if not atom:

            error = ctypes.get_last_error()

            if (
                error
                != ERROR_CLASS_ALREADY_EXISTS
            ):

                raise ctypes.WinError(error)

        else:

            self._registered_class = True

        hwnd = user32.CreateWindowExW(
            0,
            self._class_name,
            "JARVIS USB Detector",
            0,
            0,
            0,
            0,
            0,
            None,
            None,
            h_instance,
            None,
        )

        if not hwnd:

            error = ctypes.get_last_error()

            raise ctypes.WinError(error)

        self._hwnd = hwnd

        self._log(
            "Windows hidden top-level message window создано."
        )

        self._log(
            "WM_DEVICECHANGE listener активен."
        )

        msg = MSG()

        while self._running:

            result = user32.GetMessageW(
                ctypes.byref(msg),
                None,
                0,
                0,
            )

            if result == -1:

                error = ctypes.get_last_error()

                self._log(
                    f"GetMessageW error: "
                    f"{error}"
                )

                break

            if result == 0:
                break

            user32.TranslateMessage(
                ctypes.byref(msg)
            )

            user32.DispatchMessageW(
                ctypes.byref(msg)
            )

        if self._hwnd:

            user32.DestroyWindow(
                self._hwnd
            )

            self._hwnd = None

        if self._registered_class:

            user32.UnregisterClassW(
                self._class_name,
                h_instance,
            )

            self._registered_class = False

        self._message_thread_id = None

    # ========================================================
    # START
    # ========================================================

    def start(self) -> bool:

        if self._running:

            return True

        self._running = True

        # Сначала запускаем Windows message loop.
        # Это важно: если USB вставить сразу после старта,
        # окно уже должно существовать и получать WM_DEVICECHANGE.
        self._thread = threading.Thread(
            target=self._message_loop,
            daemon=True,
            name="JARVIS-USBDetector",
        )

        self._thread.start()

        deadline = (
            time.time() + 5.0
        )

        while (
            self._message_thread_id is None
            and time.time() < deadline
        ):

            time.sleep(0.05)

        if (
            self._message_thread_id
            is None
        ):

            self._log(
                "Не удалось запустить "
                "Windows message loop."
            )

            self._running = False

            if self._thread:
                self._thread.join(timeout=2.0)

            self._thread = None

            return False

        # Окно уже создано. Теперь делаем начальное сканирование.
        devices = self.scan()

        with self._lock:

            self._known_devices.clear()

            for device in devices:

                key = self._device_key(
                    device
                )

                self._known_devices[key] = (
                    device
                )

        self._log(
            "Windows USB event listener "
            "запущен."
        )

        return True


    # ========================================================
    # STOP
    # ========================================================

    def stop(self) -> None:

        if not self._running:

            return

        self._running = False

        if self._message_thread_id:

            user32.PostThreadMessageW(
                self._message_thread_id,
                WM_QUIT,
                0,
                0,
            )

        if self._thread:

            self._thread.join(
                timeout=5.0
            )

        self._thread = None

        self._log(
            "USB Detector остановлен."
        )

    # ========================================================
    # STATUS
    # ========================================================

    def get_jarvis_devices(
        self
    ) -> list[USBDevice]:

        with self._lock:

            return list(
                self._known_devices.values()
            )

    def status(self) -> dict:

        with self._lock:

            devices = [
                device.to_dict()
                for device
                in self._known_devices.values()
            ]

        return {
            "module": MODULE_NAME,
            "version": MODULE_VERSION,
            "running": self._running,
            "message_thread_id": (
                self._message_thread_id
            ),
            "window_created": (
                self._hwnd is not None
            ),
            "notification_registered": False,
            "jarvis_usb_count": len(
                devices
            ),
            "devices": devices,
        }

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(self) -> bool:

        try:

            drives = (
                self.get_logical_drives()
            )

            if not isinstance(
                drives,
                list
            ):

                return False

            for drive in drives:

                self.inspect_drive(
                    drive
                )

            self._log(
                "Self-test: OK. "
                f"Detected {len(drives)} "
                f"mounted drive(s)."
            )

            return True

        except Exception as exc:

            self._log(
                f"Self-test FAILED: "
                f"{exc}"
            )

            return False


# ============================================================
# CALLBACKS
# ============================================================

def on_usb_connected(
    device: USBDevice
) -> None:

    print()
    print("+" * 70)
    print(
        "JARVIS USB CONNECTED"
    )
    print("+" * 70)

    print(
        f"Drive: {device.drive}"
    )

    print(
        f"JARVIS root: "
        f"{device.jarvis_root}"
    )

    print(
        f"Serial: "
        f"{device.volume_serial}"
    )

    print(
        f"Product: "
        f"{device.product_name}"
    )

    print(
        f"Version: "
        f"{device.product_version}"
    )

    print(
        "SYNC: not started"
    )

    print("+" * 70)
    print()


def on_usb_disconnected(
    device: USBDevice
) -> None:

    print()
    print("-" * 70)
    print(
        "JARVIS USB DISCONNECTED"
    )
    print("-" * 70)

    print(
        f"Drive: "
        f"{device.drive}"
    )

    print(
        f"JARVIS root: "
        f"{device.jarvis_root}"
    )

    print("-" * 70)
    print()


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    print("=" * 70)
    print(
        "JARVIS V11 - USB Detector"
    )
    print(
        f"Version: {MODULE_VERSION}"
    )
    print("=" * 70)
    print()

    from usb_sync_bridge import USBSyncBridge

    bridge = USBSyncBridge(
        auto_sync=True
    )

    detector = USBDetector(
        on_connected=bridge.on_connected,
        on_disconnected=bridge.on_disconnected,
    )

    print(
        "Running self-test..."
    )

    if detector.self_test():

        print(
            "[+] USB Detector: OK"
        )

    else:

        print(
            "[-] USB Detector: FAILED"
        )

        return 1

    # --------------------------------------------------------
    # Подробное сканирование
    # --------------------------------------------------------

    detector.print_scan()

    print(
        "Currently mounted JARVIS USB devices:"
    )

    devices = detector.scan()

    if devices:

        for device in devices:

            print(
                f"  {device.drive}  "
                f"JARVIS USB  "
                f"root={device.jarvis_root}"
            )

    else:

        print(
            "  No JARVIS USB detected."
        )

    print()

    print(
        "Starting Windows USB event listener..."
    )

    print(
        "Now unplug and plug the JARVIS USB after the listener starts."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    if not detector.start():

        print(
            "[-] Failed to start "
            "USB listener."
        )

        return 1

    try:

        while detector._running:

            time.sleep(1.0)

    except KeyboardInterrupt:

        print()
        print(
            "Stopping USB Detector..."
        )

    finally:

        detector.stop()

    print(
        "USB Detector stopped."
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    raise SystemExit(
        main()
    )