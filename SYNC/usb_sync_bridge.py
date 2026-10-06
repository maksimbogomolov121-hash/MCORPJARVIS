"""
JARVIS V11 — USB Sync Bridge
=============================

Связывает:

    USBDetector
          ↓
    USBSyncBridge
          ↓
    DeviceManager
          ↓
    SyncManager
          ↓
    SyncEngine

Основной сценарий:

    USB подключён
          ↓
    USBDetector обнаружил JARVIS USB
          ↓
    Bridge получил USBDevice
          ↓
    DeviceManager регистрирует USB
          ↓
    SyncManager
          ↓
    PC → USB
          ↓
    Backup
          ↓
    Apply
          ↓
    Verify
          ↓
    Complete

ВАЖНО:
    Security этим модулем НЕ используется.

Версия: 1.2.0
"""

from __future__ import annotations

import json
import threading

from dataclasses import (
    asdict,
    dataclass,
)

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path
from typing import (
    Any,
    Optional,
)


# ============================================================
# CONSTANTS
# ============================================================

MODULE_NAME = "USBSyncBridge"
MODULE_VERSION = "1.2.0"

USB_DEVICE_TYPE = "USB"
PC_DEVICE_TYPE = "PC"

STATUS_IDLE = "idle"
STATUS_CONNECTED = "connected"
STATUS_SYNCING = "syncing"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_DISCONNECTED = "disconnected"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """
    Возвращает текущее UTC-время
    в ISO 8601.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# BRIDGE RESULT
# ============================================================

@dataclass
class BridgeResult:
    """
    Результат работы USB Sync Bridge.
    """

    success: bool

    status: str

    message: str

    device_id: Optional[str] = None

    device_name: Optional[str] = None

    jarvis_root: Optional[str] = None

    started_at: Optional[str] = None

    finished_at: Optional[str] = None

    error: Optional[str] = None

    sync_result: Optional[
        dict[str, Any]
    ] = None

    def to_dict(
        self,
    ) -> dict[str, Any]:

        return asdict(
            self
        )


# ============================================================
# USB SYNC BRIDGE
# ============================================================

class USBSyncBridge:
    """
    Связующее звено между USBDetector и SyncManager.
    """

    # ========================================================
    # INIT
    # ========================================================

    def __init__(
        self,
        root_path: str | Path | None = None,
        device_manager=None,
        sync_manager=None,
        auto_sync: bool = True,
    ) -> None:

        # ----------------------------------------------------
        # ROOT
        # ----------------------------------------------------

        if root_path is None:

            root_path = (
                Path(__file__)
                .resolve()
                .parent
                .parent
            )

        self.root_path = (
            Path(root_path)
            .expanduser()
            .resolve()
        )

        # ----------------------------------------------------
        # MANAGERS
        # ----------------------------------------------------

        self.device_manager = (
            device_manager
        )

        self.sync_manager = (
            sync_manager
        )

        # ----------------------------------------------------
        # OPTIONS
        # ----------------------------------------------------

        self.auto_sync = bool(
            auto_sync
        )

        # ----------------------------------------------------
        # RUNTIME
        # ----------------------------------------------------

        self._lock = (
            threading.RLock()
        )

        self._sync_thread: Optional[
            threading.Thread

] = None

        self._connected_device = None

        # ВАЖНО:
        # Это постоянный ID текущего подключённого USB.
        # При disconnect используется именно он.
        self._connected_device_id: Optional[
            str
        ] = None

        self._last_result: Optional[
            BridgeResult
        ] = None

        self._sync_in_progress = False

    # ========================================================
    # MANAGERS
    # ========================================================

    def _ensure_managers(
        self,
    ) -> None:
        """
        Создаёт DeviceManager и SyncManager,
        если они не переданы извне.
        """

        # ----------------------------------------------------
        # DEVICE MANAGER
        # ----------------------------------------------------

        if self.device_manager is None:

            try:

                from .device_manager import (
                    DeviceManager,
                )

            except ImportError:

                from device_manager import (
                    DeviceManager,
                )

            self.device_manager = (
                DeviceManager()
            )

        # ----------------------------------------------------
        # SYNC MANAGER
        # ----------------------------------------------------

        if self.sync_manager is None:

            try:

                from .sync_manager import (
                    SyncManager,
                )

            except ImportError:

                from sync_manager import (
                    SyncManager,
                )

            self.sync_manager = (
                SyncManager(

                    root_path=(
                        self.root_path
                    ),

                    device_manager=(
                        self.device_manager
                    ),
                )
            )

    # ========================================================
    # JSON
    # ========================================================

    @staticmethod
    def _read_json(
        path: Path,
    ) -> dict[str, Any]:

        try:

            if not path.exists():

                return {}

            with path.open(
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(
                    file
                )

            if isinstance(
                data,
                dict,
            ):

                return data

        except Exception:
            pass

        return {}

    # ========================================================
    # USB DEVICE ID
    # ========================================================

    def _get_usb_device_id(
        self,
        usb_device,
    ) -> str:
        """
        Получает постоянный ID JARVIS USB.

        Приоритет:

        1. JARVIS_USB_DEVICE.json
        2. manifest.json -> sync_device
        3. manifest.json -> config.sync.device_id
        4. volume serial
        5. UNKNOWN
        """

        jarvis_root = Path(
            usb_device.jarvis_root
        )

        # ----------------------------------------------------
        # 1. JARVIS_USB_DEVICE.json
        # ----------------------------------------------------

        marker = (
            jarvis_root
            / "JARVIS_USB_DEVICE.json"
        )

        marker_data = (
            self._read_json(
                marker
            )
        )

        device_id = str(
            marker_data.get(
                "device_id",
                "",
            )
        ).strip()

        if device_id:

            return device_id

        # ----------------------------------------------------
        # 2. manifest.json -> sync_device
        # ----------------------------------------------------

        manifest = (
            jarvis_root
            / "manifest.json"
        )

        manifest_data = (
            self._read_json(

manifest
            )
        )

        sync_device = (
            manifest_data.get(
                "sync_device"
            )
        )

        if isinstance(
            sync_device,
            dict,
        ):

            device_id = str(
                sync_device.get(
                    "device_id",
                    "",
                )
            ).strip()

            if device_id:

                return device_id

        # ----------------------------------------------------
        # 3. manifest.json -> config.sync.device_id
        # ----------------------------------------------------

        config = (
            manifest_data.get(
                "config"
            )
        )

        if isinstance(
            config,
            dict,
        ):

            sync = (
                config.get(
                    "sync"
                )
            )

            if isinstance(
                sync,
                dict,
            ):

                device_id = str(
                    sync.get(
                        "device_id",
                        "",
                    )
                ).strip()

                if device_id:

                    return device_id

        # ----------------------------------------------------
        # 4. Volume serial
        # ----------------------------------------------------

        serial = str(
            getattr(
                usb_device,
                "volume_serial",
                "",
            )
        ).strip()

        if serial:

            return (
                "JARVIS-USB-"
                + serial.upper()
            )

        # ----------------------------------------------------
        # 5. LAST RESORT
        # ----------------------------------------------------

        return (
            "JARVIS-USB-UNKNOWN"
        )

    # ========================================================
    # FIND PC
    # ========================================================

    def _find_pc_device(self):
        """
        Находит настоящий зарегистрированный ПК.

        НЕ использует строку "PC" как device_id.
        """

        self._ensure_managers()

        devices = (
            self.device_manager
            .find_by_type(
                PC_DEVICE_TYPE
            )
        )

        if not devices:

            return None

        # Сначала активный ПК.
        for device in devices:

            if device.active:

                return device

        # Если активного нет — первый.
        return devices[0]

    # ========================================================
    # FIND USB
    # ========================================================

    def _find_usb_device(
        self,
        usb_device_id: str,
    ):
        """
        Возвращает USB из DeviceManager.
        """

        self._ensure_managers()

        return (
            self.device_manager
            .get_device(
                usb_device_id
            )
        )

    # ========================================================
    # REGISTER USB
    # ========================================================

    def _register_usb_device(
        self,
        usb_device,
    ) -> str:
        """
        Регистрирует USB через реальный API
        DeviceManager.register_device().
        """

        self._ensure_managers()

        # ----------------------------------------------------
        # ID
        # ----------------------------------------------------

        device_id = (
            self._get_usb_device_id(
                usb_device
            )
        )

        # ----------------------------------------------------
        # ROOT
        # ----------------------------------------------------

        jarvis_root = (
            Path(
                usb_device.jarvis_root
            )
            .expanduser()
            .resolve()
        )


        # ----------------------------------------------------
        # NAME
        # ----------------------------------------------------

        name = str(
            getattr(
                usb_device,
                "label",
                "",
            )
            or "JARVIS USB"
        )

        # ----------------------------------------------------
        # EXISTING
        # ----------------------------------------------------

        existing = (
            self.device_manager
            .get_device(
                device_id
            )
        )

        # ----------------------------------------------------
        # NEW DEVICE
        # ----------------------------------------------------

        if existing is None:

            try:

                from .device_manager import (
                    DeviceInfo,
                )

            except ImportError:

                from device_manager import (
                    DeviceInfo,
                )

            now = utc_now()

            info = DeviceInfo(

                device_id=(
                    device_id
                ),

                device_type=(
                    USB_DEVICE_TYPE
                ),

                name=name,

                platform="Windows",

                architecture="x64",

                root_path=str(
                    jarvis_root
                ),

                created_at=now,

                last_seen=now,

                active=True,

                metadata={

                    "source": (
                        "USBDetector"
                    ),

                    "drive": str(
                        getattr(
                            usb_device,
                            "drive",
                            "",
                        )
                    ),

                    "volume_serial": str(
                        getattr(
                            usb_device,
                            "volume_serial",
                            "",
                        )
                    ),

                    "product_name": str(
                        getattr(
                            usb_device,
                            "product_name",
                            "",
                        )
                    ),

                    "product_version": str(
                        getattr(
                            usb_device,
                            "product_version",
                            "",
                        )
                    ),

                    "jarvis_root": str(
                        jarvis_root
                    ),
                },
            )

            self.device_manager.register_device(
                info
            )

        # ----------------------------------------------------
        # EXISTING DEVICE
        # ----------------------------------------------------

        else:

            try:

                existing.root_path = (
                    str(jarvis_root)
                )

                existing.last_seen = (
                    utc_now()
                )

                existing.active = True

                if existing.metadata is None:

                    existing.metadata = {}

                existing.metadata.update({

                    "drive": str(
                        getattr(
                            usb_device,
                            "drive",
                            "",
                        )
                    ),

                    "volume_serial": str(
                        getattr(
                            usb_device,
                            "volume_serial",
                            "",
                        )
                    ),

                    "product_name": str(
                        getattr(
                            usb_device,
                            "product_name",
                            "",

)
                    ),

                    "product_version": str(
                        getattr(
                            usb_device,
                            "product_version",
                            "",
                        )
                    ),

                    "jarvis_root": str(
                        jarvis_root
                    ),

                    "source": (
                        "USBDetector"
                    ),
                })

                self.device_manager.register_device(
                    existing
                )

            except Exception:

                self.device_manager.update_last_seen(
                    device_id
                )

        # ----------------------------------------------------
        # SYNC STATE
        # ----------------------------------------------------

        self.sync_manager.register_device_in_state(

            device_id=(
                device_id
            ),

            device_type=(
                USB_DEVICE_TYPE
            ),

            name=name,
        )

        return device_id

    # ========================================================
    # CONNECTED CALLBACK
    # ========================================================

    def on_connected(
        self,
        usb_device,
    ) -> None:
        """
        Callback для USBDetector.
        """

        # ----------------------------------------------------
        # STORE DEVICE
        # ----------------------------------------------------

        with self._lock:

            self._connected_device = (
                usb_device
            )

        print()

        print(
            f"[{MODULE_NAME}] "
            "JARVIS USB подключена."
        )

        print(
            f"[{MODULE_NAME}] "
            f"Root: "
            f"{getattr(usb_device, 'jarvis_root', '')}"
        )

        # ----------------------------------------------------
        # REGISTER
        # ----------------------------------------------------

        try:

            device_id = (
                self._register_usb_device(
                    usb_device
                )
            )

        except Exception as exc:

            result = BridgeResult(

                success=False,

                status=(
                    STATUS_FAILED
                ),

                message=(
                    "JARVIS USB найдена, "
                    "но регистрация устройства "
                    "не удалась."
                ),

                device_name=(
                    "JARVIS USB"
                ),

                jarvis_root=str(
                    getattr(
                        usb_device,
                        "jarvis_root",
                        "",
                    )
                ),

                finished_at=(
                    utc_now()
                ),

                error=str(
                    exc
                ),
            )

            with self._lock:

                self._last_result = (
                    result
                )

            print(
                f"[{MODULE_NAME}] "
                f"ERROR: {exc}"
            )

            return

        # ----------------------------------------------------
        # STORE REAL CONNECTED ID
        # ----------------------------------------------------

        with self._lock:

            self._connected_device_id = (
                device_id
            )

        print(
            f"[{MODULE_NAME}] "
            f"USB Device ID: {device_id}"
        )

        # ----------------------------------------------------
        # AUTO SYNC OFF
        # ----------------------------------------------------

        if not self.auto_sync:

            result = BridgeResult(

                success=True,

                status=(
                    STATUS_CONNECTED
                ),

                message=(

                    "JARVIS USB подключена. "
                    "Автосинхронизация отключена."
                ),

                device_id=(
                    device_id
                ),

                device_name=(
                    "JARVIS USB"
                ),

                jarvis_root=str(
                    usb_device.jarvis_root
                ),

                finished_at=(
                    utc_now()
                ),
            )

            with self._lock:

                self._last_result = (
                    result
                )

            print(
                f"[{MODULE_NAME}] "
                "Auto Sync: OFF"
            )

            return

        # ----------------------------------------------------
        # AUTO SYNC
        # ----------------------------------------------------

        self.start_sync(
            device_id
        )

    # ========================================================
    # DISCONNECTED CALLBACK
    # ========================================================

    def on_disconnected(
        self,
        usb_device,
    ) -> None:
        """
        Callback для отключения USB.

        ВАЖНО:
        ID берётся из сохранённого
        _connected_device_id.

        Мы НЕ вычисляем ID заново через
        volume serial, потому что это могло бы
        дать другой идентификатор.
        """

        # ----------------------------------------------------
        # GET SAVED ID
        # ----------------------------------------------------

        with self._lock:

            device_id = (
                self._connected_device_id
            )

            connected_device = (
                self._connected_device
            )

        # ----------------------------------------------------
        # FALLBACK
        # ----------------------------------------------------
        #
        # Используем вычисление только если
        # сохранённого ID почему-то нет.
        #

        if not device_id:

            try:

                device_id = (
                    self._get_usb_device_id(
                        usb_device
                    )
                )

            except Exception:

                device_id = None

        # ----------------------------------------------------
        # DEVICE MANAGER
        # ----------------------------------------------------

        if (
            device_id
            and self.device_manager
            is not None
        ):

            try:

                self.device_manager.set_active(
                    device_id,
                    False,
                )

            except Exception:
                pass

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        result = BridgeResult(

            success=True,

            status=(
                STATUS_DISCONNECTED
            ),

            message=(
                "JARVIS USB отключена."
            ),

            device_id=(
                device_id
            ),

            device_name=(
                "JARVIS USB"
            ),

            jarvis_root=(
                str(
                    getattr(
                        usb_device,
                        "jarvis_root",
                        "",
                    )
                )
            ),

            finished_at=(
                utc_now()
            ),
        )

        # ----------------------------------------------------
        # CLEAR RUNTIME
        # ----------------------------------------------------

        with self._lock:

            self._connected_device = (
                None
            )

            self._connected_device_id = (
                None
            )

            self._last_result = (
                result
            )

        # ----------------------------------------------------
        # OUTPUT
        # ----------------------------------------------------

        print()

        print(
            f"[{MODULE_NAME}] "
            "JARVIS USB отключена."
        )

        if device_id:

            print(
                f"[{MODULE_NAME}] "
                f"USB Device ID: {device_id}"
            )

    # ========================================================
    # START SYNC
    # ========================================================

    def start_sync(
        self,
        usb_device_id: str,
    ) -> bool:
        """
        Запускает синхронизацию
        в отдельном потоке.
        """

        with self._lock:

            if self._sync_in_progress:

                print(
                    f"[{MODULE_NAME}] "
                    "Синхронизация уже выполняется."
                )

                return False

            self._sync_in_progress = (
                True
            )

        self._sync_thread = (
            threading.Thread(

                target=(
                    self._sync_worker
                ),

                args=(
                    usb_device_id,
                ),

                name=(
                    "JARVIS-USBSync"
                ),

                daemon=True,
            )
        )

        self._sync_thread.start()

        return True

    # ========================================================
    # SYNC WORKER
    # ========================================================

    def _sync_worker(
        self,
        usb_device_id: str,
    ) -> None:
        """
        Выполняет PC → USB.
        """

        started_at = (
            utc_now()
        )

        try:

            self._ensure_managers()

            # ------------------------------------------------
            # FIND REAL PC
            # ------------------------------------------------

            pc_device = (
                self._find_pc_device()
            )

            if pc_device is None:

                raise RuntimeError(
                    "Зарегистрированное "
                    "устройство типа PC "
                    "не найдено."
                )

            # ------------------------------------------------
            # CHECK USB
            # ------------------------------------------------

            usb_device = (
                self._find_usb_device(
                    usb_device_id
                )
            )

            if usb_device is None:

                raise RuntimeError(
                    "JARVIS USB не найдена "
                    "в DeviceManager."
                )

            # ------------------------------------------------
            # ROOTS
            # ------------------------------------------------

            pc_root = Path(
                pc_device.root_path
            ).resolve()

            usb_root = Path(
                usb_device.root_path
            ).resolve()

            # ------------------------------------------------
            # OUTPUT
            # ------------------------------------------------

            print()

            print(
                f"[{MODULE_NAME}] "
                "========================================"
            )

            print(
                f"[{MODULE_NAME}] "
                "USB SYNC START"
            )

            print(
                f"[{MODULE_NAME}] "
                f"PC: {pc_device.device_id}"
            )

            print(
                f"[{MODULE_NAME}] "
                f"USB: {usb_device_id}"
            )

            print(
                f"[{MODULE_NAME}] "
                f"PC Root: {pc_root}"
            )

            print(
                f"[{MODULE_NAME}] "
                f"USB Root: {usb_root}"
            )

            print(
                f"[{MODULE_NAME}] "
                "========================================"
            )

            # ------------------------------------------------
            # SYNC
            # ------------------------------------------------

            result = (
                self.sync_manager.sync(

                    source_device=(
                        pc_device.device_id
                    ),

                    target_device=(
                        usb_device_id
                    ),
                )
            )

            # ------------------------------------------------
            # RESULT DICT
            # ------------------------------------------------

            if hasattr(
                result,
                "to_dict",
            ):

                result_dict = (
                    result.to_dict()
                )

            else:

                raw_dict = getattr(
                    result,
                    "__dict__",
                    None,
                )

                result_dict = (
                    dict(raw_dict)
                    if isinstance(
                        raw_dict,
                        dict,
                    )
                    else None
                )

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            success = bool(
                getattr(
                    result,
                    "success",
                    False,
                )
            )

            status = str(
                getattr(
                    result,
                    "status",
                    (
                        STATUS_COMPLETED
                        if success
                        else STATUS_FAILED
                    ),
                )
            )

            if success:

                message = (
                    "Синхронизация "
                    "PC → USB завершена."
                )

            else:

                message = (
                    "Синхронизация "
                    "PC → USB завершилась "
                    "с ошибкой."
                )

            # ------------------------------------------------
            # BRIDGE RESULT
            # ------------------------------------------------

            with self._lock:

                connected = (
                    self._connected_device
                )

            bridge_result = BridgeResult(

                success=(
                    success
                ),

                status=(
                    status
                ),

                message=(
                    message
                ),

                device_id=(
                    usb_device_id
                ),

                device_name=(
                    "JARVIS USB"
                ),

                jarvis_root=(

                    str(
                        connected.jarvis_root
                    )

                    if connected is not None

                    else str(
                        usb_root
                    )
                ),

                started_at=(
                    started_at
                ),

                finished_at=(
                    utc_now()
                ),

                sync_result=(
                    result_dict
                ),
            )

            with self._lock:

                self._last_result = (
                    bridge_result
                )

            # ------------------------------------------------
            # OUTPUT
            # ------------------------------------------------

            print()

            if success:

                print(
                    f"[{MODULE_NAME}] "
                    "========================================"
                )

                print(
                    f"[{MODULE_NAME}] "
                    "SYNC COMPLETE"
                )

                print(
                    f"[{MODULE_NAME}] "
                    "PC → USB"
                )

                print(


f"[{MODULE_NAME}] "
                    "========================================"
                )

            else:

                print(
                    f"[{MODULE_NAME}] "
                    "SYNC FAILED"
                )

                errors = getattr(
                    result,
                    "error_messages",
                    [],
                )

                for error in (
                    errors or []
                ):

                    print(
                        f"[{MODULE_NAME}] "
                        f"ERROR: {error}"
                    )

        except Exception as exc:

            bridge_result = BridgeResult(

                success=False,

                status=(
                    STATUS_FAILED
                ),

                message=(
                    "Ошибка синхронизации "
                    "PC → USB."
                ),

                device_id=(
                    usb_device_id
                ),

                device_name=(
                    "JARVIS USB"
                ),

                started_at=(
                    started_at
                ),

                finished_at=(
                    utc_now()
                ),

                error=str(
                    exc
                ),
            )

            with self._lock:

                self._last_result = (
                    bridge_result
                )

            print()

            print(
                f"[{MODULE_NAME}] "
                f"SYNC ERROR: {exc}"
            )

        finally:

            with self._lock:

                self._sync_in_progress = (
                    False
                )

    # ========================================================
    # STATUS
    # ========================================================

    def is_syncing(
        self,
    ) -> bool:

        with self._lock:

            return (
                self._sync_in_progress
            )

    # ========================================================
    # LAST RESULT
    # ========================================================

    def get_last_result(
        self,
    ) -> Optional[BridgeResult]:

        with self._lock:

            return (
                self._last_result
            )

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(
        self,
    ) -> dict[str, Any]:

        with self._lock:

            device = (
                self._connected_device
            )

            result = (
                self._last_result
            )

            return {

                "module": (
                    MODULE_NAME
                ),

                "version": (
                    MODULE_VERSION
                ),

                "auto_sync": (
                    self.auto_sync
                ),

                "sync_in_progress": (
                    self._sync_in_progress
                ),

                "usb_connected": (
                    device is not None
                ),

                "usb_device_id": (
                    self._connected_device_id
                ),

                "usb_root": (

                    str(
                        device.jarvis_root
                    )

                    if device is not None

                    else None
                ),

                "last_result": (

                    result.to_dict()

                    if result is not None

                    else None
                ),
            }

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(
        self,
    ) -> bool:
        """
        Безопасный self-test.

        НЕ запускает реальную синхронизацию.
        НЕ изменяет пользовательские файлы.
        """

        try:


            # ------------------------------------------------
            # ROOT
            # ------------------------------------------------

            if not self.root_path.exists():

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: root_path не существует."
                )

                return False

            # ------------------------------------------------
            # MANAGERS
            # ------------------------------------------------

            self._ensure_managers()

            if self.device_manager is None:

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: DeviceManager."
                )

                return False

            if self.sync_manager is None:

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: SyncManager."
                )

                return False

            # ------------------------------------------------
            # API CHECK
            # ------------------------------------------------

            if not callable(
                getattr(
                    self.device_manager,
                    "register_device",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: DeviceManager.register_device()."
                )

                return False

            if not callable(
                getattr(
                    self.device_manager,
                    "get_device",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: DeviceManager.get_device()."
                )

                return False

            if not callable(
                getattr(
                    self.device_manager,
                    "find_by_type",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: DeviceManager.find_by_type()."
                )

                return False

            if not callable(
                getattr(
                    self.device_manager,
                    "set_active",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: DeviceManager.set_active()."
                )

                return False

            if not callable(
                getattr(
                    self.sync_manager,
                    "sync",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: SyncManager.sync()."
                )

                return False

            if not callable(
                getattr(
                    self.sync_manager,
                    "register_device_in_state",
                    None,
                )
            ):

                print(
                    f"[{MODULE_NAME}] "
                    "FAIL: SyncManager.register_device_in_state()."
                )

                return False

            # ------------------------------------------------
            # OK
            # ------------------------------------------------

            print(
                f"[{MODULE_NAME}] "
                "Self-test: OK"
            )

            return True

        except Exception as exc:

            print(
                f"[{MODULE_NAME}] "
                f"Self-test FAILED: {exc}"
            )

            return False


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print(
        "=" * 70
    )

    print(
        "JARVIS V11 - USB Sync Bridge"
    )

    print(


f"Version: {MODULE_VERSION}"
    )

    print(
        "=" * 70
    )

    print()

    bridge = (
        USBSyncBridge(
            auto_sync=False
        )
    )

    result = (
        bridge.self_test()
    )

    print()

    if result:

        print(
            "[+] USB Sync Bridge: OK"
        )

    else:

        print(
            "[-] USB Sync Bridge: FAILED"
        )