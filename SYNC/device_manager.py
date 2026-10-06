"""
JARVIS V11 — Device Manager
============================

Управление устройствами экосистемы JARVIS.

Поддерживаемые типы:
    - PC
    - USB
    - MOBILE

Модуль не выполняет синхронизацию сам.
Он отвечает только за определение и хранение информации
об устройствах.

Версия: 1.0.0
"""

from __future__ import annotations

import json
import os
import platform
import socket
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# CONSTANTS
# ============================================================

MODULE_VERSION = "1.0.0"

DEVICE_PC = "PC"
DEVICE_USB = "USB"
DEVICE_MOBILE = "MOBILE"

SUPPORTED_DEVICE_TYPES = {
    DEVICE_PC,
    DEVICE_USB,
    DEVICE_MOBILE,
}


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """Возвращает текущее время в UTC в ISO-формате."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: Path) -> str:
    """Приводит путь к нормальному абсолютному виду."""
    return str(path.expanduser().resolve())


def generate_device_id(device_type: str) -> str:
    """
    Создаёт стабильный ID устройства.

    Для ПК используется комбинация:
        hostname + MAC

    Для USB/MOBILE при отсутствии постоянного ID
    используется UUID.
    """

    device_type = device_type.upper()

    hostname = socket.gethostname()

    try:
        mac = uuid.getnode()
    except Exception:
        mac = 0

    if device_type == DEVICE_PC:
        raw = f"JARVIS-{device_type}-{hostname}-{mac}"
    else:
        raw = f"JARVIS-{device_type}-{uuid.uuid4()}"

    # Убираем потенциально проблемные символы.
    safe = "".join(
        char if char.isalnum() or char in "-_" else "_"
        for char in raw
    )

    return safe


# ============================================================
# DEVICE INFO
# ============================================================

@dataclass
class DeviceInfo:
    """
    Информация об одном устройстве.
    """

    device_id: str
    device_type: str
    name: str

    platform: str
    architecture: str

    root_path: str

    created_at: str
    last_seen: str

    active: bool = True
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует объект в словарь."""
        data = asdict(self)

        if data["metadata"] is None:
            data["metadata"] = {}

        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceInfo":
        """Создаёт DeviceInfo из словаря."""
        return cls(
            device_id=str(data.get("device_id", "")),
            device_type=str(data.get("device_type", "")),
            name=str(data.get("name", "")),
            platform=str(data.get("platform", "")),
            architecture=str(data.get("architecture", "")),
            root_path=str(data.get("root_path", "")),
            created_at=str(data.get("created_at", utc_now())),
            last_seen=str(data.get("last_seen", utc_now())),
            active=bool(data.get("active", True)),
            metadata=data.get("metadata") or {},
        )


# ============================================================
# DEVICE MANAGER
# ============================================================

class DeviceManager:
    """
    Управляет устройствами JARVIS.

    Ответственность:
        - регистрация устройств;
        - удаление устройств;
        - поиск устройств;
        - определение текущего устройства;
        - сохранение списка устройств;
        - загрузка списка устройств;
        - обновление last_seen;
        - определение типа текущего устройства.
    """

    def __init__(
        self,
        storage_path: Optional[str | Path] = None,
        logger: Any = None,
    ) -> None:

        self.logger = logger

        # ----------------------------------------------------
        # STORAGE
        # ----------------------------------------------------

        if storage_path is None:
            self.storage_path = (
                Path(__file__).resolve().parent
                / "devices.json"
            )
        else:
            self.storage_path = Path(storage_path).expanduser().resolve()

        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # STATE
        # ----------------------------------------------------

        self.devices: Dict[str, DeviceInfo] = {}

        self.current_device: Optional[DeviceInfo] = None

        # ----------------------------------------------------
        # LOAD
        # ----------------------------------------------------

        self.load()

        # ----------------------------------------------------
        # CURRENT DEVICE
        # ----------------------------------------------------

        self.current_device = self.detect_current_device()

        if self.current_device is not None:
            self.register_device(self.current_device)

    # ========================================================
    # LOGGING
    # ========================================================

    def _log(
        self,
        level: str,
        message: str,
        *args: Any,
    ) -> None:
        """Безопасное логирование."""

        if self.logger is None:
            return

        method = getattr(
            self.logger,
            level,
            None,
        )

        if callable(method):
            try:
                method(message, *args)
            except Exception:
                pass

    # ========================================================
    # DEVICE DETECTION
    # ========================================================

    def detect_device_type(
        self,
        root_path: Optional[str | Path] = None,
    ) -> str:
        """
        Определяет тип устройства.

        Приоритет:
            JARVIS_USB_ROOT -> USB
            Android -> MOBILE
            иначе -> PC
        """

        # ----------------------------------------------------
        # EXPLICIT PORTABLE MODE
        # ----------------------------------------------------

        portable_root = os.environ.get(
            "JARVIS_USB_ROOT"
        )

        if portable_root:
            return DEVICE_USB

        # ----------------------------------------------------
        # ANDROID
        # ----------------------------------------------------

        system = platform.system().lower()

        if system == "android":
            return DEVICE_MOBILE

        # ----------------------------------------------------
        # DEFAULT
        # ----------------------------------------------------

        return DEVICE_PC

    # ========================================================

    def detect_current_device(self) -> Optional[DeviceInfo]:
        """
        Определяет текущее устройство и создаёт DeviceInfo.
        """

        try:
            device_type = self.detect_device_type()

            hostname = socket.gethostname()

            system_name = platform.system()
            system_release = platform.release()

            architecture = platform.machine()

            # ------------------------------------------------
            # ROOT
            # ------------------------------------------------

            portable_root = os.environ.get(
                "JARVIS_USB_ROOT"
            )

            if portable_root:
                root_path = Path(portable_root)
            else:
                root_path = Path(__file__).resolve().parents[1]

            root_path = root_path.resolve()

            # ------------------------------------------------
            # NAME
            # ------------------------------------------------

            if device_type == DEVICE_PC:
                name = f"JARVIS PC ({hostname})"

            elif device_type == DEVICE_USB:
                name = "JARVIS USB"

            else:
                name = "JARVIS Mobile"

            # ------------------------------------------------
            # EXISTING DEVICE ID
            # ------------------------------------------------

            existing_id = self._find_existing_device_id(
                device_type=device_type,
                root_path=root_path,
            )

            if existing_id:
                device_id = existing_id
            else:
                device_id = generate_device_id(
                    device_type
                )

            # ------------------------------------------------
            # METADATA
            # ------------------------------------------------

            metadata = {
                "hostname": hostname,
                "system": system_name,
                "release": system_release,
                "python": platform.python_version(),
                "machine": architecture,
                "module_version": MODULE_VERSION,
            }

            return DeviceInfo(
                device_id=device_id,
                device_type=device_type,
                name=name,
                platform=system_name,
                architecture=architecture,
                root_path=normalize_path(root_path),
                created_at=utc_now(),
                last_seen=utc_now(),
                active=True,
                metadata=metadata,
            )

        except Exception as exc:
            self._log(
                "error",
                "Не удалось определить текущее устройство: %s",
                exc,
            )

            return None

    # ========================================================
    # FIND EXISTING DEVICE
    # ========================================================

    def _find_existing_device_id(
        self,
        device_type: str,
        root_path: Path,
    ) -> Optional[str]:
        """Ищет уже зарегистрированное устройство."""

        normalized_root = normalize_path(
            root_path
        )

        for device in self.devices.values():

            if (
                device.device_type == device_type
                and normalize_path(
                    Path(device.root_path)
                ) == normalized_root
            ):
                return device.device_id

        return None

    # ========================================================
    # REGISTER
    # ========================================================

    def register_device(
        self,
        device: DeviceInfo,
    ) -> DeviceInfo:
        """
        Регистрирует устройство.

        Если устройство уже существует,
        обновляет его информацию.
        """

        if device.device_type not in SUPPORTED_DEVICE_TYPES:
            raise ValueError(
                f"Неподдерживаемый тип устройства: "
                f"{device.device_type}"
            )

        existing = self.devices.get(
            device.device_id
        )

        if existing is not None:

            device.created_at = (
                existing.created_at
            )

        device.last_seen = utc_now()
        device.active = True

        self.devices[
            device.device_id
        ] = device

        self.save()

        self._log(
            "info",
            "Устройство зарегистрировано: %s (%s)",
            device.name,
            device.device_type,
        )

        return device

    # ========================================================
    # REMOVE
    # ========================================================

    def remove_device(
        self,
        device_id: str,
    ) -> bool:
        """Удаляет устройство из списка."""

        if device_id not in self.devices:


         return False

        device = self.devices.pop(
            device_id
        )

        self.save()

        self._log(
            "info",
            "Устройство удалено: %s",
            device.name,
        )

        if (
            self.current_device is not None
            and self.current_device.device_id
            == device_id
        ):
            self.current_device = None

        return True

    # ========================================================
    # GET DEVICE
    # ========================================================

    def get_device(
        self,
        device_id: str,
    ) -> Optional[DeviceInfo]:
        """Возвращает устройство по ID."""
        return self.devices.get(device_id)

    # ========================================================
    # GET ALL
    # ========================================================

    def get_devices(
        self,
        device_type: Optional[str] = None,
        active_only: bool = False,
    ) -> List[DeviceInfo]:
        """
        Возвращает список устройств.

        Можно фильтровать:
            device_type
            active_only
        """

        result: List[DeviceInfo] = []

        for device in self.devices.values():

            if (
                device_type is not None
                and device.device_type
                != device_type.upper()
            ):
                continue

            if (
                active_only
                and not device.active
            ):
                continue

            result.append(device)

        return result

    # ========================================================
    # CURRENT DEVICE
    # ========================================================

    def get_current_device(
        self,
    ) -> Optional[DeviceInfo]:
        """Возвращает текущее устройство."""

        return self.current_device

    # ========================================================
    # UPDATE LAST SEEN
    # ========================================================

    def update_last_seen(
        self,
        device_id: str,
    ) -> bool:
        """Обновляет время последнего обнаружения."""

        device = self.devices.get(
            device_id
        )

        if device is None:
            return False

        device.last_seen = utc_now()
        device.active = True

        self.save()

        return True

    # ========================================================
    # SET ACTIVE
    # ========================================================

    def set_active(
        self,
        device_id: str,
        active: bool,
    ) -> bool:
        """Изменяет статус устройства."""

        device = self.devices.get(
            device_id
        )

        if device is None:
            return False

        device.active = active

        if active:
            device.last_seen = utc_now()

        self.save()

        return True

    # ========================================================
    # FIND BY TYPE
    # ========================================================

    def find_by_type(
        self,
        device_type: str,
    ) -> List[DeviceInfo]:
        """Возвращает устройства указанного типа."""

        return self.get_devices(
            device_type=device_type
        )

    # ========================================================
    # FIND BY NAME
    # ========================================================

    def find_by_name(
        self,
        name: str,
    ) -> Optional[DeviceInfo]:
        """Ищет устройство по имени."""

        search = name.strip().lower()

        for device in self.devices.values():

            if device.name.lower() == search:
                return device

        return None

    # ========================================================
    # DEVICE EXISTS
    # ========================================================

    def device_exists(
        self,
        device_id: str,

) -> bool:
        """Проверяет существование устройства."""
        return device_id in self.devices

    # ========================================================
    # SAVE
    # ========================================================

    def save(self) -> None:
        """Сохраняет устройства в JSON."""

        data = {
            "module_version": MODULE_VERSION,
            "updated_at": utc_now(),
            "devices": [
                device.to_dict()
                for device in self.devices.values()
            ],
        }

        temp_path = self.storage_path.with_suffix(
            ".tmp"
        )

        try:

            with temp_path.open(
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    data,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

            temp_path.replace(
                self.storage_path
            )

        except Exception as exc:

            self._log(
                "error",
                "Ошибка сохранения устройств: %s",
                exc,
            )

            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass

    # ========================================================
    # LOAD
    # ========================================================

    def load(self) -> None:
        """Загружает устройства из JSON."""

        if not self.storage_path.exists():
            return

        try:

            with self.storage_path.open(
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(file)

            devices = data.get(
                "devices",
                [],
            )

            self.devices.clear()

            for item in devices:

                try:

                    device = DeviceInfo.from_dict(
                        item
                    )

                    if (
                        device.device_type
                        in SUPPORTED_DEVICE_TYPES
                    ):
                        self.devices[
                            device.device_id
                        ] = device

                except Exception:
                    continue

        except (
            json.JSONDecodeError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:

            self._log(
                "error",
                "Ошибка загрузки устройств: %s",
                exc,
            )

    # ========================================================
    # EXPORT
    # ========================================================

    def export_data(self) -> Dict[str, Any]:
        """Возвращает состояние менеджера."""

        return {
            "module_version": MODULE_VERSION,
            "current_device": (
                self.current_device.to_dict()
                if self.current_device
                else None
            ),
            "devices": [
                device.to_dict()
                for device in self.devices.values()
            ],
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> Dict[str, Any]:
        """Возвращает краткий статус."""

        current = self.current_device

        return {
            "module": "DeviceManager",
            "version": MODULE_VERSION,
            "device_count": len(self.devices),
            "current_device": (
                current.name
                if current
                else None
            ),
            "current_device_type": (
                current.device_type
                if current
                else None
            ),
            "storage_path": normalize_path(
                self.storage_path
),
        }


# ============================================================
# SELF TEST
# ============================================================

def self_test() -> bool:
    """
    Минимальный тест модуля.

    Не изменяет основной devices.json:
    используется временный файл.
    """

    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:

        storage = (
            Path(temp_dir)
            / "devices.json"
        )

        manager = DeviceManager(
            storage_path=storage
        )

        current = (
            manager.get_current_device()
        )

        if current is None:
            return False

        if (
            current.device_type
            not in SUPPORTED_DEVICE_TYPES
        ):
            return False

        manager.save()

        second_manager = DeviceManager(
            storage_path=storage
        )

        loaded = (
            second_manager.get_device(
                current.device_id
            )
        )

        if loaded is None:
            return False

        if (
            loaded.device_type
            != current.device_type
        ):
            return False

        return True


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    manager = DeviceManager()

    print("\n=== REGISTERED DEVICES ===")

    for device in manager.get_devices():
        print(
            device.device_id,
            "|",
            device.device_type,
            "|",
            device.name,
            "|",
            device.root_path,
        )

    print("=" * 70)
    print("JARVIS V11 — DEVICE MANAGER")
    print("=" * 70)

    try:

        result = self_test()

        if result:

            print("[+] Self-test: OK")

            manager = DeviceManager()

            print()
            print(
                "[+] Текущее устройство:"
            )

            current = (
                manager.get_current_device()
            )

            if current:

                print(
                    f"    ID: {current.device_id}"
                )

                print(
                    f"    Тип: {current.device_type}"
                )

                print(
                    f"    Имя: {current.name}"
                )

                print(
                    f"    Root: {current.root_path}"
                )

                print(
                    f"    Platform: {current.platform}"
                )

                print(
                    f"    Architecture: "
                    f"{current.architecture}"
                )

            print()
            print(
                f"[+] Зарегистрировано устройств: "
                f"{len(manager.devices)}"
            )

            print()
            print("STATUS:")

            print(
                json.dumps(
                    manager.status(),
                    ensure_ascii=False,
                    indent=4,
                )
            )

        else:

            print(
                "[X] Self-test: FAILED"
            )

    except Exception as exc:

        print(
            f"[X] Ошибка: {exc}"
        )

        raise