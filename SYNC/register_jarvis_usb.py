# -*- coding: utf-8 -*-

"""
JARVIS V11
JARVIS USB Registration Tool v1.0

Назначение:
    Однократно зарегистрировать физический JARVIS USB
    в системе SYNC.

Что делает:
    1. Ищет подключённый JARVIS USB.
    2. Проверяет manifest.json.
    3. Проверяет структуру JARVIS USB.
    4. Создаёт уникальный device_id, если его ещё нет.
    5. Добавляет sync_device в manifest.json.
    6. Регистрирует устройство через DeviceManager.

Что НЕ делает:
    - не форматирует флешку;
    - не удаляет файлы;
    - не копирует весь JARVIS;
    - не запускает синхронизацию;
    - не включает Security;
    - не изменяет существующие данные manifest.json,
      кроме добавления/обновления блока sync_device.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import string
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List


# ============================================================
# CONSTANTS
# ============================================================

MODULE_NAME = "register_jarvis_usb"
MODULE_VERSION = "1.0.0"

MANIFEST_FILENAME = "manifest.json"

JARVIS_USB_TYPE = "JARVIS_USB"

SYNC_DEVICE_KEY = "sync_device"

DEVICE_ID_KEY = "device_id"
DEVICE_TYPE_KEY = "device_type"

EXPECTED_PATHS = (
    "JARVIS_USB.exe",
    "CONFIG",
    "DATA",
    "MODELS",
)

MIN_STRUCTURE_MATCHES = 2


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """
    Возвращает текущее UTC-время в ISO формате.
    """

    return datetime.now(
        timezone.utc
    ).isoformat()


def get_project_root() -> Path:
    """
    Определяет корень JARVIS_V11.

    Файл находится:
        JARVIS_V11/
        └── JARVIS_V11/
            └── SYNC/
                └── register_jarvis_usb.py

    Поэтому:
        parent      -> SYNC
        parent.parent -> JARVIS_V11
    """

    env_root = os.environ.get(
        "JARVIS_ROOT"
    )

    if env_root:
        return Path(env_root).resolve()

    return (
        Path(__file__)
        .resolve()
        .parent
        .parent
    )


def get_windows_drives() -> List[Path]:
    """
    Возвращает список доступных дисков Windows.
    """

    if os.name != "nt":
        return []

    drives: List[Path] = []

    for letter in string.ascii_uppercase:

        drive = Path(
            f"{letter}:\\"
        )

        try:

            if drive.exists() and drive.is_dir():
                drives.append(
                    drive.resolve()
                )

        except Exception:
            continue

    return drives


def load_json(
    path: Path
) -> Optional[dict]:
    """
    Безопасно загружает JSON.
    """

    try:

        with path.open(
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if isinstance(data, dict):
            return data

    except Exception as exc:

        print(
            f"[!] Не удалось прочитать {path}: {exc}"
        )

    return None


def save_json_atomic(
    path: Path,
    data: dict
) -> bool:
    """
    Безопасно сохраняет JSON через временный файл.

    Старый manifest.json остаётся целым,
    пока новый файл не будет успешно записан.
    """

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:

        with temp_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                data,
                file,
                ensure_ascii=False,
                indent=4
            )

            file.write("\n")

        os.replace(
            temp_path,
            path
        )

        return True

    except Exception as exc:

        print(
            f"[!] Ошибка сохранения {path}: {exc}"
        )

        try:

            if temp_path.exists():
                temp_path.unlink()

        except Exception:
            pass

        return False


# ============================================================
# JARVIS USB DETECTION
# ============================================================

def check_structure(
    root: Path
) -> bool:
    """
    Проверяет структуру JARVIS USB.
    """

    matches = 0

    for relative_path in EXPECTED_PATHS:

        path = root / relative_path

        try:

            if path.exists():
                matches += 1

        except Exception:
            pass

    return matches >= MIN_STRUCTURE_MATCHES


def is_jarvis_usb(
    root: Path
) -> bool:
    """
    Проверяет, похож ли накопитель на JARVIS USB.

    ВАЖНО:
        Этот метод НЕ изменяет файлы.
    """

    manifest_path = (
        root / MANIFEST_FILENAME
    )

    if not manifest_path.is_file():
        return False

    manifest = load_json(
        manifest_path
    )

    if not manifest:
        return False

    # --------------------------------------------------------
    # Product check
    # --------------------------------------------------------

    product = manifest.get(
        "product"
    )

    if isinstance(product, dict):

        product_name = str(
            product.get(
                "name",
                ""
            )
        ).strip().upper()

        if "JARVIS USB" in product_name:
            return True

    # --------------------------------------------------------
    # Existing sync_device check
    # --------------------------------------------------------

    sync_device = manifest.get(
        SYNC_DEVICE_KEY
    )

    if isinstance(sync_device, dict):

        device_type = str(
            sync_device.get(
                DEVICE_TYPE_KEY,
                ""
            )
        ).strip().upper()

        if device_type == JARVIS_USB_TYPE:
            return True

    # --------------------------------------------------------
    # Structure fallback
    # --------------------------------------------------------

    return check_structure(
        root
    )


def find_jarvis_usb() -> Optional[Path]:
    """
    Ищет JARVIS USB среди подключённых дисков.

    Если найдено несколько подходящих устройств,
    возвращает None, чтобы случайно не выбрать не ту флешку.
    """

    candidates: List[Path] = []

    # --------------------------------------------------------
    # Portable environment
    # --------------------------------------------------------

    env_usb_root = os.environ.get(
        "JARVIS_USB_ROOT"
    )

    if env_usb_root:

        root = Path(
            env_usb_root
        )

        try:

            if (
                root.exists()
                and root.is_dir()
                and is_jarvis_usb(root)
            ):
                candidates.append(
                    root.resolve()
                )

        except Exception:
            pass

    # --------------------------------------------------------
    # Windows drives
    # --------------------------------------------------------

    for drive in get_windows_drives():

        try:

            if is_jarvis_usb(drive):

                resolved = drive.resolve()

                if resolved not in candidates:
                    candidates.append(
                        resolved
                    )

        except Exception:
            continue

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    if len(candidates) == 0:
        return None

    if len(candidates) > 1:

        print()
        print(
            "[!] Найдено несколько JARVIS USB:"
        )

        for candidate in candidates:
            print(
                f"    - {candidate}"
            )

        print()
        print(
            "[!] Автоматическая регистрация отменена."
        )

        return None

    return candidates[0]


# ============================================================
# DEVICE ID
# ============================================================

def generate_device_id() -> str:
    """
    Создаёт уникальный постоянный ID.

    Формат:

        JARVIS-USB-XXXXXXXX

    UUID используется только для генерации.
    После записи ID больше не меняется.
    """

    random_part = (
        uuid.uuid4()
        .hex
        .upper()[:16]
    )

    return (
        f"JARVIS-USB-{random_part}"
    )


# ============================================================
# MANIFEST REGISTRATION
# ============================================================

def register_manifest(
    usb_root: Path,
    device_id: str
) -> bool:
    """
    Добавляет sync_device в manifest.json.

    Остальная структура manifest.json сохраняется.
    """

    manifest_path = (
        usb_root / MANIFEST_FILENAME
    )

    manifest = load_json(
        manifest_path
    )

    if manifest is None:
        return False

    # --------------------------------------------------------
    # Existing device
    # --------------------------------------------------------

    existing = manifest.get(
        SYNC_DEVICE_KEY
    )

    if isinstance(existing, dict):

        existing_id = str(
            existing.get(
                DEVICE_ID_KEY,
                ""
            )
        ).strip()

        existing_type = str(
            existing.get(
                DEVICE_TYPE_KEY,
                ""
            )
        ).strip().upper()

        if (
            existing_id
            and existing_type == JARVIS_USB_TYPE
        ):

            print()
            print(
                "[i] JARVIS USB уже зарегистрирован."
            )

            print(
                f"[i] Device ID: {existing_id}"
            )

            return True

    # --------------------------------------------------------
    # New sync device block
    # --------------------------------------------------------

    manifest[SYNC_DEVICE_KEY] = {
        DEVICE_ID_KEY: device_id,
        DEVICE_TYPE_KEY: JARVIS_USB_TYPE,
        "registered_at": utc_now(),
        "registration_version": MODULE_VERSION,
    }

    # --------------------------------------------------------
    # Update sync config if it exists
    # --------------------------------------------------------

    config = manifest.get(
        "config"
    )

    if isinstance(config, dict):

        sync_config = config.get(
            "sync"
        )

        if isinstance(sync_config, dict):

            sync_config[
                "enabled"
            ] = True

            sync_config[
                "mode"
            ] = "pc_usb"

            sync_config[
                "device_id"
            ] = device_id

        else:

            config["sync"] = {
                "enabled": True,
                "mode": "pc_usb",
                "device_id": device_id,
            }

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    print()
    print(
        "[i] Обновляем manifest.json..."
    )

    if not save_json_atomic(
        manifest_path,
        manifest
    ):

        return False

    print(
        "[+] manifest.json обновлён."
    )

    return True


# ============================================================
# DEVICE MANAGER
# ============================================================

def register_device_manager(
    project_root: Path,
    usb_root: Path,
    device_id: str
) -> bool:
    """
    Регистрирует устройство через DeviceManager.
    """

    try:

        # ----------------------------------------------------
        # Package import
        # ----------------------------------------------------

        try:

            from .device_manager import DeviceManager

        except ImportError:

            from device_manager import DeviceManager

        # ----------------------------------------------------
        # Create manager
        # ----------------------------------------------------

        manager = DeviceManager(
            project_root
        )

        # ----------------------------------------------------
        # Try common registration APIs.
        #
        # DeviceManager у нас уже существует,
        # но здесь делаем адаптацию к его API,
        # чтобы регистрация не зависела от одной
        # конкретной реализации метода.
        # ----------------------------------------------------

        registered = False

        register_method = getattr(
            manager,
            "register",
            None
        )

        if register_method:

            try:

                result = register_method(
                    device_id=device_id,
                    device_type=JARVIS_USB_TYPE,
                    name="JARVIS USB",
                    platform=platform.system(),
                    architecture=platform.machine(),
                    root_path=str(usb_root),
                    metadata={
                        "registered_by": MODULE_NAME,
                        "registered_at": utc_now(),
                        "portable": True,
                    },
                )

                registered = (
                    result is not False
                )

            except TypeError:

                # Более простой вариант API.
                result = register_method(
                    device_id,
                    JARVIS_USB_TYPE,
                    "JARVIS USB",
                )

                registered = (
                    result is not False
                )

        # ----------------------------------------------------
        # Если register() отсутствует,
        # пробуем update_device().
        # ----------------------------------------------------

        if not registered:

            update_method = getattr(
                manager,
                "update_device",
                None
            )

            if update_method:

                result = update_method(
                    device_id,
                    device_type=JARVIS_USB_TYPE,
                    name="JARVIS USB",
                    platform=platform.system(),
                    architecture=platform.machine(),
                    root_path=str(usb_root),
                    active=True,
                    last_seen=utc_now(),
                    metadata={
                        "registered_by": MODULE_NAME,
                        "portable": True,
                    },
                )

                registered = bool(
                    result
                )

        if registered:

            print(
                "[+] Устройство зарегистрировано "
                "через DeviceManager."
            )

            return True

        print(
            "[!] DeviceManager не предоставил "
            "подходящий метод регистрации."
        )

        return False

    except Exception as exc:

        print(
            f"[!] Ошибка DeviceManager: {exc}"
        )

        return False


# ============================================================
# MAIN REGISTRATION
# ============================================================

def register_jarvis_usb() -> bool:
    """
    Основная процедура регистрации.
    """

    print()
    print("=" * 64)
    print(
        "JARVIS V11 - JARVIS USB Registration"
    )
    print(
        f"Version: {MODULE_VERSION}"
    )
    print("=" * 64)

    # --------------------------------------------------------
    # Project root
    # --------------------------------------------------------

    project_root = get_project_root()

    print()
    print(
        f"Project root:\n{project_root}"
    )

    # --------------------------------------------------------
    # Find USB
    # --------------------------------------------------------

    print()
    print(
        "Поиск JARVIS USB..."
    )

    usb_root = find_jarvis_usb()

    if usb_root is None:

        print()
        print(
            "[-] JARVIS USB не найдена."
        )

        print()
        print(
            "Убедись, что нужная флешка подключена."
        )

        return False

    print()
    print(
        f"[+] JARVIS USB найдена:"
    )

    print(
        f"    {usb_root}"
    )

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    manifest_path = (
        usb_root / MANIFEST_FILENAME
    )

    manifest = load_json(
        manifest_path
    )

    if manifest is None:

        print()
        print(
            "[-] manifest.json повреждён "
            "или недоступен."
        )

        return False

    # --------------------------------------------------------
    # Existing ID
    # --------------------------------------------------------

    existing_sync_device = manifest.get(
        SYNC_DEVICE_KEY
    )

    if (
        isinstance(
            existing_sync_device,
            dict
        )
        and existing_sync_device.get(
            DEVICE_ID_KEY
        )
    ):

        existing_id = str(
            existing_sync_device[
                DEVICE_ID_KEY
            ]
        ).strip()

        print()
        print(
            "[i] Device ID уже существует:"
        )

        print(
            f"    {existing_id}"
        )

        device_id = existing_id

    else:

        # ----------------------------------------------------
        # Generate new ID
        # ----------------------------------------------------

        device_id = generate_device_id()

        print()
        print(
            "[+] Создан новый Device ID:"
        )

        print(
            f"    {device_id}"
        )

        # ----------------------------------------------------
        # Write manifest
        # ----------------------------------------------------

        if not register_manifest(
            usb_root,
            device_id
        ):

            print()
            print(
                "[-] Не удалось обновить manifest.json."
            )

            return False

    # --------------------------------------------------------
    # DeviceManager registration
    # --------------------------------------------------------

    print()
    print(
        "Регистрация устройства на ПК..."
    )

    manager_ok = register_device_manager(
        project_root,
        usb_root,
        device_id
    )

    if not manager_ok:

        print()
        print(
            "[!] manifest.json зарегистрирован,"
        )

        print(
            "    но DeviceManager не подтвердил регистрацию."
        )

        print()
        print(
            "Автоматическую синхронизацию пока НЕ запускаем."
        )

        return False

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    print()
    print("=" * 64)
    print(
        "[+] JARVIS USB УСПЕШНО ЗАРЕГИСТРИРОВАН"
    )
    print("=" * 64)

    print()
    print(
        f"Device ID:"
    )

    print(
        f"  {device_id}"
    )

    print()
    print(
        f"USB root:"
    )

    print(
        f"  {usb_root}"
    )

    print()
    print(
        "Теперь usb_monitor.py сможет отличать "
        "эту флешку от обычных USB-накопителей."
    )

    return True


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        success = register_jarvis_usb()

        raise SystemExit(
            0 if success else 1
        )

    except KeyboardInterrupt:

        print()
        print(
            "[!] Операция отменена пользователем."
        )

        raise SystemExit(2)

    except Exception as exc:

        print()
        print(
            f"[!] Критическая ошибка: {exc}"
        )

        raise SystemExit(1)