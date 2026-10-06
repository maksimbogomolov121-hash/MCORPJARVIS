"""
JARVIS USB — Portable Edition Builder v2.0

Назначение:
    Создание полностью локальной Portable Edition JARVIS.

Архитектура:

    JARVIS V11\
    ├── .venv\
    └── JARVIS_V11\
        ├── CORE\
        ├── COMMANDS\
        ├── VOICE\
        ├── Models\
        ├── SYSTEM\
        └── JARVIS_USB\
            └── build_usb.py

Результат:

    JARVIS_USB\
    ├── RUNTIME\
    │   └── Python\
    ├── JARVIS\
    ├── MODELS\
    ├── CONFIG\
    ├── DATA\
    ├── LOGS\
    ├── CACHE\
    ├── BACKUP\
    ├── manifest.json
    ├── build_report.json
    └── build_report.txt

ВАЖНО:

    Security полностью исключён.

    .venv напрямую НЕ копируется.

    Интернет НЕ используется.

    pip НЕ запускается.

    Основной JARVIS НЕ изменяется.

    Старые файлы Portable Edition удаляются
    только внутри JARVIS_USB перед пересборкой.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from JARVIS_V11.JARVIS_USB.test_portable_runtime import PYTHON_EXE

# ============================================================
# VERSION
# ============================================================

BUILDER_VERSION = "2.0"


# ============================================================
# PATH ARCHITECTURE
# ============================================================

USB_DIR = Path(__file__).resolve().parent

PROJECT_DIR = USB_DIR.parent

PROJECT_ROOT = PROJECT_DIR.parent

VENV_DIR = PROJECT_ROOT / ".venv"


# ============================================================
# OUTPUT DIRECTORIES
# ============================================================

RUNTIME_DIR = USB_DIR / "RUNTIME"

PYTHON_DIR = (
    RUNTIME_DIR / "Python"
)

JARVIS_DIR = (
    USB_DIR / "JARVIS"
)

MODELS_DIR = (
    USB_DIR / "MODELS"
)

CONFIG_DIR = (
    USB_DIR / "CONFIG"
)

DATA_DIR = (
    USB_DIR / "DATA"
)

LOGS_DIR = (
    USB_DIR / "LOGS"
)

CACHE_DIR = (
    USB_DIR / "CACHE"
)

BACKUP_DIR = (
    USB_DIR / "BACKUP"
)


# ============================================================
# REPORT FILES
# ============================================================

MANIFEST_PATH = (
    USB_DIR / "manifest.json"
)

BUILD_REPORT_PATH = (
    USB_DIR / "build_report.json"
)

BUILD_REPORT_TXT_PATH = (
    USB_DIR / "build_report.txt"
)


# ============================================================
# SECURITY EXCLUSIONS
# ============================================================

SECURITY_DIRECTORIES = {
    "SECURITY",
    "SECURITY_LOGS",
    "SECURITY_QUARANTINE",
    "SECURITY_REPORTS",
    "SECURITY_TEST",
}


# ============================================================
# BUILD EXCLUSIONS
# ============================================================

EXCLUDED_DIRECTORIES = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",

    # Security
    *SECURITY_DIRECTORIES,

    # Не копируем сборку саму в себя
    "JARVIS_USB",
}


EXCLUDED_FILES = {
    ".DS_Store",
}


# ============================================================
# MODEL EXTENSIONS
# ============================================================

MODEL_EXTENSIONS = {
    ".pt",
    ".pth",
    ".onnx",
    ".bin",
    ".model",
    ".tflite",
    ".safetensors",
    ".gguf",
}


# ============================================================
# IMPORTANT PACKAGES
# ============================================================

IMPORTANT_IMPORTS = {
    "torch": "torch",
    "torchaudio": "torchaudio",
    "numpy": "numpy",
    "scipy": "scipy",
    "librosa": "librosa",
    "vosk": "vosk",
    "speech_recognition": "speech_recognition",
    "pyaudio": "pyaudio",
    "sounddevice": "sounddevice",
    "soundfile": "soundfile",
    "pyttsx3": "pyttsx3",
    "pycaw": "pycaw",
    "win32api": "win32api",
    "pyautogui": "pyautogui",
    "kivy": "kivy",
    "google.genai": "google.genai",
    "silero": "silero",
}


# ============================================================
# OLD PC PATH MARKERS
# ============================================================

OLD_PATH_MARKERS = [
    r"C:\Users\Пользователь\Desktop\Работа с Jarvis",
    r"C:/Users/Пользователь/Desktop/Работа с Jarvis",
]


# ============================================================
# CONSOLE
# ============================================================

def header(
    title: str,
) -> None:

    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def ok(
    message: str,
) -> None:

    print(
        f"[+] {message}"
    )


def info(
    message: str,
) -> None:

    print(
        f"[i] {message}"
    )


def warning(
    message: str,
) -> None:

    print(
        f"[!] {message}"
    )


def error(
    message: str,
) -> None:

    print(
        f"[X] {message}"
    )


# ============================================================
# SIZE
# ============================================================

def format_size(
    size: int,
) -> str:

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    value = float(size)

    for unit in units:

        if value < 1024:

            return (
                f"{value:.2f} {unit}"
            )

        value /= 1024

    return (
        f"{value:.2f} PB"
    )


def file_size(
    path: Path,
) -> int:

    try:

        return path.stat().st_size

    except (
        OSError,
        FileNotFoundError,
    ):

        return 0


def directory_size(
    path: Path,
) -> int:

    if not path.exists():

        return 0

    total = 0

    try:

        for item in path.rglob("*"):

            try:

                if item.is_file():

                    total += (
                        item.stat().st_size
                    )

            except (
                OSError,
                FileNotFoundError,
            ):

                continue

    except (
        OSError,
        PermissionError,
    ):

        pass

    return total


# ============================================================
# HASH
# ============================================================

def sha256(
    path: Path,
) -> str | None:

    try:

        digest = hashlib.sha256()

        with path.open(
            "rb"
        ) as file:

            while True:

                chunk = file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                digest.update(
                    chunk
                )

        return digest.hexdigest()

    except (
        OSError,
        PermissionError,
    ):

        return None


# ============================================================
# DIRECTORY CREATION
# ============================================================

def ensure_directory(
    path: Path,
) -> None:

    path.mkdir(
        parents=True,
        exist_ok=True,
    )


# ============================================================
# COPY FILE
# ============================================================

def copy_file(
    source: Path,
    destination: Path,
) -> bool:

    try:

        ensure_directory(
            destination.parent
        )

        shutil.copy2(
            source,
            destination,
        )

        return True

    except (
        OSError,
        PermissionError,
        shutil.Error,
    ) as exc:

        warning(
            f"Не удалось скопировать "
            f"{source}: {exc}"
        )

        return False


# ============================================================
# REMOVE OLD BUILD
# ============================================================

def clean_old_build() -> None:
    """
    Удаляет старую Portable Edition.

    НИКОГДА не удаляет:
        build_usb.py
        prepare_usb.py
        test_portable_runtime.py
    """

    header(
        "ОЧИСТКА СТАРОЙ СБОРКИ"
    )

    protected_files = {
        "build_usb.py",
        "prepare_usb.py",
        "test_portable_runtime.py",
    }

    protected_paths = {
        USB_DIR / name
        for name in protected_files
    }

    removable_names = {
        "RUNTIME",
        "LIB",
        "JARVIS",
        "MODELS",
        "CONFIG",
        "DATA",
        "LOGS",
        "CACHE",
        "BACKUP",
        "manifest.json",
        "build_report.json",
        "build_report.txt",
    }

    for item in USB_DIR.iterdir():

        if item in protected_paths:
            continue

        if item.name not in removable_names:
            continue

        try:

            if item.is_dir():

                shutil.rmtree(
                    item
                )

            else:

                item.unlink()

            ok(
                f"Удалено: "
                f"{item.name}"
            )

        except (
            OSError,
            PermissionError,
        ) as exc:

            raise RuntimeError(
                f"Не удалось удалить "
                f"{item}: {exc}"
            ) from exc


# ============================================================
# CREATE STRUCTURE
# ============================================================

def create_structure() -> None:

    header(
        "СОЗДАНИЕ PORTABLE STRUCTURE"
    )

    directories = [
        RUNTIME_DIR,
        PYTHON_DIR,
        JARVIS_DIR,
        MODELS_DIR,
        CONFIG_DIR,
        DATA_DIR,
        LOGS_DIR,
        CACHE_DIR,
        BACKUP_DIR,
    ]

    for directory in directories:

        ensure_directory(
            directory
        )

        try:

            relative = (
                directory.relative_to(
                    USB_DIR
                )
            )

        except ValueError:

            relative = directory

        ok(
            str(relative)
        )


# ============================================================
# FIND BASE PYTHON
# ============================================================

def find_base_python() -> Path:
    """
    Находит настоящий CPython,
    на котором работает текущий .venv.
    """

    base_prefix = Path(
        sys.base_prefix
    ).resolve()

    python_exe = (
        base_prefix /
        "python.exe"
    )

    if python_exe.exists():

        return base_prefix

    # Дополнительные кандидаты
    candidates = [
        Path(
            sys.executable
        ).resolve().parent.parent,

        Path(
            os.environ.get(
                "LOCALAPPDATA",
                ""
            )
        ) / "Programs" / "Python",
    ]

    for candidate in candidates:

        if not candidate.exists():
            continue

        if (
            candidate /
            "python.exe"
        ).exists():

            return candidate

    raise RuntimeError(
        "Не удалось найти базовый "
        "Python runtime."
    )


# ============================================================
# COPY COMPLETE PYTHON RUNTIME
# ============================================================

def copy_python_runtime() -> dict[str, Any]:
    """
    Копирует полный CPython runtime.

    В отличие от v1.0 здесь НЕ собираются
    отдельные компоненты вручную.

    Копируются:
        python.exe
        pythonw.exe
        python*.dll
        DLLs/
        Lib/
        tcl/
        Tools/
        include/
        python312.zip
        остальные файлы runtime.

    Затем добавляется site-packages
    из рабочего .venv.
    """

    header(
        "FULL PYTHON RUNTIME"
    )

    base_python = (
        find_base_python()
    )

    venv_site_packages = (
        VENV_DIR /
        "Lib" /
        "site-packages"
    )

    if not venv_site_packages.exists():

        raise RuntimeError(
            "site-packages не найден: "
            f"{venv_site_packages}"
        )

    ok(
        f"Источник Python: "
        f"{base_python}"
    )

    ok(
        f"Версия Python: "
        f"{platform.python_version()}"
    )

    ok(
        f"Архитектура: "
        f"{platform.architecture()[0]}"
    )

    ok(
        f"venv site-packages: "
        f"{venv_site_packages}"
    )

    ensure_directory(
        PYTHON_DIR
    )

    copied_files = 0
    copied_bytes = 0
    skipped_files = 0

    # --------------------------------------------------------
    # Полный runtime.
    #
    # Не копируем:
    #   Lib/site-packages
    #
    # потому что ниже используем site-packages
    # из рабочего venv.
    # --------------------------------------------------------

    for source in base_python.rglob("*"):

        if not source.is_file():
            continue

        try:

            relative = (
                source.relative_to(
                    base_python
                )
            )

        except ValueError:

            continue

        relative_parts = {
            part.lower()
            for part in relative.parts
        }

        # ----------------------------------------------------
        # Не копируем site-packages базового Python.
        # ----------------------------------------------------

        if (
            "lib" in relative_parts
            and "site-packages"
            in relative_parts
        ):

            skipped_files += 1

            continue

        destination = (
            PYTHON_DIR /
            relative
        )

        if copy_file(
            source,
            destination,
        ):

            copied_files += 1
            copied_bytes += (
                file_size(source)
            )

        else:

            warning(
                f"Пропущен runtime-файл: "
                f"{source}"
            )

    # --------------------------------------------------------
    # Копируем site-packages из venv.
    # --------------------------------------------------------

    destination_site_packages = (
        PYTHON_DIR /
        "Lib" /
        "site-packages"
    )

    ensure_directory(
        destination_site_packages
    )

    site_packages_files = 0
    site_packages_bytes = 0

    for source in (
        venv_site_packages.rglob("*")
    ):

        if not source.is_file():
            continue

        try:

            relative = (
                source.relative_to(
                    venv_site_packages
                )
            )

        except ValueError:

            continue

        destination = (
            destination_site_packages /
            relative
        )

        if copy_file(
            source,
            destination,
        ):

            site_packages_files += 1

            site_packages_bytes += (
                file_size(source)
            )

    copied_files += (
        site_packages_files
    )

    copied_bytes += (
        site_packages_bytes
    )

    # --------------------------------------------------------
    # Проверяем критические файлы.
    # --------------------------------------------------------

    critical_files = [
        PYTHON_DIR / "python.exe",
        PYTHON_DIR / "pythonw.exe",
        PYTHON_DIR / "python312.dll",
        PYTHON_DIR / "Lib" / "ctypes" / "__init__.py",
        PYTHON_DIR / "Lib" / "socket.py",
        PYTHON_DIR / "Lib" / "site-packages",
    ]

    missing = []

    for path in critical_files:

        if not path.exists():

            missing.append(
                str(path)
            )

    if missing:

        raise RuntimeError(
            "После копирования отсутствуют "
            "критические компоненты Python:\n"
            + "\n".join(missing)
        )

    # --------------------------------------------------------
    # Не создаём ._pth вручную.
    #
    # Полный runtime должен работать
    # как обычный CPython.
    # --------------------------------------------------------

    ok(
        f"Файлов runtime: "
        f"{copied_files}"
    )

    ok(
        f"Размер runtime: "
        f"{format_size(copied_bytes)}"
    )

    ok(
        f"Файлов site-packages: "


f"{site_packages_files}"
    )

    ok(
        f"Размер site-packages: "
        f"{format_size(site_packages_bytes)}"
    )

    return {
        "source":
            str(base_python),

        "portable":
            str(PYTHON_DIR),

        "version":
            platform.python_version(),

        "architecture":
            platform.architecture()[0],

        "copied_files":
            copied_files,

        "copied_bytes":
            copied_bytes,

        "size":
            format_size(
                copied_bytes
            ),

        "site_packages_files":
            site_packages_files,

        "site_packages_bytes":
            site_packages_bytes,

        "site_packages_size":
            format_size(
                site_packages_bytes
            ),
    }


# ============================================================
# COPY JARVIS
# ============================================================

def copy_jarvis() -> dict[str, Any]:
    """
    Копирует JARVIS без Security.
    """

    header(
        "КОПИРОВАНИЕ JARVIS"
    )

    ensure_directory(
        JARVIS_DIR
    )

    copied_files = 0
    copied_bytes = 0

    skipped_files = 0
    skipped_dirs: list[str] = []

    for root, dirs, files in os.walk(
        PROJECT_DIR
    ):

        root_path = Path(
            root
        )

        # ----------------------------------------------------
        # Удаляем запрещённые каталоги из os.walk.
        # ----------------------------------------------------

        filtered_dirs = []

        for directory_name in dirs:

            if (
                directory_name
                in EXCLUDED_DIRECTORIES
            ):

                skipped_dirs.append(
                    str(
                        root_path /
                        directory_name
                    )
                )

                continue

            filtered_dirs.append(
                directory_name
            )

        dirs[:] = filtered_dirs

        # ----------------------------------------------------
        # Не заходим в JARVIS_USB.
        # ----------------------------------------------------

        if (
            root_path == USB_DIR
            or USB_DIR in root_path.parents
        ):

            dirs[:] = []

            continue

        try:

            relative = (
                root_path.relative_to(
                    PROJECT_DIR
                )
            )

        except ValueError:

            continue

        destination_root = (
            JARVIS_DIR /
            relative
        )

        ensure_directory(
            destination_root
        )

        for file_name in files:

            source = (
                root_path /
                file_name
            )

            if (
                file_name
                in EXCLUDED_FILES
            ):

                skipped_files += 1

                continue

            # Дополнительная проверка Security.
            if any(
                part.upper()
                in SECURITY_DIRECTORIES
                for part in source.parts
            ):

                skipped_files += 1

                continue

            destination = (
                destination_root /
                file_name
            )

            if copy_file(
                source,
                destination,
            ):

                copied_files += 1

                copied_bytes += (
                    file_size(source)
                )

    ok(
        f"Python/прочих файлов: "
        f"{copied_files}"
    )

    ok(
        f"Размер JARVIS: "
        f"{format_size(copied_bytes)}"
    )

    ok(
        "Security исключён ✓"
    )

    return {
        "source":
            str(PROJECT_DIR),

        "destination":
            str(JARVIS_DIR),

        "copied_files":
            copied_files,

        "copied_bytes":
            copied_bytes,

        "size":
            format_size(
            copied_bytes
            ),

        "skipped_files":
            skipped_files,

        "excluded_directories":
            skipped_dirs,
    }


# ============================================================
# COPY MODELS
# ============================================================

def copy_models() -> dict[str, Any]:
    """
    Переносит модели из JARVIS в MODELS.

    Важно:
        Модель остаётся также внутри JARVIS,
        чтобы существующий код JARVIS мог
        продолжать находить её.

    В MODELS создаётся отдельная portable-копия.
    """

    header(
        "МОДЕЛИ"
    )

    ensure_directory(
        MODELS_DIR
    )

    models = []
    total_bytes = 0

    for source in JARVIS_DIR.rglob("*"):

        if not source.is_file():
            continue

        if (
            source.suffix.lower()
            not in MODEL_EXTENSIONS
        ):

            continue

        try:

            relative = (
                source.relative_to(
                    JARVIS_DIR
                )
            )

        except ValueError:

            continue

        destination = (
            MODELS_DIR /
            relative
        )

        if not copy_file(
            source,
            destination,
        ):

            continue

        size = (
            file_size(destination)
        )

        total_bytes += size

        model = {
            "name":
                source.name,

            "source":
                str(source),

            "relative_path":
                str(relative),

            "destination":
                str(destination),

            "size_bytes":
                size,

            "size":
                format_size(size),

            "sha256":
                sha256(destination),
        }

        models.append(
            model
        )

        ok(
            f"{source.name} — "
            f"{format_size(size)}"
        )

    ok(
        f"Моделей: "
        f"{len(models)}"
    )

    ok(
        f"Размер: "
        f"{format_size(total_bytes)}"
    )

    return {
        "count":
            len(models),

        "total_bytes":
            total_bytes,

        "total_size":
            format_size(
                total_bytes
            ),

        "models":
            models,
    }


# ============================================================
# COPY REQUIREMENTS
# ============================================================

def copy_requirements() -> bool:

    source = (
        PROJECT_DIR /
        "requirements.txt"
    )

    if not source.exists():

        warning(
            "requirements.txt не найден."
        )

        return False

    destination = (
        JARVIS_DIR /
        "requirements.txt"
    )

    result = copy_file(
        source,
        destination,
    )

    if result:

        ok(
            "requirements.txt скопирован ✓"
        )

    return result


# ============================================================
# CREATE CONFIG
# ============================================================

def create_config() -> dict[str, Any]:

    header(
        "PORTABLE CONFIG"
    )

    config = {
        "portable": True,

        "edition":
            "JARVIS USB",

        "version":
            "2.0.0",

        "internet_required":
            False,

        "download_required":
            False,

        "installation_required":
            False,

        "security_module":
            False,

        "runtime": {
            "type":
                "portable",

            "python":
                "RUNTIME/Python/python.exe",
        },

        "paths": {
            "jarvis":
                "JARVIS",

            "models":
                "MODELS",

            "config":
                "CONFIG",

            "data":
                "DATA",

            "logs":
                "LOGS",

            "cache":
                "CACHE",

            "backup":
                "BACKUP",
        },

            "models": {
            "local_only":
                True,

            "vosk":
                True,

            "silero":
                True,
        },

        "sync": {
            "enabled":
                False,

            "mode":
                "future",
        },

        "created_at":
            datetime.now().isoformat(),
    }

    path = (
        CONFIG_DIR /
        "portable_config.json"
    )

    path.write_text(
        json.dumps(
            config,
            ensure_ascii=False,
            indent=4,
        ),
        encoding="utf-8",
    )

    ok(
        f"Создан: "
        f"{path}"
    )

    return config


# ============================================================
# FIND SECURITY
# ============================================================

def find_security() -> list[Path]:

    found = []

    for root, dirs, files in os.walk(
        JARVIS_DIR
    ):

        root_path = Path(
            root
        )

        dirs[:] = [
            directory
            for directory in dirs
            if directory
            not in SECURITY_DIRECTORIES
        ]

        for directory in dirs:

            if (
                directory
                in SECURITY_DIRECTORIES
            ):

                found.append(
                    root_path /
                    directory
                )

        for file_name in files:

            path = (
                root_path /
                file_name
            )

            if any(
                part.upper()
                in SECURITY_DIRECTORIES
                for part in path.parts
            ):

                found.append(
                    path
                )

    return found


# ============================================================
# SECURITY CHECK
# ============================================================

def verify_security_removed() -> dict[str, Any]:

    header(
        "ПРОВЕРКА SECURITY"
    )

    found = []

    # --------------------------------------------------------
    # Проверяем корень USB.
    # --------------------------------------------------------

    for item in USB_DIR.iterdir():

        if (
            item.name
            in SECURITY_DIRECTORIES
        ):

            found.append(
                item
            )

    # --------------------------------------------------------
    # Проверяем JARVIS.
    # --------------------------------------------------------

    for item in JARVIS_DIR.rglob("*"):

        if (
            item.name
            in SECURITY_DIRECTORIES
        ):

            found.append(
                item
            )

        if any(
            part.upper()
            in SECURITY_DIRECTORIES
            for part in item.parts
        ):

            found.append(
                item
            )

    unique = []

    seen = set()

    for path in found:

        key = str(
            path.resolve()
        ).lower()

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            path
        )

    passed = (
        len(unique) == 0
    )

    if passed:

        ok(
            "Security полностью отсутствует ✓"
        )

    else:

        error(
            "Security обнаружен!"
        )

        for path in unique:

            print(
                f"  {path}"
            )

    return {
        "passed":
            passed,

        "found":
            [
                str(path)
                for path in unique
            ],
    }


# ============================================================
# OLD PATH SCAN
# ============================================================

def scan_old_paths() -> dict[str, Any]:
    """
    Ищет старые абсолютные пути пользователя.

    Ничего не исправляет автоматически.
    """

    header(
        "ПОИСК СТАРЫХ АБСОЛЮТНЫХ ПУТЕЙ"
    )

    found = []

    text_extensions = {
        ".py",
        ".json",
        ".txt",
        ".ini",
        ".cfg",
        ".conf",
        ".yaml",
        ".yml",
        ".bat",
        ".cmd",
        ".vbs",
        ".ps1",
    }

    for file in JARVIS_DIR.rglob("*"):

        if not file.is_file():
            continue

        if (
            file.suffix.lower()
            not in text_extensions
        ):

            continue

        try:

            content = file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

        except (
            OSError,
            PermissionError,
        ):

            continue

        for marker in OLD_PATH_MARKERS:

            if (
                marker.lower()
                in content.lower()
            ):

                found.append(
                    {
                        "file":
                            str(file),

                        "marker":
                            marker,
                    }
                )

    passed = (
        len(found) == 0
    )

    if passed:

        ok(
            "Старые пути не обнаружены ✓"
        )

    else:

        warning(
            f"Найдено старых путей: "
            f"{len(found)}"
        )

        for item in found:

            print(
                f"  {item['file']}"
            )

            print(
                f"    {item['marker']}"
            )

    return {
        "passed":
            passed,

        "found":
            found,
    }


# ============================================================
# RUNTIME QUICK TEST
# ============================================================

def runtime_test() -> dict[str, Any]:
    """
    Проверяет именно собранный Python.

    Никакие библиотеки не устанавливаются.
    """

    header(
        "ПРОВЕРКА PORTABLE PYTHON"
    )

    if not PYTHON_EXE.exists():

        return {
            "passed":
                False,

            "error":
                "python.exe отсутствует",
        }

    code = """
import sys
import platform

print("EXECUTABLE=" + sys.executable)
print("VERSION=" + sys.version)
print("PREFIX=" + sys.prefix)
print("BASE_PREFIX=" + sys.base_prefix)
print("ARCH=" + platform.architecture()[0])

try:
    import _ctypes
    print("CTYPES=OK")
except Exception as e:
    print("CTYPES=ERROR:" + repr(e))

try:
    import _socket
    print("SOCKET=OK")
except Exception as e:
    print("SOCKET=ERROR:" + repr(e))
"""

    try:

        process = subprocess.run(
            [
                str(PYTHON_EXE),
                "-c",
                code,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

    except Exception as exc:

        error(
            f"Ошибка запуска: {exc}"
        )

        return {
            "passed":
                False,

            "error":
                str(exc),
        }

    stdout = (
        process.stdout.strip()
    )

    stderr = (
        process.stderr.strip()
    )

    print(
        stdout
    )

    if stderr:

        print()
        warning(
            stderr
        )

    required = [
        "CTYPES=OK",
        "SOCKET=OK",
    ]

    passed = (
        process.returncode == 0
        and all(
            marker in stdout
            for marker in required
        )
    )

    if passed:

        ok(
            "Критические модули "
            "_ctypes и _socket работают ✓"
        )

    else:

        error(
            "Portable Python всё ещё "
            "неполный."
        )

    return {
        "passed":
            passed,

        "return_code":
            process.returncode,

        "stdout":
            stdout,

        "stderr":
            stderr,
    }


# ============================================================
# PACKAGE TEST
# ============================================================

def package_test() -> dict[str, Any]:
    """
    Проверяет библиотеки уже собранного runtime.

Максим (18:03):
"""

    header(
        "ПРОВЕРКА БИБЛИОТЕК"
    )

    results = {}

    for display_name, import_name in (
        IMPORTANT_IMPORTS.items()
    ):

        code = f"""
import importlib

module = importlib.import_module(
    {import_name!r}
)

print(
    "IMPORT_OK"
)

print(
    getattr(
        module,
        "__version__",
        "unknown"
    )
)
"""

        try:

            process = subprocess.run(
                [
                    str(PYTHON_EXE),
                    "-c",
                    code,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )

            stdout = (
                process.stdout.strip()
            )

            stderr = (
                process.stderr.strip()
            )

            passed = (
                process.returncode == 0
                and "IMPORT_OK"
                in stdout
            )

            version = (
                stdout.splitlines()[-1]
                if stdout
                else None
            )

            results[
                display_name
            ] = {
                "passed":
                    passed,

                "version":
                    version,

                "error":
                    stderr
                    if stderr
                    else None,
            }

            if passed:

                ok(
                    f"{display_name}: "
                    f"✓ ({version})"
                )

            else:

                warning(
                    f"{display_name}: "
                    f"НЕ ИМПОРТИРУЕТСЯ"
                )

                if stderr:

                    print(
                        stderr.splitlines()[-1]
                    )

        except Exception as exc:

            results[
                display_name
            ] = {
                "passed":
                    False,

                "version":
                    None,

                "error":
                    str(exc),
            }

            warning(
                f"{display_name}: "
                f"ОШИБКА"
            )

    return results


# ============================================================
# CREATE MANIFEST
# ============================================================

def create_manifest(
    runtime_info: dict[str, Any],
    jarvis_info: dict[str, Any],
    models_info: dict[str, Any],
    config_info: dict[str, Any],
    security_info: dict[str, Any],
    old_paths_info: dict[str, Any],
) -> dict[str, Any]:

    header(
        "MANIFEST"
    )

    manifest = {
        "manifest_version":
            "2.0",

        "product": {
            "name":
                "JARVIS USB",

            "edition":
                "Portable Edition",

            "version":
                "2.0.0",
        },

        "builder": {
            "name":
                "JARVIS USB Builder",

            "version":
                BUILDER_VERSION,

            "built_at":
                datetime.now().isoformat(),
        },

        "portable": {
            "fully_local":
                True,

            "internet_required":
                False,

            "download_required":
                False,

            "installation_required":
                False,
        },

        "security": {
            "included":
                False,

            "excluded":
                True,
        },

        "source": {
            "project":
                str(PROJECT_DIR),

            "project_root":
                str(PROJECT_ROOT),

            "python":
                str(sys.executable),

            "python_version":
                platform.python_version(),
        },

        "runtime":
            runtime_info,

        "jarvis":
            jarvis_info,

        "models":
            models_info,

        "config":
            config_info,

        "security_verification":
            security_info,

        "old_paths":
            old_paths_info,

        "structure": {
            "runtime":
                "RUNTIME",

            "python":
                "RUNTIME/Python",

            "jarvis":
                "JARVIS",

            "models":
                "MODELS",

            "config":
                "CONFIG",

            "data":
                "DATA",

            "logs":
                "LOGS",

            "cache":
                "CACHE",

            "backup":
                "BACKUP",
        },
    }

    MANIFEST_PATH.write_text(
        json.dumps(
            manifest,
            ensure_ascii=False,
            indent=4,
        ),
        encoding="utf-8",
    )

    ok(
        f"Создан: "
        f"{MANIFEST_PATH}"
    )

    return manifest


# ============================================================
# BUILD REPORT
# ============================================================

def create_build_report(
    manifest: dict[str, Any],
    runtime_test_info: dict[str, Any],
    package_info: dict[str, Any],
) -> dict[str, Any]:

    total_size = (
        directory_size(
            USB_DIR
        )
    )

    passed_packages = [
        name
        for name, result
        in package_info.items()
        if result.get("passed")
    ]

    failed_packages = [
        name
        for name, result
        in package_info.items()
        if not result.get("passed")
    ]

    report = {
        "builder": {
            "name":
                "JARVIS USB Builder",

            "version":
                BUILDER_VERSION,
        },

        "build": {
            "status":
                "completed",

            "time":
                datetime.now().isoformat(),
        },

        "size": {
            "bytes":
                total_size,

            "human":
                format_size(
                    total_size
                ),
        },

        "runtime_test":
            runtime_test_info,

        "packages": {
            "passed":
                passed_packages,

            "failed":
                failed_packages,

            "total":
                len(package_info),
        },

        "manifest":
            manifest,

        "notes": [
            "Security полностью исключён.",
            "Интернет не использовался.",
            "pip не запускался.",
            "Основной JARVIS не изменялся.",
            "Portable Python создан отдельно.",
            "site-packages взят из рабочего .venv.",
            "Модели скопированы локально.",
        ],
    }

    BUILD_REPORT_PATH.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=4,
        ),
        encoding="utf-8",
    )

    lines = [
        "JARVIS USB — BUILD REPORT",
        "=" * 72,
        "",
        f"Builder version: {BUILDER_VERSION}",
        f"Status: {report['build']['status']}",
        f"Time: {report['build']['time']}",
        "",
        "TOTAL SIZE",
        "-" * 72,
        report["size"]["human"],
        "",
        "PORTABLE",
        "-" * 72,
        "Internet required: NO",
        "Download required: NO",
        "Installation required: NO",
        "",
        "SECURITY",
        "-" * 72,
        "EXCLUDED",
        "",
        "PACKAGES",
        "-" * 72,
        f"Passed: {len(passed_packages)}",
        f"Failed: {len(failed_packages)}",
        "",
        "JARVIS USB build completed.",
    ]

    BUILD_REPORT_TXT_PATH.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    ok(
        f"JSON report: "
        f"{BUILD_REPORT_PATH}"
    )

    ok(
        f"TXT report: "
        f"{BUILD_REPORT_TXT_PATH}"
    )

    return report


# ============================================================
# FINAL STRUCTURE CHECK
# ============================================================

def final_check() -> dict[str, Any]:

    header(

"ФИНАЛЬНАЯ ПРОВЕРКА"
    )

    required = {
        "RUNTIME":
            RUNTIME_DIR,

        "Portable Python":
            PYTHON_DIR,

        "python.exe":
            PYTHON_EXE,

        "JARVIS":
            JARVIS_DIR,

        "MODELS":
            MODELS_DIR,

        "CONFIG":
            CONFIG_DIR,

        "DATA":
            DATA_DIR,

        "LOGS":
            LOGS_DIR,

        "CACHE":
            CACHE_DIR,

        "BACKUP":
            BACKUP_DIR,

        "manifest":
            MANIFEST_PATH,
    }

    checks = {}

    all_ok = True

    for name, path in required.items():

        exists = path.exists()

        checks[name] = {
            "exists":
                exists,

            "path":
                str(path),
        }

        if exists:

            ok(
                f"{name}: ✓"
            )

        else:

            error(
                f"{name}: отсутствует"
            )

            all_ok = False

    # --------------------------------------------------------
    # Security
    # --------------------------------------------------------

    security_found = []

    for item in USB_DIR.iterdir():

        if (
            item.name
            in SECURITY_DIRECTORIES
        ):

            security_found.append(
                str(item)
            )

    if security_found:

        error(
            "Security найден!"
        )

        all_ok = False

    else:

        ok(
            "Security: отсутствует ✓"
        )

    checks[
        "security"
    ] = {
        "passed":
            not security_found,

        "found":
            security_found,
    }

    # --------------------------------------------------------
    # Size
    # --------------------------------------------------------

    total_size = (
        directory_size(
            USB_DIR
        )
    )

    checks["size"] = {
        "bytes":
            total_size,

        "human":
            format_size(
                total_size
            ),
    }

    ok(
        f"Итоговый размер: "
        f"{format_size(total_size)}"
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    if all_ok:

        ok(
            "ФИНАЛЬНАЯ ПРОВЕРКА: УСПЕШНО ✓"
        )

    else:

        warning(
            "ФИНАЛЬНАЯ ПРОВЕРКА: "
            "ТРЕБУЕТ ИСПРАВЛЕНИЙ"
        )

    return {
        "passed":
            all_ok,

        "checks":
            checks,
    }


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print("=" * 72)
    print(
        "🤖 JARVIS USB — BUILDER v2.0"
    )
    print("=" * 72)

    print()
    print(
        "Режим: ПОЛНАЯ ПЕРЕСБОРКА"
    )

    print(
        "Интернет: НЕ ИСПОЛЬЗУЕТСЯ"
    )

    print(
        "pip: НЕ ИСПОЛЬЗУЕТСЯ"
    )

    print(
        "Security: ИСКЛЮЧЁН"
    )

    print(
        "Основной JARVIS: НЕ ИЗМЕНЯЕТСЯ"
    )

    start_time = time.time()

    try:

        # ----------------------------------------------------
        # SOURCE
        # ----------------------------------------------------

        header(
            "ПРОВЕРКА ИСТОЧНИКА"
        )

        ok(
            f"USB directory: "
            f"{USB_DIR}"
        )

        ok(
            f"JARVIS project: "
            f"{PROJECT_DIR}"
        )

        ok(
            f"Project root: "
            f"{PROJECT_ROOT}"
        )

        ok(
            f".venv: "
            f"{VENV_DIR}"
        )

        if not PROJECT_DIR.exists():

            raise RuntimeError(
                "Папка JARVIS не найдена."
            )

        if not VENV_DIR.exists():

            raise RuntimeError(
                ".venv не найден."
            )

        # ----------------------------------------------------
        # CLEAN
        # ----------------------------------------------------

        clean_old_build()

        # ----------------------------------------------------
        # STRUCTURE
        # ----------------------------------------------------

        create_structure()

        # ----------------------------------------------------
        # JARVIS
        # ----------------------------------------------------

        jarvis_info = (
            copy_jarvis()
        )

        # ----------------------------------------------------
        # RUNTIME
        # ----------------------------------------------------

        runtime_info = (
            copy_python_runtime()
        )

        # ----------------------------------------------------
        # REQUIREMENTS
        # ----------------------------------------------------

        copy_requirements()

        # ----------------------------------------------------
        # MODELS
        # ----------------------------------------------------

        models_info = (
            copy_models()
        )

        # ----------------------------------------------------
        # CONFIG
        # ----------------------------------------------------

        config_info = (
            create_config()
        )

        # ----------------------------------------------------
        # SECURITY
        # ----------------------------------------------------

        security_info = (
            verify_security_removed()
        )

        # ----------------------------------------------------
        # OLD PATHS
        # ----------------------------------------------------

        old_paths_info = (
            scan_old_paths()
        )

        # ----------------------------------------------------
        # MANIFEST
        # ----------------------------------------------------

        manifest = (
            create_manifest(
                runtime_info=
                    runtime_info,

                jarvis_info=
                    jarvis_info,

                models_info=
                    models_info,

                config_info=
                    config_info,

                security_info=
                    security_info,

                old_paths_info=
                    old_paths_info,
            )
        )

        # ----------------------------------------------------
        # RUNTIME TEST
        # ----------------------------------------------------

        runtime_test_info = (
            runtime_test()
        )

        # ----------------------------------------------------
        # PACKAGE TEST
        # ----------------------------------------------------

        package_info = (
            package_test()
        )

        # ----------------------------------------------------
        # BUILD REPORT
        # ----------------------------------------------------

        create_build_report(
            manifest=
                manifest,

            runtime_test_info=
                runtime_test_info,

            package_info=
                package_info,
        )

        # ----------------------------------------------------
        # FINAL
        # ----------------------------------------------------

        final_info = (
            final_check()
        )

        elapsed = (
            time.time()
            - start_time
        )

        header(
            "СБОРКА ЗАВЕРШЕНА"
        )

        print(
            f"Время сборки: "
            f"{elapsed:.1f} сек."
        )

        print()

        if final_info["passed"]:

            print(
                "🚀 JARVIS USB BUILD v2.0: OK"
            )

            print()
            print(
                "Portable Edition создана."
            )

        else:

            print(
                "⚠ JARVIS USB BUILD v2.0: "
                "ТРЕБУЕТ ПРОВЕРКИ"
            )

        print()
        print(
            "Сборка:"
        )

        print(
            USB_DIR
)

        print()
        print(
            "Следующий этап:"
        )

        print(
            "Portable Launcher → EXE"
        )

        print()

    except KeyboardInterrupt:

        print()

        warning(
            "Сборка остановлена."
        )

    except Exception as exc:

        print()

        error(
            "ОШИБКА СБОРКИ"
        )

        print(
            f"{type(exc).__name__}: {exc}"
        )

        raise


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()