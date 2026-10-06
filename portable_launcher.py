"""
JARVIS USB — Portable Launcher v1.0

Запускает JARVIS непосредственно из Portable Edition.

Архитектура:

JARVIS_USB/
├── RUNTIME/
│   └── Python/
├── JARVIS/
│   ├── main.py
│   └── ...
├── MODELS/
├── CONFIG/
├── DATA/
├── LOGS/
├── CACHE/
├── BACKUP/
├── manifest.json
└── portable_launcher.py

ВАЖНО:
    Launcher НЕ устанавливает зависимости.
    Launcher НЕ скачивает файлы.
    Launcher НЕ использует системный Python.
    Launcher использует только Portable Python.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# VERSION
# ============================================================

LAUNCHER_VERSION = "1.0.0"


# ============================================================
# PATHS
# ============================================================

if getattr(sys, "frozen", False):
    USB_DIR = Path(sys.executable).resolve().parent
else:
    USB_DIR = Path(__file__).resolve().parent

RUNTIME_DIR = (
    USB_DIR / "RUNTIME"
)

PYTHON_DIR = (
    RUNTIME_DIR / "Python"
)

PYTHON_EXE = (
    PYTHON_DIR / "python.exe"
)

PYTHONW_EXE = (
    PYTHON_DIR / "pythonw.exe"
)

JARVIS_DIR = (
    USB_DIR / "JARVIS"
)

MAIN_PY = (
    JARVIS_DIR / "main.py"
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

MANIFEST_PATH = (
    USB_DIR / "manifest.json"
)

LAUNCHER_LOG = (
    LOGS_DIR / "portable_launcher.log"
)


# ============================================================
# CONSOLE
# ============================================================

def print_header(
    text: str,
) -> None:

    print()
    print("=" * 68)
    print(text)
    print("=" * 68)


def info(
    text: str,
) -> None:

    print(
        f"[i] {text}"
    )


def ok(
    text: str,
) -> None:

    print(
        f"[+] {text}"
    )


def warning(
    text: str,
) -> None:

    print(
        f"[!] {text}"
    )


def error(
    text: str,
) -> None:

    print(
        f"[X] {text}"
    )


# ============================================================
# LOGGING
# ============================================================

def write_log(
    message: str,
) -> None:

    try:

        LOGS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = (
            datetime.now()
            .strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        with LAUNCHER_LOG.open(
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                f"[{timestamp}] "
                f"{message}\n"
            )

    except Exception:
        pass


# ============================================================
# MANIFEST
# ============================================================

def load_manifest() -> dict:

    if not MANIFEST_PATH.exists():

        warning(
            "manifest.json не найден."
        )

        write_log(
            "manifest.json not found"
        )

        return {}

    try:

        with MANIFEST_PATH.open(
            "r",
            encoding="utf-8",
        ) as file:

            manifest = json.load(
                file
            )

        ok(
            "manifest.json загружен ✓"
        )

        write_log(
            "manifest loaded"
        )

        return manifest

    except Exception as exc:

        warning(
            f"Ошибка manifest.json: "
            f"{exc}"
        )

        write_log(
            f"manifest error: {exc}"
        )

        return {}


# ============================================================
# STRUCTURE CHECK
# ============================================================

def check_structure() -> bool:

    print_header(
        "ПРОВЕРКА PORTABLE EDITION"
    )

    required_paths = {
        "Portable Python":

        PYTHON_EXE,

        "JARVIS":
            JARVIS_DIR,

        "JARVIS main.py":
            MAIN_PY,

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
    }

    all_ok = True

    for name, path in required_paths.items():

        if path.exists():

            ok(
                f"{name}: найден"
            )

        else:

            error(
                f"{name}: отсутствует"
            )

            write_log(
                f"missing: {name} -> {path}"
            )

            all_ok = False

    return all_ok


# ============================================================
# PYTHON TEST
# ============================================================

def test_portable_python() -> bool:

    print_header(
        "ПРОВЕРКА PORTABLE PYTHON"
    )

    if not PYTHON_EXE.exists():

        error(
            "Portable Python отсутствует."
        )

        return False

    code = """
import sys
import platform

print("EXECUTABLE=" + sys.executable)
print("VERSION=" + platform.python_version())
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

        result = subprocess.run(
            [
                str(PYTHON_EXE),
                "-c",
                code,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )

    except Exception as exc:

        error(
            f"Не удалось запустить "
            f"Portable Python: {exc}"
        )

        write_log(
            f"python launch error: {exc}"
        )

        return False

    if result.stdout:

        print(
            result.stdout.strip()
        )

    if result.stderr:

        warning(
            result.stderr.strip()
        )

    success = (
        result.returncode == 0
        and "CTYPES=OK"
        in result.stdout
        and "SOCKET=OK"
        in result.stdout
    )

    if success:

        ok(
            "Portable Python работает ✓"
        )

        write_log(
            "portable python test: OK"
        )

    else:

        error(
            "Portable Python не прошёл проверку."
        )

        write_log(
            "portable python test: FAILED"
        )

    return success


# ============================================================
# JARVIS ENVIRONMENT
# ============================================================

def build_environment() -> dict[str, str]:

    environment = os.environ.copy()

    # --------------------------------------------------------
    # Указываем Portable Python/JARVIS paths.
    # --------------------------------------------------------

    environment[
        "JARVIS_PORTABLE"
    ] = "1"

    environment[
        "JARVIS_USB_ROOT"
    ] = str(
        USB_DIR
    )

    environment[
        "JARVIS_ROOT"
    ] = str(
        JARVIS_DIR
    )

    environment[
        "JARVIS_MODELS"
    ] = str(
        MODELS_DIR
    )

    environment[
        "JARVIS_CONFIG"
    ] = str(
        CONFIG_DIR
    )

    environment[
        "JARVIS_DATA"
    ] = str(
        DATA_DIR
    )

    environment[
        "JARVIS_LOGS"
    ] = str(
        LOGS_DIR
    )

    environment[
        "JARVIS_CACHE"
    ] = str(
        CACHE_DIR
    )

    environment[
        "JARVIS_BACKUP"
    ] = str(
        BACKUP_DIR
    )

    # --------------------------------------------------------
    # Добавляем Portable Python в PATH.
    # --------------------------------------------------------


    current_path = (
        environment.get(
            "PATH",
            "",
        )
    )

    environment[
        "PATH"
    ] = (
        str(PYTHON_DIR)
        + os.pathsep
        + current_path
    )

    # --------------------------------------------------------
    # Добавляем JARVIS в PYTHONPATH.
    # --------------------------------------------------------

    current_pythonpath = (
        environment.get(
            "PYTHONPATH",
            "",
        )
    )

    python_paths = [
        str(JARVIS_DIR),
        str(USB_DIR),
    ]

    if current_pythonpath:

        python_paths.append(
            current_pythonpath
        )

    environment[
        "PYTHONPATH"
    ] = os.pathsep.join(
        python_paths
    )

    return environment


# ============================================================
# LAUNCH JARVIS
# ============================================================

def launch_jarvis() -> int:

    print_header(
        "ЗАПУСК JARVIS"
    )

    if not MAIN_PY.exists():

        error(
            "JARVIS/main.py не найден."
        )

        write_log(
            "main.py not found"
        )

        return 1

    environment = (
        build_environment()
    )

    write_log(
        "starting JARVIS"
    )

    write_log(
        f"python={PYTHON_EXE}"
    )

    write_log(
        f"main={MAIN_PY}"
    )

    info(
        "Используется Portable Python:"
    )

    print(
        PYTHON_EXE
    )

    info(
        "Запускается:"
    )

    print(
        MAIN_PY
    )

    print()

    try:

        process = subprocess.Popen(
            [
                str(PYTHON_EXE),
                str(MAIN_PY),
            ],
            cwd=str(
                JARVIS_DIR
            ),
            env=environment,
        )

    except Exception as exc:

        error(
            f"Не удалось запустить JARVIS: "
            f"{exc}"
        )

        write_log(
            f"JARVIS launch error: {exc}"
        )

        return 1

    ok(
        f"JARVIS запущен. PID: "
        f"{process.pid}"
    )

    write_log(
        f"JARVIS started, PID={process.pid}"
    )

    return 0


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    print()
    print("=" * 68)
    print(
        "🤖 JARVIS USB — PORTABLE LAUNCHER v1.0"
    )
    print("=" * 68)

    print()

    info(
        f"Launcher version: "
        f"{LAUNCHER_VERSION}"
    )

    info(
        f"Portable root: "
        f"{USB_DIR}"
    )

    write_log(
        "========================================"
    )

    write_log(
        "Portable Launcher started"
    )

    write_log(
        f"version={LAUNCHER_VERSION}"
    )

    write_log(
        f"root={USB_DIR}"
    )

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    manifest = (
        load_manifest()
    )

    if manifest:

        product = (
            manifest.get(
                "product",
                {}
            )
        )

        name = (
            product.get(
                "name"
            )
        )

        version = (
            product.get(
                "version"
            )
        )

        if name:

            info(
                f"Edition: {name}"
            )

        if version:

            info(
                f"Build: {version}"
            )

    # --------------------------------------------------------
    # Structure
    # --------------------------------------------------------

    if not check_structure():

        error(
            "Portable Edition имеет "
            "повреждённую структуру."
        )

        write_log(
            "structure check: FAILED"
        )

        return 1

    ok(
        "Структура Portable Edition ✓"
    )

    # --------------------------------------------------------
    # Python
    # --------------------------------------------------------

    if not test_portable_python():

        error(
            "Portable Python не готов."
        )

        return 1

    # --------------------------------------------------------
    # Launch
    # --------------------------------------------------------

    return launch_jarvis()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        exit_code = main()

    except KeyboardInterrupt:

        print()

        warning(
            "Launcher остановлен."
        )

        write_log(
            "launcher interrupted"
        )

        exit_code = 130

    except Exception as exc:

        print()

        error(
            f"Критическая ошибка: "
            f"{type(exc).__name__}: {exc}"
        )

        write_log(
            f"critical error: "
            f"{type(exc).__name__}: {exc}"
        )

        exit_code = 1

    sys.exit(
        exit_code
    )