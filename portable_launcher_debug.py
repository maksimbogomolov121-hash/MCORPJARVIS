from __future__ import annotations

import json
import os
import subprocess
import sys
import traceback
from pathlib import Path


VERSION = "1.0.0"

USB_DIR = Path(__file__).resolve().parent

RUNTIME_DIR = USB_DIR / "RUNTIME" / "Python"
PYTHON_EXE = RUNTIME_DIR / "python.exe"

JARVIS_DIR = USB_DIR / "JARVIS"
MAIN_PY = JARVIS_DIR / "main.py"

LOGS_DIR = USB_DIR / "LOGS"
DEBUG_LOG = LOGS_DIR / "portable_launcher_debug.log"

MANIFEST_FILE = USB_DIR / "manifest.json"


def log(message: str) -> None:
    print(message)

    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    with DEBUG_LOG.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(message + "\n")


def print_header() -> None:
    print()
    print("=" * 70)
    print("🤖 JARVIS USB — DEBUG LAUNCHER")
    print("=" * 70)
    print(f"[i] Launcher version: {VERSION}")
    print(f"[i] USB root: {USB_DIR}")
    print()


def check_file(path: Path, name: str) -> bool:
    if path.exists():
        log(f"[+] {name}: {path}")
        return True

    log(f"[X] {name} НЕ НАЙДЕН: {path}")
    return False


def load_manifest() -> None:
    if not MANIFEST_FILE.exists():
        log("[!] manifest.json не найден")
        return

    try:
        with MANIFEST_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            manifest = json.load(file)

        log("[+] manifest.json загружен")

        if isinstance(manifest, dict):
            for key in (
                "edition",
                "build",
                "version",
            ):
                if key in manifest:
                    log(f"[i] {key}: {manifest[key]}")

    except Exception as exc:
        log(f"[!] Ошибка manifest.json: {exc}")


def build_environment() -> dict[str, str]:
    env = os.environ.copy()

    env["JARVIS_PORTABLE"] = "1"

    env["JARVIS_USB_ROOT"] = str(USB_DIR)
    env["JARVIS_ROOT"] = str(JARVIS_DIR)

    env["JARVIS_MODELS"] = str(
        USB_DIR / "MODELS"
    )

    env["JARVIS_CONFIG"] = str(
        USB_DIR / "CONFIG"
    )

    env["JARVIS_DATA"] = str(
        USB_DIR / "DATA"
    )

    env["JARVIS_LOGS"] = str(
        USB_DIR / "LOGS"
    )

    env["JARVIS_CACHE"] = str(
        USB_DIR / "CACHE"
    )

    env["JARVIS_BACKUP"] = str(
        USB_DIR / "BACKUP"
    )

    old_path = env.get("PATH", "")

    env["PATH"] = (
        str(RUNTIME_DIR)
        + os.pathsep
        + old_path
    )

    old_pythonpath = env.get(
        "PYTHONPATH",
        "",
    )

    python_paths = [
        str(JARVIS_DIR),
        str(USB_DIR),
    ]

    if old_pythonpath:
        python_paths.append(
            old_pythonpath
        )

    env["PYTHONPATH"] = os.pathsep.join(
        python_paths
    )

    return env


def test_python() -> bool:
    log("")
    log("=" * 70)
    log("ПРОВЕРКА PORTABLE PYTHON")
    log("=" * 70)

    code = (
        "import sys, ctypes, socket; "
        "print('EXECUTABLE=' + sys.executable); "
        "print('PREFIX=' + sys.prefix); "
        "print('BASE_PREFIX=' + sys.base_prefix); "
        "print('VERSION=' + sys.version); "
        "print('CTYPES=OK'); "
        "print('SOCKET=OK')"
    )

    try:
        result = subprocess.run(
            [
                str(PYTHON_EXE),
                "-c",
                code,
            ],
            cwd=str(USB_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.stdout:
            for line in result.stdout.splitlines():
                log(line)

        if result.stderr:
            log("[stderr]")
            for line in result.stderr.splitlines():
                log(line)

        if result.returncode != 0:
            log(
                f"[X] Portable Python завершился "
                f"с кодом {result.returncode}"
            )
            return False

        log("[+] Portable Python работает ✓")
        return True

    except Exception:
        log("[X] Ошибка запуска Portable Python")
        log(traceback.format_exc())
        return False


def launch_jarvis() -> int:
    log("")
    log("=" * 70)
    log("ЗАПУСК JARVIS")
    log("=" * 70)

    env = build_environment()

    log(
        f"[i] Python: {PYTHON_EXE}"
    )

    log(
        f"[i] JARVIS: {MAIN_PY}"
    )

    log(
        f"[i] Working directory: {JARVIS_DIR}"
    )

    log("")
    log("[i] Запускаем main.py...")
    log("[i] ВАЖНО: окно НЕ будет скрыто.")
    log("[i] Если JARVIS упадёт — traceback останется здесь.")
    log("")

    try:
        process = subprocess.Popen(
            [
                str(PYTHON_EXE),
                str(MAIN_PY),
            ],
            cwd=str(JARVIS_DIR),
            env=env,
        )

        log(
            f"[+] Процесс JARVIS запущен. PID: "
            f"{process.pid}"
        )

        log("")
        log(
            "[i] Ожидаем завершения JARVIS..."
        )
        log(
            "[i] Не закрывай это окно."
        )
        log("")

        return_code = process.wait()

        log("")
        log("=" * 70)
        log(
            f"[!] JARVIS завершился. "
            f"Exit code: {return_code}"
        )
        log("=" * 70)

        if return_code == 0:
            log(
                "[i] JARVIS завершился без ошибки."
            )
        else:
            log(
                "[X] JARVIS завершился с ошибкой!"
            )

        return return_code

    except Exception:
        log("")
        log("=" * 70)
        log("КРИТИЧЕСКАЯ ОШИБКА LAUNCHER")
        log("=" * 70)
        log(traceback.format_exc())

        return 1


def main() -> int:
    print_header()

    LOGS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    log("")
    log(
        f"Debug launcher started: {VERSION}"
    )

    load_manifest()

    log("")
    log("=" * 70)
    log("ПРОВЕРКА ФАЙЛОВ")
    log("=" * 70)

    required_ok = True

    required_ok &= check_file(
        PYTHON_EXE,
        "Portable Python",
    )

    required_ok &= check_file(
        MAIN_PY,
        "JARVIS main.py",
    )

    check_file(
        USB_DIR / "MODELS",
        "MODELS",
    )

    check_file(
        USB_DIR / "CONFIG",
        "CONFIG",
    )

    check_file(
        USB_DIR / "DATA",
        "DATA",
    )

    check_file(
        USB_DIR / "LOGS",
        "LOGS",
    )

    if not required_ok:
        log("")
        log(
            "[X] Необходимые файлы отсутствуют."
        )
        return 1

    if not test_python():
        log("")
        log(
            "[X] Portable Python не прошёл проверку."
        )
        return 1

    return launch_jarvis()


if __name__ == "__main__":
    try:
        exit_code = main()

    except KeyboardInterrupt:
        log("")
        log(
            "[!] Запуск прерван пользователем."
        )
        exit_code = 130

    except Exception:
        log("")
        log("=" * 70)
        log("НЕОБРАБОТАННАЯ ОШИБКА")
        log("=" * 70)
        log(traceback.format_exc())
        exit_code = 1

    print("")
    print("=" * 70)
    print(
        "DEBUG LAUNCHER ЗАВЕРШЁН"
    )
    print("=" * 70)
    print(
        "Лог:"
    )
    print(DEBUG_LOG)
    print("")
    print(
        "Нажми Enter, чтобы закрыть окно..."
    )

    input()

    sys.exit(exit_code)