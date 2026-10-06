from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


VERSION = "1.0.0"

USB_DIR = Path(__file__).resolve().parent

LAUNCHER = USB_DIR / "portable_launcher.py"

BUILD_DIR = USB_DIR / "_exe_build"
DIST_DIR = USB_DIR / "_exe_dist"

EXE_NAME = "JARVIS_USB.exe"


def log(message: str) -> None:
    print(message)


def clean_build_dirs() -> None:
    log("[i] Очистка старых файлов сборки...")

    for path in (BUILD_DIR, DIST_DIR):
        if path.exists():
            shutil.rmtree(path)

    spec_file = USB_DIR / "portable_launcher.spec"

    if spec_file.exists():
        spec_file.unlink()

    log("[+] Очистка завершена ✓")


def check_launcher() -> bool:
    if not LAUNCHER.exists():
        log(
            f"[X] Не найден launcher: {LAUNCHER}"
        )
        return False

    log(
        f"[+] portable_launcher.py найден ✓"
    )

    return True


def check_pyinstaller() -> bool:
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                "--version",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            log("[X] PyInstaller не запускается.")
            return False

        version = result.stdout.strip()

        log(
            f"[+] PyInstaller: {version} ✓"
        )

        return True

    except Exception as exc:
        log(
            f"[X] Ошибка проверки PyInstaller: {exc}"
        )
        return False


def build_exe() -> bool:
    log("")
    log("=" * 70)
    log("СБОРКА JARVIS_USB.EXE")
    log("=" * 70)

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--console",
        "--name",
        "JARVIS_USB",
        "--icon",
        str(USB_DIR / "JARVIS_USB_ICONKA.ico"),
        "--distpath",
        str(DIST_DIR),
        "--workpath",
        str(BUILD_DIR),
        str(LAUNCHER),
    ]

    log("[i] Запускаем PyInstaller...")
    log("")

    result = subprocess.run(
        command,
        cwd=str(USB_DIR),
    )

    if result.returncode != 0:
        log("")
        log(
            f"[X] PyInstaller завершился "
            f"с кодом {result.returncode}"
        )
        return False

    exe_path = DIST_DIR / EXE_NAME

    if not exe_path.exists():
        log(
            f"[X] EXE не найден: {exe_path}"
        )
        return False

    size_mb = (
        exe_path.stat().st_size
        / 1024
        / 1024
    )

    log("")
    log("[+] EXE успешно создан ✓")
    log(f"[i] Файл: {exe_path}")
    log(
        f"[i] Размер: {size_mb:.2f} MB"
    )

    return True


def copy_exe_to_usb_root() -> Path | None:
    source = DIST_DIR / EXE_NAME
    target = USB_DIR / EXE_NAME

    if not source.exists():
        log("[X] Исходный EXE не найден.")
        return None

    if target.exists():
        target.unlink()

    shutil.copy2(
        source,
        target,
    )

    log("")
    log(
        "[+] EXE скопирован в корень JARVIS_USB ✓"
    )
    log(f"[i] {target}")

    return target


def verify_exe(exe_path: Path) -> bool:
    log("")
    log("=" * 70)
    log("ПРОВЕРКА EXE")
    log("=" * 70)

    if not exe_path.exists():
        log("[X] EXE отсутствует.")
        return False

    log("[+] EXE существует ✓")

    try:
        result = subprocess.run(
            [
                str(exe_path),
                "--help",
            ],
            cwd=str(USB_DIR),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        log(
            f"[i] Тестовый exit code: "
            f"{result.returncode}"
        )

        if result.stdout:
            log("[i] stdout:")
            print(result.stdout)

        if result.stderr:
            log("[i] stderr:")

            print(result.stderr)

        return True

    except subprocess.TimeoutExpired:
        log(
            "[!] EXE не завершился за 30 секунд."
        )
        log(
            "[i] Это нормально, если JARVIS "
            "уже начал работать."
        )
        return True

    except Exception as exc:
        log(
            f"[X] Ошибка запуска EXE: {exc}"
        )
        return False


def main() -> int:
    print()
    print("=" * 70)
    print("🤖 JARVIS USB — EXE BUILDER")
    print("=" * 70)
    print(
        f"[i] Builder version: {VERSION}"
    )
    print(
        f"[i] USB directory: {USB_DIR}"
    )
    print()

    clean_build_dirs()

    if not check_launcher():
        return 1

    if not check_pyinstaller():
        return 1

    if not build_exe():
        return 1

    exe_path = copy_exe_to_usb_root()

    if exe_path is None:
        return 1

    log("")
    log("=" * 70)
    log("СБОРКА ЗАВЕРШЕНА")
    log("=" * 70)

    log(
        f"[+] {EXE_NAME} готов ✓"
    )

    log("")
    log(
        "Структура теперь должна выглядеть примерно так:"
    )
    log("")
    log(
        "JARVIS_USB/"
    )
    log(
        "├── JARVIS_USB.exe"
    )
    log(
        "├── RUNTIME/"
    )
    log(
        "├── JARVIS/"
    )
    log(
        "├── MODELS/"
    )
    log(
        "├── CONFIG/"
    )
    log(
        "├── DATA/"
    )
    log(
        "├── LOGS/"
    )
    log(
        "├── CACHE/"
    )
    log(
        "├── BACKUP/"
    )
    log(
        "└── manifest.json"
    )

    log("")
    log(
        "[i] Пока НЕ удаляй _exe_build и _exe_dist."
    )
    log(
        "[i] Сначала протестируем EXE."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())