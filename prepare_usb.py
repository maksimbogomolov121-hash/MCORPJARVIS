"""
prepare_usb.py
JARVIS USB — анализатор текущей установки JARVIS.

Назначение:
    Анализирует существующий JARVIS PC и определяет,
    какие компоненты потенциально потребуются для
    полностью автономной JARVIS USB версии.

ВАЖНО:
    Этот скрипт ничего не устанавливает,
    ничего не удаляет и не изменяет существующий JARVIS.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from datetime import datetime
from typing import Any


# ============================================================
# PATHS
# ============================================================

USB_DIR = Path(__file__).resolve().parent
PROJECT_DIR = USB_DIR.parent

REPORT_PATH = USB_DIR / "usb_prepare_report.json"
TEXT_REPORT_PATH = USB_DIR / "usb_prepare_report.txt"


# ============================================================
# OUTPUT
# ============================================================

def print_header(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def print_status(name: str, value: Any) -> None:
    print(f"[+] {name}: {value}")


def print_warning(message: str) -> None:
    print(f"[!] {message}")


# ============================================================
# SAFE JSON
# ============================================================

def json_safe(value: Any) -> Any:
    """
    Преобразует значения в формат, пригодный для JSON.
    """
    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


# ============================================================
# FILE HELPERS
# ============================================================

def get_file_size(path: Path) -> int:
    """
    Возвращает размер файла.
    """
    try:
        return path.stat().st_size
    except (OSError, FileNotFoundError):
        return 0


def get_directory_size(path: Path) -> int:
    """
    Рекурсивно считает размер папки.
    """
    total = 0

    if not path.exists():
        return 0

    try:
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    total += item.stat().st_size
            except (OSError, FileNotFoundError):
                continue
    except (OSError, PermissionError):
        pass

    return total


def format_size(size: int) -> str:
    """
    Красивое отображение размера.
    """
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
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} PB"


# ============================================================
# DIRECTORY ANALYSIS
# ============================================================

def analyze_directory(path: Path) -> dict[str, Any]:
    """
    Анализирует папку проекта.
    """

    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "is_directory": path.is_dir(),
        "size_bytes": 0,
        "size_human": "0 B",
        "file_count": 0,
        "directory_count": 0,
    }

    if not path.exists() or not path.is_dir():
        return result

    size = 0
    files = 0
    directories = 0

    try:
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    files += 1
                    size += item.stat().st_size

                elif item.is_dir():
                    directories += 1

            except (OSError, FileNotFoundError):
                continue

    except (OSError, PermissionError):
        pass

    result["size_bytes"] = size
    result["size_human"] = format_size(size)
    result["file_count"] = files
    result["directory_count"] = directories

    return result


# ============================================================
# PROJECT STRUCTURE
# ============================================================

def analyze_project_structure() -> dict[str, Any]:
    """
    Анализирует структуру текущего JARVIS.
    """

    print_header("СТРУКТУРА JARVIS")

    result: dict[str, Any] = {
        "project_path": str(PROJECT_DIR),
        "exists": PROJECT_DIR.exists(),
        "directories": {},
        "files": {},
    }

    if not PROJECT_DIR.exists():
        print_warning(
            f"Проект JARVIS не найден: {PROJECT_DIR}"
        )
        return result

    for item in sorted(PROJECT_DIR.iterdir()):
        if item.name == "JARVIS_USB":
            continue

        if item.is_dir():
            info = analyze_directory(item)
            result["directories"][item.name] = info

            print_status(
                f"Папка {item.name}",
                info["size_human"],
            )

        elif item.is_file():
            size = get_file_size(item)

            result["files"][item.name] = {
                "path": str(item),
                "size_bytes": size,
                "size_human": format_size(size),
            }

            print_status(
                f"Файл {item.name}",
                format_size(size),
            )

    return result


# ============================================================
# PYTHON ENVIRONMENT
# ============================================================

def find_python_environment() -> dict[str, Any]:
    """
    Определяет используемый Python и возможный .venv.
    """

    print_header("PYTHON ENVIRONMENT")

    python_executable = Path(sys.executable).resolve()

    result: dict[str, Any] = {
        "python_executable": str(python_executable),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "architecture": platform.architecture()[0],
        "platform": platform.platform(),
        "venv_path": None,
        "venv_exists": False,
        "venv_size_bytes": 0,
        "venv_size_human": "0 B",
    }

    print_status(
        "Python",
        platform.python_version(),
    )

    print_status(
        "Исполняемый файл",
        python_executable,
    )

    print_status(
        "Архитектура",
        platform.architecture()[0],
    )

    possible_venv = PROJECT_DIR / ".venv"

    if possible_venv.exists() and possible_venv.is_dir():
        result["venv_path"] = str(possible_venv)
        result["venv_exists"] = True

        size = get_directory_size(possible_venv)

        result["venv_size_bytes"] = size
        result["venv_size_human"] = format_size(size)

        print_status(
            ".venv",
            format_size(size),
        )
    else:
        print_warning(
            ".venv в корне проекта не найден."
        )

    return result


# ============================================================
# PYTHON PACKAGES
# ============================================================

def get_installed_packages() -> list[dict[str, str]]:
    """
    Получает список установленных Python-пакетов
    через importlib.metadata.
    """

    print_header("PYTHON PACKAGES")

    packages: list[dict[str, str]] = []

    try:
        from importlib import metadata

        distributions = sorted(
            metadata.distributions(),
            key=lambda d: (
                d.metadata.get("Name") or ""
            ).lower(),
        )

        for distribution in distributions:
            name = distribution.metadata.get(
                "Name"
            )

            version = distribution.version

            if not name:
                continue

            packages.append(
                {

"name": name,
                    "version": version,
                }
            )

        print_status(
            "Найдено пакетов",
            len(packages),
        )

    except Exception as exc:
        print_warning(
            f"Не удалось получить список пакетов: {exc}"
        )

    return packages


# ============================================================
# IMPORTANT PACKAGES
# ============================================================

IMPORTANT_PACKAGES = [
    "torch",
    "torchaudio",
    "numpy",
    "scipy",
    "librosa",
    "vosk",
    "SpeechRecognition",
    "PyAudio",
    "sounddevice",
    "soundfile",
    "pyttsx3",
    "pycaw",
    "pywin32",
    "PyAutoGUI",
    "Kivy",
    "google-genai",
    "silero",
]


def analyze_important_packages(
    packages: list[dict[str, str]],
) -> dict[str, Any]:
    """
    Проверяет наличие ключевых библиотек.
    """

    print_header("ВАЖНЫЕ БИБЛИОТЕКИ")

    installed = {
        package["name"].lower(): package
        for package in packages
    }

    result: dict[str, Any] = {}

    for package_name in IMPORTANT_PACKAGES:
        key = package_name.lower()

        found = installed.get(key)

        if found:
            result[package_name] = {
                "installed": True,
                "name": found["name"],
                "version": found["version"],
            }

            print_status(
                package_name,
                f"{found['version']} ✓",
            )

        else:
            result[package_name] = {
                "installed": False,
                "name": package_name,
                "version": None,
            }

            print_warning(
                f"{package_name}: не найден"
            )

    return result


# ============================================================
# IMPORT CHECK
# ============================================================

IMPORT_MAP = {
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


def check_imports() -> dict[str, Any]:
    """
    Проверяет, какие важные модули реально импортируются.
    """

    print_header("IMPORT CHECK")

    result: dict[str, Any] = {}

    for display_name, module_name in IMPORT_MAP.items():
        try:
            spec = importlib.util.find_spec(module_name)

            available = spec is not None

        except (ImportError, ModuleNotFoundError, ValueError):
            available = False

        result[display_name] = {
            "module": module_name,
            "available": available,
        }

        if available:
            print_status(
                display_name,
                "доступен ✓",
            )
        else:
            print_warning(
                f"{display_name}: недоступен"
            )

    return result


# ============================================================
# MODEL SEARCH
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


def search_models() -> list[dict[str, Any]]:
    """
    Ищет модели внутри проекта JARVIS.

    Поиск ограничен проектом, чтобы не сканировать
    весь компьютер.
    """

    print_header("SEARCH MODELS")

    models: list[dict[str, Any]] = []

    skip_directories = {
        ".git",
        "__pycache__",
        "JARVIS_USB",
    }

    try:
        for path in PROJECT_DIR.rglob("*"):

            if not path.is_file():
                continue

            if any(

part in skip_directories
                for part in path.parts
            ):
                continue

            suffix = path.suffix.lower()

            if suffix not in MODEL_EXTENSIONS:
                continue

            size = get_file_size(path)

            model_info = {
                "path": str(path),
                "relative_path": str(
                    path.relative_to(PROJECT_DIR)
                ),
                "name": path.name,
                "extension": suffix,
                "size_bytes": size,
                "size_human": format_size(size),
            }

            models.append(model_info)

            print_status(
                path.name,
                format_size(size),
            )

    except (OSError, PermissionError) as exc:
        print_warning(
            f"Ошибка поиска моделей: {exc}"
        )

    print_status(
        "Найдено моделей",
        len(models),
    )

    return models


# ============================================================
# VOSK SEARCH
# ============================================================

def search_vosk() -> dict[str, Any]:
    """
    Ищет Vosk и его модели.
    """

    print_header("VOSK")

    result: dict[str, Any] = {
        "directories": [],
        "files": [],
    }

    possible_names = {
        "vosk",
        "models",
        "model",
    }

    try:
        for path in PROJECT_DIR.rglob("*"):

            if path.name.lower() not in possible_names:
                continue

            if path.is_dir():
                size = get_directory_size(path)

                result["directories"].append(
                    {
                        "path": str(path),
                        "size_bytes": size,
                        "size_human": format_size(size),
                    }
                )

    except (OSError, PermissionError):
        pass

    try:
        import vosk

        vosk_path = Path(vosk.__file__).resolve()

        result["vosk_package"] = {
            "path": str(vosk_path.parent),
            "size_bytes": get_directory_size(
                vosk_path.parent
            ),
            "size_human": format_size(
                get_directory_size(
                    vosk_path.parent
                )
            ),
        }

        print_status(
            "Vosk package",
            vosk_path.parent,
        )

    except Exception as exc:
        result["vosk_package"] = {
            "error": str(exc),
        }

        print_warning(
            f"Vosk package не удалось определить: {exc}"
        )

    return result


# ============================================================
# SILERO SEARCH
# ============================================================

def search_silero() -> dict[str, Any]:
    """
    Ищет Silero и модель v5_ru.pt.
    """

    print_header("SILERO")

    result: dict[str, Any] = {
        "models": [],
        "packages": [],
    }

    try:
        for path in PROJECT_DIR.rglob("*"):

            if not path.is_file():
                continue

            name_lower = path.name.lower()

            if (
                "silero" in name_lower
                or name_lower == "v5_ru.pt"
            ):
                size = get_file_size(path)

                result["models"].append(
                    {
                        "path": str(path),
                        "relative_path": str(
                            path.relative_to(PROJECT_DIR)
                        ),
                        "name": path.name,
                        "size_bytes": size,
                        "size_human": format_size(size),
                    }
                )

                print_status(
                    path.name,
                    format_size(size),
                )

    except (OSError, PermissionError):
        pass

    try:
        import silero

        package_path = Path(
            silero.__file__
        ).resolve().parent

        result["packages"].append(
            {
                "name": "silero",
                "path": str(package_path),
                "size_bytes": get_directory_size(
                    package_path
                ),
                "size_human": format_size(
                    get_directory_size(
                        package_path
                    )
                ),
            }
        )

        print_status(
            "Silero package",
            package_path,
        )

    except Exception as exc:
        result["packages"].append(
            {
                "name": "silero",
                "error": str(exc),
            }
        )

        print_warning(
            f"Silero package не удалось определить: {exc}"
        )

    return result


# ============================================================
# JARVIS FILES
# ============================================================

def collect_jarvis_files() -> dict[str, Any]:
    """
    Собирает список Python-файлов текущего JARVIS.
    """

    print_header("JARVIS PYTHON FILES")

    files: list[dict[str, Any]] = []

    skip_directories = {
        ".git",
        "__pycache__",
        "JARVIS_USB",
        ".venv",
    }

    try:
        for path in PROJECT_DIR.rglob("*.py"):

            if any(
                part in skip_directories
                for part in path.parts
            ):
                continue

            size = get_file_size(path)

            files.append(
                {
                    "path": str(path),
                    "relative_path": str(
                        path.relative_to(PROJECT_DIR)
                    ),
                    "name": path.name,
                    "size_bytes": size,
                    "size_human": format_size(size),
                }
            )

    except (OSError, PermissionError) as exc:
        print_warning(
            f"Ошибка сбора Python-файлов: {exc}"
        )

    print_status(
        "Python-файлов",
        len(files),
    )

    return {
        "count": len(files),
        "files": files,
    }


# ============================================================
# USB SPACE
# ============================================================

def analyze_usb_space() -> dict[str, Any]:
    """
    Определяет доступное место на диске проекта.

    Сейчас это просто информация.
    Никаких операций с USB не выполняется.
    """

    print_header("USB SPACE")

    try:
        usage = shutil.disk_usage(
            USB_DIR
        )

        result = {
            "total_bytes": usage.total,
            "total_human": format_size(
                usage.total
            ),
            "used_bytes": usage.used,
            "used_human": format_size(
                usage.used
            ),
            "free_bytes": usage.free,
            "free_human": format_size(
                usage.free
            ),
        }

        print_status(
            "Общий объём",
            format_size(usage.total),
        )

        print_status(
            "Свободно",
            format_size(usage.free),
        )

        return result

    except OSError as exc:
        print_warning(
            f"Не удалось определить место: {exc}"
        )

        return {
            "error": str(exc),
        }


# ============================================================
# TOTAL SIZE
# ============================================================

def calculate_required_components_size(
    python_info: dict[str, Any],
    models: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Считает ориентировочный объём найденных компонентов.

    Это НЕ финальный размер USB-сборки.
    """

    venv_size = python_info.get(
        "venv_size_bytes",
        0,
    )

    models_size = sum(
        int(model.get("size_bytes", 0))
        for model in models
    )

    result = {
        "venv_size_bytes": venv_size,
        "venv_size_human": format_size(
            venv_size
        ),

        "models_size_bytes": models_size,
        "models_size_human": format_size(
            models_size
        ),
        "known_components_bytes": (
            venv_size + models_size
        ),
        "known_components_human": format_size(
            venv_size + models_size
        ),
    }

    print_header("ОБЪЁМ")

    print_status(
        ".venv",
        result["venv_size_human"],
    )

    print_status(
        "Модели",
        result["models_size_human"],
    )

    print_status(
        "Известные компоненты",
        result["known_components_human"],
    )

    return result


# ============================================================
# REPORT
# ============================================================

def build_report() -> dict[str, Any]:
    """
    Формирует полный отчёт.
    """

    started_at = datetime.now().isoformat()

    project_structure = (
        analyze_project_structure()
    )

    python_info = (
        find_python_environment()
    )

    packages = (
        get_installed_packages()
    )

    important_packages = (
        analyze_important_packages(
            packages
        )
    )

    imports = check_imports()

    models = search_models()

    vosk = search_vosk()

    silero = search_silero()

    jarvis_files = (
        collect_jarvis_files()
    )

    usb_space = (
        analyze_usb_space()
    )

    size_info = (
        calculate_required_components_size(
            python_info,
            models,
        )
    )

    finished_at = datetime.now().isoformat()

    return {
        "tool": "JARVIS USB prepare_usb.py",
        "report_version": "1.0",
        "analysis_started": started_at,
        "analysis_finished": finished_at,

        "paths": {
            "project_dir": str(PROJECT_DIR),
            "usb_dir": str(USB_DIR),
        },

        "system": {
            "os": platform.system(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "architecture": platform.architecture()[0],
            "machine": platform.machine(),
        },

        "python": python_info,

        "packages": {
            "count": len(packages),
            "important": important_packages,
            "all": packages,
        },

        "imports": imports,

        "models": models,

        "vosk": vosk,

        "silero": silero,

        "jarvis_files": jarvis_files,

        "project_structure": project_structure,

        "usb_space": usb_space,

        "size": size_info,

        "security": {
            "security_module_included": False,
            "reason": (
                "JARVIS USB не должен содержать "
                "основной Security-модуль JARVIS PC."
            ),
        },

        "notes": [
            (
                "Этот отчёт является анализом, "
                "а не процессом сборки."
            ),
            (
                "Ничего из существующего JARVIS "
                "не изменялось."
            ),
            (
                "Финальный состав Portable Edition "
                "будет определён после анализа."
            ),
            (
                "Portable Edition должна содержать "
                "локальный runtime, библиотеки и модели."
            ),
            (
                "Загрузка компонентов из интернета "
                "при первом запуске не планируется."
            ),
        ],
    }


# ============================================================
# SAVE JSON
# ============================================================

def save_json_report(
    report: dict[str, Any],
) -> None:
    """
    Сохраняет JSON-отчёт.
    """

    with REPORT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            json_safe(report),
            file,
            ensure_ascii=False,
            indent=4,
        )


# ============================================================
# SAVE TEXT REPORT
# ============================================================

def save_text_report(
    report: dict[str, Any],
) -> None:
    """
    Сохраняет краткий читаемый отчёт.
    """

    lines: list[str] = []

    lines.append(
        "JARVIS USB — PREPARATION REPORT"
    )
    lines.append("=" * 70)
    lines.append(
        f"Версия отчёта: "
        f"{report['report_version']}"
    )
    lines.append(
        f"Дата: "
        f"{report['analysis_finished']}"
    )

    lines.append("")
    lines.append("SYSTEM")
    lines.append("-" * 70)

    system = report["system"]

    lines.append(
        f"OS: {system['os']}"
    )
    lines.append(
        f"Platform: {system['platform']}"
    )
    lines.append(
        f"Architecture: "
        f"{system['architecture']}"
    )

    lines.append("")
    lines.append("PYTHON")
    lines.append("-" * 70)

    python_info = report["python"]

    lines.append(
        f"Version: "
        f"{python_info['python_version']}"
    )

    lines.append(
        f"Executable: "
        f"{python_info['python_executable']}"
    )

    lines.append(
        f".venv: "
        f"{python_info['venv_size_human']}"
    )

    lines.append("")
    lines.append("IMPORTANT PACKAGES")
    lines.append("-" * 70)

    for name, info in report[
        "packages"
    ]["important"].items():

        if info["installed"]:
            lines.append(
                f"[OK] {name} "
                f"{info['version']}"
            )
        else:
            lines.append(
                f"[--] {name} "
                f"NOT FOUND"
            )

    lines.append("")
    lines.append("MODELS")
    lines.append("-" * 70)

    for model in report["models"]:
        lines.append(
            f"{model['relative_path']} "
            f"— {model['size_human']}"
        )

    lines.append("")
    lines.append("VOSK")
    lines.append("-" * 70)

    vosk_package = report[
        "vosk"
    ].get("vosk_package")

    if vosk_package:
        lines.append(
            json.dumps(
                vosk_package,
                ensure_ascii=False,
                indent=2,
            )
        )

    lines.append("")
    lines.append("SILERO")
    lines.append("-" * 70)

    for model in report[
        "silero"
    ].get("models", []):
        lines.append(
            f"{model['relative_path']} "
            f"— {model['size_human']}"
        )

    lines.append("")
    lines.append("JARVIS PYTHON FILES")
    lines.append("-" * 70)

    lines.append(
        f"Количество: "
        f"{report['jarvis_files']['count']}"
    )

    lines.append("")
    lines.append("SIZE")
    lines.append("-" * 70)

    size = report["size"]

    lines.append(
        f".venv: "
        f"{size['venv_size_human']}"
    )

    lines.append(
        f"Models: "
        f"{size['models_size_human']}"
    )

    lines.append(
        f"Known components: "
        f"{size['known_components_human']}"
    )

    lines.append("")
    lines.append("SECURITY")
    lines.append("-" * 70)

    lines.append(
        "Основной Security-модуль "
        "JARVIS PC в JARVIS USB НЕ включается."
    )

    lines.append("")
    lines.append("NOTES")
    lines.append("-" * 70)

    for note in report["notes"]:
        lines.append(
            f"- {note}"
        )

    lines.append("")
    lines.append(
        "Конец отчёта."
    )

    with TEXT_REPORT_PATH.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(
            "\n".join(lines)
        )


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    """
    Точка входа.
    """

    print()
    print("=" * 70)
    print("🤖 JARVIS USB — PREPARATION TOOL")
    print("=" * 70)
    print()
    print(
        "Режим: АНАЛИЗ"
    )
    print(
        "Существующий JARVIS НЕ изменяется."
    )
    print(
        "Файлы НЕ копируются."
    )
    print(

         "Файлы НЕ удаляются."
    )
    print(
        "Ничего НЕ устанавливается."
    )

    try:
        report = build_report()

        save_json_report(
            report
        )

        save_text_report(
            report
        )

        print_header(
            "ГОТОВО"
        )

        print_status(
            "JSON отчёт",
            REPORT_PATH,
        )

        print_status(
            "TXT отчёт",
            TEXT_REPORT_PATH,
        )

        print()
        print(
            "Анализ завершён успешно."
        )
        print(
            "Теперь можно определить точный "
            "состав JARVIS USB."
        )

    except KeyboardInterrupt:
        print()
        print(
            "Анализ остановлен пользователем."
        )

    except Exception as exc:
        print()
        print(
            "ОШИБКА ПОДГОТОВКИ:"
        )
        print(
            f"{type(exc).__name__}: {exc}"
        )

        raise


if __name__ == "__main__":
    main()