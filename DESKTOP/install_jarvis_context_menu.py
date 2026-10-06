"""
DESKTOP/install_jarvis_context_menu.py

Устанавливает пункты JARVIS в контекстное меню Windows Explorer.

Создаёт:

ПКМ по файлу
    JARVIS
        Проверить файл

ПКМ по папке
    JARVIS
        Проверить папку
"""

from __future__ import annotations

import sys
import winreg
from pathlib import Path


APP_NAME = "JARVIS"


def set_registry_value(
    root: winreg.HKEYType,
    key_path: str,
    value_name: str,
    value: str,
) -> None:

    key = winreg.CreateKeyEx(
        root,
        key_path,
        0,
        winreg.KEY_WRITE,
    )

    try:

        winreg.SetValueEx(
            key,
            value_name,
            0,
            winreg.REG_SZ,
            value,
        )

    finally:

        winreg.CloseKey(key)


def create_menu() -> None:

    project_dir = (
        Path(__file__)
        .resolve()
        .parent.parent
    )

    script_path = (
        project_dir
        / "DESKTOP"
        / "jarvis_context_menu.py"
    )

    python_exe = (
        Path(sys.executable)
        .resolve()
    )

    if not script_path.exists():

        raise FileNotFoundError(
            f"Не найден обработчик: {script_path}"
        )

    python_command = (
        f'"{python_exe}" '
        f'"{script_path}" '
    )

    # =====================================================
    # FILE
    # =====================================================

    file_menu = (
        r"Software\Classes\*\shell\JARVIS"
    )

    file_command = (
        file_menu
        + r"\command"
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        file_menu,
        "",
        "JARVIS",
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        file_menu,
        "Icon",
        str(python_exe),
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        file_command,
        "",
        python_command
        + r'file "%1"',
    )

    # =====================================================
    # FOLDER
    # =====================================================

    folder_menu = (
        r"Software\Classes\Directory\shell\JARVIS"
    )

    folder_command = (
        folder_menu
        + r"\command"
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        folder_menu,
        "",
        "JARVIS",
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        folder_menu,
        "Icon",
        str(python_exe),
    )

    set_registry_value(
        winreg.HKEY_CURRENT_USER,
        folder_command,
        "",
        python_command
        + r'folder "%1"',
    )

    print()
    print("=" * 60)
    print("JARVIS CONTEXT MENU")
    print("=" * 60)
    print()
    print("Контекстное меню установлено.")
    print()
    print("Для файлов:")
    print("  ПКМ → JARVIS → Проверить файл")
    print()
    print("Для папок:")
    print("  ПКМ → JARVIS → Проверить папку")
    print()
    print(f"Python: {python_exe}")
    print(f"Handler: {script_path}")
    print()


def remove_key_recursive(
    root: winreg.HKEYType,
    key_path: str,
) -> None:

    try:

        key = winreg.OpenKey(
            root,
            key_path,
            0,
            winreg.KEY_READ
            | winreg.KEY_WRITE,
        )

    except FileNotFoundError:

        return

    try:

        while True:

            try:

                child = winreg.EnumKey(
                    key,
                    0,
                )

                remove_key_recursive(
                    root,
                    key_path
                    + "\\"
                    + child,
                )

            except OSError:

                break

    finally:

        winreg.CloseKey(key)

    try:

        winreg.DeleteKey(
            root,
            key_path,
        )

    except FileNotFoundError:
        pass


def remove_menu() -> None:

    remove_key_recursive(
        winreg.HKEY_CURRENT_USER,
        r"Software\Classes\*\shell\JARVIS",
    )

    remove_key_recursive(
        winreg.HKEY_CURRENT_USER,
        r"Software\Classes\Directory\shell\JARVIS",
    )

    print()
    print(
        "Контекстное меню JARVIS удалено."
    )
    print()


def main() -> None:

    if (
        len(sys.argv) > 1
        and sys.argv[1].lower()
        == "remove"
    ):

        remove_menu()

        return

    create_menu()


if __name__ == "__main__":
    main()