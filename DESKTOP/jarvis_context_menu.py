"""
DESKTOP/jarvis_context_menu.py

Обработчик контекстного меню Windows для JARVIS.

Windows передаёт этому файлу путь выбранного объекта.

Примеры:
    python jarvis_context_menu.py file "C:\\test.txt"
    python jarvis_context_menu.py folder "C:\\TestFolder"
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path
from typing import Any


SECURITY_HOST = "127.0.0.1"
SECURITY_PORT = 8765
SECURITY_TIMEOUT = 5.0


def security_request(
    action: str,
    **kwargs: Any,
) -> dict[str, Any] | None:
    """
    Отправляет запрос в Security IPC Server.
    """

    payload = {
        "action": action,
        **kwargs,
    }

    try:
        with socket.create_connection(
            (
                SECURITY_HOST,
                SECURITY_PORT,
            ),
            timeout=SECURITY_TIMEOUT,
        ) as sock:

            message = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                )
                + "\n"
            )

            sock.sendall(
                message.encode("utf-8")
            )

            data = b""

            while b"\n" not in data:

                chunk = sock.recv(4096)

                if not chunk:
                    break

                data += chunk

            if not data:
                return None

            response_line = (
                data.split(
                    b"\n",
                    1,
                )[0]
            )

            return json.loads(
                response_line.decode(
                    "utf-8"
                )
            )

    except Exception as exc:

        print(
            f"Ошибка Security IPC: {exc}"
        )

        return None


def scan_file(
    path: str,
) -> None:
    """
    Отправляет файл в Security.
    """

    file_path = Path(path)

    if not file_path.exists():
        print(
            "Файл не существует:"
            f" {file_path}"
        )
        return

    if not file_path.is_file():
        print(
            "Указанный объект не является файлом."
        )
        return

    response = security_request(
        "scan_file",
        path=str(file_path),
    )

    if not response:

        print(
            "Security недоступен."
        )

        return

    if not response.get(
        "ok",
        False,
    ):

        print(
            "Security не смог проверить файл:"
            f" {response.get('error', 'неизвестная ошибка')}"
        )

        return

    print(
        "Проверка файла отправлена в Security."
    )

    print(
        json.dumps(
            response,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )


def scan_folder(
    path: str,
) -> None:
    """
    Отправляет папку в Security.
    """

    folder_path = Path(path)

    if not folder_path.exists():

        print(
            "Папка не существует:"
            f" {folder_path}"
        )

        return

    if not folder_path.is_dir():

        print(
            "Указанный объект не является папкой."
        )

        return

    response = security_request(
        "scan_folder",
        path=str(folder_path),
    )

    if not response:

        print(
            "Security недоступен."
        )

        return

    if not response.get(
        "ok",
        False,
    ):

        print(
            "Security не смог проверить папку:"
            f" {response.get('error', 'неизвестная ошибка')}"
        )

        return

    print(
        "Проверка папки отправлена в Security."
    )

    print(
        json.dumps(
            response,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )


def main() -> int:
    """
    Точка входа.
    """

    if len(sys.argv) < 3:

        print(
            "Использование:"
        )

        print(
            "  jarvis_context_menu.py "
            "file <path>"
)

        print(
            "  jarvis_context_menu.py "
            "folder <path>"
        )

        return 1

    target_type = (
        sys.argv[1]
        .strip()
        .lower()
    )

    target_path = " ".join(
        sys.argv[2:]
    ).strip()

    if not target_path:

        print(
            "Путь к объекту не указан."
        )

        return 1

    if target_type == "file":

        scan_file(
            target_path
        )

        return 0

    if target_type == "folder":

        scan_folder(
            target_path
        )

        return 0

    print(
        "Неизвестный тип объекта:"
        f" {target_type}"
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )