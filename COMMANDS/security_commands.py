"""
COMMANDS/security_commands.py

Команды JARVIS для взаимодействия с Security.
"""

from __future__ import annotations

import json
import socket
from typing import Optional, Dict, Any

from DESKTOP.active_target import ActiveTarget


class SecurityCommands:
    """
    Управление командами JARVIS, связанными с Security.

    Архитектура:

        VoiceCommands
              ↓
        SecurityCommands
              ↓
        ActiveTarget
              ↓
        Security IPC
              ↓
        Security
    """

    SECURITY_HOST = "127.0.0.1"
    SECURITY_PORT = 8765
    SECURITY_TIMEOUT = 2.0

    def __init__(self, logger=None):
        self.logger = logger
        self.active_target = ActiveTarget(logger=logger)

    # ==========================================================
    # Логирование
    # ==========================================================

    def _log(self, message: str) -> None:

        if self.logger:

            try:
                self.logger.info(message)
            except Exception:
                pass

    # ==========================================================
    # IPC
    # ==========================================================

    def _security_request(
        self,
        action: str,
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Отправляет JSON-запрос Security IPC Server.
        """

        payload = {
            "action": action,
            **kwargs
        }

        try:

            with socket.create_connection(
                (
                    self.SECURITY_HOST,
                    self.SECURITY_PORT
                ),
                timeout=self.SECURITY_TIMEOUT
            ) as sock:

                message = (
                    json.dumps(
                        payload,
                        ensure_ascii=False
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
                    self._log(
                        "Security IPC не вернул ответ."
                    )

                    return None

                response_line = (
                    data.split(
                        b"\n",
                        1
                    )[0]
                )

                response = json.loads(
                    response_line.decode(
                        "utf-8"
                    )
                )

                return response

        except (ConnectionRefusedError, TimeoutError):

            self._log(
                "Security IPC Server недоступен."
            )

            return None

        except OSError as exc:

            self._log(
                f"Ошибка подключения к Security IPC: {exc}"
            )

            return None

        except json.JSONDecodeError as exc:

            self._log(
                f"Некорректный JSON от Security: {exc}"
            )

            return None

        except Exception as exc:

            self._log(
                f"Ошибка Security IPC: {exc}"
            )

            return None

    # ==========================================================
    # Проверка файла
    # ==========================================================

    def check_file(self) -> str:
        """
        Проверяет выделенный файл.
        """

        target = self.active_target.get_selected()

        if not target:

            return (
                "Не удалось определить выделенный объект. "
                "Выделите файл в Проводнике."
            )

        if target["type"] != "file":

            return (
                "Сейчас выделена папка, а не файл."
            )

        path = target["path"]

        self._log(
            f"Запрос проверки файла: {path}"
        )

        response = self._security_request(
            "scan_file",
            path=path
        )

        if not response:

            return (
                "Security сейчас недоступен."
            )

        if not response.get("ok", False):

            error = response.get(
                "error",
                "неизвестная ошибка"
            )

            return (
                f"Security не смог проверить файл: {error}"
            )

        return self._format_scan_result(
            "файл",
            target["name"],
            response
        )

    # ==========================================================
    # Проверка папки
    # ==========================================================

    def check_folder(self) -> str:
        """
        Проверяет выделенную папку.
        """

        target = self.active_target.get_selected()

        if not target:

            return (
                "Не удалось определить выделенный объект. "
                "Выделите папку в Проводнике."
            )

        if target["type"] != "folder":

            return (
                "Сейчас выделен файл, а не папка."
            )

        path = target["path"]

        self._log(
            f"Запрос проверки папки: {path}"
        )

        response = self._security_request(
            "scan_folder",
            path=path
        )

        if not response:

            return (
                "Security сейчас недоступен."
            )

        if not response.get("ok", False):

            error = response.get(
                "error",
                "неизвестная ошибка"
            )

            return (
                f"Security не смог проверить папку: {error}"
            )

        return self._format_scan_result(
            "папку",
            target["name"],
            response
        )

    # ==========================================================
    # Форматирование результата
    # ==========================================================

    def _format_scan_result(
        self,
        target_type: str,
        target_name: str,
        response: Dict[str, Any]
    ) -> str:
        """
        Превращает ответ Security в короткий ответ для JARVIS.
        """

        result = response.get(
            "result"
        )

        if result is None:

            result = response.get(
                "data"
            )

        if result is None:

            return (
                f"Проверка {target_type} "
                f"{target_name} завершена."
            )

        if isinstance(result, dict):

            threat = result.get(
                "threat"
            )

            status = result.get(
                "status"
            )

            risk = result.get(
                "risk"
            )

            if threat is True:

                return (
                    f"Внимание. В {target_type} "
                    f"{target_name} обнаружена потенциальная угроза."
                )

            if status:

                return (
                    f"Проверка {target_type} "
                    f"{target_name} завершена. "
                    f"Статус: {status}."
                )

            if risk:

                return (
                    f"Проверка {target_type} "
                    f"{target_name} завершена. "
                    f"Уровень риска: {risk}."
                )

        return (
            f"Проверка {target_type} "
            f"{target_name} завершена."
        )

    # ==========================================================
    # Универсальный обработчик
    # ==========================================================

    def execute(
        self,
        command: str
    ) -> Optional[str]:
        """
        Обрабатывает Security-команды.
        """

        if not command:

            return None

        command = command.lower().strip()

        # ------------------------------
        # Проверка файла
        # ------------------------------

        if (
            "проверь файл" in command
            or "проверить файл" in command
        ):

            return self.check_file()

        # ------------------------------
        # Проверка папки
        # ------------------------------

        if (
            "проверь папку" in command
            or "проверить папку" in command
        ):

            return self.check_folder()

        return None