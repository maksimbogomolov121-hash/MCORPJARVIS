"""
security_ipc_server.py
IPC-сервер Security.

Назначение:
- принимает команды от JARVIS по TCP;
- работает независимо от JARVIS;
- предоставляет Security API через локальный IPC;
- позволяет проверять конкретные файлы и папки;
- поддерживает управление состоянием JARVIS в Security.

Протокол:
- TCP
- JSON
- одна команда = одна строка
- один ответ = одна строка
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from typing import Any, Optional


class SecurityIPCServer:
    """
    Локальный IPC-сервер Security.

    JARVIS подключается к нему через:
        127.0.0.1:8765

    Security при этом остаётся самостоятельным процессом.
    """

    HOST = "127.0.0.1"
    PORT = 8765

    BUFFER_SIZE = 4096
    SOCKET_TIMEOUT = 2.0

    # ========================================================
    # INIT
    # ========================================================

    def __init__(
        self,
        security_api: Any = None,
        security_voice_interface: Any = None,
        jarvis_security_bridge: Any = None,
        logger: Any = None,
    ) -> None:
        """
        Инициализация IPC-сервера.

        Parameters
        ----------
        security_api:
            Экземпляр SecurityAPI.

        security_voice_interface:
            Интерфейс голосового управления Security.

        jarvis_security_bridge:
            Bridge между Security и JARVIS.

        logger:
            Общий logger Security.
        """

        self.security_api = security_api

        self.security_voice_interface = (
            security_voice_interface
        )

        self.jarvis_security_bridge = (
            jarvis_security_bridge
        )

        self.logger = (
            logger
            if logger is not None
            else logging.getLogger(
                "JARVIS.Security.IPC"
            )
        )

        self._server_socket: Optional[
            socket.socket
        ] = None

        self._server_thread: Optional[
            threading.Thread
        ] = None

        self._running = False

        self._lock = threading.Lock()

    # ========================================================
    # START
    # ========================================================

    def start(self) -> bool:
        """
        Запускает IPC-сервер.

        Returns
        -------
        bool
            True, если сервер успешно запущен.
        """

        with self._lock:
            if self._running:
                self._log(
                    "info",
                    "Security IPC Server уже запущен.",
                )
                return True

            try:
                server_socket = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                )

                server_socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_REUSEADDR,
                    1,
                )

                server_socket.bind(
                    (
                        self.HOST,
                        self.PORT,
                    )
                )

                server_socket.listen(5)

                server_socket.settimeout(
                    self.SOCKET_TIMEOUT
                )

                self._server_socket = server_socket
                self._running = True

                self._server_thread = (
                    threading.Thread(
                        target=self._server_loop,
                        name="SecurityIPCServer",
                        daemon=True,
                    )
                )

                self._server_thread.start()

                self._log(
                    "info",
                    (
                        "Security IPC Server запущен "
                        "на %s:%s."
                    ),
                    self.HOST,
                    self.PORT,
                )

                return True


            except Exception as exc:
                self._running = False

                if self._server_socket is not None:
                    try:
                        self._server_socket.close()
                    except Exception:
                        pass

                self._server_socket = None

                self._log(
                    "error",
                    (
                        "Ошибка запуска Security IPC Server: "
                        "%s"
                    ),
                    exc,
                )

                return False

    # ========================================================
    # STOP
    # ========================================================

    def stop(self) -> None:
        """
        Останавливает IPC-сервер.
        """

        with self._lock:
            if not self._running:
                return

            self._running = False

            server_socket = self._server_socket
            self._server_socket = None

        if server_socket is not None:
            try:
                server_socket.shutdown(
                    socket.SHUT_RDWR
                )
            except Exception:
                pass

            try:
                server_socket.close()
            except Exception:
                pass

        server_thread = self._server_thread
        self._server_thread = None

        if (
            server_thread is not None
            and server_thread.is_alive()
            and server_thread
            is not threading.current_thread()
        ):
            server_thread.join(
                timeout=2.0
            )

        self._log(
            "info",
            "Security IPC Server остановлен.",
        )

    # ========================================================
    # STATUS
    # ========================================================

    def is_running(self) -> bool:
        """
        Возвращает состояние IPC-сервера.
        """

        return self._running

    # ========================================================
    # SERVER LOOP
    # ========================================================

    def _server_loop(self) -> None:
        """
        Основной цикл приёма IPC-подключений.
        """

        self._log(
            "info",
            "Security IPC Server ожидает подключения JARVIS.",
        )

        while self._running:
            server_socket = self._server_socket

            if server_socket is None:
                break

            try:
                connection, address = (
                    server_socket.accept()
                )

            except socket.timeout:
                continue

            except OSError:
                if not self._running:
                    break

                self._log(
                    "error",
                    "Ошибка accept() Security IPC Server.",
                )
                continue

            except Exception as exc:
                if not self._running:
                    break

                self._log(
                    "error",
                    (
                        "Ошибка при принятии IPC "
                        "подключения: %s"
                    ),
                    exc,
                )
                continue

            client_thread = threading.Thread(
                target=self._handle_client,
                args=(
                    connection,
                    address,
                ),
                daemon=True,
            )

            client_thread.start()

    # ========================================================
    # CLIENT
    # ========================================================

    def _handle_client(
        self,
        connection: socket.socket,
        address: Any,
    ) -> None:
        """
        Обрабатывает одно подключение клиента.
        """

        try:
            connection.settimeout(
                self.SOCKET_TIMEOUT


)

            self._log(
                "info",
                (
                    "IPC-клиент подключён: %s"
                ),
                address,
            )

            buffer = ""

            while self._running:
                try:
                    data = connection.recv(
                        self.BUFFER_SIZE
                    )

                except socket.timeout:
                    break

                except ConnectionResetError:
                    break

                if not data:
                    break

                buffer += data.decode(
                    "utf-8",
                    errors="replace",
                )

                while "\n" in buffer:
                    line, buffer = (
                        buffer.split(
                            "\n",
                            1,
                        )
                    )

                    line = line.strip()

                    if not line:
                        continue

                    try:
                        request = json.loads(
                            line
                        )

                    except json.JSONDecodeError as exc:
                        self._send_response(
                            connection,
                            {
                                "ok": False,
                                "error": (
                                    "Некорректный JSON."
                                ),
                                "details": str(exc),
                            },
                        )
                        continue

                    if not isinstance(
                        request,
                        dict,
                    ):
                        self._send_response(
                            connection,
                            {
                                "ok": False,
                                "error": (
                                    "IPC-запрос должен "
                                    "быть JSON-объектом."
                                ),
                            },
                        )
                        continue

                    response = (
                        self._process_request(
                            request
                        )
                    )

                    self._send_response(
                        connection,
                        response,
                    )

        except Exception as exc:
            self._log(
                "error",
                (
                    "Ошибка обработки IPC-клиента "
                    "%s: %s"
                ),
                address,
                exc,
            )

        finally:
            try:
                connection.close()
            except Exception:
                pass

            self._log(
                "info",
                (
                    "IPC-клиент отключён: %s"
                ),
                address,
            )

    # ========================================================
    # REQUEST ROUTER
    # ========================================================

    def _process_request(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Маршрутизация IPC-запроса.
        """

        action = request.get(
            "action"
        )

        if not isinstance(
            action,
            str,
        ):
            return {
                "ok": False,
                "error": (
                    "IPC-запрос не содержит "
                    "корректного action."
                ),
            }

        action = action.strip().lower()

        try:
            if action == "ping":
                return self._action_ping()

            if action == "jarvis_on":
                return self._action_jarvis_on()

            if action == "jarvis_off":

             return self._action_jarvis_off()

            if action == "voice_command":
                return self._action_voice_command(
                    request
                )

            if action == "security_status":
                return self._action_security_status()

            if action == "scan_file":
                return self._action_scan_file(
                    request
                )

            if action == "scan_folder":
                return self._action_scan_folder(
                    request
                )

            return {
                "ok": False,
                "error": (
                    "Неизвестное IPC-действие."
                ),
                "action": action,
            }

        except Exception as exc:
            self._log(
                "error",
                (
                    "Ошибка IPC-действия '%s': %s"
                ),
                action,
                exc,
            )

            return {
                "ok": False,
                "action": action,
                "error": str(exc),
            }

    # ========================================================
    # PING
    # ========================================================

    def _action_ping(
        self,
    ) -> dict[str, Any]:
        """
        Проверка доступности Security IPC.
        """

        return {
            "ok": True,
            "action": "ping",
            "service": "JARVIS Security",
            "status": "online",
        }

    # ========================================================
    # JARVIS ON
    # ========================================================

    def _action_jarvis_on(
        self,
    ) -> dict[str, Any]:
        """
        Сообщает Security, что JARVIS подключился.
        """

        voice_interface = (
            self.security_voice_interface
        )

        if voice_interface is None:
            return {
                "ok": False,
                "action": "jarvis_on",
                "error": (
                    "SecurityVoiceInterface "
                    "не подключён."
                ),
            }

        set_active = getattr(
            voice_interface,
            "set_jarvis_active",
            None,
        )

        if not callable(set_active):
            return {
                "ok": False,
                "action": "jarvis_on",
                "error": (
                    "SecurityVoiceInterface "
                    "не поддерживает "
                    "set_jarvis_active()."
                ),
            }

        set_active(True)

        self._log(
            "info",
            "JARVIS подключён к Security.",
        )

        return {
            "ok": True,
            "action": "jarvis_on",
            "jarvis_active": True,
        }

    # ========================================================
    # JARVIS OFF
    # ========================================================

    def _action_jarvis_off(
        self,
    ) -> dict[str, Any]:
        """
        Сообщает Security, что JARVIS отключается.
        """

        voice_interface = (
            self.security_voice_interface
        )

        if voice_interface is None:
            return {
                "ok": False,
                "action": "jarvis_off",
                "error": (
                    "SecurityVoiceInterface "
                    "не подключён."
                ),
            }

        set_active = getattr(
            voice_interface,
            "set_jarvis_active",
            None,
        )

        if not callable(set_active):
            return {
                "ok": False,
                "action": "jarvis_off",
                "error": (
                    "SecurityVoiceInterface "
                    "не поддерживает "
                    "set_jarvis_active()."
                ),
            }

        set_active(False)

        self._log(
            "info",

"JARVIS отключён от Security.",
        )

        return {
            "ok": True,
            "action": "jarvis_off",
            "jarvis_active": False,
        }

    # ========================================================
    # VOICE COMMAND
    # ========================================================

    def _action_voice_command(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Передаёт голосовую команду в SecurityVoiceInterface.
        """

        text = request.get(
            "text"
        )

        if not isinstance(
            text,
            str,
        ):
            return {
                "ok": False,
                "action": "voice_command",
                "error": (
                    "Не указан текст команды."
                ),
            }

        text = text.strip()

        if not text:
            return {
                "ok": False,
                "action": "voice_command",
                "error": (
                    "Текст команды пуст."
                ),
            }

        voice_interface = (
            self.security_voice_interface
        )

        if voice_interface is None:
            return {
                "ok": False,
                "action": "voice_command",
                "error": (
                    "SecurityVoiceInterface "
                    "не подключён."
                ),
            }

        process = getattr(
            voice_interface,
            "process",
            None,
        )

        if not callable(process):
            return {
                "ok": False,
                "action": "voice_command",
                "error": (
                    "SecurityVoiceInterface "
                    "не поддерживает process()."
                ),
            }

        result = process(text)

        self._log(
            "info",
            (
                "Security получил команду JARVIS: %s"
            ),
            text,
        )

        return {
            "ok": True,
            "action": "voice_command",
            "text": text,
            "result": result,
        }

    # ========================================================
    # SECURITY STATUS
    # ========================================================

    def _action_security_status(
        self,
    ) -> dict[str, Any]:
        """
        Возвращает текущее состояние Security.
        """

        voice_interface = (
            self.security_voice_interface
        )

        status: dict[str, Any] = {
            "ok": True,
            "service": "JARVIS Security",
            "ipc_server": {
                "running": self.is_running(),
                "host": self.HOST,
                "port": self.PORT,
            },
        }

        if voice_interface is not None:
            get_status = getattr(
                voice_interface,
                "get_status",
                None,
            )

            if callable(get_status):
                try:
                    voice_status = get_status()

                    if isinstance(
                        voice_status,
                        dict,
                    ):
                        status[
                            "voice_interface"
                        ] = voice_status
                    else:
                        status[
                            "voice_interface"
                        ] = {
                            "status": voice_status
                        }

                except Exception as exc:
                    status[
                        "voice_interface"
                    ] = {
                        "error": str(exc)
                    }

            else:
                is_active = getattr(
                    voice_interface,
                    "is_jarvis_active",
                    None,
                )

                if callable(is_active):
                    try:

                     jarvis_active = bool(
                            is_active()
                        )
                    except Exception:
                        jarvis_active = False
                else:
                    jarvis_active = False

                status[
                    "voice_interface"
                ] = {
                    "jarvis_active": jarvis_active,
                    "voice_control_available": (
                        jarvis_active
                    ),
                }

        return status

    # ========================================================
    # SCAN FILE
    # ========================================================

    def _action_scan_file(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Проверяет конкретный файл через SecurityAPI.
        """

        file_path = request.get(
            "path"
        )

        if not isinstance(
            file_path,
            str,
        ):
            return {
                "ok": False,
                "action": "scan_file",
                "error": (
                    "Не указан путь к файлу."
                ),
            }

        file_path = file_path.strip()

        if not file_path:
            return {
                "ok": False,
                "action": "scan_file",
                "error": (
                    "Путь к файлу пуст."
                ),
            }

        security_api = (
            self.security_api
        )

        if security_api is None:
            return {
                "ok": False,
                "action": "scan_file",
                "error": (
                    "SecurityAPI не подключён "
                    "к IPC Server."
                ),
            }

        scan_file = getattr(
            security_api,
            "scan_file",
            None,
        )

        if not callable(scan_file):
            return {
                "ok": False,
                "action": "scan_file",
                "error": (
                    "SecurityAPI не поддерживает "
                    "scan_file()."
                ),
            }

        context = request.get(
            "context"
        )

        if not isinstance(
            context,
            dict,
        ):
            context = None

        self._log(
            "info",
            (
                "Запущена проверка файла через IPC: %s"
            ),
            file_path,
        )

        result = scan_file(
            file_path,
            context=context,
        )

        return {
            "ok": True,
            "action": "scan_file",
            "path": file_path,
            "result": result,
        }

    # ========================================================
    # SCAN FOLDER
    # ========================================================

    def _action_scan_folder(
        self,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Проверяет конкретную папку через SecurityAPI.
        """

        folder_path = request.get(
            "path"
        )

        if not isinstance(
            folder_path,
            str,
        ):
            return {
                "ok": False,
                "action": "scan_folder",
                "error": (
                    "Не указан путь к папке."
                ),
            }

        folder_path = folder_path.strip()

        if not folder_path:
            return {
                "ok": False,
                "action": "scan_folder",
                "error": (
                    "Путь к папке пуст."
                ),
            }

        security_api = (
            self.security_api
        )

        if security_api is None:
            return {
                "ok": False,
                "action": "scan_folder",
                "error": (
                    "SecurityAPI не подключён "
                    "к IPC Server."
                ),
            }

        scan_folder = getattr(
            security_api,
            "scan_folder",
            None,
        )

        if not callable(scan_folder):
            return {
                "ok": False,
                "action": "scan_folder",
                "error": (
                    "SecurityAPI не поддерживает "
                    "scan_folder()."
                ),
            }

        context = request.get(
            "context"
        )

        if not isinstance(
            context,
            dict,
        ):
            context = None

        self._log(
            "info",
            (
                "Запущена проверка папки через IPC: %s"
            ),
            folder_path,
        )

        result = scan_folder(
            folder_path,
            context=context,
        )

        return {
            "ok": True,
            "action": "scan_folder",
            "path": folder_path,
            "result": result,
        }

    # ========================================================
    # RESPONSE
    # ========================================================

    @staticmethod
    def _send_response(
        connection: socket.socket,
        response: dict[str, Any],
    ) -> None:
        """
        Отправляет JSON-ответ клиенту.
        """

        payload = (
            json.dumps(
                response,
                ensure_ascii=False,
                default=str,
            )
            + "\n"
        )

        connection.sendall(
            payload.encode("utf-8")
        )

    # ========================================================
    # LOGGING
    # ========================================================

    def _log(
        self,
        level: str,
        message: str,
        *args: Any,
    ) -> None:
        """
        Унифицированное логирование.
        """

        try:
            log_method = getattr(
                self.logger,
                level,
                None,
            )

            if callable(log_method):
                log_method(
                    message,
                    *args,
                )

        except Exception:
            pass


__all__ = [
    "SecurityIPCServer",
]