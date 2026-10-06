"""
network_scanner.py

Network Scanner для JARVIS Security.

V2.7

Отвечает за:
- получение активных сетевых соединений;
- получение listening-портов;
- определение PID процесса;
- определение имени процесса;
- формирование единого результата;
- базовую сетевую статистику.

ВАЖНО:
Модуль только собирает информацию.
Он НЕ блокирует соединения,
НЕ закрывает порты
и НЕ изменяет сетевые настройки.
"""

import socket


class NetworkScanner:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

        self.last_connections = []

        self.last_listening = []

        self.last_results = []

        self.log(
            "Network Scanner V2.7 инициализирован."
        )

    # ==========================================================
    # ПОЛНОЕ СКАНИРОВАНИЕ
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сетевого сканирования."
        )

        connections = self.scan_connections()

        listening = self.scan_listening()

        results = {

            "connections":
                list(connections),

            "listening":
                list(listening),

            "statistics":
                self.get_statistics(
                    connections,
                    listening
                )

        }

        self.last_results = results

        self.log(
            "Сетевое сканирование завершено. "
            f"Соединений: {len(connections)}, "
            f"портов: {len(listening)}"
        )

        return dict(
            results
        )

    # ==========================================================
    # АКТИВНЫЕ СОЕДИНЕНИЯ
    # ==========================================================

    def scan_connections(self):

        connections = []

        try:

            import psutil

            raw_connections = (
                psutil.net_connections(
                    kind="inet"
                )
            )

        except ImportError:

            self.log(
                "Модуль psutil не установлен."
            )

            return []

        except Exception as error:

            self.log(
                f"Ошибка получения соединений: {error}"
            )

            return []

        for connection in raw_connections:

            try:

                local_address = ""

                local_port = None

                remote_address = ""

                remote_port = None

                # ==================================================
                # Локальный адрес
                # ==================================================

                if connection.laddr:

                    local_address = (
                        connection.laddr.ip
                    )

                    local_port = (
                        connection.laddr.port
                    )

                # ==================================================
                # Удалённый адрес
                # ==================================================

                if connection.raddr:

                    remote_address = (
                        connection.raddr.ip
                    )

                    remote_port = (
                        connection.raddr.port
                    )

                pid = connection.pid

                process_name = (
                    self._get_process_name(
                        pid
                    )
                )

                result = {

                    "pid":
                        pid,

                    "process":
                        process_name,

                    "local_address":
                        local_address,

                    "local_port":
                        local_port,

                    "remote_address":


                    remote_address,

                    "remote_port":
                        remote_port,

                    "status":
                        connection.status,

                    "family":
                        self._get_family_name(
                            connection.family
                        ),

                    "type":
                        self._get_socket_type_name(
                            connection.type
                        )

                }

                connections.append(
                    result
                )

            except Exception as error:

                self.log(
                    f"Ошибка обработки соединения: {error}"
                )

        self.last_connections = list(
            connections
        )

        return list(
            connections
        )

    # ==========================================================
    # LISTENING-ПОРТЫ
    # ==========================================================

    def scan_listening(self):

        listening = []

        try:

            import psutil

            raw_connections = (
                psutil.net_connections(
                    kind="inet"
                )
            )

        except ImportError:

            self.log(
                "Модуль psutil не установлен."
            )

            return []

        except Exception as error:

            self.log(
                f"Ошибка получения listening-портов: {error}"
            )

            return []

        for connection in raw_connections:

            try:

                if connection.status != (
                    psutil.CONN_LISTEN
                ):

                    continue

                address = ""

                port = None

                if connection.laddr:

                    address = (
                        connection.laddr.ip
                    )

                    port = (
                        connection.laddr.port
                    )

                pid = connection.pid

                process_name = (
                    self._get_process_name(
                        pid
                    )
                )

                result = {

                    "pid":
                        pid,

                    "process":
                        process_name,

                    "address":
                        address,

                    "port":
                        port,

                    "family":
                        self._get_family_name(
                            connection.family
                        ),

                    "type":
                        self._get_socket_type_name(
                            connection.type
                        )

                }

                listening.append(
                    result
                )

            except Exception as error:

                self.log(
                    f"Ошибка обработки listening-порта: "
                    f"{error}"
                )

        self.last_listening = list(
            listening
        )

        return list(
            listening
        )

    # ==========================================================
    # ИМЯ ПРОЦЕССА
    # ==========================================================

    def _get_process_name(
        self,
        pid
    ):

        if pid is None:

            return "UNKNOWN"

        try:

            import psutil

            process = psutil.Process(
                pid
            )

            return process.name()

        except Exception:

            return "UNKNOWN"

    # ==========================================================
    # НАЗВАНИЕ FAMILY
    # ==========================================================

    def _get_family_name(
        self,
        family
    ):

        if family == socket.AF_INET:

            return "IPv4"

        if family == socket.AF_INET6:

            return "IPv6"


            return str(
            family
        )

    # ==========================================================
    # ТИП SOCKET
    # ==========================================================

    def _get_socket_type_name(
        self,
        socket_type
    ):

        if socket_type == socket.SOCK_STREAM:

            return "TCP"

        if socket_type == socket.SOCK_DGRAM:

            return "UDP"

        if socket_type == socket.SOCK_RAW:

            return "RAW"

        return str(
            socket_type
        )

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self,
        connections=None,
        listening=None
    ):

        if connections is None:

            connections = (
                self.last_connections
            )

        if listening is None:

            listening = (
                self.last_listening
            )

        statistics = {

            "connections":
                len(connections),

            "listening":
                len(listening),

            "established":
                0,

            "time_wait":
                0,

            "close_wait":
                0,

            "tcp":
                0,

            "udp":
                0,

            "ipv4":
                0,

            "ipv6":
                0,

            "processes":
                set()

        }

        for connection in connections:

            status = str(
                connection.get(
                    "status",
                    ""
                )
            ).upper()

            socket_type = str(
                connection.get(
                    "type",
                    ""
                )
            ).upper()

            family = str(
                connection.get(
                    "family",
                    ""
                )
            ).upper()

            if status == "ESTABLISHED":

                statistics[
                    "established"
                ] += 1

            elif status == "TIME_WAIT":

                statistics[
                    "time_wait"
                ] += 1

            elif status == "CLOSE_WAIT":

                statistics[
                    "close_wait"
                ] += 1

            if socket_type == "TCP":

                statistics[
                    "tcp"
                ] += 1

            elif socket_type == "UDP":

                statistics[
                    "udp"
                ] += 1

            if family == "IPV4":

                statistics[
                    "ipv4"
                ] += 1

            elif family == "IPV6":

                statistics[
                    "ipv6"
                ] += 1

            pid = connection.get(
                "pid"
            )

            if pid is not None:

                statistics[
                    "processes"
                ].add(
                    pid
                )

        statistics[
            "processes"
        ] = len(
            statistics[
                "processes"
            ]
        )

        return statistics

    # ==========================================================
    # ПОСЛЕДНИЕ РЕЗУЛЬТАТЫ
    # ==========================================================

    def get_last_results(self):

        if not self.last_results:

            return {

                "connections": [],

                "listening": [],

                "statistics":
                    self.get_statistics()

            }

        return dict(
            self.last_results
        )

    # ==========================================================
    # ПОСЛЕДНИЕ СОЕДИНЕНИЯ
    # ==========================================================

    def get_last_connections(self):

        return list(
            self.last_connections
        )


    # ==========================================================
    # ПОСЛЕДНИЕ LISTENING-ПОРТЫ
    # ==========================================================

    def get_last_listening(self):

        return list(
            self.last_listening
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.last_connections = []

        self.last_listening = []

        self.last_results = []

        self.log(
            "Результаты Network Scanner очищены."
        )

    # ==========================================================
    # ЛОГИРОВАНИЕ
    # ==========================================================

    def log(
        self,
        message
    ):

        if self.logger:

            if hasattr(
                self.logger,
                "info"
            ):

                self.logger.info(
                    message
                )

                return

        print(
            f"[SECURITY] {message}"
        )