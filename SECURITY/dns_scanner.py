"""
dns_scanner.py

DNS Scanner для JARVIS Security.

V2.9

Отвечает за:
- получение DNS-серверов Windows;
- определение сетевых интерфейсов;
- получение DNS-конфигурации;
- проверку DNS-разрешения доменных имён;
- формирование статистики.

ВАЖНО:
Модуль работает в режиме чтения.
Он НЕ изменяет DNS-настройки.
"""


import json
import socket
import subprocess


class DNSScanner:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

        self.last_interfaces = []

        self.last_results = {

            "interfaces": [],

            "statistics": {}

        }

        self.log(
            "DNS Scanner V2.9 инициализирован."
        )

    # ==========================================================
    # ПОЛНОЕ СКАНИРОВАНИЕ
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сканирования DNS."
        )

        interfaces = (
            self.scan_dns_configuration()
        )

        statistics = (
            self.get_statistics(
                interfaces
            )
        )

        result = {

            "interfaces":
                list(interfaces),

            "statistics":
                statistics

        }

        self.last_interfaces = list(
            interfaces
        )

        self.last_results = result

        self.log(
            "Сканирование DNS завершено. "
            f"Интерфейсов: {len(interfaces)}"
        )

        return dict(
            result
        )

    # ==========================================================
    # DNS-КОНФИГУРАЦИЯ WINDOWS
    # ==========================================================

    def scan_dns_configuration(self):

        command = [

            "powershell",

            "-NoProfile",

            "-NonInteractive",

            "-Command",

            (
                "Get-DnsClientServerAddress | "
                "Select-Object InterfaceAlias,"
                "InterfaceIndex,"
                "AddressFamily,"
                "ServerAddresses | "
                "ConvertTo-Json -Compress"
            )

        ]

        try:

            process = subprocess.run(

                command,

                capture_output=True,

                text=True,

                encoding="utf-8",

                errors="replace",

                timeout=30

            )

        except subprocess.TimeoutExpired:

            self.log(
                "Сканирование DNS превысило "
                "лимит времени."
            )

            return []

        except Exception as error:

            self.log(
                f"Ошибка запуска PowerShell: {error}"
            )

            return []

        if process.returncode != 0:

            self.log(
                "PowerShell вернул ошибку: "
                f"{process.stderr.strip()}"
            )

            return []

        output = (
            process.stdout.strip()
        )

        if not output:

            self.log(
                "DNS-конфигурация не найдена."
            )

            return []

        try:

            data = json.loads(
                output
            )

        except Exception as error:

            self.log(
                f"Ошибка разбора DNS-данных: "
                f"{error}"
            )

            return []

        if isinstance(
            data,
            dict
        ):

            data = [
                data
            ]

        if not isinstance(
            data,
            list
        ):

            return []

        interfaces = []

        for item in data:

            if not isinstance(
                item,
                dict
            ):

                continue

            interface_name = (
                item.get(
                    "InterfaceAlias"


                )
            )

            interface_index = (
                item.get(
                    "InterfaceIndex"
                )
            )

            address_family = (
                item.get(
                    "AddressFamily"
                )
            )

            servers = (
                item.get(
                    "ServerAddresses"
                )
            )

            if servers is None:

                servers = []

            elif isinstance(
                servers,
                str
            ):

                servers = [
                    servers
                ]

            elif not isinstance(
                servers,
                list
            ):

                servers = [
                    str(servers)
                ]

            servers = [

                str(server)

                for server
                in servers

                if server

            ]

            result = {

                "interface":
                    interface_name,

                "interface_index":
                    interface_index,

                "address_family":
                    self._get_address_family_name(
                        address_family
                    ),

                "dns_servers":
                    servers

            }

            interfaces.append(
                result
            )

        return list(
            interfaces
        )

    # ==========================================================
    # ПРОВЕРКА DNS-РАЗРЕШЕНИЯ
    # ==========================================================

    def resolve_domain(
        self,
        domain
    ):

        if not domain:

            return {

                "domain":
                    domain,

                "resolved":
                    False,

                "addresses":
                    [],

                "error":
                    "Домен не указан."

            }

        domain = str(
            domain
        ).strip()

        try:

            addresses = socket.getaddrinfo(
                domain,
                None
            )

            resolved_addresses = []

            for item in addresses:

                address = item[
                    4
                ][0]

                if address not in (
                    resolved_addresses
                ):

                    resolved_addresses.append(
                        address
                    )

            return {

                "domain":
                    domain,

                "resolved":
                    True,

                "addresses":
                    resolved_addresses,

                "error":
                    None

            }

        except socket.gaierror as error:

            return {

                "domain":
                    domain,

                "resolved":
                    False,

                "addresses":
                    [],

                "error":
                    str(error)

            }

        except Exception as error:

            return {

                "domain":
                    domain,

                "resolved":
                    False,

                "addresses":
                    [],

                "error":
                    str(error)

            }

    # ==========================================================
    # НАЗВАНИЕ ADDRESS FAMILY
    # ==========================================================

    def _get_address_family_name(
        self,
        value
    ):

        if value is None:

            return "UNKNOWN"

        value = str(
            value
        ).upper()

        if "2" == value:

            return "IPv4"

        if "23" == value:

            return "IPv6"

        if "IPV4" in value:

            return "IPv4"

        if "IPV6" in value:

            return "IPv6"

        return value


    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self,
        interfaces=None
    ):

        if interfaces is None:

            interfaces = (
                self.last_interfaces
            )

        statistics = {

            "interfaces":
                len(interfaces),

            "interfaces_with_dns":
                0,

            "dns_servers":
                0,

            "unique_dns_servers":
                0,

            "ipv4":
                0,

            "ipv6":
                0

        }

        unique_servers = set()

        for interface in interfaces:

            servers = interface.get(
                "dns_servers",
                []
            )

            if servers:

                statistics[
                    "interfaces_with_dns"
                ] += 1

            statistics[
                "dns_servers"
            ] += len(
                servers
            )

            for server in servers:

                unique_servers.add(
                    server
                )

            family = str(
                interface.get(
                    "address_family",
                    ""
                )
            ).upper()

            if family == "IPV4":

                statistics[
                    "ipv4"
                ] += 1

            elif family == "IPV6":

                statistics[
                    "ipv6"
                ] += 1

        statistics[
            "unique_dns_servers"
        ] = len(
            unique_servers
        )

        return statistics

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНИХ РЕЗУЛЬТАТОВ
    # ==========================================================

    def get_last_results(self):

        return dict(
            self.last_results
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНЕЙ КОНФИГУРАЦИИ
    # ==========================================================

    def get_last_interfaces(self):

        return list(
            self.last_interfaces
        )

    # ==========================================================
    # СПИСОК ВСЕХ DNS-СЕРВЕРОВ
    # ==========================================================

    def get_dns_servers(self):

        servers = []

        for interface in (
            self.last_interfaces
        ):

            for server in interface.get(
                "dns_servers",
                []
            ):

                if server not in servers:

                    servers.append(
                        server
                    )

        return servers

    # ==========================================================
    # ПРОВЕРКА НАЛИЧИЯ DNS
    # ==========================================================

    def has_dns_configuration(self):

        return bool(
            self.get_dns_servers()
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.last_interfaces = []

        self.last_results = {

            "interfaces": [],

            "statistics": {}

        }

        self.log(
            "Результаты DNS Scanner очищены."
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