"""
correlation_engine.py

Correlation Engine для JARVIS Security.

V3.0

Объединяет результаты различных Security-модулей
в связанные security entities.

Источники:
- ProcessScanner
- StartupScanner
- NetworkScanner
- FirewallScanner
- DNSScanner

ВАЖНО:
Correlation Engine не определяет вирус самостоятельно.
Его задача — найти связи между объектами.
Окончальный анализ выполняется другими компонентами.
"""


class CorrelationEngine:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

        self.last_results = []

        self.last_statistics = {

            "entities": 0,

            "processes": 0,

            "startup_links": 0,

            "network_links": 0,

            "firewall_links": 0,

            "dns_servers": 0

        }

        self.log(
            "Correlation Engine V3.0 инициализирован."
        )

    # ==========================================================
    # ОСНОВНАЯ КОРРЕЛЯЦИЯ
    # ==========================================================

    def correlate(
        self,
        processes=None,
        startup=None,
        network=None,
        firewall=None,
        dns=None
    ):

        processes = (
            processes
            if isinstance(processes, list)
            else []
        )

        startup = (
            startup
            if isinstance(startup, list)
            else []
        )

        network = (
            network
            if isinstance(network, list)
            else []
        )

        firewall = (
            firewall
            if isinstance(firewall, list)
            else []
        )

        dns = (
            dns
            if isinstance(dns, dict)
            else {}
        )

        self.log(
            "Начало корреляции Security-данных."
        )

        # ======================================================
        # Подготавливаем сетевые данные
        # ======================================================

        network_connections = (
            self._extract_network_connections(
                network
            )
        )

        # ======================================================
        # Подготавливаем Firewall
        # ======================================================

        firewall_rules = (
            self._extract_firewall_rules(
                firewall
            )
        )

        # ======================================================
        # Создаём lookup-таблицы
        # ======================================================

        startup_by_name = (
            self._build_startup_lookup(
                startup
            )
        )

        network_by_pid = (
            self._build_network_lookup(
                network_connections
            )
        )

        firewall_by_program = (
            self._build_firewall_lookup(
                firewall_rules
            )
        )

        # ======================================================
        # Создаём entities
        # ======================================================

        entities = []

        processed_pids = set()

        for process in processes:

            if not isinstance(
                process,
                dict
            ):

                continue

            pid = process.get(
                "pid"
            )

            name = process.get(
                "name"
            )

            if pid is None:

                continue

            if pid in processed_pids:

                continue

            processed_pids.add(
                pid
            )

            entity = {

                "pid":
                    pid,

                "process":
                    name,

                "session_name":
                    process.get(
                        "session_name"


),

                "session_number":
                    process.get(
                        "session_number"
                    ),

                "memory":
                    process.get(
                        "memory"
                    ),

                "startup":
                    [],

                "network":
                    [],

                "firewall":
                    [],

                "dns":
                    self._build_dns_data(
                        dns
                    )

            }

            # ==================================================
            # Startup correlation
            # ==================================================

            process_name = str(
                name
                or ""
            ).lower()

            if process_name:

                entity[
                    "startup"
                ] = list(
                    startup_by_name.get(
                        process_name,
                        []
                    )
                )

            # ==================================================
            # Network correlation
            # ==================================================

            entity[
                "network"
            ] = list(
                network_by_pid.get(
                    pid,
                    []
                )
            )

            # ==================================================
            # Firewall correlation
            # ==================================================

            firewall_matches = (
                self._match_firewall_rules(
                    name,
                    firewall_by_program
                )
            )

            entity[
                "firewall"
            ] = firewall_matches

            entities.append(
                entity
            )

        # ======================================================
        # Сохраняем
        # ======================================================

        self.last_results = list(
            entities
        )

        self.last_statistics = (
            self._build_statistics(
                entities,
                startup,
                network_connections,
                firewall_rules,
                dns
            )
        )

        self.log(
            "Корреляция завершена. "
            f"Связанных объектов: {len(entities)}"
        )

        return list(
            entities
        )

    # ==========================================================
    # NETWORK DATA
    # ==========================================================

    def _extract_network_connections(
        self,
        network
    ):

        if not isinstance(
            network,
            list
        ):

            return []

        return [

            item

            for item
            in network

            if isinstance(
                item,
                dict
            )

        ]

    # ==========================================================
    # FIREWALL DATA
    # ==========================================================

    def _extract_firewall_rules(
        self,
        firewall
    ):

        if not isinstance(
            firewall,
            list
        ):

            return []

        return [

            item

            for item
            in firewall

            if isinstance(
                item,
                dict
            )

        ]

    # ==========================================================
    # STARTUP LOOKUP
    # ==========================================================

    def _build_startup_lookup(
        self,
        startup
    ):

        lookup = {}

        for item in startup:

            if not isinstance(
                item,
                dict
            ):

                continue

            name = item.get(
                "name"
            )


            command = item.get(
                "command",
                ""
            )

            if not name:

                continue

            key = str(
                name
            ).lower()

            if key not in lookup:

                lookup[key] = []

            lookup[key].append(
                dict(item)
            )

            # ==================================================
            # Дополнительная связь через имя executable
            # ==================================================

            command_name = (
                self._extract_executable_name(
                    command
                )
            )

            if command_name:

                command_key = (
                    command_name.lower()
                )

                if command_key not in lookup:

                    lookup[command_key] = []

                if item not in lookup[
                    command_key
                ]:

                    lookup[
                        command_key
                    ].append(
                        dict(item)
                    )

        return lookup

    # ==========================================================
    # NETWORK LOOKUP ПО PID
    # ==========================================================

    def _build_network_lookup(
        self,
        connections
    ):

        lookup = {}

        for connection in connections:

            pid = connection.get(
                "pid"
            )

            if pid is None:

                continue

            if pid not in lookup:

                lookup[pid] = []

            lookup[pid].append(
                dict(connection)
            )

        return lookup

    # ==========================================================
    # FIREWALL LOOKUP
    # ==========================================================

    def _build_firewall_lookup(
        self,
        rules
    ):

        lookup = {}

        for rule in rules:

            program = rule.get(
                "program"
            )

            if not program:

                continue

            program = str(
                program
            ).lower()

            executable = (
                self._extract_executable_name(
                    program
                )
            )

            if not executable:

                continue

            if executable not in lookup:

                lookup[
                    executable
                ] = []

            lookup[
                executable
            ].append(
                dict(rule)
            )

        return lookup

    # ==========================================================
    # FIREWALL MATCH
    # ==========================================================

    def _match_firewall_rules(
        self,
        process_name,
        firewall_lookup
    ):

        if not process_name:

            return []

        executable = (
            self._extract_executable_name(
                process_name
            )
        )

        if not executable:

            return []

        return [

            dict(rule)

            for rule
            in firewall_lookup.get(
                executable.lower(),
                []
            )

        ]

    # ==========================================================
    # DNS DATA
    # ==========================================================

    def _build_dns_data(
        self,
        dns
    ):

        if not isinstance(
            dns,
            dict
        ):

            return {

                "servers": [],

                "interfaces": []

            }

        interfaces = (
            dns.get(
                "interfaces",
                []
            )
        )

        if not isinstance(
            interfaces,
            list
        ):

            interfaces = []

        servers = []

        for interface in interfaces:


            if not isinstance(
                interface,
                dict
            ):

                continue

            interface_servers = (
                interface.get(
                    "dns_servers",
                    []
                )
            )

            if not isinstance(
                interface_servers,
                list
            ):

                continue

            for server in (
                interface_servers
            ):

                if server not in servers:

                    servers.append(
                        server
                    )

        return {

            "servers":
                servers,

            "interfaces":
                [
                    dict(item)

                    for item
                    in interfaces

                    if isinstance(
                        item,
                        dict
                    )
                ]

        }

    # ==========================================================
    # ИЗВЛЕЧЕНИЕ EXECUTABLE
    # ==========================================================

    def _extract_executable_name(
        self,
        value
    ):

        if not value:

            return None

        value = str(
            value
        ).strip()

        # ======================================================
        # Убираем кавычки
        # ======================================================

        value = value.strip(
            '"'
        )

        # ======================================================
        # Если есть параметры,
        # оставляем только путь
        # ======================================================

        if " " in value:

            first_part = (
                value.split(
                    " "
                )[0]
            )

            first_part = (
                first_part.strip(
                    '"'
                )
            )

            value = first_part

        # ======================================================
        # Извлекаем имя файла
        # ======================================================

        value = value.replace(
            "\\",
            "/"
        )

        executable = (
            value.split(
                "/"
            )[-1]
        )

        if not executable:

            return None

        return executable

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def _build_statistics(
        self,
        entities,
        startup,
        network,
        firewall,
        dns
    ):

        statistics = {

            "entities":
                len(entities),

            "processes":
                len(entities),

            "startup_links":
                0,

            "network_links":
                0,

            "firewall_links":
                0,

            "dns_servers":
                0

        }

        for entity in entities:

            statistics[
                "startup_links"
            ] += len(
                entity.get(
                    "startup",
                    []
                )
            )

            statistics[
                "network_links"
            ] += len(
                entity.get(
                    "network",
                    []
                )
            )

            statistics[
                "firewall_links"
            ] += len(
                entity.get(
                    "firewall",
                    []
                )
            )

        # ======================================================
        # DNS
        # ======================================================

        dns_servers = set()

        if isinstance(
            dns,
            dict
        ):

            interfaces = (
                dns.get(
                    "interfaces",
                    []


)
            )

            if isinstance(
                interfaces,
                list
            ):

                for interface in interfaces:

                    if not isinstance(
                        interface,
                        dict
                    ):

                        continue

                    servers = (
                        interface.get(
                            "dns_servers",
                            []
                        )
                    )

                    if not isinstance(
                        servers,
                        list
                    ):

                        continue

                    for server in servers:

                        dns_servers.add(
                            server
                        )

        statistics[
            "dns_servers"
        ] = len(
            dns_servers
        )

        return statistics

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНИХ РЕЗУЛЬТАТОВ
    # ==========================================================

    def get_last_results(self):

        return [

            dict(entity)

            for entity
            in self.last_results

        ]

    # ==========================================================
    # ПОЛУЧЕНИЕ СТАТИСТИКИ
    # ==========================================================

    def get_statistics(self):

        return dict(
            self.last_statistics
        )

    # ==========================================================
    # ПОИСК ПО PID
    # ==========================================================

    def find_by_pid(
        self,
        pid
    ):

        for entity in self.last_results:

            if entity.get(
                "pid"
            ) == pid:

                return dict(
                    entity
                )

        return None

    # ==========================================================
    # ПОИСК ПО ИМЕНИ
    # ==========================================================

    def find_by_process(
        self,
        process_name
    ):

        if not process_name:

            return []

        target = str(
            process_name
        ).lower()

        results = []

        for entity in self.last_results:

            name = str(
                entity.get(
                    "process",
                    ""
                )
            ).lower()

            if name == target:

                results.append(
                    dict(entity)
                )

        return results

    # ==========================================================
    # ПРОЦЕССЫ С СЕТЕВОЙ АКТИВНОСТЬЮ
    # ==========================================================

    def get_network_processes(self):

        return [

            dict(entity)

            for entity
            in self.last_results

            if entity.get(
                "network"
            )

        ]

    # ==========================================================
    # ПРОЦЕССЫ ИЗ АВТОЗАГРУЗКИ
    # ==========================================================

    def get_startup_processes(self):

        return [

            dict(entity)

            for entity
            in self.last_results

            if entity.get(
                "startup"
            )

        ]

    # ==========================================================
    # ПРОЦЕССЫ С FIREWALL RULE
    # ==========================================================

    def get_firewall_processes(self):

        return [

            dict(entity)

            for entity
            in self.last_results

            if entity.get(
                "firewall"
            )

        ]

    # ==========================================================
    # ПРОЦЕССЫ С НЕСКОЛЬКИМИ СВЯЗЯМИ
    # ==========================================================

    def get_high_activity_processes(
        self,


                minimum_network_connections=3
    ):

        results = []

        for entity in self.last_results:

            network = entity.get(
                "network",
                []
            )

            if len(network) >= (
                minimum_network_connections
            ):

                results.append(
                    dict(entity)
                )

        return results

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.last_results = []

        self.last_statistics = {

            "entities": 0,

            "processes": 0,

            "startup_links": 0,

            "network_links": 0,

            "firewall_links": 0,

            "dns_servers": 0

        }

        self.log(
            "Результаты Correlation Engine очищены."
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