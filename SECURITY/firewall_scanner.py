"""
firewall_scanner.py

Firewall Scanner для JARVIS Security.

V2.8

Отвечает за чтение правил Windows Firewall.

Модуль:
- получает правила Windows Firewall;
- определяет направление;
- определяет действие;
- определяет состояние;
- получает программу, протокол и порты;
- формирует статистику.

ВАЖНО:
Модуль работает только в режиме чтения.
Он НЕ изменяет правила Firewall.
"""


import subprocess


class FirewallScanner:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

        self.last_rules = []

        self.last_results = {

            "rules": [],

            "statistics": {}

        }

        self.log(
            "Firewall Scanner V2.8 инициализирован."
        )

    # ==========================================================
    # ПОЛНОЕ СКАНИРОВАНИЕ
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сканирования Windows Firewall."
        )

        rules = self.scan_rules()

        statistics = (
            self.get_statistics(
                rules
            )
        )

        result = {

            "rules":
                list(rules),

            "statistics":
                statistics

        }

        self.last_results = result

        self.log(
            "Сканирование Firewall завершено. "
            f"Правил: {len(rules)}"
        )

        return dict(
            result
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПРАВИЛ
    # ==========================================================

    def scan_rules(self):

        command = [

            "powershell",

            "-NoProfile",

            "-NonInteractive",

            "-Command",

            (
                "Get-NetFirewallRule | "
                "ForEach-Object { "
                "$p = $_ | Get-NetFirewallPortFilter; "
                "$a = $_ | Get-NetFirewallApplicationFilter; "
                "[PSCustomObject]@{"
                "Name=$_.DisplayName;"
                "Enabled=$_.Enabled;"
                "Direction=$_.Direction;"
                "Action=$_.Action;"
                "Profile=$_.Profile;"
                "Protocol=$p.Protocol;"
                "LocalPort=$p.LocalPort;"
                "RemotePort=$p.RemotePort;"
                "Program=$a.Program;"
                "} "
                "} | ConvertTo-Json -Compress"
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
                "Сканирование Firewall превысило "
                "лимит времени."
            )

            return []

        except Exception as error:

            self.log(
                f"Ошибка запуска Firewall Scanner: "
                f"{error}"
            )

            return []

        if process.returncode != 0:

            error_text = (
                process.stderr.strip()
            )

            self.log(
                "PowerShell вернул ошибку: "
                f"{error_text}"
            )

            return []

        output = (
            process.stdout.strip()
        )

        if not output:

            self.log(
                "Windows Firewall не вернул правила."
            )

            self.last_rules = []

            return []

        try:

            import json

            data = json.loads(
                output
            )

        except Exception as error:

            self.log(
                f"Ошибка разбора данных Firewall: "
                f"{error}"
            )

            return []


        # ======================================================
        # PowerShell может вернуть:
        #
        # один объект
        # или список объектов
        # ======================================================

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

        rules = []

        for item in data:

            if not isinstance(
                item,
                dict
            ):

                continue

            rule = {

                "name":
                    item.get(
                        "Name"
                    ),

                "enabled":
                    self._normalize_value(
                        item.get(
                            "Enabled"
                        )
                    ),

                "direction":
                    self._normalize_value(
                        item.get(
                            "Direction"
                        )
                    ),

                "action":
                    self._normalize_value(
                        item.get(
                            "Action"
                        )
                    ),

                "profile":
                    self._normalize_value(
                        item.get(
                            "Profile"
                        )
                    ),

                "protocol":
                    self._normalize_value(
                        item.get(
                            "Protocol"
                        )
                    ),

                "local_port":
                    self._normalize_value(
                        item.get(
                            "LocalPort"
                        )
                    ),

                "remote_port":
                    self._normalize_value(
                        item.get(
                            "RemotePort"
                        )
                    ),

                "program":
                    self._normalize_value(
                        item.get(
                            "Program"
                        )
                    )

            }

            rules.append(
                rule
            )

        self.last_rules = list(
            rules
        )

        return list(
            rules
        )

    # ==========================================================
    # НОРМАЛИЗАЦИЯ ЗНАЧЕНИЙ
    # ==========================================================

    def _normalize_value(
        self,
        value
    ):

        if value is None:

            return None

        if isinstance(
            value,
            list
        ):

            return ", ".join(

                str(item)

                for item
                in value

            )

        return str(
            value
        )

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self,
        rules=None
    ):

        if rules is None:

            rules = (
                self.last_rules
            )

        statistics = {

            "total":
                len(rules),

            "enabled":
                0,

            "disabled":
                0,

            "inbound":
                0,

            "outbound":
                0,

            "allow":
                0,

            "block":
                0,

            "tcp":
                0,

            "udp":
                0,

            "program_rules":
                0

        }

        for rule in rules:

            enabled = str(
                rule.get(
                    "enabled",
                    ""
                )
            ).lower()

            direction = str(


                rule.get(
                    "direction",
                    ""
                )
            ).lower()

            action = str(
                rule.get(
                    "action",
                    ""
                )
            ).lower()

            protocol = str(
                rule.get(
                    "protocol",
                    ""
                )
            ).lower()

            program = rule.get(
                "program"
            )

            # ==================================================
            # ENABLED
            # ==================================================

            if enabled == "true":

                statistics[
                    "enabled"
                ] += 1

            elif enabled == "false":

                statistics[
                    "disabled"
                ] += 1

            # ==================================================
            # DIRECTION
            # ==================================================

            if direction == "inbound":

                statistics[
                    "inbound"
                ] += 1

            elif direction == "outbound":

                statistics[
                    "outbound"
                ] += 1

            # ==================================================
            # ACTION
            # ==================================================

            if action == "allow":

                statistics[
                    "allow"
                ] += 1

            elif action == "block":

                statistics[
                    "block"
                ] += 1

            # ==================================================
            # PROTOCOL
            # ==================================================

            if "tcp" in protocol:

                statistics[
                    "tcp"
                ] += 1

            elif "udp" in protocol:

                statistics[
                    "udp"
                ] += 1

            # ==================================================
            # PROGRAM
            # ==================================================

            if program:

                statistics[
                    "program_rules"
                ] += 1

        return statistics

    # ==========================================================
    # ПРАВИЛА ВХОДЯЩЕГО ТРАФИКА
    # ==========================================================

    def get_inbound_rules(self):

        return [

            dict(rule)

            for rule
            in self.last_rules

            if str(
                rule.get(
                    "direction",
                    ""
                )
            ).lower() == "inbound"

        ]

    # ==========================================================
    # ПРАВИЛА ИСХОДЯЩЕГО ТРАФИКА
    # ==========================================================

    def get_outbound_rules(self):

        return [

            dict(rule)

            for rule
            in self.last_rules

            if str(
                rule.get(
                    "direction",
                    ""
                )
            ).lower() == "outbound"

        ]

    # ==========================================================
    # РАЗРЕШАЮЩИЕ ПРАВИЛА
    # ==========================================================

    def get_allow_rules(self):

        return [

            dict(rule)

            for rule
            in self.last_rules

            if str(
                rule.get(
                    "action",
                    ""
                )
            ).lower() == "allow"

        ]

    # ==========================================================
    # БЛОКИРУЮЩИЕ ПРАВИЛА
    # ==========================================================

    def get_block_rules(self):

        return [

            dict(rule)

            for rule
            in self.last_rules

            if str(


                rule.get(
                    "action",
                    ""
                )
            ).lower() == "block"

        ]

    # ==========================================================
    # ВКЛЮЧЁННЫЕ ПРАВИЛА
    # ==========================================================

    def get_enabled_rules(self):

        return [

            dict(rule)

            for rule
            in self.last_rules

            if str(
                rule.get(
                    "enabled",
                    ""
                )
            ).lower() == "true"

        ]

    # ==========================================================
    # ПОСЛЕДНИЕ РЕЗУЛЬТАТЫ
    # ==========================================================

    def get_last_results(self):

        return dict(
            self.last_results
        )

    # ==========================================================
    # ПОСЛЕДНИЕ ПРАВИЛА
    # ==========================================================

    def get_last_rules(self):

        return list(
            self.last_rules
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.last_rules = []

        self.last_results = {

            "rules": [],

            "statistics": {}

        }

        self.log(
            "Результаты Firewall Scanner очищены."
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