"""
startup_behavior.py

JARVIS Security Core V2.2

Мониторинг поведения автозагрузки.

Модуль:
- получает текущие записи автозагрузки;
- создаёт начальный снимок;
- обнаруживает новые записи;
- обнаруживает удалённые записи;
- обнаруживает изменения существующих записей;
- передаёт события в BehaviorEngine.

Важно:
модуль не изменяет автозагрузку и ничего не удаляет.
"""

import time


class StartupBehaviorMonitor:

    def __init__(
        self,
        startup_scanner,
        behavior_engine,
        logger=None
    ):

        self.startup_scanner = startup_scanner
        self.behavior_engine = behavior_engine
        self.logger = logger

        # ======================================================
        # Предыдущий снимок
        # ======================================================

        self.previous_startup = {}

        # ======================================================
        # Состояние мониторинга
        # ======================================================

        self.running = False

        self.log(
            "Startup Behavior Monitor инициализирован."
        )

    # ==========================================================
    # Получение записей автозагрузки
    # ==========================================================

    def get_startup_entries(self):

        try:

            entries = self.startup_scanner.scan()

        except Exception as e:

            self.log(
                f"Ошибка получения автозагрузки: {e}"
            )

            return []

        if entries is None:

            return []

        if isinstance(
            entries,
            dict
        ):

            entries = [
                entries
            ]

        return list(
            entries
        )

    # ==========================================================
    # Получение имени записи
    # ==========================================================

    def get_name(
        self,
        entry
    ):

        if not isinstance(
            entry,
            dict
        ):

            return "unknown"

        name = (
            entry.get("name")
            or entry.get("Name")
            or entry.get("startup_name")
            or entry.get("StartupName")
        )

        if name:

            return str(
                name
            )

        return "unknown"

    # ==========================================================
    # Получение команды
    # ==========================================================

    def get_command(
        self,
        entry
    ):

        if not isinstance(
            entry,
            dict
        ):

            return ""

        command = (
            entry.get("command")
            or entry.get("Command")
            or entry.get("path")
            or entry.get("Path")
            or entry.get("executable")
            or entry.get("exe")
        )

        if command:

            return str(
                command
            )

        return ""

    # ==========================================================
    # Создание уникального ключа
    # ==========================================================

    def make_key(
        self,
        entry
    ):

        name = self.get_name(
            entry
        )

        location = ""

        if isinstance(
            entry,
            dict
        ):

            location = (
                entry.get("location")
                or entry.get("Location")
                or entry.get("source")
                or entry.get("Source")
                or ""
            )

        return (
            f"{name}|{location}"
        )

    # ==========================================================
    # Нормализация записи
    # ==========================================================

    def normalize_entry(
        self,
        entry
    ):

        if not isinstance(
            entry,
            dict
        ):

            return None

        return {

            "key":
                self.make_key(
                    entry
                ),

            "name":
                self.get_name(
                    entry
                ),

            "command":
                self.get_command(
                    entry
                ),

            "location":
                (
                    entry.get("location")
                    or entry.get("Location")
                    or entry.get("source")
                    or entry.get("Source")
                    or ""
                ),

            "enabled":
                entry.get(
                    "enabled",
                    entry.get(
                        "Enabled"
                    )
                ),

            "raw":
                entry

        }

    # ==========================================================
    # Создание снимка
    # ==========================================================

    def create_snapshot(self):

        entries = (
            self.get_startup_entries()
        )

        snapshot = {}

        for entry in entries:

            normalized = (
                self.normalize_entry(
                    entry
                )
            )

            if normalized is None:

                continue

            key = normalized[
                "key"
            ]

            snapshot[key] = normalized

        return snapshot

    # ==========================================================
    # Начальная инициализация
    # ==========================================================

    def initialize(self):

        snapshot = (
            self.create_snapshot()
        )

        self.previous_startup = (
            dict(snapshot)
        )

        self.log(
            "Начальный снимок автозагрузки создан. "
            f"Записей: {len(snapshot)}"
        )

        return dict(
            snapshot
        )

    # ==========================================================
    # Проверка изменений
    # ==========================================================

    def analyze_snapshot(
        self,
        current_startup
    ):

        if current_startup is None:

            current_startup = {}

        if not isinstance(
            current_startup,
            dict
        ):

            current_startup = {}

        # ======================================================
        # Сохраняем старый снимок
        # ======================================================

        old_startup = dict(
            self.previous_startup
        )

        current_keys = set(
            current_startup.keys()
        )

        previous_keys = set(
            old_startup.keys()
        )

        # ======================================================
        # Новые записи
        # ======================================================

        new_keys = (
            current_keys
            - previous_keys
        )

        # ======================================================
        # Удалённые записи
        # ======================================================

        removed_keys = (
            previous_keys
            - current_keys
        )

        # ======================================================
        # Изменённые записи
        # ======================================================

        common_keys = (
            current_keys
            & previous_keys
        )

        changed_keys = set()

        for key in common_keys:

            old_entry = old_startup[
                key
            ]

            new_entry = current_startup[
                key
            ]

            if (
                old_entry.get(
                    "command"
                )
                != new_entry.get(
                    "command"
                )
                or
                old_entry.get(
                    "enabled"
                )
                != new_entry.get(


        "enabled"
                )
            ):

                changed_keys.add(
                    key
                )

        new_entries = []

        removed_entries = []

        changed_entries = []

        # ======================================================
        # Обработка новых записей
        # ======================================================

        for key in new_keys:

            entry = current_startup[
                key
            ]

            new_entries.append(
                entry
            )

            name = entry.get(
                "name",
                "unknown"
            )

            command = entry.get(
                "command",
                ""
            )

            description = (
                f"Обнаружена новая запись "
                f"автозагрузки: {name}"
            )

            if command:

                description += (
                    f" | Команда: {command}"
                )

            self.behavior_engine.add_event(
                name,
                "STARTUP_ENTRY_CREATED",
                description,
                15
            )

            self.log(
                f"Новая запись автозагрузки: "
                f"{name}"
            )

        # ======================================================
        # Обработка удалённых записей
        # ======================================================

        for key in removed_keys:

            entry = old_startup[
                key
            ]

            removed_entries.append(
                entry
            )

            name = entry.get(
                "name",
                "unknown"
            )

            description = (
                f"Запись автозагрузки удалена: "
                f"{name}"
            )

            self.behavior_engine.add_event(
                name,
                "STARTUP_ENTRY_REMOVED",
                description,
                5
            )

            self.log(
                f"Запись автозагрузки удалена: "
                f"{name}"
            )

        # ======================================================
        # Обработка изменённых записей
        # ======================================================

        for key in changed_keys:

            old_entry = old_startup[
                key
            ]

            new_entry = current_startup[
                key
            ]

            changed_entries.append({

                "old":
                    old_entry,

                "new":
                    new_entry

            })

            name = new_entry.get(
                "name",
                "unknown"
            )

            old_command = old_entry.get(
                "command",
                ""
            )

            new_command = new_entry.get(
                "command",
                ""
            )

            description = (
                f"Изменена запись "
                f"автозагрузки: {name}"
            )

            if old_command != new_command:

                description += (
                    " | Изменена команда."
                )

            if (
                old_entry.get("enabled")
                != new_entry.get("enabled")
            ):

                description += (
                    " | Изменено состояние."
                )

            self.behavior_engine.add_event(
                name,
                "STARTUP_ENTRY_CHANGED",
                description,
                20
            )

            self.log(
                f"Изменена запись автозагрузки: "
                f"{name}"
            )

        # ======================================================
        # Обновляем состояние после анализа
        # ======================================================

        self.previous_startup = (
            dict(current_startup)
        )

        return {

            "new":
                new_entries,


                "removed":
                removed_entries,

            "changed":
                changed_entries,

            "total":
                len(current_startup)

        }

    # ==========================================================
    # Проверка
    # ==========================================================

    def check(self):

        current_snapshot = (
            self.create_snapshot()
        )

        if not self.previous_startup:

            self.previous_startup = (
                dict(current_snapshot)
            )

            self.log(
                "Создан первый снимок автозагрузки. "
                f"Записей: {len(current_snapshot)}"
            )

            return {

                "new": [],

                "removed": [],

                "changed": [],

                "total":
                    len(current_snapshot)

            }

        return self.analyze_snapshot(
            current_snapshot
        )

    # ==========================================================
    # Запуск мониторинга
    # ==========================================================

    def start(
        self,
        interval=2,
        iterations=None
    ):

        try:

            interval = float(
                interval
            )

        except (
            TypeError,
            ValueError
        ):

            interval = 2

        if interval < 0.5:

            interval = 0.5

        self.running = True

        self.initialize()

        self.log(
            "Startup Behavior Monitor запущен."
        )

        count = 0

        try:

            while self.running:

                self.check()

                count += 1

                if (
                    iterations is not None
                    and count >= iterations
                ):

                    break

                time.sleep(
                    interval
                )

        except KeyboardInterrupt:

            self.log(
                "Мониторинг автозагрузки "
                "остановлен пользователем."
            )

        except Exception as e:

            self.log(
                f"Ошибка мониторинга автозагрузки: {e}"
            )

        finally:

            self.running = False

        self.log(
            "Startup Behavior Monitor остановлен."
        )

    # ==========================================================
    # Остановка
    # ==========================================================

    def stop(self):

        self.running = False

        self.log(
            "Запрошена остановка "
            "Startup Behavior Monitor."
        )

    # ==========================================================
    # Текущее состояние
    # ==========================================================

    def get_current_startup(self):

        return dict(
            self.previous_startup
        )

    # ==========================================================
    # Количество записей
    # ==========================================================

    def get_startup_count(self):

        return len(
            self.previous_startup
        )

    # ==========================================================
    # Очистка
    # ==========================================================

    def clear(self):

        self.previous_startup.clear()

        self.running = False

        self.log(
            "Состояние Startup Behavior Monitor очищено."
        )

    # ==========================================================
    # Логирование
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

            else:

                print(
                    f"[SECURITY] {message}"
                )

        else:


                print(
                f"[SECURITY] {message}"
            )