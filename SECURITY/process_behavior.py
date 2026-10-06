"""
process_behavior.py

JARVIS Security Core V2.1

Мониторинг поведения процессов.

Модуль:
- получает список процессов;
- создаёт снимок состояния;
- обнаруживает новые процессы;
- обнаруживает завершившиеся процессы;
- передаёт события в BehaviorEngine;
- хранит текущее состояние.

Важно:
Модуль НЕ завершает процессы,
НЕ блокирует их и НЕ изменяет систему.
"""

import time


class ProcessBehaviorMonitor:

    def __init__(
        self,
        process_scanner,
        behavior_engine,
        logger=None
    ):

        self.process_scanner = process_scanner
        self.behavior_engine = behavior_engine
        self.logger = logger

        # ======================================================
        # Предыдущий снимок процессов
        # ======================================================

        self.previous_processes = {}

        # ======================================================
        # Состояние мониторинга
        # ======================================================

        self.running = False

        self.log(
            "Process Behavior Monitor инициализирован."
        )

    # ==========================================================
    # Получение процессов
    # ==========================================================

    def get_processes(self):

        try:

            processes = self.process_scanner.scan()

        except Exception as e:

            self.log(
                f"Ошибка получения процессов: {e}"
            )

            return []

        if processes is None:

            return []

        if isinstance(
            processes,
            dict
        ):

            processes = [
                processes
            ]

        return list(
            processes
        )

    # ==========================================================
    # Получение PID
    # ==========================================================

    def get_pid(
        self,
        process
    ):

        if not isinstance(
            process,
            dict
        ):

            return None

        pid = process.get(
            "pid"
        )

        if pid is None:

            pid = process.get(
                "PID"
            )

        try:

            return int(pid)

        except (
            TypeError,
            ValueError
        ):

            return None

    # ==========================================================
    # Получение имени процесса
    # ==========================================================

    def get_process_name(
        self,
        process
    ):

        if not isinstance(
            process,
            dict
        ):

            return "unknown"

        name = (
            process.get("name")
            or process.get("Name")
            or process.get("process_name")
            or process.get("ProcessName")
        )

        if name:

            return str(
                name
            )

        pid = self.get_pid(
            process
        )

        if pid is not None:

            return f"PID_{pid}"

        return "unknown"

    # ==========================================================
    # Создание уникального ключа процесса
    # ==========================================================

    def make_process_key(
        self,
        process
    ):

        pid = self.get_pid(
            process
        )

        if pid is not None:

            return f"PID:{pid}"

        name = self.get_process_name(
            process
        )

        return f"NAME:{name}"

    # ==========================================================
    # Нормализация процесса
    # ==========================================================

    def normalize_process(
        self,
        process
    ):

        if not isinstance(
            process,
            dict
        ):

            return None

        pid = self.get_pid(
            process
        )

        name = self.get_process_name(
            process
        )

        key = self.make_process_key(
            process
        )

        return {

            "key":
                key,

            "pid":
                pid,

            "name":
                name,

            "path":
                process.get(
                    "path",
                    process.get(
                        "exe",
                        process.get(
                            "executable"
                        )
                    )
                ),

            "memory":
                process.get(
                    "memory",
                    process.get(
                        "memory_usage"
                    )
                ),

            "parent_pid":
                process.get(
                    "parent_pid",
                    process.get(
                        "ppid"
                    )
                ),

            "raw":
                process

        }

    # ==========================================================
    # Создание снимка процессов
    # ==========================================================

    def create_snapshot(self):

        processes = self.get_processes()

        snapshot = {}

        for process in processes:

            normalized = (
                self.normalize_process(
                    process
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
    # Первый снимок
    # ==========================================================

    def initialize(self):

        snapshot = (
            self.create_snapshot()
        )

        self.previous_processes = (
            dict(snapshot)
        )

        self.log(
            "Начальный снимок процессов создан. "
            f"Процессов: {len(snapshot)}"
        )

        return dict(
            snapshot
        )

    # ==========================================================
    # Анализ изменения состояния
    # ==========================================================

    def analyze_snapshot(
        self,
        current_processes
    ):

        if current_processes is None:

            current_processes = {}

        if not isinstance(
            current_processes,
            dict
        ):

            current_processes = {}

        # ======================================================
        # Сохраняем старый снимок
        #
        # Важно:
        # Не изменяем previous_processes до завершения анализа.
        # ======================================================

        old_processes = dict(
            self.previous_processes
        )

        current_keys = set(
            current_processes.keys()
        )

        previous_keys = set(
            old_processes.keys()
        )

        # ======================================================
        # Новые процессы
        # ======================================================

        new_keys = (
            current_keys
            - previous_keys
        )

        # ======================================================
        # Завершившиеся процессы
        # ======================================================

        terminated_keys = (
            previous_keys
            - current_keys
        )

        new_processes = []

        terminated_processes = []

        # ======================================================
        # Обработка новых процессов
        # ======================================================

        for key in new_keys:

            process = (
                current_processes[key]
            )

            new_processes.append(
                process
            )

            name = process.get(
                "name",
                "unknown"
            )


            pid = process.get(
                "pid"
            )

            description = (
                f"Обнаружен новый процесс: "
                f"{name}"
            )

            self.behavior_engine.add_event(
                name,
                "PROCESS_CREATED",
                description,
                5
            )

            self.log(
                f"Новый процесс: "
                f"{name} | PID: {pid}"
            )

        # ======================================================
        # Обработка завершившихся процессов
        # ======================================================

        for key in terminated_keys:

            process = (
                old_processes[key]
            )

            terminated_processes.append(
                process
            )

            name = process.get(
                "name",
                "unknown"
            )

            pid = process.get(
                "pid"
            )

            description = (
                f"Процесс завершён: "
                f"{name}"
            )

            self.behavior_engine.add_event(
                name,
                "PROCESS_TERMINATED",
                description,
                0
            )

            self.log(
                f"Процесс завершён: "
                f"{name} | PID: {pid}"
            )

        # ======================================================
        # Обновляем состояние ПОСЛЕ анализа
        # ======================================================

        self.previous_processes = (
            dict(current_processes)
        )

        return {

            "new":
                new_processes,

            "terminated":
                terminated_processes,

            "total":
                len(current_processes)

        }

    # ==========================================================
    # Проверка изменений
    # ==========================================================

    def check(self):

        current_snapshot = (
            self.create_snapshot()
        )

        # ======================================================
        # Если монитор запускается впервые
        # ======================================================

        if not self.previous_processes:

            self.previous_processes = (
                dict(current_snapshot)
            )

            self.log(
                "Создан первый снимок процессов. "
                f"Процессов: {len(current_snapshot)}"
            )

            return {

                "new": [],

                "terminated": [],

                "total":
                    len(current_snapshot)

            }

        # ======================================================
        # Анализируем изменения
        # ======================================================

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
            "Process Behavior Monitor запущен."
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


"Мониторинг остановлен пользователем."
            )

        except Exception as e:

            self.log(
                f"Ошибка мониторинга процессов: {e}"
            )

        finally:

            self.running = False

        self.log(
            "Process Behavior Monitor остановлен."
        )

    # ==========================================================
    # Остановка
    # ==========================================================

    def stop(self):

        self.running = False

        self.log(
            "Запрошена остановка "
            "Process Behavior Monitor."
        )

    # ==========================================================
    # Получение текущих процессов
    # ==========================================================

    def get_current_processes(self):

        return dict(
            self.previous_processes
        )

    # ==========================================================
    # Количество отслеживаемых процессов
    # ==========================================================

    def get_process_count(self):

        return len(
            self.previous_processes
        )

    # ==========================================================
    # Очистка состояния
    # ==========================================================

    def clear(self):

        self.previous_processes.clear()

        self.running = False

        self.log(
            "Состояние Process Behavior Monitor очищено."
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