"""
security_scheduler.py

Планировщик JARVIS Security.

V2.5

Отвечает за:
- создание задач безопасности;
- запуск задач через заданный интервал;
- однократный запуск;
- остановку задач;
- удаление задач;
- получение информации о задачах;
- безопасную обработку ошибок.

Модуль не выполняет сканирование самостоятельно.
Он только управляет временем запуска переданных функций.
"""

import threading
import time
from datetime import datetime


class SecurityScheduler:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

        # Все зарегистрированные задачи
        self.tasks = {}

        # Блокировка общего состояния
        self._lock = threading.RLock()

        # Счётчик ID
        self._task_counter = 0

        # Состояние планировщика
        self.running = False

        self.log(
            "Security Scheduler V2.5 инициализирован."
        )

    # ==========================================================
    # СОЗДАНИЕ ID
    # ==========================================================

    def _generate_task_id(self):

        with self._lock:

            self._task_counter += 1

            return (
                f"security_task_"
                f"{self._task_counter}"
            )

    # ==========================================================
    # ДОБАВЛЕНИЕ ЗАДАЧИ
    # ==========================================================

    def add_task(
        self,
        name,
        callback,
        interval=None,
        run_once=False,
        enabled=True,
        delay=0
    ):

        if not name:

            raise ValueError(
                "Имя задачи не указано."
            )

        if not callable(callback):

            raise TypeError(
                "callback должен быть вызываемым объектом."
            )

        if not run_once:

            if interval is None:

                raise ValueError(
                    "Для периодической задачи "
                    "необходимо указать interval."
                )

            if interval <= 0:

                raise ValueError(
                    "interval должен быть больше 0."
                )

        if delay < 0:

            raise ValueError(
                "delay не может быть отрицательным."
            )

        task_id = (
            self._generate_task_id()
        )

        task = {

            "id":
                task_id,

            "name":
                name,

            "callback":
                callback,

            "interval":
                interval,

            "run_once":
                run_once,

            "enabled":
                enabled,

            "running":
                False,

            "executions":
                0,

            "errors":
                0,

            "created_at":
                datetime.now().isoformat(),

            "last_run":
                None,

            "next_run":
                None,

            "delay":
                delay,

            "thread":
                None,

            "stop_event":
                threading.Event()

        }

        with self._lock:

            self.tasks[task_id] = task

        self.log(
            f"Задача добавлена: "
            f"{name} ({task_id})"
        )

        return task_id

    # ==========================================================
    # ЗАПУСК ЗАДАЧИ
    # ==========================================================

    def start_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                self.log(
                    f"Задача не найдена: {task_id}"
                )

                return False

            if task["running"]:

                return False


            if not task["enabled"]:

                return False

            task["running"] = True

            task["stop_event"].clear()

            thread = threading.Thread(

                target=self._task_worker,

                args=(task_id,),

                daemon=True,

                name=f"SecurityTask-{task_id}"

            )

            task["thread"] = thread

            thread.start()

        self.log(
            f"Задача запущена: "
            f"{task['name']}"
        )

        return True

    # ==========================================================
    # ВНУТРЕННИЙ WORKER
    # ==========================================================

    def _task_worker(
        self,
        task_id
    ):

        while True:

            with self._lock:

                task = self.tasks.get(
                    task_id
                )

                if task is None:

                    return

                stop_event = (
                    task["stop_event"]
                )

                run_once = (
                    task["run_once"]
                )

                delay = (
                    task["delay"]
                )

                interval = (
                    task["interval"]
                )

                callback = (
                    task["callback"]
                )

                name = (
                    task["name"]
                )

            # ==================================================
            # Ожидание delay
            # ==================================================

            if delay > 0:

                stopped = (
                    stop_event.wait(
                        delay
                    )
                )

                if stopped:

                    self._finish_task(
                        task_id
                    )

                    return

                with self._lock:

                    task = self.tasks.get(
                        task_id
                    )

                    if task is not None:

                        task["delay"] = 0

            # ==================================================
            # Проверяем остановку
            # ==================================================

            if stop_event.is_set():

                self._finish_task(
                    task_id
                )

                return

            # ==================================================
            # Выполнение callback
            # ==================================================

            with self._lock:

                task = self.tasks.get(
                    task_id
                )

                if task is None:

                    return

                task["last_run"] = (
                    datetime.now().isoformat()
                )

            try:

                callback()

                with self._lock:

                    task = self.tasks.get(
                        task_id
                    )

                    if task is not None:

                        task["executions"] += 1

                self.log(
                    f"Задача выполнена: {name}"
                )

            except Exception as error:

                with self._lock:

                    task = self.tasks.get(
                        task_id
                    )

                    if task is not None:

                        task["errors"] += 1

                self.log(
                    f"Ошибка задачи {name}: "
                    f"{error}"
                )

            # ==================================================
            # Однократная задача
            # ==================================================

            if run_once:

                self._finish_task(
                    task_id
                )

                return

            # ==================================================
            # Следующий запуск
            # ==================================================

            with self._lock:

                task = self.tasks.get(
                    task_id
                )

                if task is None:

                    return

                task["next_run"] = (
                    datetime.now().isoformat()
                )

            stopped = (
                stop_event.wait(
                    interval
                )
            )

            if stopped:

                self._finish_task(
                    task_id
                )

                return

    # ==========================================================
    # ЗАВЕРШЕНИЕ ЗАДАЧИ
    # ==========================================================

    def _finish_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return

            task["running"] = False

            task["thread"] = None

            task["next_run"] = None

    # ==========================================================
    # ОСТАНОВКА ЗАДАЧИ
    # ==========================================================

    def stop_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return False

            task["stop_event"].set()

            task["running"] = False

        self.log(
            f"Задача остановлена: "
            f"{task['name']}"
        )

        return True

    # ==========================================================
    # ВКЛЮЧЕНИЕ ЗАДАЧИ
    # ==========================================================

    def enable_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return False

            task["enabled"] = True

        self.log(
            f"Задача включена: "
            f"{task['name']}"
        )

        return True

    # ==========================================================
    # ОТКЛЮЧЕНИЕ ЗАДАЧИ
    # ==========================================================

    def disable_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return False

            task["enabled"] = False

            task["stop_event"].set()

            task["running"] = False

        self.log(
            f"Задача отключена: "
            f"{task['name']}"
        )

        return True

    # ==========================================================
    # УДАЛЕНИЕ ЗАДАЧИ
    # ==========================================================

    def remove_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return False

            task["stop_event"].set()

            del self.tasks[
                task_id
            ]

        self.log(
            f"Задача удалена: {task_id}"
        )

        return True

    # ==========================================================
    # ЗАПУСК ВСЕХ ЗАДАЧ
    # ==========================================================

    def start_all(self):

        self.running = True

        started = 0

        with self._lock:

            task_ids = list(
                self.tasks.keys()
            )

        for task_id in task_ids:

            if self.start_task(
                task_id
            ):

                started += 1

        self.log(
            f"Запущено задач: {started}"
        )

        return started

    # ==========================================================
    # ОСТАНОВКА ВСЕХ ЗАДАЧ
    # ==========================================================

    def stop_all(self):

        stopped = 0

        with self._lock:

            task_ids = list(
                self.tasks.keys()
            )

        for task_id in task_ids:

            if self.stop_task(
                task_id
            ):

                stopped += 1

        self.running = False

        self.log(
            f"Остановлено задач: {stopped}"
        )

        return stopped

    # ==========================================================
    # ПОЛУЧЕНИЕ ЗАДАЧИ
    # ==========================================================

    def get_task(
        self,
        task_id
    ):

        with self._lock:

            task = self.tasks.get(
                task_id
            )

            if task is None:

                return None

            return self._public_task(
                task
            )

    # ==========================================================
    # ПОЛУЧЕНИЕ ВСЕХ ЗАДАЧ
    # ==========================================================

    def get_tasks(self):

        with self._lock:

            return [

                self._public_task(
                    task
                )

                for task
                in self.tasks.values()

            ]

    # ==========================================================
    # ПУБЛИЧНЫЕ ДАННЫЕ ЗАДАЧИ
    # ==========================================================

    def _public_task(
        self,
        task
    ):

        return {

            "id":
                task["id"],

            "name":
                task["name"],

            "interval":
                task["interval"],

            "run_once":
                task["run_once"],

            "enabled":
                task["enabled"],

            "running":
                task["running"],

            "executions":
                task["executions"],

            "errors":
                task["errors"],

            "created_at":
                task["created_at"],

            "last_run":
                task["last_run"],

            "next_run":
                task["next_run"]

        }

    # ==========================================================
    # КОЛИЧЕСТВО ЗАДАЧ
    # ==========================================================

    def count(self):

        with self._lock:

            return len(
                self.tasks
            )

    # ==========================================================
    # КОЛИЧЕСТВО АКТИВНЫХ ЗАДАЧ
    # ==========================================================

    def running_count(self):

        with self._lock:

            return sum(

                1

                for task
                in self.tasks.values()

                if task["running"]

            )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.stop_all()

        with self._lock:

            self.tasks.clear()

        self.log(
            "Все задачи Security Scheduler очищены."
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