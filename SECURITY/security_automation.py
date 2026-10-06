"""
JARVIS SECURITY
V6.0 - Security Automation

Автоматизация периодических и событийных проверок Security-системы.

Основные возможности:
- регистрация автоматических задач;
- запуск задач вручную;
- запуск задач по интервалу;
- включение/выключение задач;
- однократные и повторяющиеся задачи;
- защита от одновременного запуска одной задачи;
- история запусков;
- обработка ошибок;
- безопасная остановка автоматизации;
- интеграция с SecurityController;
- отсутствие Sandbox-зависимостей.
"""

from __future__ import annotations

import threading
import time
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class SecurityAutomation:
    """
    Центральный модуль автоматизации Security.

    SecurityAutomation не анализирует угрозы самостоятельно.
    Его задача — вовремя запускать существующие компоненты Security.

    Типичная архитектура:

        SecurityScheduler
                ↓
        SecurityAutomation
                ↓
        SecurityController
                ↓
        SecurityPipeline
                ↓
        DecisionEngine
                ↓
        SecurityPolicy
                ↓
        ResponseEngine
    """

    VERSION = "6.0"

    # ---------------------------------------------------------
    # TASK STATUSES
    # ---------------------------------------------------------

    TASK_ENABLED = "ENABLED"
    TASK_DISABLED = "DISABLED"
    TASK_RUNNING = "RUNNING"
    TASK_COMPLETED = "COMPLETED"
    TASK_FAILED = "FAILED"

    # ---------------------------------------------------------
    # AUTOMATION STATUS
    # ---------------------------------------------------------

    STATUS_STOPPED = "STOPPED"
    STATUS_RUNNING = "RUNNING"
    STATUS_STOPPING = "STOPPING"

    # ---------------------------------------------------------
    # INIT
    # ---------------------------------------------------------

    def __init__(
        self,
        controller=None,
        logger=None,
    ):
        """
        :param controller:
            SecurityController.

        :param logger:
            Необязательный Security logger.
        """

        self.controller = controller
        self.logger = logger

        self.status = self.STATUS_STOPPED

        self.tasks: Dict[str, Dict[str, Any]] = {}

        self.history: List[Dict[str, Any]] = []

        self._lock = threading.RLock()

        self._stop_event = threading.Event()

        self._thread: Optional[threading.Thread] = None

    # =========================================================
    # TASK MANAGEMENT
    # =========================================================

    def register_task(
        self,
        task_id: str,
        name: str,
        callback: Optional[Callable[..., Any]] = None,
        interval: Optional[float] = None,
        data: Any = None,
        context: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
        run_once: bool = False,
    ) -> Dict[str, Any]:
        """
        Регистрирует автоматическую задачу.

        :param task_id:
            Уникальный идентификатор задачи.

        :param name:
            Человекочитаемое название.

        :param callback:
            Функция, которую необходимо выполнить.

        :param interval:
            Интервал в секундах.
            None = задача не запускается автоматически.

        :param data:
            Данные для SecurityController.

        :param context:
            Контекст операции.

        :param enabled:
            Активна ли задача.

        :param run_once:
            Выполнить только один раз.
        """

        if not task_id:
            raise ValueError("task_id cannot be empty")

        if not name:
            raise ValueError("name cannot be empty")

        if callback is not None and not callable(callback):
            raise TypeError("callback must be callable")

        if interval is not None:

            try:
                interval = float(interval)

            except (TypeError, ValueError):

                raise ValueError(
                    "interval must be a number"
                )

            if interval <= 0:

                raise ValueError(
                    "interval must be greater than zero"
                )

        with self._lock:

            if task_id in self.tasks:

                raise ValueError(
                    f"Task already exists: {task_id}"
                )

            task = {
                "task_id": task_id,
                "name": name,
                "callback": callback,
                "interval": interval,
                "data": data,
                "context": context or {},
                "enabled": bool(enabled),
                "run_once": bool(run_once),
                "status": (
                    self.TASK_ENABLED
                    if enabled
                    else self.TASK_DISABLED
                ),
                "created_at": datetime.now().isoformat(),
                "last_run": None,
                "next_run": None,
                "last_result": None,
                "run_count": 0,
                "error_count": 0,
            }

            if interval is not None and enabled:

                task["next_run"] = (
                    time.time() + interval
                )

            self.tasks[task_id] = task

            self._log(
                f"Automation task registered: {task_id}"
            )

            return self._public_task(task)

    # =========================================================
    # REMOVE TASK
    # =========================================================

    def unregister_task(
        self,
        task_id: str,
    ) -> bool:

        with self._lock:

            if task_id not in self.tasks:
                return False

            del self.tasks[task_id]

            self._log(
                f"Automation task removed: {task_id}"
            )

            return True

    # =========================================================
    # ENABLE TASK
    # =========================================================

    def enable_task(
        self,
        task_id: str,
    ) -> bool:

        with self._lock:

            task = self.tasks.get(task_id)

            if task is None:
                return False

            task["enabled"] = True

            if task["status"] != self.TASK_RUNNING:

                task["status"] = self.TASK_ENABLED

            if task["interval"] is not None:

                task["next_run"] = (
                    time.time()
                    + task["interval"]
                )

            self._log(
                f"Automation task enabled: {task_id}"
            )

            return True

    # =========================================================
    # DISABLE TASK
    # =========================================================

    def disable_task(
        self,
        task_id: str,
    ) -> bool:

        with self._lock:

            task = self.tasks.get(task_id)

            if task is None:
                return False

            task["enabled"] = False

            if task["status"] != self.TASK_RUNNING:

                task["status"] = self.TASK_DISABLED

            task["next_run"] = None

            self._log(
                f"Automation task disabled: {task_id}"
            )

            return True

    # =========================================================
    # GET TASK
    # =========================================================

    def get_task(
        self,
        task_id: str,
    ) -> Optional[Dict[str, Any]]:

        with self._lock:

            task = self.tasks.get(task_id)

            if task is None:
                return None

            return self._public_task(task)

    # =========================================================
    # GET ALL TASKS
    # =========================================================

    def get_tasks(
        self,

) -> List[Dict[str, Any]]:

        with self._lock:

            return [
                self._public_task(task)
                for task in self.tasks.values()
            ]

    # =========================================================
    # MANUAL RUN
    # =========================================================

    def run_task(
        self,
        task_id: str,
        data: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ручной запуск конкретной задачи.
        """

        with self._lock:

            task = self.tasks.get(task_id)

            if task is None:

                return {
                    "success": False,
                    "status": "NOT_FOUND",
                    "task_id": task_id,
                    "error": "Task not found",
                }

            if task["status"] == self.TASK_RUNNING:

                return {
                    "success": False,
                    "status": "ALREADY_RUNNING",
                    "task_id": task_id,
                    "error": "Task is already running",
                }

            task["status"] = self.TASK_RUNNING

        return self._execute_task(
            task,
            data=data,
            context=context,
        )

    # =========================================================
    # EXECUTE TASK
    # =========================================================

    def _execute_task(
        self,
        task: Dict[str, Any],
        data: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        task_id = task["task_id"]

        started_at = datetime.now().isoformat()

        try:

            callback = task.get("callback")

            task_data = (
                data
                if data is not None
                else task.get("data")
            )

            task_context = (
                context
                if context is not None
                else task.get("context", {})
            )

            # -------------------------------------------------
            # CALLBACK
            # -------------------------------------------------

            if callback is not None:

                result = callback(
                    task_data,
                    task_context,
                )

            # -------------------------------------------------
            # SECURITY CONTROLLER
            # -------------------------------------------------

            elif self.controller is not None:

                result = self.controller.run(
                    data=task_data,
                    context=task_context,
                )

            # -------------------------------------------------
            # NOTHING TO EXECUTE
            # -------------------------------------------------

            else:

                raise RuntimeError(
                    "No callback or SecurityController configured"
                )

            finished_at = datetime.now().isoformat()

            with self._lock:

                task["status"] = self.TASK_COMPLETED

                task["last_run"] = finished_at

                task["last_result"] = result

                task["run_count"] += 1

                # -------------------------------------------------
                # NEXT RUN
                # -------------------------------------------------

                if (
                    task["enabled"]
                    and task["interval"] is not None
                    and not task["run_once"]
                ):

                    task["next_run"] = (
                        time.time()
                        + task["interval"]
                    )

                else:

                    task["next_run"] = None

                    if task["run_once"]:

                        task["enabled"] = False
                        task["status"] = self.TASK_COMPLETED


            history_entry = {
                "task_id": task_id,
                "success": True,
                "status": self.TASK_COMPLETED,
                "started_at": started_at,
                "finished_at": finished_at,
                "result": result,
            }

            self._store_history(history_entry)

            self._log(
                f"Automation task completed: {task_id}"
            )

            return history_entry

        except Exception as exc:

            finished_at = datetime.now().isoformat()

            with self._lock:

                task["status"] = self.TASK_FAILED

                task["last_run"] = finished_at

                task["last_result"] = None

                task["run_count"] += 1

                task["error_count"] += 1

                if (
                    task["enabled"]
                    and task["interval"] is not None
                    and not task["run_once"]
                ):

                    task["next_run"] = (
                        time.time()
                        + task["interval"]
                    )

            history_entry = {
                "task_id": task_id,
                "success": False,
                "status": self.TASK_FAILED,
                "started_at": started_at,
                "finished_at": finished_at,
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }

            self._store_history(history_entry)

            self._log(
                f"Automation task failed: {task_id} - {exc}"
            )

            return history_entry

    # =========================================================
    # START AUTOMATION
    # =========================================================

    def start(self) -> bool:

        with self._lock:

            if self.status == self.STATUS_RUNNING:
                return False

            self.status = self.STATUS_RUNNING

            self._stop_event.clear()

            self._thread = threading.Thread(
                target=self._automation_loop,
                name="SecurityAutomation",
                daemon=True,
            )

            self._thread.start()

            self._log(
                "Security automation started"
            )

            return True

    # =========================================================
    # STOP AUTOMATION
    # =========================================================

    def stop(
        self,
        timeout: float = 5.0,
    ) -> bool:

        with self._lock:

            if self.status == self.STATUS_STOPPED:
                return False

            self.status = self.STATUS_STOPPING

            self._stop_event.set()

            thread = self._thread

        if thread is not None:

            thread.join(
                timeout=max(0.0, float(timeout))
            )

        with self._lock:

            self.status = self.STATUS_STOPPED

            self._thread = None

            for task in self.tasks.values():

                if task["status"] == self.TASK_RUNNING:
                    continue

                if task["enabled"]:

                    task["status"] = self.TASK_ENABLED

                else:

                    task["status"] = self.TASK_DISABLED

            self._log(
                "Security automation stopped"
            )

        return True

    # =========================================================
    # AUTOMATION LOOP
    # =========================================================

    def _automation_loop(self) -> None:

        while not self._stop_event.is_set():

            now = time.time()

            due_tasks = []

            with self._lock:

                for task in self.tasks.values():

                    if not task["enabled"]:
                        continue

                    if task["interval"] is None:
                        continue

                    if task["status"] == self.TASK_RUNNING:
                        continue

                    next_run = task.get("next_run")

                    if next_run is None:

                        task["next_run"] = (
                            now
                            + task["interval"]
                        )

                        continue

                    if now >= next_run:

                        task["status"] = self.TASK_RUNNING

                        due_tasks.append(task)

            # -------------------------------------------------
            # EXECUTE DUE TASKS
            # -------------------------------------------------

            for task in due_tasks:

                if self._stop_event.is_set():
                    break

                self._execute_task(task)

            # -------------------------------------------------
            # SMALL SLEEP
            # -------------------------------------------------

            self._stop_event.wait(0.5)

    # =========================================================
    # RUN ALL TASKS
    # =========================================================

    def run_all(
        self,
    ) -> List[Dict[str, Any]]:

        results = []

        with self._lock:

            task_ids = list(
                self.tasks.keys()
            )

        for task_id in task_ids:

            result = self.run_task(
                task_id
            )

            results.append(result)

        return results

    # =========================================================
    # HISTORY
    # =========================================================

    def _store_history(
        self,
        result: Dict[str, Any],
    ) -> None:

        with self._lock:

            self.history.append(result)

            # Ограничиваем историю,
            # чтобы она не росла бесконечно.

            if len(self.history) > 1000:

                del self.history[
                    :-1000
                ]

    # =========================================================
    # GET HISTORY
    # =========================================================

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:

        with self._lock:

            history = list(
                self.history
            )

        if limit is None:
            return history

        try:

            limit = int(limit)

        except (TypeError, ValueError):

            return history

        if limit <= 0:
            return []

        return history[-limit:]

    # =========================================================
    # CLEAR HISTORY
    # =========================================================

    def clear_history(self) -> None:

        with self._lock:
            self.history.clear()

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self) -> str:

        with self._lock:
            return self.status

    def is_running(self) -> bool:

        return (
            self.get_status()
            == self.STATUS_RUNNING
        )

    def is_stopped(self) -> bool:

        return (
            self.get_status()
            == self.STATUS_STOPPED
        )

    # =========================================================
    # STATISTICS
    # =========================================================

    def get_statistics(
        self,
    ) -> Dict[str, Any]:

        with self._lock:

            total_tasks = len(self.tasks)

            enabled_tasks = sum(
                1
                for task in self.tasks.values()
                if task["enabled"]
            )

            running_tasks = sum(
                1
                for task in self.tasks.values()
                if task["status"]
                == self.TASK_RUNNING
            )

            total_runs = sum(

task["run_count"]
                for task in self.tasks.values()
            )

            total_errors = sum(
                task["error_count"]
                for task in self.tasks.values()
            )

            return {
                "version": self.VERSION,
                "status": self.status,
                "total_tasks": total_tasks,
                "enabled_tasks": enabled_tasks,
                "running_tasks": running_tasks,
                "total_runs": total_runs,
                "total_errors": total_errors,
                "history_size": len(self.history),
            }

    # =========================================================
    # PUBLIC TASK
    # =========================================================

    @staticmethod
    def _public_task(
        task: Dict[str, Any],
    ) -> Dict[str, Any]:

        return {
            "task_id": task["task_id"],
            "name": task["name"],
            "interval": task["interval"],
            "enabled": task["enabled"],
            "run_once": task["run_once"],
            "status": task["status"],
            "created_at": task["created_at"],
            "last_run": task["last_run"],
            "next_run": task["next_run"],
            "last_result": task["last_result"],
            "run_count": task["run_count"],
            "error_count": task["error_count"],
        }

    # =========================================================
    # LOGGER
    # =========================================================

    def _log(
        self,
        message: str,
    ) -> None:

        if self.logger is None:
            return

        try:

            if hasattr(self.logger, "log"):

                self.logger.log(message)

            elif hasattr(self.logger, "info"):

                self.logger.info(message)

        except Exception:
            pass

    # =========================================================
    # SHUTDOWN
    # =========================================================

    def shutdown(self) -> None:

        try:

            if self.is_running():

                self.stop()

        except Exception:
            pass

    # =========================================================
    # DESTRUCTOR
    # =========================================================

    def __del__(self):

        try:

            self.shutdown()

        except Exception:
            pass