 
"""
process_manager.py
Управление процессами JARVIS.
"""

import psutil
import subprocess


class ProcessManager:
    def __init__(self, logger=None):
        self.logger = logger

    # --------------------------
    # Получить список процессов
    # --------------------------

    def get_processes(self):
        processes = []

        for process in psutil.process_iter(["pid", "name"]):
            try:
                processes.append({
                    "pid": process.info["pid"],
                    "name": process.info["name"]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes


    # --------------------------
    # Проверить, запущен ли процесс
    # --------------------------

    def is_running(self, process_name: str) -> bool:
        process_name = process_name.lower()

        for process in psutil.process_iter(["name"]):
            try:
                if process.info["name"] and process.info["name"].lower() == process_name:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return False


    # --------------------------
    # Завершить процесс
    # --------------------------

    def kill_process(self, process_name: str) -> bool:
        process_name = process_name.lower()

        for process in psutil.process_iter(["pid", "name"]):
            try:
                if process.info["name"] and process.info["name"].lower() == process_name:

                    process.kill()

                    if self.logger:
                        self.logger.info(f"Процесс завершён: {process_name}")

                    return True

            except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                if self.logger:
                    self.logger.error(f"Ошибка завершения процесса: {error}")

        return False


    # --------------------------
    # Завершить процесс по PID
    # --------------------------

    def kill_pid(self, pid: int) -> bool:
        try:
            process = psutil.Process(pid)
            process.kill()

            if self.logger:
                self.logger.info(f"Процесс завершён (PID {pid})")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка завершения PID {pid}: {error}")

            return False


    # --------------------------
    # Запустить программу
    # --------------------------

    def start_process(self, command: str) -> bool:
        try:
            subprocess.Popen(command, shell=True)

            if self.logger:
                self.logger.info(f"Запущен процесс: {command}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка запуска процесса: {error}")

            return False


    # --------------------------
    # Получить информацию о процессе
    # --------------------------

    def get_process_info(self, process_name: str):
        process_name = process_name.lower()

        for process in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent"]
        ):
            try:
                if process.info["name"] and process.info["name"].lower() == process_name:
                    return process.info

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return None