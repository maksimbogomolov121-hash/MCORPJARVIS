"""
process_scanner.py
Сканирование запущенных процессов Windows
для JARVIS Security Core V1.
"""

import os
import subprocess


class ProcessScanner:
    """
    Собирает информацию о процессах,
    запущенных в системе.

    Ничего не завершает и не изменяет.
    """

    def __init__(self, logger=None):

        self.logger = logger

    # ==========================================================
    # Сканирование процессов
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сканирования процессов..."
        )

        processes = []

        try:

            # Используем встроенную команду Windows.
            # Никаких сторонних программ.

            result = subprocess.run(
                [
                    "tasklist",
                    "/FO",
                    "CSV",
                    "/NH"
                ],
                capture_output=True,
                text=True,
                encoding="cp866",
                errors="replace"
            )

            if result.returncode != 0:

                self.log(
                    "Не удалось получить список процессов."
                )

                return []

            # ==================================================
            # Обработка строк tasklist
            # ==================================================

            for line in result.stdout.splitlines():

                line = line.strip()

                if not line:

                    continue

                parts = self.parse_csv_line(
                    line
                )

                if len(parts) < 5:

                    continue

                name = parts[0]
                pid = parts[1]
                session_name = parts[2]
                session_number = parts[3]
                memory = parts[4]

                process = {

                    "name":
                        name,

                    "pid":
                        self.safe_int(pid),

                    "session_name":
                        session_name,

                    "session_number":
                        self.safe_int(
                            session_number
                        ),

                    "memory":
                        memory,

                }

                processes.append(
                    process
                )

            self.log(
                f"Сканирование процессов завершено. "
                f"Найдено процессов: {len(processes)}"
            )

            return processes

        except Exception as e:

            self.log(
                f"Ошибка сканирования процессов: {e}"
            )

            return []

    # ==========================================================
    # Поиск конкретного процесса
    # ==========================================================

    def find_process(self, name):

        if not name:

            return []

        name = name.lower().strip()

        processes = self.scan()

        found = []

        for process in processes:

            process_name = process.get(
                "name",
                ""
            ).lower()

            if name in process_name:

                found.append(
                    process
                )

        return found

    # ==========================================================
    # Проверка существования процесса
    # ==========================================================

    def is_running(self, name):

        return bool(
            self.find_process(name)
        )

    # ==========================================================
    # Получение количества процессов
    # ==========================================================

    def count(self):

        processes = self.scan()

        return len(processes)

    # ==========================================================
    # CSV parser
    # ==========================================================

    def parse_csv_line(self, line):

        parts = []

        current = ""

        inside_quotes = False

        for char in line:

            if char == '"':

                inside_quotes = not inside_quotes

                continue

            if char == "," and not inside_quotes:

                parts.append(
                    current.strip()
                )

                current = ""

                continue

            current += char

        parts.append(
            current.strip()
        )

        return parts

    # ==========================================================
    # Безопасное преобразование в число
    # ==========================================================

    def safe_int(self, value):

        try:

            return int(
                str(value).strip()
            )

        except (ValueError, TypeError):

            return 0

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )

        else:

            print(
                f"[SECURITY] {message}"
            )