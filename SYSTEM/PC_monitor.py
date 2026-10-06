"""
PC_monitor.py
Мониторинг состояния компьютера.
"""

import psutil


class PCMonitor:

    def __init__(self, logger=None):
        self.logger = logger

    # ==========================================
    # Главный обработчик
    # ==========================================

    def execute(self, command):

        if not command:
            return False

        command = command.lower().strip()

        if "анализ системы" in command:
            return self.analyze_system()

        if any(word in command for word in [
            "сколько на процессоре",
            "нагрузка процессора",
            "нагрузка cpu",
            "процессор"
        ]):
            return self.cpu_usage()

        if any(word in command for word in [
            "оперативная память",
            "использование памяти",
            "сколько памяти"
        ]):
            return self.ram_usage_text()

        if any(word in command for word in [
            "свободное место",
            "сколько места",
            "место на диске"
        ]):
            return self.free_storage_text()

        return False

    # ==========================================
    # Полный анализ системы
    # ==========================================

    def analyze_system(self):

        try:

            cpu = psutil.cpu_percent(interval=1)

            ram = psutil.virtual_memory()

            ram_used = round(
                ram.used / (1024 ** 3),
                1
            )

            ram_total = round(
                ram.total / (1024 ** 3),
                1
            )

            ram_percent = ram.percent

            disk = psutil.disk_usage("C:\\")

            disk_free = round(
                disk.free / (1024 ** 3),
                1
            )

            disk_total = round(
                disk.total / (1024 ** 3),
                1
            )

            battery = psutil.sensors_battery()

            battery_percent = (
                battery.percent
                if battery
                else None
            )

            self.log(
                f"CPU: {cpu}% | "
                f"RAM: {ram_used}/{ram_total} ГБ "
                f"({ram_percent}%) | "
                f"Диск C: свободно {disk_free} ГБ "
                f"из {disk_total} ГБ"
            )

            response = (
                f"Состояние системы. "
                f"Загрузка процессора {int(cpu)} процентов. "
                f"Используется {ram_used} из {ram_total} гигабайт "
                f"оперативной памяти. "
                f"Свободно {disk_free} гигабайт "
                f"на диске C."
            )

            if battery_percent is not None:

                response += (
                    f" Заряд батареи "
                    f"{int(battery_percent)} процентов."
                )

            self.log(
                "Анализ системы выполнен"
            )

            return response

        except Exception as e:

            self.log(
                f"Ошибка анализа системы: {e}"
            )

            return (
                "Не удалось получить "
                "состояние системы."
            )

    # ==========================================
    # Загрузка процессора
    # ==========================================

    def cpu_usage(self):

        try:

            cpu = psutil.cpu_percent(
                interval=1
            )

            self.log(
                f"Загрузка процессора: {cpu}%"
            )

            return (
                f"Загрузка процессора "
                f"{int(cpu)} процентов."
            )

        except Exception as e:

            self.log(
                f"Ошибка проверки процессора: {e}"
            )

            return (
                "Не удалось получить "
                "загрузку процессора."
            )

    # ==========================================
    # Использование оперативной памяти
    # ==========================================


    def ram_usage_text(self):

        try:

            ram = psutil.virtual_memory()

            used = round(
                ram.used / (1024 ** 3),
                1
            )

            total = round(
                ram.total / (1024 ** 3),
                1
            )

            percent = ram.percent

            self.log(
                f"RAM: {used}/{total} ГБ ({percent}%)"
            )

            return (
                f"Используется {used} "
                f"из {total} гигабайт "
                f"оперативной памяти. "
                f"Загрузка памяти "
                f"{int(percent)} процентов."
            )

        except Exception as e:

            self.log(
                f"Ошибка проверки оперативной памяти: {e}"
            )

            return (
                "Не удалось получить "
                "информацию об оперативной памяти."
            )

    # ==========================================
    # Свободное место на диске — данные
    # ==========================================

    def free_storage(self):

        try:

            disk = psutil.disk_usage("C:\\")

            free_gb = round(
                disk.free / (1024 ** 3),
                1
            )

            self.log(
                f"Свободно на диске C: {free_gb} ГБ"
            )

            return free_gb

        except Exception as e:

            self.log(
                f"Ошибка получения свободного места: {e}"
            )

            return None

    # ==========================================
    # Свободное место на диске — текст
    # ==========================================

    def free_storage_text(self):

        free_gb = self.free_storage()

        if free_gb is None:

            return (
                "Не удалось проверить "
                "свободное место на диске."
            )

        return (
            f"На диске C свободно "
            f"{free_gb} гигабайт."
        )

    # ==========================================
    # Получить данные RAM
    # ==========================================

    def ram_usage(self):

        return psutil.virtual_memory()

    # ==========================================
    # Получить данные диска
    # ==========================================

    def disk_usage(self):

        return psutil.disk_usage("C:\\")

    # ==========================================
    # Получить данные батареи
    # ==========================================

    def battery(self):

        return psutil.sensors_battery()

    # ==========================================
    # Логирование
    # ==========================================

    def log(self, message):

        if self.logger:

            self.logger.info(message)

        else:

            print(message)