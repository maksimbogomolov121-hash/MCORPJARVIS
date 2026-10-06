"""
startup_scanner.py
Сканирование программ, запускающихся вместе с Windows.

JARVIS Security V1.3
"""

import os
import winreg


class StartupScanner:

    def __init__(self, logger=None):

        self.logger = logger

        self.last_results = []

    # ==========================================================
    # Сканирование автозагрузки
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сканирования автозагрузки..."
        )

        results = []

        # ------------------------------------------------------
        # Реестр Windows
        # ------------------------------------------------------

        registry_locations = [

            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKCU"
            ),

            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                "HKLM"
            ),

            (
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKCU_RUNONCE"
            ),

            (
                winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                "HKLM_RUNONCE"
            ),
        ]

        for hive, key_path, source in registry_locations:

            results.extend(
                self.scan_registry(
                    hive,
                    key_path,
                    source
                )
            )

        # ------------------------------------------------------
        # Папка автозагрузки пользователя
        # ------------------------------------------------------

        results.extend(
            self.scan_startup_folder()
        )

        self.last_results = results

        self.log(
            f"Сканирование автозагрузки завершено. "
            f"Найдено объектов: {len(results)}"
        )

        return results

    # ==========================================================
    # Сканирование раздела реестра
    # ==========================================================

    def scan_registry(
        self,
        hive,
        key_path,
        source
    ):

        results = []

        try:

            key = winreg.OpenKey(
                hive,
                key_path,
                0,
                winreg.KEY_READ
            )

        except FileNotFoundError:

            return results

        except PermissionError:

            self.log(
                f"Нет доступа к разделу: {source}"
            )

            return results

        try:

            index = 0

            while True:

                try:

                    name, value, value_type = (
                        winreg.EnumValue(
                            key,
                            index
                        )
                    )

                except OSError:

                    break

                results.append(
                    {
                        "name": name,
                        "command": str(value),
                        "type": "registry",
                        "source": source,
                        "location": key_path,
                    }
                )

                self.log(
                    f"Найдена автозагрузка: "
                    f"{name} -> {value}"
                )

                index += 1

        finally:

            winreg.CloseKey(key)

        return results

    # ==========================================================
    # Папка автозагрузки Windows
    # ==========================================================

    def scan_startup_folder(self):

        results = []

        startup_path = os.path.join(
            os.path.expanduser("~"),

r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        )

        if not os.path.exists(
            startup_path
        ):

            return results

        try:

            for name in os.listdir(
                startup_path
            ):

                full_path = os.path.join(
                    startup_path,
                    name
                )

                results.append(
                    {
                        "name": name,
                        "command": full_path,
                        "type": "startup_folder",
                        "source": "USER_STARTUP",
                        "location": startup_path,
                    }
                )

                self.log(
                    f"Найден объект автозагрузки: "
                    f"{full_path}"
                )

        except PermissionError:

            self.log(
                "Нет доступа к папке автозагрузки."
            )

        return results

    # ==========================================================
    # Последние результаты
    # ==========================================================

    def get_results(self):

        return list(
            self.last_results
        )

    # ==========================================================
    # Количество объектов
    # ==========================================================

    def count(self):

        return len(
            self.last_results
        )

    # ==========================================================
    # Очистка результатов
    # ==========================================================

    def clear_results(self):

        self.last_results = []

        self.log(
            "Результаты сканирования автозагрузки очищены."
        )

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