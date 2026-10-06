"""
usb_scanner.py
Сканирование подключённых накопителей Windows.

JARVIS Security V1.4
"""

import os
import platform
import string

try:
    import win32api
    import win32file
except ImportError:
    win32api = None
    win32file = None


class USBScanner:

    def __init__(self, logger=None):

        self.logger = logger
        self.last_results = []

    # ==========================================================
    # Сканирование накопителей
    # ==========================================================

    def scan(self):

        self.log(
            "Начало сканирования USB-накопителей..."
        )

        results = []

        if platform.system() != "Windows":

            self.log(
                "USB Scanner сейчас поддерживает только Windows."
            )

            self.last_results = []

            return results

        # ------------------------------------------------------
        # Проверяем наличие pywin32
        # ------------------------------------------------------

        if win32api is None or win32file is None:

            self.log(
                "Не установлен пакет pywin32."
            )

            self.last_results = []

            return results

        try:

            drives = win32api.GetLogicalDriveStrings()

            drives = drives.split("\x00")

            for drive in drives:

                if not drive:
                    continue

                try:

                    drive_type = win32file.GetDriveType(
                        drive
                    )

                except Exception as e:

                    self.log(
                        f"Не удалось определить тип диска "
                        f"{drive}: {e}"
                    )

                    continue

                # DRIVE_REMOVABLE = 2
                if drive_type == win32file.DRIVE_REMOVABLE:

                    information = self.get_drive_info(
                        drive
                    )

                    results.append(
                        information
                    )

                    self.log(
                        f"Найден съёмный накопитель: "
                        f"{drive}"
                    )

        except Exception as e:

            self.log(
                f"Ошибка сканирования USB: {e}"
            )

        self.last_results = results

        self.log(
            f"Сканирование USB завершено. "
            f"Найдено накопителей: {len(results)}"
        )

        return list(results)

    # ==========================================================
    # Информация о диске
    # ==========================================================

    def get_drive_info(self, drive):

        drive = drive.rstrip("\\/")

        result = {

            "drive": drive,

            "type": "removable",

            "label": "",

            "filesystem": "",

            "total_bytes": 0,

            "free_bytes": 0,

        }

        # ------------------------------------------------------
        # Метка диска
        # ------------------------------------------------------

        try:

            label = win32api.GetVolumeInformation(
                drive + "\\"
            )[0]

            result["label"] = label

        except Exception:

            pass

        # ------------------------------------------------------
        # Файловая система
        # ------------------------------------------------------

        try:

            filesystem = win32api.GetVolumeInformation(
                drive + "\\"
            )[4]

            result["filesystem"] = filesystem

        except Exception:

            pass

        # ------------------------------------------------------
        # Размер и свободное место
        # ------------------------------------------------------

        try:

            total, free = win32api.GetDiskFreeSpaceEx(
                drive + "\\"
            )[:2]


            result["total_bytes"] = int(
                total
            )

            result["free_bytes"] = int(
                free
            )

        except Exception:

            pass

        return result

    # ==========================================================
    # Последние результаты
    # ==========================================================

    def get_results(self):

        return list(
            self.last_results
        )

    # ==========================================================
    # Количество USB
    # ==========================================================

    def count(self):

        return len(
            self.last_results
        )

    # ==========================================================
    # Проверка наличия USB
    # ==========================================================

    def has_usb(self):

        return bool(
            self.last_results
        )

    # ==========================================================
    # Очистка результатов
    # ==========================================================

    def clear_results(self):

        self.last_results = []

        self.log(
            "Результаты USB-сканирования очищены."
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