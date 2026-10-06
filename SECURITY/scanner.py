"""
scanner.py
Сканирование файлов и папок для JARVIS Security V1.1.
"""

import hashlib
import os
from datetime import datetime


class FileScanner:
    """
    Сканер файлов JARVIS Security.

    Ничего не удаляет и не изменяет.
    Только собирает информацию об объектах.
    """

    # Исполняемые и потенциально опасные типы
    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".dll",
        ".sys",
        ".scr",
        ".msi",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".com",
    }

    def __init__(self, logger=None):

        self.logger = logger

    # ==========================================================
    # Сканирование объекта
    # ==========================================================

    def scan(self, path):

        if not path:
            return None

        path = os.path.abspath(
            os.path.expanduser(path)
        )

        if not os.path.exists(path):

            self.log(
                f"Объект не найден: {path}"
            )

            return None

        # ------------------------------------------------------
        # Файл
        # ------------------------------------------------------

        if os.path.isfile(path):

            return self.scan_file(path)

        # ------------------------------------------------------
        # Папка
        # ------------------------------------------------------

        if os.path.isdir(path):

            return self.scan_directory(path)

        return None

    # ==========================================================
    # Сканирование одного файла
    # ==========================================================

    def scan_file(self, path):

        try:

            absolute_path = os.path.abspath(path)

            stat = os.stat(
                absolute_path
            )

            extension = (
                os.path.splitext(
                    absolute_path
                )[1]
                .lower()
            )

            result = {

                "path": absolute_path,

                "name": os.path.basename(
                    absolute_path
                ),

                "extension": extension,

                "size": stat.st_size,

                "modified": datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat(
                    sep=" ",
                    timespec="seconds"
                ),

                "is_executable": (
                    extension
                    in self.EXECUTABLE_EXTENSIONS
                ),

                "sha256": self.calculate_sha256(
                    absolute_path
                ),

            }

            self.log(
                f"Просканирован файл: {absolute_path}"
            )

            return result

        except (OSError, PermissionError) as e:

            self.log(
                f"Ошибка сканирования файла "
                f"{path}: {e}"
            )

            return None

    # ==========================================================
    # Сканирование папки
    # ==========================================================

    def scan_directory(self, path):

        results = []

        try:

            for root, dirs, files in os.walk(
                path,
                topdown=True
            ):

                # ------------------------------------------------
                # Игнорируем системные проблемы доступа
                # ------------------------------------------------

                dirs[:] = [
                    directory
                    for directory in dirs
                    if self.can_access_directory(
                        os.path.join(
                            root,
                            directory
                        )
                    )
                ]

                for filename in files:

                    file_path = os.path.join(root,
                        filename
                    )

                    result = self.scan_file(
                        file_path
                    )

                    if result:

                        results.append(
                            result
                        )

        except (OSError, PermissionError) as e:

            self.log(
                f"Ошибка сканирования папки "
                f"{path}: {e}"
            )

        self.log(
            f"Сканирование завершено: "
            f"{path}. "
            f"Найдено файлов: {len(results)}"
        )

        return results

    # ==========================================================
    # Проверка доступа к папке
    # ==========================================================

    def can_access_directory(self, path):

        try:

            return os.access(
                path,
                os.R_OK
            )

        except OSError:

            return False

    # ==========================================================
    # SHA-256
    # ==========================================================

    def calculate_sha256(self, path):

        sha256 = hashlib.sha256()

        try:

            with open(
                path,
                "rb"
            ) as file:

                while True:

                    chunk = file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    sha256.update(
                        chunk
                    )

            return sha256.hexdigest()

        except (
            OSError,
            PermissionError
        ) as e:

            self.log(
                f"Не удалось вычислить SHA-256 "
                f"{path}: {e}"
            )

            return None

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