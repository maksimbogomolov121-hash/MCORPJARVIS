 
"""
file_manager.py
Модуль работы с файлами и папками JARVIS.
"""

import os
import shutil
import subprocess


class FileManager:
    def __init__(self, logger=None):
        self.logger = logger

    # --------------------------
    # Открытие
    # --------------------------

    def open_file(self, path: str) -> bool:
        try:
            os.startfile(path)

            if self.logger:
                self.logger.info(f"Открыт файл: {path}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка открытия файла: {error}")

            return False


    def open_folder(self, path: str) -> bool:
        try:
            subprocess.Popen(f'explorer "{path}"')

            if self.logger:
                self.logger.info(f"Открыта папка: {path}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка открытия папки: {error}")

            return False


    # --------------------------
    # Создание
    # --------------------------

    def create_folder(self, path: str) -> bool:
        try:
            os.makedirs(path, exist_ok=True)

            if self.logger:
                self.logger.info(f"Создана папка: {path}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка создания папки: {error}")

            return False


    # --------------------------
    # Удаление
    # --------------------------

    def delete_file(self, path: str) -> bool:
        try:
            os.remove(path)

            if self.logger:
                self.logger.info(f"Удалён файл: {path}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка удаления файла: {error}")

            return False


    def delete_folder(self, path: str) -> bool:
        try:
            shutil.rmtree(path)

            if self.logger:
                self.logger.info(f"Удалена папка: {path}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка удаления папки: {error}")

            return False


    # --------------------------
    # Копирование
    # --------------------------

    def copy_file(self, source: str, destination: str) -> bool:
        try:
            shutil.copy2(source, destination)

            if self.logger:
                self.logger.info(f"Файл скопирован: {source} -> {destination}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка копирования: {error}")

            return False


    # --------------------------
    # Перемещение
    # --------------------------

    def move_file(self, source: str, destination: str) -> bool:
        try:
            shutil.move(source, destination)

            if self.logger:
                self.logger.info(f"Файл перемещён: {source} -> {destination}")

            return True

        except Exception as error:
            if self.logger:
                self.logger.error(f"Ошибка перемещения: {error}")

            return False


    # --------------------------
    # Проверка существования
    # --------------------------

    def exists(self, path: str) -> bool:
        return os.path.exists(path)