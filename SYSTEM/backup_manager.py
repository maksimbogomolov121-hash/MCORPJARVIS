"""
backup_manager.py
Создание резервной копии проекта JARVIS.
"""

import os
import shutil
from datetime import datetime


class BackupManager:
    """
    Создание резервной копии проекта JARVIS.
    """

    def __init__(self, logger=None):
        self.logger = logger

        # Путь к проекту JARVIS
        self.source_folder = r"C:\Users\Пользователь\Desktop\Работа с Jarvis\JARVIS V11"

        # Папка хранения резервных копий
        self.backup_folder = r"C:\Users\Пользователь\Desktop\BACKUPS"

    # ==========================================
    # Создать резервную копию
    # ==========================================

    def create_backup(self):

        try:

            os.makedirs(
                self.backup_folder,
                exist_ok=True
            )

            backup_name = datetime.now().strftime(
                "Jarvis_backup_%Y-%m-%d_%H-%M-%S"
            )

            destination = os.path.join(
                self.backup_folder,
                backup_name
            )

            shutil.copytree(
                self.source_folder,
                destination
            )

            self.log("Резервная копия создана")

            return True

        except Exception as e:

            self.log(f"Ошибка резервной копии: {e}")

            return False

    # ==========================================
    # Логирование
    # ==========================================

    def log(self, message):

        if self.logger:
            self.logger.info(message)
        else:
            print(message)