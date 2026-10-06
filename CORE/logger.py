"""
logger.py
Система логирования JARVIS.
"""

import logging
import os


class Logger:
    """
    Логирование работы JARVIS.
    """

    def __init__(self):
        os.makedirs("logs", exist_ok=True)

        self.logger = logging.getLogger("JARVIS")

        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)

            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] %(message)s",
                "%d.%m.%Y %H:%M:%S"
            )

            # Запись в файл
            file_handler = logging.FileHandler(
                "logs/jarvis.log",
                encoding="utf-8"
            )
            file_handler.setFormatter(formatter)

            # Вывод в консоль
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)

            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def info(self, message: str):
        self.logger.info(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def error(self, message: str):
        self.logger.error(message)

    def debug(self, message: str):
        self.logger.debug(message)
