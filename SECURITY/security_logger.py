"""
security_logger.py
Журнал событий JARVIS Security Core.
"""

import logging
import os
from datetime import datetime


class SecurityLogger:

    def __init__(
        self,
        log_path=None,
        name="JARVIS_SECURITY"
    ):

        # ======================================================
        # Путь к журналу
        # ======================================================

        if log_path:

            self.log_path = os.path.abspath(
                log_path
            )

        else:

            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )

            logs_directory = os.path.join(
                project_root,
                "SECURITY_LOGS"
            )

            os.makedirs(
                logs_directory,
                exist_ok=True
            )

            self.log_path = os.path.join(
                logs_directory,
                "security.log"
            )

        # ======================================================
        # Создание папки
        # ======================================================

        log_directory = os.path.dirname(
            self.log_path
        )

        if log_directory:

            os.makedirs(
                log_directory,
                exist_ok=True
            )

        # ======================================================
        # Logger
        # ======================================================

        self.logger = logging.getLogger(
            name
        )

        self.logger.setLevel(
            logging.INFO
        )

        self.logger.propagate = False

        # ======================================================
        # Не создаём несколько обработчиков
        # ======================================================

        already_configured = False

        for handler in self.logger.handlers:

            if isinstance(
                handler,
                logging.FileHandler
            ):

                try:

                    if os.path.abspath(
                        handler.baseFilename
                    ) == os.path.abspath(
                        self.log_path
                    ):

                        already_configured = True

                        break

                except Exception:

                    pass

        # ======================================================
        # Создаём FileHandler
        # ======================================================

        if not already_configured:

            file_handler = logging.FileHandler(
                self.log_path,
                encoding="utf-8"
            )

            formatter = logging.Formatter(
                "[%(asctime)s] "
                "[%(levelname)s] "
                "%(message)s",
                datefmt="%d.%m.%Y %H:%M:%S"
            )

            file_handler.setFormatter(
                formatter
            )

            self.logger.addHandler(
                file_handler
            )

        # ======================================================
        # Событие запуска
        # ======================================================

        self.info(
            "Security Logger инициализирован."
        )

    # ==========================================================
    # INFO
    # ==========================================================

    def info(self, message):

        self.logger.info(
            str(message)
        )

    # ==========================================================
    # WARNING
    # ==========================================================

    def warning(self, message):

        self.logger.warning(
            str(message)
        )

    # ==========================================================
    # ERROR
    # ==========================================================

    def error(self, message):


        self.logger.error(
            str(message)
        )

    # ==========================================================
    # CRITICAL
    # ==========================================================

    def critical(self, message):

        self.logger.critical(
            str(message)
        )

    # ==========================================================
    # DEBUG
    # ==========================================================

    def debug(self, message):

        self.logger.debug(
            str(message)
        )

    # ==========================================================
    # Произвольное событие
    # ==========================================================

    def log(
        self,
        message,
        level="INFO"
    ):

        level = str(
            level
        ).upper()

        if level == "WARNING":

            self.warning(message)

        elif level == "ERROR":

            self.error(message)

        elif level == "CRITICAL":

            self.critical(message)

        elif level == "DEBUG":

            self.debug(message)

        else:

            self.info(message)

    # ==========================================================
    # Получение пути к журналу
    # ==========================================================

    def get_log_path(self):

        return self.log_path

    # ==========================================================
    # Чтение журнала
    # ==========================================================

    def read(self):

        if not os.path.exists(
            self.log_path
        ):

            return ""

        try:

            with open(
                self.log_path,
                "r",
                encoding="utf-8"
            ) as file:

                return file.read()

        except Exception as e:

            return (
                f"Ошибка чтения журнала: {e}"
            )

    # ==========================================================
    # Очистка журнала
    # ==========================================================

    def clear(self):

        try:

            # Закрываем FileHandler
            for handler in self.logger.handlers:

                if isinstance(
                    handler,
                    logging.FileHandler
                ):

                    handler.close()

            # Очищаем обработчики
            self.logger.handlers.clear()

            # Очищаем файл
            with open(
                self.log_path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write("")

            # Возвращаем обработчик
            file_handler = logging.FileHandler(
                self.log_path,
                encoding="utf-8"
            )

            formatter = logging.Formatter(
                "[%(asctime)s] "
                "[%(levelname)s] "
                "%(message)s",
                datefmt="%d.%m.%Y %H:%M:%S"
            )

            file_handler.setFormatter(
                formatter
            )

            self.logger.addHandler(
                file_handler
            )

            self.info(
                "Журнал очищен."
            )

            return True

        except Exception as e:

            print(
                f"[SECURITY] "
                f"Ошибка очистки журнала: {e}"
            )

            return False

    # ==========================================================
    # Закрытие
    # ==========================================================

    def close(self):

        for handler in self.logger.handlers:

            if isinstance(
                handler,
                logging.FileHandler
            ):

                handler.close()

        self.logger.handlers.clear()