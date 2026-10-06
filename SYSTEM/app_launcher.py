 
"""
app_launcher.py
Модуль запуска приложений JARVIS.
"""

import os
import subprocess


class AppLauncher:
    """
    Управление запуском программ.
    """

    def __init__(self, logger=None):
        self.logger = logger

        # База известных приложений
        self.apps = {
            "браузер": "start chrome",
            "chrome": "start chrome",
            "гугл": "start chrome",

            "проводник": "explorer",

            "калькулятор": "calc",

            "блокнот": "notepad",

            "cmd": "cmd",
            "командная строка": "cmd",
        }


    def launch(self, app_name: str):
        """
        Запуск приложения по названию.
        """

        app_name = app_name.lower().strip()

        if app_name in self.apps:
            try:
                subprocess.Popen(
                    self.apps[app_name],
                    shell=True
                )

                if self.logger:
                    self.logger.info(
                        f"Запущено приложение: {app_name}"
                    )

                return True

            except Exception as error:
                if self.logger:
                    self.logger.error(
                        f"Ошибка запуска {app_name}: {error}"
                    )

                return False


        # Попытка запуска напрямую
        try:
            subprocess.Popen(app_name)

            if self.logger:
                self.logger.info(
                    f"Запущено напрямую: {app_name}"
                )

            return True

        except Exception:
            if self.logger:
                self.logger.warning(
                    f"Приложение не найдено: {app_name}"
                )

            return False