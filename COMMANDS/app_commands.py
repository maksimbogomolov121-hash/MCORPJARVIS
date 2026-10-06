"""
app_commands.py
Команды запуска приложений для JARVIS.
"""

import os
import subprocess
import platform


class AppCommands:

    def __init__(self, logger=None):

        self.logger = logger

        self.apps = {

            # ==================================================
            # Браузеры
            # ==================================================

            "браузер": "start chrome",
            "хром": "start chrome",
            "гугл": "start chrome",

            # ==================================================
            # Windows
            # ==================================================

            "блокнот": "notepad.exe",
            "калькулятор": "calc.exe",
            "проводник": "explorer.exe",
            "диспетчер задач": "taskmgr.exe",
            "терминал": "cmd.exe",
            "cmd": "cmd.exe",

            "этот компьютер":
                "explorer.exe shell:MyComputerFolder",

            "рабочий стол":
                "desktop",

            "загрузки":
                "downloads",

            # ==================================================
            # Пользовательские программы
            # ==================================================

            "telegram":
                r"C:\Users\User\AppData\Roaming\Telegram Desktop",

            "майнкрафт":
                r"C:\Users\User\AppData\Roaming\.minecraft\TLauncher.exe",

            "блендер":
                r"C:\Program Files\Blender Foundation\Blender 5.0",

            "макс":
                r"C:\Program Files\MAX\max.exe",

            "впн":
                r"C:\Program Files\FlyFrogLLC\Happ\Happ.exe",

            "дюна":
                r"надо спросить у Миши как лучше сделать",
        }

    # ==========================================================
    # Обработчик команды
    # ==========================================================

    def execute(self, command):

        if not command:
            return False

        command = command.lower().strip()

        # ------------------------------------------------------
        # Поиск приложения
        # ------------------------------------------------------

        for name, path in self.apps.items():

            if name in command:

                return self.launch(
                    path,
                    name
                )

        self.log(
            f"Приложение не найдено: {command}"
        )

        return False

    # ==========================================================
    # Запуск приложения
    # ==========================================================

    def launch(self, path, name):

        try:

            system = platform.system()

            # ==================================================
            # WINDOWS
            # ==================================================

            if system == "Windows":

                # ------------------------------------------------
                # Рабочий стол
                # ------------------------------------------------

                if path == "desktop":

                    desktop_path = os.path.join(
                        os.path.expanduser("~"),
                        "Desktop"
                    )

                    os.startfile(
                        desktop_path
                    )

                # ------------------------------------------------
                # Загрузки
                # ------------------------------------------------

                elif path == "downloads":

                    downloads_path = os.path.join(os.path.expanduser("~"),
                        "Downloads"
                    )

                    os.startfile(
                        downloads_path
                    )

                # ------------------------------------------------
                # Этот компьютер
                # ------------------------------------------------

                elif path == (
                    "explorer.exe shell:MyComputerFolder"
                ):

                    subprocess.Popen(
                        [
                            "explorer.exe",
                            "shell:MyComputerFolder"
                        ]
                    )

                # ------------------------------------------------
                # Команды start
                # ------------------------------------------------

                elif path.startswith("start "):

                    subprocess.Popen(
                        path,
                        shell=True
                    )

                # ------------------------------------------------
                # Обычные EXE
                # ------------------------------------------------

                else:

                    subprocess.Popen(
                        path
                    )

            # ==================================================
            # LINUX
            # ==================================================

            elif system == "Linux":

                subprocess.Popen(
                    path.split()
                )

            # ==================================================
            # MACOS
            # ==================================================

            elif system == "Darwin":

                subprocess.Popen(
                    [
                        "open",
                        "-a",
                        name
                    ]
                )

            # ==================================================
            # Неизвестная ОС
            # ==================================================

            else:

                self.log(
                    f"Неподдерживаемая ОС: {system}"
                )

                return False

            self.log(
                f"Запущено приложение: {name}"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка запуска {name}: {e}"
            )

            return False

    # ==========================================================
    # Добавление приложения
    # ==========================================================

    def add_application(self, name, path):

        self.apps[
            name.lower()
        ] = path

        self.log(
            f"Добавлено приложение: {name}"
        )

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(message)

        else:

            print(message)