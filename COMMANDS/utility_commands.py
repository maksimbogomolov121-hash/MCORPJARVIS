"""
utility_commands.py
Утилиты и простые команды JARVIS.
"""

import datetime
import platform
import socket
import os
import pyautogui
import winshell
import shutil

from SYSTEM.PC_monitor import PCMonitor


class UtilityCommands:

    def __init__(self, logger=None):
        self.logger = logger
        self.pc_monitor = PCMonitor(logger)

    def close_window(self):
        try:
            pyautogui.hotkey("alt", "f4")
            self.log("Активное окно закрыто")
            return "Окно закрыто."
        except Exception as e:
            self.log(f"Ошибка закрытия окна: {e}")
            return False

    def execute(self, command):
        command = command.lower().strip()

        if (
                "сколько памяти" in command
                or "че там по памяти" in command
                or "что там по памяти" in command
        ):

            free = self.pc_monitor.free_storage()

            if free is not None:
                result = f"Свободно {free} гигабайт"

                self.log(result)

                return result

            return "Не удалось получить информацию о памяти."

        if "другой язык" in command:
            return self.change_language()

        if "блютуз" in command or "bluetooth" in command:
            return self.open_bluetooth()

        if "время" in command or "сколько время" in command:
            return self.get_time()

        if "дата" in command or "число" in command or "какое сегодня число" in command:
            return self.get_date()

        if "закрой окно" in command:
            return self.close_window()

        if "очисти корзину" in command:
            return self.clear_recycle_bin()

        if "очисти темп" in command:
            return self.clear_temp()

        if "день недели" in command:
            return self.get_day()

        if "информация о компьютере" in command:
            return self.system_info()

        if "калькулятор" in command:
            return self.calculate(command)

        self.log(f"Неизвестная утилита: {command}")
        return False

    def get_time(self):
        now = datetime.datetime.now()
        result = f"Сейчас {now.hour}:{now.minute:02d}"
        self.log(result)
        return result

    def get_date(self):
        now = datetime.datetime.now()
        result = f"Сегодня {now.day:02d}.{now.month:02d}.{now.year}"
        self.log(result)
        return result

    def get_day(self):
        days = [
            "понедельник", "вторник", "среда", "четверг",
            "пятница", "суббота", "воскресенье"
        ]
        result = f"Сегодня {days[datetime.datetime.today().weekday()]}"
        self.log(result)
        return result

    def system_info(self):
        try:
            result = (
                f"Операционная система: {platform.system()}\n"
                f"Версия: {platform.release()}\n"
                f"Компьютер: {socket.gethostname()}\n"
                f"Пользователь: {os.getlogin()}"
            )
            self.log("Получена информация о системе")
            return result
        except Exception as e:
            self.log(f"Ошибка получения информации о системе: {e}")
            return False

    def calculate(self, command):
        try:
            expression = command.replace("калькулятор", "").strip()
            result = eval(expression, {"__builtins__": {}}, {})
            answer = f"Ответ: {result}"
            self.log(answer)
            return answer
        except Exception:
            return "Не удалось выполнить вычисление."

    def change_language(self):
        try:
            pyautogui.hotkey("alt", "shift")
            self.log("Язык клавиатуры переключен")
            return True
        except Exception as e:
            self.log(f"Ошибка переключения языка: {e}")
            return False

    def open_bluetooth(self):
        try:
            if platform.system() == "Windows":
                os.system("start ms-settings:bluetooth")
                self.log("Открыты настройки Bluetooth")
                return True
            self.log("Bluetooth доступен только в Windows")
            return False
        except Exception as e:
            self.log(f"Ошибка открытия Bluetooth: {e}")
            return False

    def clear_recycle_bin(self):
        try:
            if platform.system() == "Windows":
                winshell.recycle_bin().empty(
                    confirm=False,
                    show_progress=False,
                    sound=True
                )
                self.log("Корзина очищена")
                return True
            self.log("Очистка корзины доступна только в Windows")
            return False
        except Exception as e:
            self.log(f"Ошибка очистки корзины: {e}")
            return False

    def clear_temp(self):
        try:
            temp_folder = os.environ.get("TEMP")

            if not temp_folder:
                self.log("TEMP папка не найдена")
                return False

            deleted = 0

            for filename in os.listdir(temp_folder):
                file_path = os.path.join(temp_folder, filename)

                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                        deleted += 1
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        deleted += 1
                except Exception:
                    continue

            message = f"TEMP очищен. Удалено объектов: {deleted}"
            self.log(message)
            return message

        except Exception as e:
            self.log(f"Ошибка очистки TEMP: {e}")
            return False

    def log(self, message):
        if self.logger:
            self.logger.info(message)
        else:
            print(message)
