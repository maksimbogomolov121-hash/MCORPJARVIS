"""
system_commands.py
Системные команды JARVIS.
"""

import os
import platform
import subprocess
import pyautogui

from SYSTEM.backup_manager import BackupManager
from SYSTEM.screen_manager import ScreenManager
from SYSTEM.confirmation_manager import ConfirmationManager
from SYSTEM.night_mode import NightMode


class SystemCommands:
    """
    Системные команды JARVIS.
    """

    def __init__(self, logger=None):

        self.logger = logger

        self.backup_manager = BackupManager(
            logger
        )

        self.confirmation = ConfirmationManager()

        self.night_mode = NightMode()

        self.screen_manager = ScreenManager(
            logger
        )

    # ==========================================================
    # Скриншот
    # ==========================================================

    def screenshot(self):

        try:

            result = self.screen_manager.screenshot()

            if result:
                self.log(
                    "Скриншот выполнен"
                )

            return result

        except Exception as e:

            self.log(
                f"Ошибка скриншота: {e}"
            )

            return False

    # ==========================================================
    # Свернуть все окна
    # ==========================================================

    def minimize_windows(self):

        try:

            pyautogui.hotkey(
                "win",
                "d"
            )

            self.log(
                "Все окна свернуты"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка сворачивания окон: {e}"
            )

            return False

    # ==========================================================
    # Главный обработчик
    # ==========================================================

    def execute(self, command):

        if not command:
            return False

        command = command.lower().strip()

        # ------------------------------------------------------
        # Подтверждение ранее запрошенной команды
        # ------------------------------------------------------

        if "подтверждаю" in command:

            action = self.confirmation.confirm()

            if action == "shutdown":
                return self.shutdown()

            if action == "restart":
                return self.restart()

            return "Нет ожидающих команд."

        # ------------------------------------------------------
        # Отмена команды
        # ------------------------------------------------------

        if "отмена" in command:

            self.confirmation.cancel()

            return "Команда отменена."

        # ------------------------------------------------------
        # Выключение интернета
        # ------------------------------------------------------

        if "выключи интернет" in command:

            return self.disable_wifi()

        # ------------------------------------------------------
        # Создание резервной копии
        # ------------------------------------------------------

        if "создай резервную копию" in command:

            return self.backup_manager.create_backup()

        # ------------------------------------------------------
        # Ночной режим
        # ------------------------------------------------------

        if "ночной режим" in command:

            self.night_mode.enable()

            return "Ночной режим включён."

        # ------------------------------------------------------
        # Обычный режим
        # ------------------------------------------------------

        if "обычный режим" in command:

            self.night_mode.disable()

            return "Обычный режим включён."

        # ------------------------------------------------------
        # Выключение компьютера
        # ------------------------------------------------------

        if (
                "выключи компьютер" in command
                or "выключить компьютер" in command
                or "выключение компьютера" in command
        ):
            self.confirmation.request(
                "shutdown"
            )

            return "Подтвердите выключение."

        # ------------------------------------------------------
        # Перезагрузка компьютера
        # ------------------------------------------------------

        if (
                "перезагрузи компьютер" in command
                or "перезагрузить компьютер" in command
                or "перезагрузка компьютера" in command
        ):
            self.confirmation.request(
                "restart"
            )

            return "Подтвердите перезагрузку."

        # ------------------------------------------------------
        # Блокировка экрана
        # ------------------------------------------------------

        if "заблокируй экран" in command:

            return self.lock()

        # ------------------------------------------------------
        # Спящий режим
        # ------------------------------------------------------

        if "спящий режим" in command:

            return self.sleep()

        # ------------------------------------------------------
        # Скриншот
        # ------------------------------------------------------

        if "скриншот" in command:

            return self.screenshot()

        # ------------------------------------------------------
        # Команда не найдена
        # ------------------------------------------------------

        self.log(
            f"Неизвестная системная команда: {command}"
        )

        return False

    # ==========================================================
    # Выключение интернета
    # ==========================================================

    def disable_wifi(self):

        try:

            if platform.system() != "Windows":

                self.log(
                    "Отключение Wi-Fi реализовано для Windows"
                )

                return False

            os.system(
                'netsh interface set interface "Wi-Fi" disable'
            )

            self.log(
                "Wi-Fi отключён"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка отключения Wi-Fi: {e}"
            )

            return False

    # ==========================================================
    # Выключение компьютера
    # ==========================================================

    def shutdown(self):

        try:

            system = platform.system()

            if system == "Windows":

                os.system(
                    "shutdown /s /t 5"
                )

            elif system == "Linux":

                os.system(
                    "shutdown now"
                )

            elif system == "Darwin":

                os.system(
                    "sudo shutdown -h now"
                )

            else:

                return False

            self.log(
                "Компьютер выключается"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка выключения: {e}"
            )

            return False

    # ==========================================================
    # Перезагрузка компьютера
    # ==========================================================

    def restart(self):

        try:

            system = platform.system()

            if system == "Windows":

                os.system(
                    "shutdown /r /t 5"
                )

            elif system == "Linux":

                os.system(
                    "reboot"
                )

            elif system == "Darwin":

                os.system(
                    "sudo shutdown -r now"
                )

            else:

                return False

            self.log(
                "Компьютер перезагружается"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка перезагрузки: {e}"
            )

            return False


# ==========================================================
    # Блокировка компьютера
    # ==========================================================

    def lock(self):

        try:

            system = platform.system()

            if system == "Windows":

                os.system(
                    "rundll32.exe user32.dll,LockWorkStation"
                )

            elif system == "Linux":

                os.system(
                    "loginctl lock-session"
                )

            elif system == "Darwin":

                os.system(
                    "pmset displaysleepnow"
                )

            else:

                return False

            self.log(
                "Компьютер заблокирован"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка блокировки: {e}"
            )

            return False

    # ==========================================================
    # Сон компьютера
    # ==========================================================

    def sleep(self):

        try:

            system = platform.system()

            if system == "Windows":

                subprocess.run(
                    [
                        "rundll32.exe",
                        "powrprof.dll,SetSuspendState",
                        "0,1,0"
                    ],
                    check=False
                )

            elif system == "Linux":

                os.system(
                    "systemctl suspend"
                )

            elif system == "Darwin":

                os.system(
                    "pmset sleepnow"
                )

            else:

                return False

            self.log(
                "Компьютер переходит в сон"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка сна: {e}"
            )

            return False

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )

        else:

            print(message)