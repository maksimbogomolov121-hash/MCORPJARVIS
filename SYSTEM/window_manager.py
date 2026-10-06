"""
window_manager.py
Управление окнами Windows для JARVIS.
"""


import pyautogui
import ctypes


class WindowManager:
    """
    Управление окнами компьютера.
    """


    def __init__(self, logger=None):

        self.logger = logger



    # ==========================================
    # Закрытие активного окна
    # ==========================================

    def close_window(self):

        try:

            pyautogui.hotkey(
                "alt",
                "f4"
            )


            self.log(
                "Активное окно закрыто"
            )


            return True


        except Exception as e:

            self.log(
                f"Ошибка закрытия окна: {e}"
            )

            return False



    # ==========================================
    # Свернуть все окна
    # ==========================================

    def minimize_all(self):

        print("WINDOW TEST: minimize_all() вызвана")

        try:

            ctypes.windll.user32.keybd_event(
                0x5B,  # Win
                0,
                0,
                0
            )

            ctypes.windll.user32.keybd_event(
                0x44,  # D
                0,
                0,
                0
            )

            ctypes.windll.user32.keybd_event(
                0x44,  # D
                0,
                2,
                0
            )

            ctypes.windll.user32.keybd_event(
                0x5B,  # Win
                0,
                2,
                0
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



    # ==========================================
    # Логирование
    # ==========================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )