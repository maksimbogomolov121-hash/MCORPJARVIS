 
"""
screen_manager.py
Управление скриншотами JARVIS.
"""

import pyautogui


class ScreenManager:
    """
    Работа со скриншотами.
    """

    def __init__(self, logger=None):

        self.logger = logger


    # ==========================================
    # Создание скриншота
    # ==========================================

    def screenshot(self):

        try:

            pyautogui.hotkey(
                "win",
                "printscreen"
            )


            self.log(
                "Скриншот сделан"
            )


            return True


        except Exception as e:

            self.log(
                f"Ошибка создания скриншота: {e}"
            )

            return False



    # ==========================================
    # Логирование
    # ==========================================

    def log(self, message):

        if self.logger:

            self.logger.info(message)