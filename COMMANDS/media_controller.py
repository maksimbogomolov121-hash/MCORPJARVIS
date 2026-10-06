"""
media_controller.py
Управление мультимедиа Windows.
"""

import pyautogui


class MediaController:

    def __init__(self, logger=None):

        self.logger = logger

    # ==========================================
    # Следующий трек
    # ==========================================

    def next_track(self):

        try:

            pyautogui.press("nexttrack")

            self.log(
                "Следующий трек"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка next track: {e}"
            )

            return False

    # ==========================================
    # Предыдущий трек
    # ==========================================

    def previous_track(self):

        try:

            pyautogui.press("prevtrack")

            self.log(
                "Предыдущий трек"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка previous track: {e}"
            )

            return False

    # ==========================================
    # Пауза
    # ==========================================

    def pause(self):

        try:

            pyautogui.press(
                "playpause"
            )

            self.log(
                "Медиа поставлено на паузу"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка паузы: {e}"
            )

            return False

    # ==========================================
    # Продолжить воспроизведение
    # ==========================================

    def play(self):

        try:

            pyautogui.press(
                "playpause"
            )

            self.log(
                "Воспроизведение продолжено"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка воспроизведения: {e}"
            )

            return False

    # ==========================================
    # Play / Pause
    # ==========================================

    def play_pause(self):

        try:

            pyautogui.press(
                "playpause"
            )

            self.log(
                "Play/Pause"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка PlayPause: {e}"
            )

            return False

    # ==========================================
    # Стоп
    # ==========================================

    def stop(self):

        try:

            pyautogui.press(
                "playpause"
            )

            self.log(
                "Стоп"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка Stop: {e}"
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

        else:

            print(message)