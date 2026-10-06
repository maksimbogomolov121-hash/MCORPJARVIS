"""
volume_manager.py
Управление громкостью Windows для JARVIS.
"""

from pycaw.pycaw import AudioUtilities


class VolumeManager:

    def __init__(self, logger=None):

        self.logger = logger

        try:

            devices = AudioUtilities.GetSpeakers()
            self.volume = devices.EndpointVolume

            self.log(
                "Управление громкостью инициализировано"
            )

        except Exception as e:

            self.volume = None

            self.log(
                f"Ошибка инициализации громкости: {e}"
            )

    # ==========================================================
    # Установить громкость
    # ==========================================================

    def set_volume(self, level):

        try:

            if self.volume is None:
                return False

            level = max(
                0,
                min(100, int(level))
            )

            self.volume.SetMasterVolumeLevelScalar(
                level / 100.0,
                None
            )

            self.log(
                f"Громкость установлена: {level}%"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка установки громкости: {e}"
            )

            return False

    # ==========================================================
    # Увеличить громкость
    # ==========================================================

    def volume_up(self):

        try:

            if self.volume is None:
                return False

            current = (
                self.volume.GetMasterVolumeLevelScalar()
            )

            new_volume = min(
                1.0,
                current + 0.1
            )

            self.volume.SetMasterVolumeLevelScalar(
                new_volume,
                None
            )

            self.log(
                f"Громкость увеличена до {round(new_volume * 100)}%"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка увеличения громкости: {e}"
            )

            return False

    # ==========================================================
    # Уменьшить громкость
    # ==========================================================

    def volume_down(self):

        try:

            if self.volume is None:
                return False

            current = (
                self.volume.GetMasterVolumeLevelScalar()
            )

            new_volume = max(
                0.0,
                current - 0.1
            )

            self.volume.SetMasterVolumeLevelScalar(
                new_volume,
                None
            )

            self.log(
                f"Громкость уменьшена до {round(new_volume * 100)}%"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка уменьшения громкости: {e}"
            )

            return False

    # ==========================================================
    # Выключить звук
    # ==========================================================

    def mute(self):

        try:

            if self.volume is None:
                return False

            self.volume.SetMute(
                1,
                None
            )

            self.log(
                "Звук выключен"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка отключения звука: {e}"
            )

            return False

    # ==========================================================
    # Включить звук
    # ==========================================================

    def unmute(self):

        try:

            if self.volume is None:
                return False

            # Сначала снимаем mute
            self.volume.SetMute(
                0,
                None
            )

            # Читаем состояние

            muted = self.volume.GetMute()

            # Если Windows всё ещё считает звук выключенным,
            # пробуем снять mute ещё раз.
            if muted:
                self.volume.SetMute(
                    False,
                    None
                )

            self.log(
                "Звук включен"
            )

            return True

        except Exception as e:

            self.log(
                f"Ошибка включения звука: {e}"
            )

            return False

    # ==========================================================
    # Получить текущую громкость
    # ==========================================================

    def get_volume(self):

        try:

            if self.volume is None:
                return None

            current = (
                self.volume.GetMasterVolumeLevelScalar()
            )

            return round(
                current * 100
            )

        except Exception as e:

            self.log(
                f"Ошибка получения громкости: {e}"
            )

            return None

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(message)

        else:

            print(message)