 
"""
night_mode.py
Ночной режим JARVIS.
"""

from pycaw.pycaw import AudioUtilities
from comtypes import CLSCTX_ALL


class NightMode:

    def __init__(self):

        self.enabled = False

        devices = AudioUtilities.GetSpeakers()

        self.volume = devices.EndpointVolume

    # -----------------------------------------
    # Включить
    # -----------------------------------------

    def enable(self):

        self.enabled = True

        self.volume.SetMasterVolumeLevelScalar(
            0.1,
            None
        )

        return True

    # -----------------------------------------
    # Выключить
    # -----------------------------------------

    def disable(self):

        self.enabled = False

        return True

    # -----------------------------------------
    # Проверка
    # -----------------------------------------

    def is_enabled(self):

        return self.enabled