"""
startup.py
Инициализация и запуск JARVIS.
"""

from CORE.logger import Logger
from VOICE.speech_output import SpeechOutput


class Startup:
    """
    Отвечает за запуск и инициализацию JARVIS.
    """

    def __init__(self):
        self.logger = Logger()
        self.speech = SpeechOutput()
        #self.memory = Memory()

    def initialize(self):
        """Запуск всех необходимых компонентов."""

        self.logger.info("========================================")
        self.logger.info("Запуск JARVIS...")
        self.logger.info("Инициализация системы...")

        # Загрузка памяти
        #self.memory.load()

        # Голосовое приветствие
        self.speech.speak("Системы запущены. JARVIS готов к работе!")

        self.logger.info("JARVIS успешно запущен.")
        self.logger.info("========================================")

    def shutdown(self):
        """Корректное завершение работы."""

        self.logger.info("Завершение работы JARVIS...")

        #self.memory.save()

        self.speech.speak("До встречи.")

        self.logger.info("JARVIS выключен.")