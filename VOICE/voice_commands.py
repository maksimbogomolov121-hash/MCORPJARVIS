"""
voice_commands.py
Обработка голосовых команд JARVIS.
"""

import time
import random

from VOICE.speech_output import SpeechOutput
from COMMANDS.command_handler import CommandHandler
from COMMANDS.security_commands import SecurityCommands


class VoiceCommands:
    """
    Управление голосовыми командами JARVIS.
    """

    def __init__(self, speech_output: SpeechOutput):

        self.speech = speech_output

        self.voice_enabled = True
        self.confirmation_enabled = True

        self.command_handler = CommandHandler(
            speech_output=self.speech
        )

        # ---------------------------------------------
        # Security
        # ---------------------------------------------

        self.security_commands = SecurityCommands()

        # ---------------------------------------------
        # Состояние подтверждения
        # ---------------------------------------------

        self.waiting_confirmation = False

        # Время, до которого ждём подтверждение
        self.confirmation_timeout = 10

        self.confirmation_start_time = 0

    # ==========================================
    # Основной обработчик
    # ==========================================

    def execute(self, command: str):

        if not command:
            return False

        command = command.lower().strip()

        # ==================================================
        # Подтверждение глубокого поиска Universal Open
        # ==================================================

        if self.command_handler.universal_open.waiting_confirmation:

            result = (
                self.command_handler.universal_open.handle_confirmation(
                    command
                )
            )

            if result:
                return True

        # ==================================================
        # Security-команды
        # ==================================================

        security_result = self.security_commands.execute(
            command
        )

        if security_result is not None:

            self.speak(
                security_result
            )

            return True

        # ------------------------------
        # Проверка присутствия JARVIS
        # ------------------------------

        if (
            "ты здесь" in command
            or "ты тут" in command
        ):
            responses = [
                "Разумеется, сэр. Я никуда не уходил.",
                "Я здесь, сэр. Система полностью готова.",
                "На связи, сэр. Внимательно слушаю.",
                "Всегда рядом, сэр. Что вам нужно?",
                "Я здесь. Ждал вашего обращения.",
                "На месте, сэр. Можете продолжать.",
                "Разумеется. Я вас слышу.",
                "Я в сети, сэр. Чем могу быть полезен?",
                "Здесь, сэр. Все системы функционируют.",
                "Я здесь, сэр. Надеюсь, вы не собирались меня выключать.",
                "На связи. Как всегда.",
                "Я слушаю, сэр. Приступаем?",
                "Присутствую, сэр. Ожидаю дальнейших указаний.",
                "Я здесь. Можете не волноваться.",
                "Система активна, сэр. Я полностью в вашем распоряжении."
            ]

            self.speak(
                random.choice(responses)
            )

            return True

        # ------------------------------
        # Ответ на благодарность
        # ------------------------------

        if "спасибо" in command:

            self.speak(
                "Всегда к вашим услугам, сэр."
            )

            return True

        # ------------------------------
        # Скорость речи
        # ------------------------------

        if "говори медленнее" in command:

            self.speech.set_rate(140)

            self.speak(
                "Хорошо."
            )

            return True

        if "говори быстрее" in command:

            self.speech.set_rate(220)

            self.speak(
                "Хорошо."
            )

            return True

        if "обычная скорость" in command:

            self.speech.set_rate(180)

            self.speak(
                "Скорость восстановлена."
            )

            return True

        # ------------------------------
        # Громкость
        # ------------------------------

        if "говори громче" in command:

            self.speech.set_volume(1.0)

            self.speak(
                "Громкость увеличена."
            )

            return True

        if "говори тише" in command:

            self.speech.set_volume(0.4)

            self.speak(
                "Громкость уменьшена."
            )

            return True

        # ------------------------------
        # Голос
        # ------------------------------

        if "замолчи" in command:

            self.voice_enabled = False

            self.speech.stop()

            return True

        if command == "говори":

            self.voice_enabled = True

            self.speak(
                "Я снова с вами."
            )

            return True

        # ------------------------------
        # Подтверждение
        # ------------------------------

        if "выключи подтверждение" in command:

            self.confirmation_enabled = False

            self.speak(
                "Звуки подтверждения отключены."
            )

            return True

        if "включи подтверждение" in command:

            self.confirmation_enabled = True

            self.speak(
                "Звуки подтверждения включены."
            )

            return True

        # ------------------------------
        # Выполнение команды
        # ------------------------------

        result = self.command_handler.execute(
            command
        )

        # ==================================================
        # JARVIS должен завершиться
        # ==================================================

        if result == "shutdown":

            self.speak(
                "Выключаю питание."
            )

            return "shutdown"

        # ==================================================
        # Команда требует подтверждения
        # ==================================================

        if isinstance(result, str):

            if (
                "подтвердите" in result.lower()
                or "подтверди" in result.lower()
            ):
                self.waiting_confirmation = True

                self.confirmation_start_time = time.time()

                self.speak(result)

                return True

            self.speak(result)

            return True

        # ==================================================
        # Обычный успешный результат
        # ==================================================

        if result:

            return True

        return False

    # ==========================================
    # Обработка подтверждения
    # ==========================================

    def execute_confirmation(self, command: str):

        if not command:
            return False

        command = command.lower().strip()

        # ---------------------------------------------
        # Проверяем таймаут
        # ---------------------------------------------

        elapsed = (
            time.time()
            - self.confirmation_start_time
        )

        if elapsed > self.confirmation_timeout:

            self.waiting_confirmation = False

            self.speak(
                "Время подтверждения истекло. "
                "Команда отменена."
            )

            return False

        # ---------------------------------------------
        # Подтверждение
        # ---------------------------------------------

        if (
            "подтверждаю" in command
            or "подтверждаю команду" in command
            or command == "да"
            or "давай" in command
        ):


            self.waiting_confirmation = False

            result = self.command_handler.execute(
                "подтверждаю"
            )

            if result == "shutdown":

                self.speak(
                    "Выключаю питание."
                )

                return "shutdown"

            if result:

                if isinstance(result, str):

                    self.speak(result)

                return True

            self.speak(
                "Не удалось выполнить подтверждённую команду."
            )

            return False

        # ---------------------------------------------
        # Отмена
        # ---------------------------------------------

        if (
            "отмена" in command
            or "отменяю" in command
            or command == "нет"
            or "не надо" in command
        ):
            self.waiting_confirmation = False

            self.command_handler.execute(
                "отмена"
            )

            self.speak(
                "Команда отменена."
            )

            return True

        # ---------------------------------------------
        # Ничего подходящего
        # ---------------------------------------------

        self.speak(
            "Ожидаю подтверждение или отмену."
        )

        return True

    # ==========================================
    # Проверка ожидания подтверждения
    # ==========================================

    def is_waiting_confirmation(self):

        if not self.waiting_confirmation:
            return False

        elapsed = (
            time.time()
            - self.confirmation_start_time
        )

        if elapsed > self.confirmation_timeout:

            self.waiting_confirmation = False

            return False

        return True

    # ==========================================
    # Вспомогательные методы
    # ==========================================

    def speak(self, text: str):

        if self.voice_enabled:

            self.speech.speak(text)

    def confirm(self):

        if self.confirmation_enabled:

            self.speech.confirm()

    def is_voice_enabled(self):

        return self.voice_enabled

    def is_confirmation_enabled(self):

        return self.confirmation_enabled