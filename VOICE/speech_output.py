"""
speech_output.py
Голосовой вывод JARVIS через Silero TTS.
"""

import os
import re
import threading
import tempfile
import wave

import torch
from playsound import playsound


class SpeechOutput:
    """
    Модуль синтеза речи JARVIS.

    Silero TTS:
    текст -> подготовка текста -> синтез речи -> WAV -> воспроизведение
    """

    def __init__(self):

        self.is_speaking = False

        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        # ======================================================
        # Пути
        # ======================================================

        # Папка VOICE
        self.voice_dir = os.path.dirname(
            os.path.abspath(__file__)
        )

        # Файл модели Silero V5
        self.model_path = os.path.join(
            self.voice_dir,
            "v5_ru.pt"
        )

        # Корень проекта JARVIS_V11
        self.project_dir = os.path.dirname(
            self.voice_dir
        )

        # Папка системных звуков
        self.sounds_dir = os.path.join(
            self.project_dir,
            "SOUNDS"
        )

        # ======================================================
        # Настройки Silero
        # ======================================================

        self.sample_rate = 48000

        # Русский голос
        self.speaker = "eugene"

        # ======================================================
        # Загрузка модели
        # ======================================================

        print("Загрузка Silero TTS...")

        try:

            # --------------------------------------------------
            # Проверяем модель
            # --------------------------------------------------

            if not os.path.isfile(
                self.model_path
            ):

                raise FileNotFoundError(
                    "Файл модели Silero не найден:\n"
                    f"{self.model_path}\n\n"
                    "Помести файл v5_ru.pt в папку VOICE."
                )

            print(
                f"Модель найдена: {self.model_path}"
            )

            # --------------------------------------------------
            # CPU
            # --------------------------------------------------

            self.device = torch.device(
                "cpu"
            )

            # --------------------------------------------------
            # Количество потоков
            # --------------------------------------------------

            try:

                torch.set_num_threads(4)

            except Exception:

                pass

            # --------------------------------------------------
            # Загрузка локальной модели Silero V5
            # --------------------------------------------------

            print("Загрузка локальной модели Silero V5...")

            with open(self.model_path, "rb") as model_file:
                importer = torch.package.PackageImporter(model_file)
                self.model = importer.load_pickle("tts_models", "model")

            # --------------------------------------------------
            # Перенос модели на CPU
            # --------------------------------------------------

            self.model.to(
                self.device
            )

            # --------------------------------------------------
            # Тестовый текст
            # --------------------------------------------------

            self.example_text = (
                "Пример текста для проверки."
            )

            print(
                "Silero TTS загружен."
            )

        except Exception as e:

            print(
                f"Ошибка загрузки Silero TTS: {e}"
            )

            raise

    # ==========================================================
    # Подготовка текста для русского произношения
    # ==========================================================

    def prepare_text(
        self,
        text: str
    ):

        if not text:

            return ""

        text = str(
            text
        )

        # ------------------------------------------------------
        # Английские слова и названия
        # ------------------------------------------------------

        replacements = {

            "PCMonitor":
                "мониторинг компьютера",

            "Bluetooth":
                "Блютуз",

            "bluetooth":
                "Блютуз",

            "YouTube":
                "Ютуб",

            "Youtube":
                "Ютуб",

            "youtube":
                "Ютуб",

            "Windows":
                "Виндовс",

            "windows":
                "Виндовс",

            "Google":
                "Гугл",

            "google":
                "Гугл",

            "JARVIS":
                "Джарвис",

            "Jarvis":
                "Джарвис",

            "Wi-Fi":
                "вай фай",

            "WiFi":
                "вай фай",

            "USB":
                "ю эс би",

            "CPU":
                "процессор",

            "GPU":
                "видеокарта",

            "RAM":
                "оперативная память",

            "AIMP":
                "АИМП",

            "VK":
                "ВК",

            "PC":
                "компьютер",
        }

        # ------------------------------------------------------
        # Сначала длинные варианты
        # ------------------------------------------------------

        for old, new in sorted(
            replacements.items(),
            key=lambda item: len(item[0]),
            reverse=True
        ):

            text = re.sub(
                rf"\b{re.escape(old)}\b",
                new,
                text,
                flags=re.IGNORECASE
            )

        # ------------------------------------------------------
        # Время
        #
        # 13:02 -> тринадцать часов две минуты
        # 21:05 -> двадцать один час пять минут
        # ------------------------------------------------------

        def replace_time(match):

            hour = int(
                match.group(1)
            )

            minute = int(
                match.group(2)
            )

            hour_word = self.number_to_words(
                hour
            )

            minute_word = self.number_to_words(
                minute
            )

            hour_form = self.plural_form(
                hour,
                "час",
                "часа",
                "часов"
            )

            minute_form = self.plural_form(
                minute,
                "минута",
                "минуты",
                "минут"
            )

            return (
                f"{hour_word} {hour_form} "
                f"{minute_word} {minute_form}"
            )

        text = re.sub(
            r"\b([01]?\d|2[0-3]):([0-5]\d)\b",
            replace_time,
            text
        )

        # ------------------------------------------------------
        # Числа
        # ------------------------------------------------------

        def replace_number(match):

            number = int(
                match.group(0)
            )

            # Безопасно обрабатываем числа до 999999
            if number <= 999999:

                return self.number_to_words(
                    number
                )

            return match.group(0)

        text = re.sub(
            r"\b\d+\b",
            replace_number,
            text
        )

        # ------------------------------------------------------
        # Лишние символы
        # ------------------------------------------------------

        text = text.replace(
            "_",
            " "
        )

        text = text.replace(
            "/",
            " "
        )

        text = re.sub(

r"\s+",
            " ",
            text
        ).strip()

        return text

    # ==========================================================
    # Число -> русские слова
    # ==========================================================

    def number_to_words(
        self,
        number
    ):

        if number == 0:

            return "ноль"

        if number < 0:

            return (
                "минус "
                + self.number_to_words(
                    abs(number)
                )
            )

        ones = [

            "",

            "один",

            "два",

            "три",

            "четыре",

            "пять",

            "шесть",

            "семь",

            "восемь",

            "девять"
        ]

        teens = [

            "десять",

            "одиннадцать",

            "двенадцать",

            "тринадцать",

            "четырнадцать",

            "пятнадцать",

            "шестнадцать",

            "семнадцать",

            "восемнадцать",

            "девятнадцать"
        ]

        tens = [

            "",

            "",

            "двадцать",

            "тридцать",

            "сорок",

            "пятьдесят",

            "шестьдесят",

            "семьдесят",

            "восемьдесят",

            "девяносто"
        ]

        hundreds = [

            "",

            "сто",

            "двести",

            "триста",

            "четыреста",

            "пятьсот",

            "шестьсот",

            "семьсот",

            "восемьсот",

            "девятьсот"
        ]

        def under_1000(n):

            result = []

            if n >= 100:

                result.append(
                    hundreds[n // 100]
                )

                n %= 100

            if 10 <= n <= 19:

                result.append(
                    teens[n - 10]
                )

                return " ".join(
                    result
                )

            if n >= 20:

                result.append(
                    tens[n // 10]
                )

                n %= 10

            if n > 0:

                result.append(
                    ones[n]
                )

            return " ".join(
                result
            )

        # ------------------------------------------------------
        # Числа меньше 1000
        # ------------------------------------------------------

        if number < 1000:

            return under_1000(
                number
            )

        # ------------------------------------------------------
        # Тысячи
        # ------------------------------------------------------

        thousands = number // 1000

        remainder = number % 1000

        result = []

        # ------------------------------------------------------
        # Особые формы для тысяч
        # ------------------------------------------------------

        if thousands % 100 == 1:

            thousand_word = "одна"

        elif thousands % 100 == 2:

            thousand_word = "две"

        else:

            thousand_word = self.number_to_words(
                thousands
            )

        result.append(
            thousand_word
        )

        # ------------------------------------------------------
        # Форма слова "тысяча"
        # ------------------------------------------------------

        last_two = thousands % 100

        if 11 <= last_two <= 19:

            result.append(
                "тысяч"
            )

        else:

            last = thousands % 10

            if last == 1:

                result.append(
                    "тысяча"
                )

            elif last in (2, 3, 4):

                result.append(
                    "тысячи"
                )

            else:

                result.append(
                    "тысяч"
                )

        # ------------------------------------------------------
        # Остаток
        # ------------------------------------------------------

        if remainder:

            result.append(
                under_1000(
                    remainder
                )
            )

        return " ".join(
            result
        )

    # ==========================================================
    # Склонение существительных
    # ==========================================================

    def plural_form(
        self,
        number,
        one,
        few,
        many
    ):

        number %= 100

        if 11 <= number <= 19:

            return many

        number %= 10

        if number == 1:

            return one

        if number in (2, 3, 4):

            return few

        return many

    # ==========================================================
    # Совместимость со старым названием
    # ==========================================================

    def plural_for(
        self,
        number,
        one,
        few,
        many
    ):

        return self.plural_form(
            number,
            one,
            few,
            many
        )

    # ==========================================================
    # Озвучивание текста
    # ==========================================================

    def speak(
        self,
        text: str
    ):

        if not text:

            return

        text = str(
            text
        ).strip()

        if not text:

            return

        # ======================================================
        # Подготавливаем текст
        # ======================================================

        text = self.prepare_text(
            text
        )

        if not text:

            return

        # ======================================================
        # Блокируем наложение нескольких фраз
        # ======================================================

        with self._lock:

            self.is_speaking = True

            self._stop_event.clear()

            wav_path = None

            try:

                print(
                    f"JARVIS: {text}"
                )

                # ==================================================
                # Синтез речи
                # ==================================================

                audio = self.model.apply_tts(
                    text=text,
                    speaker=self.speaker,
                    sample_rate=self.sample_rate,
                    put_accent=True,
                    put_yo=True
                )

                if audio is None:

                    print(
                        "Silero не вернул аудио."
                    )

                    return

                # ==================================================
                # Уникальный временный WAV
                # ==================================================

                temp_file = tempfile.NamedTemporaryFile(
                    suffix=".wav",
                    prefix="jarvis_",
                    delete=False
                )

                wav_path = temp_file.name

                temp_file.close()

                # ==================================================
                # Tensor -> WAV
                # ==================================================

                audio = audio.detach().cpu()

                audio = torch.clamp(
                    audio,
                    -1.0,
                    1.0
                )

                audio = (
                    audio.numpy() * 32767
                ).astype(
                    "int16"
                )

                # ==================================================
                # Запись WAV
                # ==================================================

                with wave.open(
                    wav_path,
                    "wb"
                ) as wav_file:

                    wav_file.setnchannels(
                        1
                    )

                    wav_file.setsampwidth(
                        2
                    )

                    wav_file.setframerate(
                        self.sample_rate
                    )

                    wav_file.writeframes(
                        audio.tobytes()
                    )

                # ==================================================
                # Воспроизведение
                # ==================================================

                if not self._stop_event.is_set():

                    playsound(
                        wav_path,
                        block=True
                    )

            except Exception as e:

                print(
                    f"Ошибка Silero TTS: {e}"
                )

            finally:

                self.is_speaking = False

                # ==================================================
                # Удаление временного WAV
                # ==================================================

                if wav_path:

                    try:

                        if os.path.exists(
                            wav_path
                        ):

                            os.remove(
                                wav_path
                            )

                    except OSError:

                        pass

    # ==========================================================
    # Остановка речи
    # ==========================================================

    def stop(self):

        self._stop_event.set()

        self.is_speaking = False

    # ==========================================================
    # Воспроизведение системного звука
    # ==========================================================

    def play_sound(
        self,
        sound_path: str
    ):

        if not sound_path:

            return

        # ------------------------------------------------------
        # Если передан относительный путь
        # ------------------------------------------------------

        if not os.path.isabs(
            sound_path
        ):

            sound_path = os.path.join(
                self.project_dir,
                sound_path
            )

        # ------------------------------------------------------
        # Проверяем существование
        # ------------------------------------------------------

        if not os.path.exists(
            sound_path
        ):

            print(
                f"Системный звук не найден: {sound_path}"
            )

            return

        # ------------------------------------------------------
        # Воспроизведение в отдельном потоке
        # ------------------------------------------------------

        threading.Thread(
            target=playsound,
            args=(sound_path,),
            daemon=True
        ).start()

    # ==========================================================
    # Системные звуки
    # ==========================================================

    def confirm(self):

        self.play_sound(
            os.path.join(
                self.sounds_dir,
                "confirm.wav"
            )
        )

    def activated(self):

        self.play_sound(
            os.path.join(
                self.sounds_dir,
                "activated.wav"
            )
        )

    def error(self):

        self.play_sound(
            os.path.join(
                self.sounds_dir,
                "error.wav"
            )
        )

    def notification(self):

        self.play_sound(
            os.path.join(
                self.sounds_dir,
                "notification.wav"
            )
        )

    def startup(self):

        self.play_sound(
            os.path.join(
                self.sounds_dir,
                "startup.wav"
            )
        )

    def shutdown(self):

        self.play_sound(

os.path.join(
                self.sounds_dir,
                "shutdown.wav"
            )
        )

    # ==========================================================
    # Скорость речи
    # ==========================================================

    def set_rate(
        self,
        rate: int
    ):

        # Оставляем для совместимости
        # со старой архитектурой JARVIS.

        return True

    # ==========================================================
    # Громкость речи
    # ==========================================================

    def set_volume(
        self,
        volume: float
    ):

        # Громкость регулируется Windows.
        # Метод оставлен для совместимости
        # со старой архитектурой JARVIS.

        return True
