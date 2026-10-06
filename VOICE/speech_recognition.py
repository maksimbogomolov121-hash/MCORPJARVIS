"""
speech_recognition.py
Распознавание речи JARVIS через Vosk.
"""

import json
import queue

import sounddevice as sd
from vosk import Model, KaldiRecognizer


class SpeechRecognition:
    """
    Модуль распознавания речи JARVIS.
    """

    def __init__(
        self,
        model_path="Models/vosk-model-small-ru-0.22",
        samplerate=16000,
    ):
        self.model = Model(model_path)

        self.samplerate = samplerate
        self.audio_queue = queue.Queue()

        self.running = False
        self.device = None

        self._find_microphone()

        self.recognizer = KaldiRecognizer(
            self.model,
            self.samplerate
        )

    # ======================================================
    # ПОИСК МИКРОФОНА
    # ======================================================

    def _find_microphone(self):

        try:

            devices = sd.query_devices()

            # Ищем Realtek с входными каналами.
            for index, device in enumerate(devices):

                name = device["name"].lower()

                if (
                    device["max_input_channels"] > 0
                    and "realtek" in name
                ):

                    self.device = index

                    print(
                        f"Микрофон: {device['name']}"
                    )

                    print(
                        f"Устройство №{index}"
                    )

                    print(
                        f"Частота устройства: "
                        f"{device['default_samplerate']} Гц"
                    )

                    return

            # Если Realtek не найден —
            # используем микрофон Windows по умолчанию.

            default_device = sd.default.device[0]

            if default_device is not None:
                if default_device >= 0:

                    self.device = default_device

                    device = sd.query_devices(
                        default_device
                    )

                    print(
                        f"Микрофон по умолчанию: "
                        f"{device['name']}"
                    )

                    print(
                        f"Устройство №{default_device}"
                    )

                    return

            print(
                "Микрофон не найден."
            )

        except Exception as e:

            print(
                f"Ошибка поиска микрофона: {e}"
            )

            self.device = None

    # ======================================================
    # CALLBACK
    # ======================================================

    def _callback(
        self,
        indata,
        frames,
        time,
        status
    ):

        if status:

            print(
                f"Ошибка аудиопотока: {status}"
            )

        self.audio_queue.put(
            bytes(indata)
        )

    # ======================================================
    # LISTEN
    # ======================================================

    def listen(self):

        if not self.running:
            return None

        if self.device is None:

            print(
                "Микрофон не найден."
            )

            self.running = False

            return None

        try:

            print(
                "Слушаю..."
            )

            # ВАЖНО:
            # Используем InputStream, а не RawInputStream.
            #
            # Это позволяет sounddevice самостоятельно
            # работать с обычным float32-потоком.

            with sd.InputStream(
                samplerate=self.samplerate,
                blocksize=4000,
                device=self.device,
                channels=1,
                dtype="int16",
                callback=self._callback,
            ):

                while self.running:

                    data = self.audio_queue.get()

                    if self.recognizer.AcceptWaveform(


data
                    ):

                        result = json.loads(
                            self.recognizer.Result()
                        )

                        text = result.get(
                            "text",
                            ""
                        ).strip().lower()

                        if text:

                            print(
                                f"Распознано: {text}"
                            )

                            return text

        except sd.PortAudioError as e:

            print()
            print(
                "========================================"
            )
            print(
                "ОШИБКА МИКРОФОНА"
            )
            print(
                "========================================"
            )
            print(e)
            print()
            print(
                f"Использовалось устройство №"
                f"{self.device}"
            )
            print(
                "JARVIS остановил распознавание речи."
            )
            print(
                "========================================"
            )

            self.running = False

            return None

        except Exception as e:

            print()
            print(
                "========================================"
            )
            print(
                "ОШИБКА РАСПОЗНАВАНИЯ РЕЧИ"
            )
            print(
                "========================================"
            )
            print(e)
            print(
                "========================================"
            )

            self.running = False

            return None

        return None

    # ======================================================
    # START
    # ======================================================

    def start(self):

        self.running = True

    # ======================================================
    # STOP
    # ======================================================

    def stop(self):

        self.running = False

    # ======================================================
    # RUN
    # ======================================================

    def run(self, callback):

        self.start()

        while self.running:

            text = self.listen()

            if text:

                callback(text)