"""
universal_open.py
Универсальное открытие приложений, папок и файлов JARVIS.
"""

import os
import re
import difflib
import threading
import time


class UniversalOpen:

    def __init__(self, app_commands, logger=None, speech=None):

        self.app_commands = app_commands
        self.logger = logger
        self.speech = speech

        # ======================================================
        # Состояние глубокого поиска
        # ======================================================

        self.waiting_confirmation = False
        self.pending_query = None

        self.confirmation_thread = None
        self.confirmation_stop = threading.Event()

        # ======================================================
        # Где искать в первую очередь
        # ======================================================

        self.search_locations = [

            os.path.expanduser("~/Desktop"),

            os.path.expanduser("~/Downloads"),

            os.path.expanduser("~/Documents"),

            os.path.join(
                os.environ.get("APPDATA", ""),
                "Microsoft",
                "Windows",
                "Start Menu"
            ),

            os.path.join(
                os.environ.get("PROGRAMDATA", ""),
                "Microsoft",
                "Windows",
                "Start Menu"
            ),

            r"C:\Program Files",

            r"C:\Program Files (x86)",
        ]

    # ==========================================================
    # Главный обработчик
    # ==========================================================

    def execute(self, command):

        if not command:
            return False

        query = self.extract_query(command)

        if not query:
            return False

        self.log(
            f"Universal Open: поиск '{query}'"
        )

        # ------------------------------------------------------
        # Сначала поиск среди AppCommands
        # ------------------------------------------------------

        result = self.search_app_commands(query)

        if result:

            self.log(
                f"Universal Open: найдено через AppCommands: {result}"
            )

            return self.open_path(
                result,
                query
            )

        # ------------------------------------------------------
        # Затем быстрый поиск
        # ------------------------------------------------------

        result = self.quick_search(query)

        if result:

            self.log(
                f"Universal Open: найдено: {result}"
            )

            return self.open_path(
                result,
                query
            )

        # ------------------------------------------------------
        # Ничего не найдено
        # ------------------------------------------------------

        self.pending_query = query
        self.ask_deep_search()

        return True

    # ==========================================================
    # Извлечение названия объекта
    # ==========================================================

    def extract_query(self, command):

        command = command.lower().strip()

        # Убираем активационные слова
        phrases = [

            "открой",
            "открывай",

            "запусти",
            "запуск",

            "открыть",

            "программу",
            "приложение",

            "папку",
            "файл",

            "мне",
            "пожалуйста",
        ]

        for phrase in phrases:

            command = re.sub(
                rf"\b{re.escape(phrase)}\b",
                " ",
                command
            )

        command = re.sub(
            r"\s+",
            " ",
            command
        ).strip()

        return command

    # ==========================================================
    # Поиск в AppCommands
    # ==========================================================


    def search_app_commands(self, query):

        apps = getattr(
            self.app_commands,
            "apps",
            {}
        )

        if not apps:
            return None

        query = self.normalize(query)

        # Точное совпадение
        for name, path in apps.items():

            if self.normalize(name) == query:

                return path

        # Совпадение по содержанию
        for name, path in apps.items():

            normalized_name = self.normalize(name)

            if (
                query in normalized_name
                or normalized_name in query
            ):

                return path

        # Похожее название
        names = list(apps.keys())

        normalized_names = [
            self.normalize(name)
            for name in names
        ]

        matches = difflib.get_close_matches(
            query,
            normalized_names,
            n=1,
            cutoff=0.65
        )

        if matches:

            index = normalized_names.index(
                matches[0]
            )

            return apps[
                names[index]
            ]

        return None

    # ==========================================================
    # Быстрый поиск
    # ==========================================================

    def quick_search(self, query):

        normalized_query = self.normalize(
            query
        )

        best_match = None
        best_score = 0

        for location in self.search_locations:

            if not location:
                continue

            if not os.path.exists(location):
                continue

            try:

                for root, dirs, files in os.walk(
                    location
                ):

                    # Не углубляемся слишком сильно
                    depth = root.replace(
                        location,
                        ""
                    ).count(
                        os.sep
                    )

                    if depth > 3:

                        dirs[:] = []

                        continue

                    for name in dirs + files:

                        clean_name = os.path.splitext(
                            name
                        )[0]

                        normalized_name = self.normalize(
                            clean_name
                        )

                        score = self.similarity(
                            normalized_query,
                            normalized_name
                        )

                        if score > best_score:

                            best_score = score

                            best_match = os.path.join(
                                root,
                                name
                            )

            except (PermissionError, OSError):

                continue

        # Не принимаем случайные совпадения
        if best_score >= 0.65:

            return best_match

        return None

    # ==========================================================
    # Глубокий поиск
    # ==========================================================

    def deep_search(self, query):

        self.log(
            f"Universal Open: глубокий поиск '{query}'"
        )

        normalized_query = self.normalize(
            query
        )

        best_match = None
        best_score = 0

        # Ищем начиная с корня диска
        for drive in self.get_drives():

            try:

                for root, dirs, files in os.walk(
                    drive
                ):

                    # Системные каталоги пропускаем
                    lower_root = root.lower()

                    if any(skip in lower_root for skip in [
                        r"\windows\winsxs",
                        r"\windows\system32",
                        r"\$recycle.bin",
                        r"\system volume information",
                    ]):


                        dirs[:] = []

                        continue

                    for name in dirs + files:

                        clean_name = os.path.splitext(
                            name
                        )[0]

                        normalized_name = self.normalize(
                            clean_name
                        )

                        score = self.similarity(
                            normalized_query,
                            normalized_name
                        )

                        if score > best_score:

                            best_score = score

                            best_match = os.path.join(
                                root,
                                name
                            )

            except (
                PermissionError,
                OSError
            ):

                continue

        if best_score >= 0.65:

            return best_match

        return None

    # ==========================================================
    # Спросить разрешение на глубокий поиск
    # ==========================================================

    def ask_deep_search(self):

        if self.waiting_confirmation:

            return

        self.waiting_confirmation = True

        self.confirmation_stop.clear()

        self.speak(
            "Сэр, я не нашёл объект в основных каталогах. "
            "Начать глубокий поиск?"
        )

        self.confirmation_thread = threading.Thread(
            target=self.confirmation_reminder,
            daemon=True
        )

        self.confirmation_thread.start()

    # ==========================================================
    # Напоминание каждую минуту
    # ==========================================================

    def confirmation_reminder(self):

        while not self.confirmation_stop.wait(
            60
        ):

            if not self.waiting_confirmation:

                break

            self.speak(
                "Сэр, я всё ещё ожидаю подтверждения "
                "на глубокий поиск."
            )

    # ==========================================================
    # Ответ на подтверждение
    # ==========================================================

    def handle_confirmation(self, command):

        if not self.waiting_confirmation:

            return False

        command = command.lower().strip()

        # ------------------------------------------------------
        # Да
        # ------------------------------------------------------

        if any(word in command for word in [
            "да",
            "начинай",
            "начать",
            "запускай",
            "подтверждаю",
            "ищи",
            "давай"
        ]):

            query = self.pending_query

            self.finish_confirmation()

            self.speak(
                "Начинаю глубокий поиск."
            )

            threading.Thread(
                target=self.run_deep_search,
                args=(query,),
                daemon=True
            ).start()

            return True

        # ------------------------------------------------------
        # Нет
        # ------------------------------------------------------

        if any(word in command for word in [
            "нет",
            "отмена",
            "отменяю",
            "не надо",
            "не нужно"
        ]):

            self.finish_confirmation()

            self.speak(
                "Глубокий поиск отменён."
            )

            return True

        return False

    # ==========================================================
    # Запуск глубокого поиска
    # ==========================================================

    def run_deep_search(self, query):

        result = self.deep_search(
            query
        )

        if result:

            self.log(
                f"Universal Open: глубокий поиск нашёл {result}"
            )

            self.speak(


        "Объект найден. Открываю."
            )

            self.open_path(
                result,
                query
            )

        else:

            self.speak(
                "К сожалению, я не смог найти этот объект "
                "на компьютере."
            )

    # ==========================================================
    # Завершение ожидания
    # ==========================================================

    def finish_confirmation(self):

        self.waiting_confirmation = False

        self.pending_query = None

        self.confirmation_stop.set()

    # ==========================================================
    # Открытие найденного пути
    # ==========================================================

    def open_path(self, path, name):

        try:

            if not path:

                return False

            # Специальные команды AppCommands
            if isinstance(path, str):

                if path == "desktop":

                    path = os.path.expanduser(
                        "~/Desktop"
                    )

                elif path == "downloads":

                    path = os.path.expanduser(
                        "~/Downloads"
                    )

                elif path.startswith(
                    "start "
                ):

                    os.system(
                        path
                    )

                    return True

                elif path == (
                    "explorer.exe shell:MyComputerFolder"
                ):

                    os.system(
                        path
                    )

                    return True

            if os.path.exists(path):

                os.startfile(path)

                return True

            # На случай специальных Windows-команд
            os.system(
                path
            )

            return True

        except Exception as e:

            self.log(
                f"Universal Open: ошибка открытия {name}: {e}"
            )

            return False

    # ==========================================================
    # Нормализация
    # ==========================================================

    def normalize(self, text):

        text = str(text).lower().strip()

        # Убираем расширения
        text = re.sub(
            r"\.(exe|lnk|bat|cmd|url|com)$",
            "",
            text
        )

        # Убираем пробелы и символы
        text = re.sub(
            r"[^a-zа-яё0-9]",
            "",
            text
        )

        return text

    # ==========================================================
    # Сравнение похожести
    # ==========================================================

    def similarity(self, first, second):

        first = self.normalize(first)
        second = self.normalize(second)

        if not first or not second:

            return 0

        if first == second:

            return 1.0

        if first in second:

            return 0.90

        if second in first:

            return 0.85

        return difflib.SequenceMatcher(
            None,
            first,
            second
        ).ratio()

    # ==========================================================
    # Получение дисков
    # ==========================================================

    def get_drives(self):

        drives = []

        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":

            drive = f"{letter}:\\"

            if os.path.exists(drive):

                drives.append(drive)

        return drives

    # ==========================================================
    # Озвучивание
    # ==========================================================

    def speak(self, text):

        if self.speech:

            try:

                self.speech.speak(
                    text
                )

            except Exception as e:

                self.log(


       f"Universal Open: ошибка речи: {e}"
                )

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