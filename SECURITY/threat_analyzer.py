"""
threat_analyzer.py
Анализ подозрительности файлов для JARVIS Security V1.2.
"""


class ThreatAnalyzer:
    """
    Анализатор угроз JARVIS Security.

    Получает данные от FileScanner и рассчитывает
    предварительный Risk Score от 0 до 100.
    """

    # ==========================================================
    # Настройки анализа
    # ==========================================================

    SCORE_EXECUTABLE = 5
    SCORE_SCRIPT = 10
    SCORE_SYSTEM_FILE = 5
    SCORE_UNKNOWN_LOCATION = 10
    SCORE_TEMP_LOCATION = 10
    SCORE_HIDDEN_FILE = 5
    SCORE_DOUBLE_EXTENSION = 15
    SCORE_NO_EXTENSION = 3
    SCORE_MISSING_HASH = 2

    # Расширения скриптов
    SCRIPT_EXTENSIONS = {
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".com",
    }

    # Системные расширения
    SYSTEM_EXTENSIONS = {
        ".sys",
        ".dll",
    }

    # ==========================================================
    # Конструктор
    # ==========================================================

    def __init__(self, logger=None):

        self.logger = logger

    # ==========================================================
    # Анализ одного файла
    # ==========================================================

    def analyze(self, file_data):

        if not file_data:

            return None

        score = 0
        reasons = []

        path = str(
            file_data.get(
                "path",
                ""
            )
        )

        name = str(
            file_data.get(
                "name",
                ""
            )
        )

        extension = str(
            file_data.get(
                "extension",
                ""
            )
        ).lower()

        is_executable = bool(
            file_data.get(
                "is_executable",
                False
            )
        )

        sha256 = file_data.get(
            "sha256"
        )

        # ======================================================
        # Исполняемый файл
        # ======================================================

        if is_executable:

            score += self.SCORE_EXECUTABLE

            reasons.append(
                "Файл является исполняемым."
            )

        # ======================================================
        # Скрипт
        # ======================================================

        if extension in self.SCRIPT_EXTENSIONS:

            score += self.SCORE_SCRIPT

            reasons.append(
                "Файл является скриптом, "
                "который может выполнять команды."
            )

        # ======================================================
        # Системный файл
        # ======================================================

        if extension in self.SYSTEM_EXTENSIONS:

            score += self.SCORE_SYSTEM_FILE

            reasons.append(
                "Файл относится к системным компонентам."
            )

        # ======================================================
        # Временные каталоги
        # ======================================================

        if self.is_temp_location(path):

            score += self.SCORE_TEMP_LOCATION

            reasons.append(
                "Файл находится во временном каталоге."
            )

        # ======================================================
        # Необычное расположение
        # ======================================================

        if self.is_unknown_location(path):

            score += self.SCORE_UNKNOWN_LOCATION

            reasons.append(
                "Файл находится в необычном расположении."
            )

        # ======================================================
        # Скрытый файл
        # ======================================================

        if self.is_hidden_file(path):

            score += self.SCORE_HIDDEN_FILE


            reasons.append(
                "Файл имеет скрытые атрибуты."
            )

        # ======================================================
        # Двойное расширение
        # ======================================================

        if self.has_double_extension(name):

            score += self.SCORE_DOUBLE_EXTENSION

            reasons.append(
                "Имя файла содержит подозрительную "
                "комбинацию расширений."
            )

        # ======================================================
        # Отсутствие расширения
        # ======================================================

        if not extension:

            score += self.SCORE_NO_EXTENSION

            reasons.append(
                "У файла отсутствует расширение."
            )

        # ======================================================
        # Отсутствие SHA-256
        # ======================================================

        if not sha256:

            score += self.SCORE_MISSING_HASH

            reasons.append(
                "Не удалось получить SHA-256."
            )

        # ======================================================
        # Ограничиваем результат
        # ======================================================

        score = min(
            max(score, 0),
            100
        )

        level = self.get_risk_level(
            score
        )

        result = {

            "path":
                path,

            "name":
                name,

            "score":
                score,

            "level":
                level,

            "reasons":
                reasons,

            "sha256":
                sha256,

        }

        self.log(
            f"Анализ: {name} | "
            f"Risk Score: {score} | "
            f"Уровень: {level}"
        )

        return result

    # ==========================================================
    # Анализ списка файлов
    # ==========================================================

    def analyze_files(self, files):

        if not files:

            return []

        results = []

        for file_data in files:

            result = self.analyze(
                file_data
            )

            if result:

                results.append(
                    result
                )

        return results

    # ==========================================================
    # Определение уровня риска
    # ==========================================================

    def get_risk_level(self, score):

        if score >= 70:

            return "ВЫСОКИЙ"

        if score >= 40:

            return "ПОДОЗРИТЕЛЬНЫЙ"

        if score >= 20:

            return "СРЕДНИЙ"

        return "НИЗКИЙ"

    # ==========================================================
    # Проверка временного каталога
    # ==========================================================

    def is_temp_location(self, path):

        normalized = path.lower().replace(
            "\\",
            "/"
        )

        temp_locations = [
            "/temp/",
            "/tmp/",
            "/appdata/local/temp/",
        ]

        for location in temp_locations:

            if location in normalized:

                return True

        return False

    # ==========================================================
    # Проверка необычного расположения
    # ==========================================================

    def is_unknown_location(self, path):

        normalized = path.lower().replace(
            "\\",
            "/"
        )

        known_locations = [
            "/windows/",
            "/program files/",
            "/program files (x86)/",
            "/users/",
            "/appdata/",
        ]

        for location in known_locations:

            if location in normalized:

                return False

        return True

    # ==========================================================
    # Проверка скрытого файла
    # ==========================================================

    def is_hidden_file(self, path):

        try:

            import os

            filename = os.path.basename(
                path
            )

            # В Windows основная проверка
            # скрытого атрибута выполняется
            # через системные атрибуты.

            if filename.startswith("."):

                return True

            return False

        except Exception:

            return False

    # ==========================================================
    # Проверка двойного расширения
    # ==========================================================

    def has_double_extension(self, filename):

        if not filename:

            return False

        parts = filename.lower().split(
            "."
        )

        if len(parts) < 3:

            return False

        # Например:
        # document.pdf.exe
        # photo.jpg.scr

        dangerous_extensions = {
            ".exe",
            ".scr",
            ".bat",
            ".cmd",
            ".com",
            ".msi",
            ".vbs",
            ".ps1",
            ".js",
        }

        last_extension = (
            "."
            + parts[-1]
        )

        if last_extension not in dangerous_extensions:

            return False

        return True

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )

        else:

            print(
                f"[SECURITY] {message}"
            )