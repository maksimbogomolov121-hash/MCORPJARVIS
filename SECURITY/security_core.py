"""
security_core.py

Главный координатор JARVIS Security Core.

V1:
- сканирование файлов;
- анализ угроз;
- сканирование процессов;
- сканирование автозагрузки;
- сканирование USB;
- карантин;
- отчёты;
- журналирование.

V2:
- Behavior Engine;
- мониторинг поведения процессов;
- мониторинг поведения автозагрузки.

V2.3:
- единая интеграция всех компонентов;
- единое состояние Security Core;
- управление поведенческим мониторингом.
"""

import os


from SECURITY.scanner import (
    FileScanner
)

from SECURITY.threat_analyzer import (
    ThreatAnalyzer
)

from SECURITY.process_scanner import (
    ProcessScanner
)

from SECURITY.startup_scanner import (
    StartupScanner
)

from SECURITY.usb_scanner import (
    USBScanner
)

from SECURITY.quarantine import (
    QuarantineManager
)

from SECURITY.security_report import (
    SecurityReport
)

from SECURITY.security_logger import (
    SecurityLogger
)

from SECURITY.behavior_engine import (
    BehaviorEngine
)

from SECURITY.process_behavior import (
    ProcessBehaviorMonitor
)

from SECURITY.startup_behavior import (
    StartupBehaviorMonitor
)


class SecurityCore:

    def __init__(
        self,
        logger=None
    ):

        # ======================================================
        # Security Logger
        # ======================================================

        if logger is None:

            self.security_logger = (
                SecurityLogger()
            )

            self.logger = (
                self.security_logger
            )

        else:

            self.logger = logger

            self.security_logger = None

        # ======================================================
        # V1 COMPONENTS
        # ======================================================

        self.scanner = FileScanner(
            self.logger
        )

        self.threat_analyzer = (
            ThreatAnalyzer(
                self.logger
            )
        )

        self.process_scanner = (
            ProcessScanner(
                self.logger
            )
        )

        self.startup_scanner = (
            StartupScanner(
                self.logger
            )
        )

        self.usb_scanner = (
            USBScanner(
                self.logger
            )
        )

        self.quarantine_manager = (
            QuarantineManager(
                self.logger
            )
        )

        self.report_manager = (
            SecurityReport(
                self.logger
            )
        )

        # ======================================================
        # V2 BEHAVIOR ENGINE
        # ======================================================

        self.behavior_engine = (
            BehaviorEngine()
        )

        # ======================================================
        # V2.1 PROCESS BEHAVIOR
        # ======================================================

        self.process_behavior = (
            ProcessBehaviorMonitor(
                self.process_scanner,
                self.behavior_engine,
                self.logger
            )
        )

        # ======================================================
        # V2.2 STARTUP BEHAVIOR
        # ======================================================

        self.startup_behavior = (
            StartupBehaviorMonitor(
                self.startup_scanner,
                self.behavior_engine,
                self.logger
            )
        )

        # ======================================================
        # СОСТОЯНИЕ ПОСЛЕДНИХ РЕЗУЛЬТАТОВ
        # ======================================================

        self.last_scan_path = None

        self.last_scan_results = []

        self.last_analysis_results = []

        self.last_process_results = []

        self.last_startup_results = []

        self.last_usb_results = []

        # ======================================================
        # Состояние поведенческого мониторинга
        # ======================================================

        self.behavior_monitoring = False

        # ======================================================
        # Запуск
        # ======================================================

        self.log(
            "Security Core V2.3 инициализирован."
        )

    # ==========================================================
    # СКАНИРОВАНИЕ ФАЙЛОВ
    # ==========================================================

    def scan(
        self,
        path
    ):

        if not path:

            self.log(
                "Путь для сканирования не указан."
            )

            return None

        path = os.path.abspath(
            os.path.expanduser(
                path
            )
        )

        if not os.path.exists(
            path
        ):

            self.log(
                f"Путь не существует: {path}"
            )

            return None

        self.log(
            f"Начало сканирования: {path}"
        )

        scan_results = (
            self.scanner.scan(
                path
            )
        )

        if scan_results is None:

            self.log(
                "Сканирование не выполнено."
            )

            return None

        if isinstance(
            scan_results,
            dict
        ):

            scan_results = [
                scan_results
            ]

        scan_results = list(
            scan_results
        )

        # ======================================================
        # Сохраняем результаты сканирования
        # ======================================================

        self.last_scan_path = path

        self.last_scan_results = (
            scan_results
        )

        # ======================================================
        # Анализ угроз
        # ======================================================

        analysis_results = (
            self.threat_analyzer.analyze_files(
                scan_results
            )
        )

        if analysis_results is None:

            analysis_results = []

        self.last_analysis_results = list(
            analysis_results
        )

        self.log(
            f"Сканирование завершено: "
            f"{len(scan_results)} файлов."
        )

        return list(
            self.last_analysis_results
        )

    # ==========================================================
    # СКАНИРОВАНИЕ ОДНОГО ФАЙЛА
    # ==========================================================

    def scan_file(
        self,
        path
    ):

        if not path:

            return None

        path = os.path.abspath(
            os.path.expanduser(
                path
            )
        )

        if not os.path.exists(
            path
        ):

            self.log(
                f"Файл не существует: {path}"
            )

            return None

        self.log(
            f"Проверка файла: {path}"
        )

        scan_result = (
            self.scanner.scan_file(
                path
            )
        )

        if not scan_result:

            return None

        analysis_result = (
            self.threat_analyzer.analyze(
                scan_result
            )
        )

        if analysis_result:

            self.last_scan_path = path

            self.last_scan_results = [
                scan_result
            ]

            self.last_analysis_results = [
                analysis_result
            ]

        return analysis_result

    # ==========================================================
    # СКАНИРОВАНИЕ ПРОЦЕССОВ
    # ==========================================================

    def scan_processes(self):

        self.log(
            "Начало сканирования процессов."
        )

        results = (
            self.process_scanner.scan()
        )

        if results is None:

            results = []


        if isinstance(
            results,
            dict
        ):

            results = [
                results
            ]

        self.last_process_results = list(
            results
        )

        self.log(
            "Сканирование процессов завершено. "
            f"Найдено процессов: {len(results)}"
        )

        return list(
            results
        )

    # ==========================================================
    # СКАНИРОВАНИЕ АВТОЗАГРУЗКИ
    # ==========================================================

    def scan_startup(self):

        self.log(
            "Начало сканирования автозагрузки."
        )

        results = (
            self.startup_scanner.scan()
        )

        if results is None:

            results = []

        if isinstance(
            results,
            dict
        ):

            results = [
                results
            ]

        self.last_startup_results = list(
            results
        )

        self.log(
            "Сканирование автозагрузки завершено. "
            f"Найдено объектов: {len(results)}"
        )

        return list(
            results
        )

    # ==========================================================
    # СКАНИРОВАНИЕ USB
    # ==========================================================

    def scan_usb(self):

        self.log(
            "Начало сканирования USB."
        )

        results = (
            self.usb_scanner.scan()
        )

        if results is None:

            results = []

        if isinstance(
            results,
            dict
        ):

            results = [
                results
            ]

        self.last_usb_results = list(
            results
        )

        self.log(
            "Сканирование USB завершено. "
            f"Найдено накопителей: {len(results)}"
        )

        return list(
            results
        )

    # ==========================================================
    # ПОВЕДЕНЧЕСКИЙ АНАЛИЗ ПРОЦЕССОВ
    # ==========================================================

    def check_process_behavior(self):

        self.log(
            "Проверка поведения процессов."
        )

        result = (
            self.process_behavior.check()
        )

        return result

    # ==========================================================
    # ПОВЕДЕНЧЕСКИЙ АНАЛИЗ АВТОЗАГРУЗКИ
    # ==========================================================

    def check_startup_behavior(self):

        self.log(
            "Проверка поведения автозагрузки."
        )

        result = (
            self.startup_behavior.check()
        )

        return result

    # ==========================================================
    # ЕДИНАЯ ПРОВЕРКА ПОВЕДЕНИЯ
    # ==========================================================

    def check_behavior(self):

        self.log(
            "Запуск единой проверки поведения."
        )

        process_result = (
            self.check_process_behavior()
        )

        startup_result = (
            self.check_startup_behavior()
        )

        return {

            "processes":
                process_result,

            "startup":
                startup_result

        }

    # ==========================================================
    # ЗАПУСК ПОВЕДЕНЧЕСКОГО МОНИТОРИНГА
    # ==========================================================

    def start_behavior_monitoring(
        self,
        interval=2,
        iterations=None
    ):

        if self.behavior_monitoring:

            self.log(
                "Поведенческий мониторинг уже запущен."
            )

            return False

        self.behavior_monitoring = True

        self.log(
            "Запуск поведенческого мониторинга."
        )

        try:

            self.process_behavior.initialize()

            self.startup_behavior.initialize()

            self.process_behavior.start(
                interval=interval,


    iterations=iterations
            )

        except Exception as e:

            self.log(
                f"Ошибка поведенческого мониторинга: {e}"
            )

        finally:

            self.behavior_monitoring = False

        self.log(
            "Поведенческий мониторинг остановлен."
        )

        return True

    # ==========================================================
    # ОСТАНОВКА ПОВЕДЕНЧЕСКОГО МОНИТОРИНГА
    # ==========================================================

    def stop_behavior_monitoring(self):

        self.process_behavior.stop()

        self.startup_behavior.stop()

        self.behavior_monitoring = False

        self.log(
            "Запрошена остановка поведенческого мониторинга."
        )

        return True

    # ==========================================================
    # ПОЛУЧЕНИЕ СОБЫТИЙ
    # ==========================================================

    def get_behavior_events(self):

        try:

            return list(
                self.behavior_engine.get_events()
            )

        except Exception:

            return []

    # ==========================================================
    # АНАЛИЗ ОБЪЕКТА
    # ==========================================================

    def analyze_behavior_object(
        self,
        object_name
    ):

        if not object_name:

            return None

        try:

            return (
                self.behavior_engine.analyze_object(
                    object_name
                )
            )

        except Exception as e:

            self.log(
                f"Ошибка анализа поведения "
                f"{object_name}: {e}"
            )

            return None

    # ==========================================================
    # ПОДОЗРИТЕЛЬНЫЕ ФАЙЛЫ
    # ==========================================================

    def get_suspicious_files(
        self,
        minimum_score=40
    ):

        suspicious = []

        for result in (
            self.last_analysis_results
        ):

            score = result.get(
                "score",
                0
            )

            try:

                score = float(
                    score
                )

            except (
                TypeError,
                ValueError
            ):

                score = 0

            if score >= minimum_score:

                suspicious.append(
                    result
                )

        return suspicious

    # ==========================================================
    # ФАЙЛЫ ВЫСОКОГО РИСКА
    # ==========================================================

    def get_high_risk_files(self):

        high_risk = []

        for result in (
            self.last_analysis_results
        ):

            score = result.get(
                "score",
                0
            )

            try:

                score = float(
                    score
                )

            except (
                TypeError,
                ValueError
            ):

                score = 0

            if score >= 70:

                high_risk.append(
                    result
                )

        return high_risk

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(self):

        results = (
            self.last_analysis_results
        )

        statistics = {

            "total":
                len(results),

            "low":
                0,

            "medium":
                0,

            "suspicious":
                0,

            "high":
                0

        }

        for result in results:

            level = str(
                result.get(
                    "level",
                    ""
                )
            ).upper()

            if level == "НИЗКИЙ":

                statistics["low"] += 1


            elif level == "СРЕДНИЙ":

                statistics["medium"] += 1

            elif level == "ПОДОЗРИТЕЛЬНЫЙ":

                statistics["suspicious"] += 1

            elif level == "ВЫСОКИЙ":

                statistics["high"] += 1

        return statistics

    # ==========================================================
    # КАРАНТИН
    # ==========================================================

    def quarantine_file(
        self,
        file_path,
        reason="",
        score=0
    ):

        self.log(
            "Запрос на помещение файла "
            f"в карантин: {file_path}"
        )

        return (
            self.quarantine_manager.quarantine(
                file_path,
                reason,
                score
            )
        )

    # ==========================================================
    # ВОССТАНОВЛЕНИЕ ИЗ КАРАНТИНА
    # ==========================================================

    def restore_quarantined_file(
        self,
        quarantine_id
    ):

        return (
            self.quarantine_manager.restore(
                quarantine_id
            )
        )

    # ==========================================================
    # СОЗДАНИЕ ОТЧЁТА
    # ==========================================================

    def create_report(self):

        return (
            self.report_manager.create_report(
                self.last_analysis_results,
                self.last_scan_path
            )
        )

    # ==========================================================
    # СОХРАНЕНИЕ JSON
    # ==========================================================

    def save_report_json(self):

        return (
            self.report_manager.save_json()
        )

    # ==========================================================
    # СОХРАНЕНИЕ TXT
    # ==========================================================

    def save_report_txt(self):

        return (
            self.report_manager.save_txt()
        )

    # ==========================================================
    # ПОСЛЕДНИЕ РЕЗУЛЬТАТЫ
    # ==========================================================

    def get_last_results(self):

        return list(
            self.last_analysis_results
        )

    # ==========================================================
    # ПОСЛЕДНИЕ ПРОЦЕССЫ
    # ==========================================================

    def get_last_processes(self):

        return list(
            self.last_process_results
        )

    # ==========================================================
    # ПОСЛЕДНЯЯ АВТОЗАГРУЗКА
    # ==========================================================

    def get_last_startup(self):

        return list(
            self.last_startup_results
        )

    # ==========================================================
    # ПОСЛЕДНИЕ USB
    # ==========================================================

    def get_last_usb(self):

        return list(
            self.last_usb_results
        )

    # ==========================================================
    # СОСТОЯНИЕ ПОВЕДЕНИЯ
    # ==========================================================

    def get_behavior_status(self):

        return {

            "running":
                self.behavior_monitoring,

            "processes":
                self.process_behavior.get_process_count(),

            "startup":
                self.startup_behavior.get_startup_count(),

            "events":
                len(
                    self.get_behavior_events()
                )

        }

    # ==========================================================
    # ЕСТЬ ЛИ РЕЗУЛЬТАТЫ
    # ==========================================================

    def has_results(self):

        return bool(
            self.last_analysis_results
        )

    # ==========================================================
    # ОЧИСТКА РЕЗУЛЬТАТОВ
    # ==========================================================

    def clear_results(self):

        self.last_scan_path = None

        self.last_scan_results = []

        self.last_analysis_results = []

        self.last_process_results = []

        self.last_startup_results = []

        self.last_usb_results = []

        self.log(
            "Результаты Security Core очищены."
        )

    # ==========================================================
    # КРАТКАЯ СВОДКА
    # ==========================================================

    def get_summary(self):

        statistics = (
            self.get_statistics()
        )

        return {

            "path":
                self.last_scan_path,

            "files":
                statistics["total"],

            "low":
                statistics["low"],

            "medium":
                statistics["medium"],

            "suspicious":
                statistics["suspicious"],

            "high":
                statistics["high"],

            "processes":
                len(
                    self.last_process_results
                ),

            "startup":
                len(
                    self.last_startup_results
                ),

            "usb":
                len(
                    self.last_usb_results
                ),

            "quarantine":
                self.quarantine_manager.count(),

            "behavior_events":
                len(
                    self.get_behavior_events()
                ),

            "behavior_monitoring":
                self.behavior_monitoring

        }

    # ==========================================================
    # ЛОГИРОВАНИЕ
    # ==========================================================

    def log(
        self,
        message
    ):

        if self.logger:

            if hasattr(
                self.logger,
                "info"
            ):

                self.logger.info(
                    message
                )

            else:

                print(
                    f"[SECURITY] {message}"
                )

        else:

            print(
                f"[SECURITY] {message}"
            )