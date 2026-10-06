"""
security_report.py
Формирование отчётов JARVIS Security Core.

V1
"""

import json
import os
from datetime import datetime


class SecurityReport:

    def __init__(self, logger=None, reports_path=None):

        self.logger = logger

        # ======================================================
        # Папка отчётов
        # ======================================================

        if reports_path:

            self.reports_path = os.path.abspath(
                reports_path
            )

        else:

            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )

            self.reports_path = os.path.join(
                project_root,
                "SECURITY_REPORTS"
            )

        os.makedirs(
            self.reports_path,
            exist_ok=True
        )

        self.last_report = None

        self.log(
            f"Security Report готов: "
            f"{self.reports_path}"
        )

    # ==========================================================
    # Создание отчёта
    # ==========================================================

    def create_report(
        self,
        results,
        scan_path=None
    ):

        if results is None:

            results = []

        if not isinstance(results, list):

            results = [
                results
            ]

        statistics = self._get_statistics(
            results
        )

        report = {

            "created_at":
                datetime.now().isoformat(),

            "scan_path":
                scan_path,

            "statistics":
                statistics,

            "files":
                results,

        }

        self.last_report = report

        self.log(
            f"Отчёт создан. "
            f"Объектов: {len(results)}"
        )

        return report

    # ==========================================================
    # Статистика
    # ==========================================================

    def _get_statistics(self, results):

        statistics = {

            "total": len(results),

            "low": 0,

            "medium": 0,

            "suspicious": 0,

            "high": 0,

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
    # Сохранение JSON
    # ==========================================================

    def save_json(
        self,
        report=None,
        filename=None
    ):

        if report is None:

            report = self.last_report

        if not report:

            self.log(
                "Нет отчёта для сохранения."
            )

            return None

        if filename is None:

            filename = (
                "security_report_"
                + datetime.now().strftime(
                    "%Y%m%d_%H%M%S"
                )
                + ".json"
            )

        path = os.path.join(
            self.reports_path,
            filename
        )

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    report,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

            self.log(
                f"JSON-отчёт сохранён: {path}"
            )

            return path


        except Exception as e:

            self.log(
                f"Ошибка сохранения JSON-отчёта: {e}"
            )

            return None

    # ==========================================================
    # Сохранение TXT
    # ==========================================================

    def save_txt(
        self,
        report=None,
        filename=None
    ):

        if report is None:

            report = self.last_report

        if not report:

            self.log(
                "Нет отчёта для сохранения."
            )

            return None

        if filename is None:

            filename = (
                "security_report_"
                + datetime.now().strftime(
                    "%Y%m%d_%H%M%S"
                )
                + ".txt"
            )

        path = os.path.join(
            self.reports_path,
            filename
        )

        try:

            lines = []

            lines.append(
                "========================================"
            )

            lines.append(
                "        JARVIS SECURITY REPORT"
            )

            lines.append(
                "========================================"
            )

            lines.append("")

            lines.append(
                f"Дата: {report.get('created_at')}"
            )

            lines.append(
                f"Путь сканирования: "
                f"{report.get('scan_path')}"
            )

            lines.append("")

            lines.append(
                "СТАТИСТИКА"
            )

            lines.append(
                "----------------------------------------"
            )

            statistics = report.get(
                "statistics",
                {}
            )

            lines.append(
                f"Всего: "
                f"{statistics.get('total', 0)}"
            )

            lines.append(
                f"Низкий риск: "
                f"{statistics.get('low', 0)}"
            )

            lines.append(
                f"Средний риск: "
                f"{statistics.get('medium', 0)}"
            )

            lines.append(
                f"Подозрительных: "
                f"{statistics.get('suspicious', 0)}"
            )

            lines.append(
                f"Высокий риск: "
                f"{statistics.get('high', 0)}"
            )

            lines.append("")

            lines.append(
                "ОБЪЕКТЫ"
            )

            lines.append(
                "----------------------------------------"
            )

            files = report.get(
                "files",
                []
            )

            if not files:

                lines.append(
                    "Объекты не найдены."
                )

            for index, result in enumerate(
                files,
                start=1
            ):

                lines.append("")

                lines.append(
                    f"[{index}] "
                    f"{result.get('name', 'Без имени')}"
                )

                lines.append(
                    f"Путь: "
                    f"{result.get('path', 'Н/Д')}"
                )

                lines.append(
                    f"Risk Score: "
                    f"{result.get('score', 0)}"
                )

                lines.append(
                    f"Уровень: "
                    f"{result.get('level', 'Н/Д')}"
                )

                reasons = result.get(
                    "reasons",
                    []
                )

                if reasons:

                    lines.append(
                        "Причины:"
                    )

                    for reason in reasons:

                        lines.append(
                            f" - {reason}"
                        )

            lines.append("")

            lines.append(
                "========================================"
            )


            lines.append(
                "        КОНЕЦ ОТЧЁТА"
            )

            lines.append(
                "========================================"
            )

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    "\n".join(lines)
                )

            self.log(
                f"TXT-отчёт сохранён: {path}"
            )

            return path

        except Exception as e:

            self.log(
                f"Ошибка сохранения TXT-отчёта: {e}"
            )

            return None

    # ==========================================================
    # Получение последнего отчёта
    # ==========================================================

    def get_last_report(self):

        return self.last_report

    # ==========================================================
    # Получение статистики последнего отчёта
    # ==========================================================

    def get_statistics(self):

        if not self.last_report:

            return {

                "total": 0,
                "low": 0,
                "medium": 0,
                "suspicious": 0,
                "high": 0,

            }

        return dict(
            self.last_report.get(
                "statistics",
                {}
            )
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

            print(
                f"[SECURITY] {message}"
            )