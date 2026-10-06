"""
risk_engine.py

JARVIS Security Core V3.1
Движок оценки риска.

Назначение:
- принимает события от Security Core / Correlation Engine;
- извлекает индикаторы угроз;
- рассчитывает Risk Score;
- определяет уровень риска;
- формирует причины и объяснение;
- хранит последний результат.
"""

from __future__ import annotations


class RiskEngine:

    # ==========================================================
    # БАЗОВЫЕ ВЕСА ИНДИКАТОРОВ
    # ==========================================================

    DEFAULT_WEIGHTS = {

        "suspicious_file": 20,

        "suspicious_process": 25,

        "network_connection": 10,

        "external_connection": 15,

        "startup_change": 20,

        "persistence": 25,

        "usb_device": 10,

        "malware": 50,

        "trojan": 60,

        "ransomware": 80,

        "critical": 80,

        "high": 50,

        "medium": 25,

        "suspicious": 20,

    }

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None,
        weights=None
    ):

        self.logger = logger

        self.weights = dict(
            self.DEFAULT_WEIGHTS
        )

        if isinstance(
            weights,
            dict
        ):

            self.weights.update(
                weights
            )

        self.last_result = {

            "score": 0,

            "level": "LOW",

            "reasons": [],

            "events": 0,

            "unique_indicators": 0,

        }

        self.log(
            "Risk Engine V3.1 инициализирован."
        )

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

                return

            if callable(
                self.logger
            ):

                self.logger(
                    message
                )

                return

        print(
            f"[SECURITY] {message}"
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ВЕСА
    # ==========================================================

    def get_weight(
        self,
        indicator
    ):

        if not indicator:

            return 0

        indicator = str(
            indicator
        ).lower().strip()

        return self.weights.get(
            indicator,
            0
        )

    # ==========================================================
    # ОПРЕДЕЛЕНИЕ УРОВНЯ РИСКА
    # ==========================================================

    def get_level(
        self,
        score
    ):

        try:

            score = int(
                score
            )

        except (
            TypeError,
            ValueError
        ):

            score = 0

        score = max(
            0,
            min(
                100,
                score
            )
        )

        if score >= 70:

            return "CRITICAL"

        if score >= 40:

            return "HIGH"

        if score >= 20:

            return "MEDIUM"

        return "LOW"

    # ==========================================================
    # ИЗВЛЕЧЕНИЕ ИНДИКАТОРОВ
    # ==========================================================

    def _extract_indicators(
        self,
        event
    ):

        indicators = []

        if not isinstance(
            event,
            dict
        ):

            return indicators

        # ------------------------------------------------------
        # Boolean-индикаторы
        # ------------------------------------------------------


        for indicator in self.weights:

            value = event.get(
                indicator
            )

            if value is True:

                indicators.append(
                    indicator
                )

        # ------------------------------------------------------
        # Тип события
        # ------------------------------------------------------

        event_type = event.get(
            "type"
        )

        if isinstance(
            event_type,
            str
        ):

            normalized_type = (
                event_type
                .lower()
                .strip()
            )

            if normalized_type in self.weights:

                indicators.append(
                    normalized_type
                )

        # ------------------------------------------------------
        # Уровень события
        # ------------------------------------------------------

        level = event.get(
            "level"
        )

        if isinstance(
            level,
            str
        ):

            normalized_level = (
                level
                .lower()
                .strip()
            )

            if normalized_level in self.weights:

                indicators.append(
                    normalized_level
                )

        # ------------------------------------------------------
        # Список indicators
        # ------------------------------------------------------

        event_indicators = event.get(
            "indicators"
        )

        if isinstance(
            event_indicators,
            (list, tuple, set)
        ):

            for indicator in event_indicators:

                if not isinstance(
                    indicator,
                    str
                ):

                    continue

                normalized_indicator = (
                    indicator
                    .lower()
                    .strip()
                )

                if normalized_indicator in self.weights:

                    indicators.append(
                        normalized_indicator
                    )

        # ------------------------------------------------------
        # Удаление дубликатов
        # ------------------------------------------------------

        unique_indicators = []

        for indicator in indicators:

            if indicator not in unique_indicators:

                unique_indicators.append(
                    indicator
                )

        return unique_indicators

    # ==========================================================
    # ОСНОВНОЙ РАСЧЁТ RISK SCORE
    # ==========================================================

    def calculate(
        self,
        events
    ):

        # ------------------------------------------------------
        # Нормализация входных данных
        # ------------------------------------------------------

        if events is None:

            events = []

        elif isinstance(
            events,
            dict
        ):

            events = [
                events
            ]

        elif not isinstance(
            events,
            (list, tuple)
        ):

            events = []

        self.log(
            f"Начало оценки риска. "
            f"Событий: {len(events)}"
        )

        # ------------------------------------------------------
        # Начальные значения
        # ------------------------------------------------------

        score = 0

        reasons = []

        unique_indicators = []

        # ------------------------------------------------------
        # Обработка событий
        # ------------------------------------------------------

        for event in events:

            indicators = (
                self._extract_indicators(
                    event
                )
            )

            for indicator in indicators:

                # Один и тот же индикатор
                # учитывается только один раз.

                if indicator in unique_indicators:

                    continue

                unique_indicators.append(
                    indicator
                )

                weight = self.get_weight(
                    indicator
                )

                if weight <= 0:

                    continue

                score += weight

                reasons.append(
                    {
                        "indicator": indicator,
                        "weight": weight,
                    }
                )

        # ------------------------------------------------------
        # Ограничение Score
        # ------------------------------------------------------

        score = max(
            0,
            min(
                100,
                score
            )
        )

        # ------------------------------------------------------
        # Определение уровня
        # ------------------------------------------------------

        level = self.get_level(
            score
        )

        # ------------------------------------------------------
        # Сохранение результата
        # ------------------------------------------------------

        self.last_result = {

            "score": score,

            "level": level,

            "reasons": list(
                reasons
            ),

            "events": len(
                events
            ),

            "unique_indicators": len(
                unique_indicators
            ),

        }

        self.log(
            f"Оценка риска завершена. "
            f"Score: {score}, "
            f"Level: {level}"
        )

        return dict(
            self.last_result
        )

    # ==========================================================
    # СОВМЕСТИМЫЕ НАЗВАНИЯ API
    # ==========================================================

    def assess(
        self,
        events
    ):

        return self.calculate(
            events
        )

    def analyze(
        self,
        events
    ):

        return self.calculate(
            events
        )

    def evaluate(
        self,
        events
    ):

        return self.calculate(
            events
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНЕГО РЕЗУЛЬТАТА
    # ==========================================================

    def get_last_result(
        self
    ):

        return dict(
            self.last_result
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ SCORE
    # ==========================================================

    def get_score(
        self
    ):

        return self.last_result.get(
            "score",
            0
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ УРОВНЯ
    # ==========================================================

    def get_current_level(
        self
    ):

        return self.last_result.get(
            "level",
            "LOW"
        )

    # ==========================================================
    # ОБЪЯСНЕНИЕ РИСКА
    # ==========================================================

    def get_explanation(
        self
    ):

        score = self.get_score()

        level = self.get_current_level()

        reasons = self.last_result.get(
            "reasons",
            []
        )

        if not reasons:

            return (
                f"Risk Score: {score}/100. "
                f"Уровень: {level}. "
                f"Значимых индикаторов не обнаружено."
            )

        explanation_parts = []

        for reason in reasons:

            indicator = reason.get(
                "indicator",
                "unknown"
            )

            weight = reason.get(
                "weight",
                0
            )

            explanation_parts.append(


f"{indicator} (+{weight})"
            )

        return (
            f"Risk Score: {score}/100. "
            f"Уровень: {level}. "
            f"Индикаторы: "
            f"{', '.join(explanation_parts)}."
        )

    # ==========================================================
    # СБРОС
    # ==========================================================

    def reset(
        self
    ):

        self.last_result = {

            "score": 0,

            "level": "LOW",

            "reasons": [],

            "events": 0,

            "unique_indicators": 0,

        }

        self.log(
            "Risk Engine сброшен."
        )

        return self.get_last_result()
