"""
security_pipeline.py
JARVIS Security Core V4.0

Единый Pipeline анализа Security Core.

Назначение:
- принимает данные от компонентов Security Core V3;
- запускает последовательный анализ;
- передаёт данные между Detection / IOC / Correlation / Threat Chain / Risk;
- формирует единый результат анализа;
- хранит последний результат;
- предоставляет статистику и краткую сводку.

ВАЖНО:
V4.0 НЕ принимает решения о блокировке.
V4.0 НЕ выполняет автоматические реакции.
V4.0 НЕ останавливает процессы.
V4.0 НЕ удаляет файлы.
V4.0 НЕ изменяет систему.

Эти полномочия будут проектироваться отдельно перед V4.1/V4.2.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class SecurityPipeline:
    """
    Главный аналитический pipeline Security Core V4.0.

    Pipeline объединяет результаты компонентов V3:

        Event
          ↓
        DetectionEngine
          ↓
        IOCEngine
          ↓
        CorrelationEngine
          ↓
        ThreatChain
          ↓
        RiskEngine
          ↓
        Unified Result
    """

    VERSION = "4.0"

    def __init__(
        self,
        detection_engine=None,
        ioc_engine=None,
        correlation_engine=None,
        threat_chain=None,
        risk_engine=None,
        logger=None,
    ):
        self.detection_engine = detection_engine
        self.ioc_engine = ioc_engine
        self.correlation_engine = correlation_engine
        self.threat_chain = threat_chain
        self.risk_engine = risk_engine
        self.logger = logger

        self.last_input_events: List[Dict[str, Any]] = []
        self.last_detections: List[Any] = []
        self.last_ioc_matches: List[Any] = []
        self.last_correlations: List[Any] = []
        self.last_threat_chains: List[Any] = []

        self.last_risk_result: Dict[str, Any] = {
            "score": 0,
            "level": "LOW",
            "reasons": [],
            "events": 0,
            "unique_indicators": 0,
        }

        self.last_result: Dict[str, Any] = {}

        self.running = False
        self.last_run_time: Optional[str] = None

        self.log(
            "Security Pipeline V4.0 инициализирован."
        )

    # ==========================================================
    # ЛОГИРОВАНИЕ
    # ==========================================================

    def log(self, message: str):
        """
        Универсальное логирование.
        """

        if self.logger is not None:

            if hasattr(self.logger, "info"):

                self.logger.info(message)
                return

            if hasattr(self.logger, "log"):

                self.logger.log(message)
                return

        print(
            f"[SECURITY PIPELINE] {message}"
        )

    # ==========================================================
    # НОРМАЛИЗАЦИЯ ДАННЫХ
    # ==========================================================

    @staticmethod
    def _normalize_events(
        events: Any
    ) -> List[Dict[str, Any]]:
        """
        Приводит входные данные к списку событий.
        """

        if events is None:
            return []

        if isinstance(events, dict):
            return [dict(events)]

        if isinstance(events, (list, tuple)):

            normalized = []

            for item in events:

                if isinstance(item, dict):

                    normalized.append(
                        dict(item)
                    )

                else:

                    normalized.append(
                        {
                            "value": item
                        }
                    )

            return normalized

        return [
            {
                "value": events
            }
        ]

    # ==========================================================
    # ПРОВЕРКА КОМПОНЕНТОВ
    # ==========================================================


    def get_component_status(self) -> Dict[str, bool]:
        """
        Возвращает состояние подключённых компонентов.
        """

        return {
            "detection_engine":
                self.detection_engine is not None,

            "ioc_engine":
                self.ioc_engine is not None,

            "correlation_engine":
                self.correlation_engine is not None,

            "threat_chain":
                self.threat_chain is not None,

            "risk_engine":
                self.risk_engine is not None,
        }

    # ==========================================================
    # ПОЛНЫЙ PIPELINE
    # ==========================================================

    def run(
        self,
        events: Any
    ) -> Dict[str, Any]:
        """
        Запускает полный аналитический pipeline.

        Никаких действий над системой здесь нет.
        """

        self.running = True

        start_time = datetime.now().isoformat()

        self.log(
            "Запуск Security Pipeline V4.0."
        )

        normalized_events = (
            self._normalize_events(events)
        )

        self.last_input_events = list(
            normalized_events
        )

        self.log(
            f"Получено событий: "
            f"{len(normalized_events)}"
        )

        try:

            detections = (
                self._run_detection(
                    normalized_events
                )
            )

            ioc_matches = (
                self._run_ioc(
                    normalized_events,
                    detections
                )
            )

            correlations = (
                self._run_correlation(
                    normalized_events,
                    detections,
                    ioc_matches
                )
            )

            threat_chains = (
                self._run_threat_chain(
                    normalized_events,
                    detections,
                    correlations
                )
            )

            risk_result = (
                self._run_risk(
                    normalized_events,
                    detections,
                    correlations,
                    threat_chains,
                    ioc_matches
                )
            )

            result = (
                self._build_result(
                    normalized_events,
                    detections,
                    ioc_matches,
                    correlations,
                    threat_chains,
                    risk_result,
                    start_time
                )
            )

            self.last_result = result

            self.last_run_time = (
                datetime.now().isoformat()
            )

            self.log(
                "Security Pipeline V4.0 "
                "завершил анализ."
            )

            return dict(
                self.last_result
            )

        except Exception as error:

            self.log(
                f"Ошибка Security Pipeline: "
                f"{error}"
            )

            error_result = (
                self._build_error_result(
                    normalized_events,
                    start_time,
                    error
                )
            )

            self.last_result = error_result

            return dict(
                error_result
            )

        finally:

            self.running = False

    # ==========================================================
    # DETECTION ENGINE
    # ==========================================================

    def _run_detection(
        self,
        events: List[Dict[str, Any]]
    ) -> List[Any]:
        """
        Передаёт события в DetectionEngine.
        """

        self.log(
            "Этап 1: Detection Engine."
        )

        if self.detection_engine is None:

            self.log(
                "Detection Engine не подключён."
            )


            self.last_detections = []

            return []

        results = []

        for event in events:

            try:

                if hasattr(
                    self.detection_engine,
                    "process_event"
                ):

                    detected = (
                        self.detection_engine.process_event(
                            event,
                            source="SECURITY_PIPELINE"
                        )
                    )

                elif hasattr(
                    self.detection_engine,
                    "detect"
                ):

                    detected = (
                        self.detection_engine.detect(
                            event
                        )
                    )

                elif hasattr(
                    self.detection_engine,
                    "process"
                ):

                    detected = (
                        self.detection_engine.process(
                            event
                        )
                    )

                else:

                    detected = None

                if detected is None:
                    continue

                if isinstance(
                    detected,
                    list
                ):

                    results.extend(
                        detected
                    )

                else:

                    results.append(
                        detected
                    )

            except Exception as error:

                self.log(
                    f"Ошибка Detection Engine: "
                    f"{error}"
                )

        self.last_detections = list(
            results
        )

        self.log(
            f"Detection Engine завершён. "
            f"Обнаружений: {len(results)}"
        )

        return list(results)

    # ==========================================================
    # IOC ENGINE
    # ==========================================================

    def _run_ioc(
        self,
        events: List[Dict[str, Any]],
        detections: List[Any]
    ) -> List[Any]:
        """
        Проверяет события на IOC.
        """

        self.log(
            "Этап 2: IOC Engine."
        )

        if self.ioc_engine is None:

            self.log(
                "IOC Engine не подключён."
            )

            self.last_ioc_matches = []

            return []

        matches = []

        for event in events:

            try:

                if hasattr(
                    self.ioc_engine,
                    "match_event"
                ):

                    result = (
                        self.ioc_engine.match_event(
                            event
                        )
                    )

                elif hasattr(
                    self.ioc_engine,
                    "check_event"
                ):

                    result = (
                        self.ioc_engine.check_event(
                            event
                        )
                    )

                elif hasattr(
                    self.ioc_engine,
                    "match"
                ):

                    result = (
                        self.ioc_engine.match(
                            event
                        )
                    )

                else:

                    result = []

                if result is None:
                    continue

                if isinstance(
                    result,
                    list
                ):

                    matches.extend(
                        result
                    )

                else:

                    matches.append(
                        result
                    )

            except Exception as error:

                self.log(
                    f"Ошибка IOC Engine: "
                    f"{error}"
                )

        self.last_ioc_matches = list(


                   matches
        )

        self.log(
            f"IOC Engine завершён. "
            f"Совпадений: {len(matches)}"
        )

        return list(matches)

    # ==========================================================
    # CORRELATION ENGINE
    # ==========================================================

    def _run_correlation(
        self,
        events: List[Dict[str, Any]],
        detections: List[Any],
        ioc_matches: List[Any]
    ) -> List[Any]:
        """
        Объединяет связанные события.
        """

        self.log(
            "Этап 3: Correlation Engine."
        )

        if self.correlation_engine is None:

            self.log(
                "Correlation Engine "
                "не подключён."
            )

            self.last_correlations = []

            return []

        correlation_input = []

        correlation_input.extend(
            events
        )

        correlation_input.extend(
            self._convert_to_events(
                detections
            )
        )

        correlation_input.extend(
            self._convert_to_events(
                ioc_matches
            )
        )

        try:

            if hasattr(
                self.correlation_engine,
                "correlate"
            ):

                result = (
                    self.correlation_engine.correlate(
                        correlation_input
                    )
                )

            elif hasattr(
                self.correlation_engine,
                "process"
            ):

                result = (
                    self.correlation_engine.process(
                        correlation_input
                    )
                )

            elif hasattr(
                self.correlation_engine,
                "run"
            ):

                result = (
                    self.correlation_engine.run(
                        correlation_input
                    )
                )

            else:

                result = []

        except Exception as error:

            self.log(
                f"Ошибка Correlation Engine: "
                f"{error}"
            )

            result = []

        if result is None:

            result = []

        if not isinstance(
            result,
            list
        ):

            result = [result]

        self.last_correlations = list(
            result
        )

        self.log(
            f"Correlation Engine завершён. "
            f"Связей: {len(result)}"
        )

        return list(result)

    # ==========================================================
    # THREAT CHAIN
    # ==========================================================

    def _run_threat_chain(
        self,
        events: List[Dict[str, Any]],
        detections: List[Any],
        correlations: List[Any]
    ) -> List[Any]:
        """
        Строит цепочки угроз.
        """

        self.log(
            "Этап 4: Threat Chain."
        )

        if self.threat_chain is None:

            self.log(
                "Threat Chain не подключён."
            )

            self.last_threat_chains = []

            return []

        chain_input = []

        chain_input.extend(
            events
        )

        chain_input.extend(
            self._convert_to_events(
                detections
            )
        )

        chain_input.extend(
            self._convert_to_events(
                correlations
            )
        )

        try:

            if hasattr(
                self.threat_chain,
                "build_chain"
            ):

                result = (
                    self.threat_chain.build_chain(
                        chain_input
                    )
                )

            elif hasattr(
                self.threat_chain,
                "build"
            ):

                result = (
                    self.threat_chain.build(
                        chain_input


)
                )

            elif hasattr(
                self.threat_chain,
                "process"
            ):

                result = (
                    self.threat_chain.process(
                        chain_input
                    )
                )

            elif hasattr(
                self.threat_chain,
                "run"
            ):

                result = (
                    self.threat_chain.run(
                        chain_input
                    )
                )

            else:

                result = []

        except Exception as error:

            self.log(
                f"Ошибка Threat Chain: "
                f"{error}"
            )

            result = []

        if result is None:

            result = []

        if not isinstance(
            result,
            list
        ):

            result = [result]

        self.last_threat_chains = list(
            result
        )

        self.log(
            f"Threat Chain завершён. "
            f"Цепочек: {len(result)}"
        )

        return list(result)

    # ==========================================================
    # RISK ENGINE
    # ==========================================================

    def _run_risk(
        self,
        events: List[Dict[str, Any]],
        detections: List[Any],
        correlations: List[Any],
        threat_chains: List[Any],
        ioc_matches: List[Any]
    ) -> Dict[str, Any]:
        """
        Оценивает общий риск.
        """

        self.log(
            "Этап 5: Risk Engine."
        )

        if self.risk_engine is None:

            self.log(
                "Risk Engine не подключён."
            )

            return {
                "score": 0,
                "level": "LOW",
                "reasons": [],
                "events": len(events),
                "unique_indicators": 0,
            }

        risk_input = []

        risk_input.extend(
            events
        )

        risk_input.extend(
            self._convert_to_events(
                detections
            )
        )

        risk_input.extend(
            self._convert_to_events(
                correlations
            )
        )

        risk_input.extend(
            self._convert_to_events(
                threat_chains
            )
        )

        risk_input.extend(
            self._convert_to_events(
                ioc_matches
            )
        )

        try:

            if hasattr(
                self.risk_engine,
                "assess"
            ):

                result = (
                    self.risk_engine.assess(
                        risk_input
                    )
                )

            elif hasattr(
                self.risk_engine,
                "evaluate"
            ):

                result = (
                    self.risk_engine.evaluate(
                        risk_input
                    )
                )

            elif hasattr(
                self.risk_engine,
                "calculate_risk"
            ):

                result = (
                    self.risk_engine.calculate_risk(
                        risk_input
                    )
                )

            elif hasattr(
                self.risk_engine,
                "calculate"
            ):

                result = (
                    self.risk_engine.calculate(
                        risk_input
                    )
                )

            else:

                result = None

        except Exception as error:

            self.log(
                f"Ошибка Risk Engine: "
                f"{error}"
            )

            result = None

        if not isinstance(
            result,
            dict
        ):

            result = {
                "score": 0,
                "level": "LOW",
                "reasons": [],
                "events": len(risk_input),
                "unique_indicators": 0,


}

        result.setdefault(
            "score",
            0
        )

        result.setdefault(
            "level",
            "LOW"
        )

        result.setdefault(
            "reasons",
            []
        )

        result.setdefault(
            "events",
            len(risk_input)
        )

        result.setdefault(
            "unique_indicators",
            0
        )

        self.last_risk_result = dict(
            result
        )

        self.log(
            f"Risk Engine завершён. "
            f"Score: {result.get('score', 0)}, "
            f"Level: {result.get('level', 'LOW')}"
        )

        return dict(result)

    # ==========================================================
    # ПРЕОБРАЗОВАНИЕ ДАННЫХ
    # ==========================================================

    @staticmethod
    def _convert_to_events(
        data: Any
    ) -> List[Dict[str, Any]]:
        """
        Преобразует произвольные результаты
        компонентов в словари событий.
        """

        if data is None:
            return []

        if isinstance(
            data,
            dict
        ):

            return [
                dict(data)
            ]

        if not isinstance(
            data,
            (list, tuple)
        ):

            data = [data]

        result = []

        for item in data:

            if isinstance(
                item,
                dict
            ):

                result.append(
                    dict(item)
                )

            else:

                result.append(
                    {
                        "value": item
                    }
                )

        return result

    # ==========================================================
    # ФОРМИРОВАНИЕ РЕЗУЛЬТАТА
    # ==========================================================

    def _build_result(
        self,
        events: List[Dict[str, Any]],
        detections: List[Any],
        ioc_matches: List[Any],
        correlations: List[Any],
        threat_chains: List[Any],
        risk_result: Dict[str, Any],
        start_time: str
    ) -> Dict[str, Any]:
        """
        Создаёт единый результат Pipeline.
        """

        return {

            "pipeline": {

                "version":
                    self.VERSION,

                "started":
                    start_time,

                "finished":
                    datetime.now().isoformat(),

                "status":
                    "completed",
            },

            "input": {

                "events":
                    len(events),

                "data":
                    list(events),
            },

            "detection": {

                "count":
                    len(detections),

                "results":
                    list(detections),
            },

            "ioc": {

                "matches":
                    len(ioc_matches),

                "results":
                    list(ioc_matches),
            },

            "correlation": {

                "count":
                    len(correlations),

                "results":
                    list(correlations),
            },

            "threat_chain": {

                "count":
                    len(threat_chains),

                "results":
                    list(threat_chains),
            },

            "risk": {

                "score":
                    risk_result.get(
                        "score",
                        0
                    ),

                "level":
                    risk_result.get(
                        "level",
                        "LOW"
                    ),

                "reasons":
                    list(
                        risk_result.get(
                            "reasons",
                            []
                        )
                    ),

                "events":
                    risk_result.get(


                "events",
                        0
                    ),

                "unique_indicators":
                    risk_result.get(
                        "unique_indicators",
                        0
                    ),
            },

            "components":
                self.get_component_status(),

            "actions": {

                "decision":
                    False,

                "response":
                    False,

                "system_changes":
                    False,
            },
        }

    # ==========================================================
    # РЕЗУЛЬТАТ ОШИБКИ
    # ==========================================================

    def _build_error_result(
        self,
        events: List[Dict[str, Any]],
        start_time: str,
        error: Exception
    ) -> Dict[str, Any]:
        """
        Формирует безопасный результат при ошибке.
        """

        return {

            "pipeline": {

                "version":
                    self.VERSION,

                "started":
                    start_time,

                "finished":
                    datetime.now().isoformat(),

                "status":
                    "error",

                "error":
                    str(error),
            },

            "input": {

                "events":
                    len(events),

                "data":
                    list(events),
            },

            "detection": {

                "count":
                    0,

                "results":
                    [],
            },

            "ioc": {

                "matches":
                    0,

                "results":
                    [],
            },

            "correlation": {

                "count":
                    0,

                "results":
                    [],
            },

            "threat_chain": {

                "count":
                    0,

                "results":
                    [],
            },

            "risk": {

                "score":
                    0,

                "level":
                    "LOW",

                "reasons":
                    [],

                "events":
                    0,

                "unique_indicators":
                    0,
            },

            "components":
                self.get_component_status(),

            "actions": {

                "decision":
                    False,

                "response":
                    False,

                "system_changes":
                    False,
            },
        }

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(
        self
    ) -> Dict[str, Any]:
        """
        Возвращает последний результат Pipeline.
        """

        return dict(
            self.last_result
        )

    # ==========================================================
    # СОБЫТИЯ
    # ==========================================================

    def get_last_events(
        self
    ) -> List[Dict[str, Any]]:
        """
        Возвращает последние входные события.
        """

        return list(
            self.last_input_events
        )

    # ==========================================================
    # DETECTIONS
    # ==========================================================

    def get_last_detections(
        self
    ) -> List[Any]:
        """
        Возвращает последние обнаружения.
        """

        return list(
            self.last_detections
        )

    # ==========================================================
    # IOC
    # ==========================================================

    def get_last_ioc_matches(
        self
    ) -> List[Any]:
        """
        Возвращает последние IOC совпадения.
        """

        return list(


        self.last_ioc_matches
        )

    # ==========================================================
    # CORRELATIONS
    # ==========================================================

    def get_last_correlations(
        self
    ) -> List[Any]:
        """
        Возвращает последние корреляции.
        """

        return list(
            self.last_correlations
        )

    # ==========================================================
    # THREAT CHAINS
    # ==========================================================

    def get_last_threat_chains(
        self
    ) -> List[Any]:
        """
        Возвращает последние цепочки угроз.
        """

        return list(
            self.last_threat_chains
        )

    # ==========================================================
    # RISK
    # ==========================================================

    def get_last_risk(
        self
    ) -> Dict[str, Any]:
        """
        Возвращает последнюю оценку риска.
        """

        return dict(
            self.last_risk_result
        )

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def get_summary(
        self
    ) -> Dict[str, Any]:
        """
        Возвращает краткую сводку Pipeline.
        """

        risk = (
            self.last_risk_result
            if isinstance(
                self.last_risk_result,
                dict
            )
            else {}
        )

        return {

            "version":
                self.VERSION,

            "running":
                self.running,

            "events":
                len(
                    self.last_input_events
                ),

            "detections":
                len(
                    self.last_detections
                ),

            "ioc_matches":
                len(
                    self.last_ioc_matches
                ),

            "correlations":
                len(
                    self.last_correlations
                ),

            "threat_chains":
                len(
                    self.last_threat_chains
                ),

            "risk_score":
                risk.get(
                    "score",
                    0
                ),

            "risk_level":
                risk.get(
                    "level",
                    "LOW"
                ),

            "last_run":
                self.last_run_time,
        }

    # ==========================================================
    # ПРОВЕРКА РЕЗУЛЬТАТОВ
    # ==========================================================

    def has_result(
        self
    ) -> bool:
        """
        Проверяет наличие результата Pipeline.
        """

        return bool(
            self.last_result
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):
        """
        Полностью очищает состояние Pipeline.
        """

        self.last_input_events = []

        self.last_detections = []

        self.last_ioc_matches = []

        self.last_correlations = []

        self.last_threat_chains = []

        self.last_risk_result = {

            "score":
                0,

            "level":
                "LOW",

            "reasons":
                [],

            "events":
                0,

            "unique_indicators":
                0,
        }

        self.last_result = {}

        self.last_run_time = None

        self.log(
            "Security Pipeline результаты очищены."
        )

    # ==========================================================
    # СТАТУС
    # ==========================================================

    def is_running(
        self
    ) -> bool:
        """
        Проверяет, выполняется ли Pipeline.
        """

        return bool(
            self.running
        )

    # ==========================================================
    # ВЕРСИЯ
    # ==========================================================

    def get_version(
        self
    ) -> str:
        """
        Возвращает версию Pipeline.
        """

        return self.VERSION


# ==============================================================
# Совместимость с возможным импортом
# ==============================================================

SecurityPipelineV4 = SecurityPipeline


# ==============================================================
# Минимальная локальная проверка
# ==============================================================

if __name__ == "__main__":

    print(
        "=" * 60
    )

    print(
        "JARVIS SECURITY PIPELINE V4.0"
    )

    print(
        "=" * 60
    )

    pipeline = SecurityPipeline()

    print(
        "Version:",
        pipeline.get_version()
    )

    print(
        "Components:",
        pipeline.get_component_status()
    )

    result = pipeline.run(
        [
            {
                "type": "TEST",
                "source": "V4_TEST",
                "severity": "LOW",
                "description":
                    "Тестовое событие Pipeline."
            }
        ]
    )

    print()
    print(
        "Pipeline result:"
    )

    print(
        result
    )

    print()
    print(
        "Summary:"
    )

    print(
        pipeline.get_summary()
    )

    print(
        "=" * 60
    )