"""
detection_engine.py

JARVIS Security Core V3.6

Единый движок обнаружения.

Назначение:
- объединение результатов различных Security-модулей;
- создание единого формата detection;
- нормализация обнаружений;
- удаление дубликатов;
- классификация severity;
- работа с IOC matches;
- работа с behavioral events;
- хранение последних обнаружений;
- статистика;
- подготовка данных для Correlation/Risk Engine.

Detection Engine НЕ выполняет самостоятельное сканирование.
Он обрабатывает результаты уже существующих Security-модулей.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
import copy
import hashlib


class DetectionEngine:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None,
        max_detections=10000
    ):

        self.logger = logger

        try:
            max_detections = int(
                max_detections
            )
        except (
            TypeError,
            ValueError
        ):
            max_detections = 10000

        if max_detections < 1:
            max_detections = 10000

        self.max_detections = max_detections

        self.detections = []

        self.last_detections = []

        self.total_detections = 0

        self.total_processed = 0

        self.last_result = {
            "detections": 0,
            "processed": 0,
        }

        self.log(
            "Detection Engine V3.6 инициализирован."
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
    # ВРЕМЯ
    # ==========================================================

    def _timestamp(
        self
    ):

        return datetime.now().isoformat(
            timespec="seconds"
        )

    # ==========================================================
    # КОПИРОВАНИЕ
    # ==========================================================

    def _copy(
        self,
        value
    ):

        try:

            return copy.deepcopy(
                value
            )

        except (
            TypeError,
            ValueError
        ):

            if isinstance(
                value,
                dict
            ):

                return dict(
                    value
                )

            if isinstance(
                value,
                list
            ):

                return list(
                    value
                )

            return value

    # ==========================================================
    # НОРМАЛИЗАЦИЯ SEVERITY
    # ==========================================================

    def normalize_severity(
        self,
        severity
    ):

        if severity is None:

            return "LOW"

        value = str(
            severity
        ).strip().upper()

        aliases = {

            "INFO": "LOW",

            "INFORMATION": "LOW",

            "LOW": "LOW",

            "НИЗКИЙ": "LOW",

            "MEDIUM": "MEDIUM",

            "MED": "MEDIUM",

            "СРЕДНИЙ": "MEDIUM",

            "SUSPICIOUS": "HIGH",

            "ПОДОЗРИТЕЛЬНЫЙ": "HIGH",

            "HIGH": "HIGH",

            "ВЫСОКИЙ": "HIGH",

            "CRITICAL": "CRITICAL",

            "КРИТИЧЕСКИЙ": "CRITICAL",

        }

        return aliases.get(
            value,
            "LOW"
        )

    # ==========================================================
    # НОРМАЛИЗАЦИЯ TYPE
    # ==========================================================

    def normalize_type(
        self,
        detection_type
    ):

        if detection_type is None:

            return "UNKNOWN"

        value = str(
            detection_type
        ).strip().upper()

        aliases = {

            "FILE": "FILE",

            "FILES": "FILE",

            "PROCESS": "PROCESS",

            "PROCESSES": "PROCESS",

            "STARTUP": "STARTUP",

            "AUTOSTART": "STARTUP",

            "USB": "USB",

            "NETWORK": "NETWORK",

            "CONNECTION": "NETWORK",

            "IOC": "IOC",

            "BEHAVIOR": "BEHAVIOR",

            "BEHAVIOUR": "BEHAVIOR",

            "MALWARE": "MALWARE",

            "THREAT": "THREAT",

            "SUSPICIOUS": "SUSPICIOUS",

            "UNKNOWN": "UNKNOWN",

        }

        return aliases.get(
            value,
            value
        )

    # ==========================================================
    # ГЕНЕРАЦИЯ ID
    # ==========================================================

    def _generate_id(
        self,
        detection
    ):

        important = {

            "type": detection.get(
                "type"
            ),

            "source": detection.get(
                "source"
            ),

            "indicator": detection.get(
                "indicator"
            ),

            "value": detection.get(
                "value"
            ),

            "description": detection.get(
                "description"
            ),

        }

        raw = repr(
            sorted(
                important.items()
            )
        )

        return hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

    # ==========================================================
    # СОЗДАНИЕ DETECTION
    # ==========================================================

    def create_detection(
        self,
        detection_type="UNKNOWN",
        source="unknown",
        value=None,
        indicator=None,
        severity="LOW",
        score=0,
        description="",
        metadata=None,
        event=None
    ):

        detection = {

            "id": None,

            "timestamp":
                self._timestamp(),

            "type":
                self.normalize_type(
                    detection_type
                ),

            "source":
                str(
                    source
                ),

            "value":
                value,

            "indicator":
                indicator,

            "severity":
                self.normalize_severity(
                    severity
                ),

            "score":
                self._normalize_score(
                    score
                ),

            "description":
                str(
                    description
                ),

            "metadata":
                self._copy(
                    metadata
                    if isinstance(
                        metadata,
                        dict
                    )
                    else {}
                ),

            "event":
                self._copy(
                    event
                    if isinstance(
                        event,
                        dict
                    )
                    else {}
                ),

        }

        detection["id"] = (
            self._generate_id(
                detection
            )
        )

        return detection

    # ==========================================================
    # НОРМАЛИЗАЦИЯ SCORE
    # ==========================================================

    def _normalize_score(
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

        if score < 0:

            score = 0

        if score > 100:

            score = 100

        return score

    # ==========================================================
    # ДОБАВЛЕНИЕ DETECTION
    # ==========================================================

    def add_detection(
        self,
        detection=None,
        **kwargs
    ):

        if detection is None:

            detection = {}

        if not isinstance(
            detection,
            dict
        ):

            return None

        data = self._copy(
            detection
        )

        data.update(
            kwargs
        )

        normalized = (
            self.create_detection(

                detection_type=data.get(
                    "type",
                    "UNKNOWN"
                ),

                source=data.get(
                    "source",
                    "unknown"
                ),

                value=data.get(
                    "value"
                ),

                indicator=data.get(
                    "indicator"
                ),

                severity=data.get(
                    "severity",
                    "LOW"
                ),

                score=data.get(
                    "score",
                    0
                ),

                description=data.get(
                    "description",
                    ""
                ),

                metadata=data.get(
                    "metadata"
                ),

                event=data.get(
                    "event"
                )

            )
        )

        # ------------------------------------------------------
        # Сохраняем дополнительные поля
        # ------------------------------------------------------

        for key, value in data.items():

            if key not in normalized:

                normalized[
                    key
                ] = self._copy(
                    value
                )

        # ------------------------------------------------------
        # Защита от дубликатов
        # ------------------------------------------------------

        if self._is_duplicate(
            normalized
        ):

            return self._find_duplicate(
                normalized
            )

        self.detections.append(
            normalized
        )

        self.total_detections += 1

        self._enforce_limit()

        return self._copy(
            normalized
        )

    # ==========================================================
    # ПРОВЕРКА ДУБЛИКАТА
    # ==========================================================

    def _is_duplicate(
        self,
        detection
    ):

        detection_id = detection.get(
            "id"
        )

        for existing in self.detections:

            if existing.get(
                "id"
            ) == detection_id:

                return True

        return False

    # ==========================================================
    # ПОИСК ДУБЛИКАТА
    # ==========================================================

    def _find_duplicate(
        self,
        detection
    ):

        detection_id = detection.get(
            "id"
        )

        for existing in self.detections:

            if existing.get(
                "id"
            ) == detection_id:

                return self._copy(
                    existing
                )

        return None

    # ==========================================================
    # ОБРАБОТКА ОДНОГО СОБЫТИЯ
    # ==========================================================

    def process_event(
        self,
        event,
        source="event"
    ):

        if not isinstance(
            event,
            dict
        ):

            return []


        self.total_processed += 1

        detections = []

        # ------------------------------------------------------
        # Уже готовое detection
        # ------------------------------------------------------

        if (
            "detection" in event
            and isinstance(
                event.get(
                    "detection"
                ),
                dict
            )
        ):

            result = self.add_detection(
                event[
                    "detection"
                ]
            )

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # Threat
        # ------------------------------------------------------

        if (
            event.get(
                "threat"
            )
            or event.get(
                "malware"
            )
            or event.get(
                "malicious"
            )
        ):

            result = self.add_detection({

                "type": "THREAT",

                "source": source,

                "value":
                    event.get(
                        "value"
                    ),

                "indicator":
                    event.get(
                        "indicator"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "HIGH"
                    ),

                "score":
                    event.get(
                        "score",
                        70
                    ),

                "description":
                    event.get(
                        "description",
                        "Обнаружена потенциальная угроза."
                    ),

                "event": event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # IOC match
        # ------------------------------------------------------

        ioc_matches = event.get(
            "ioc_matches"
        )

        if ioc_matches is None:

            ioc_matches = event.get(
                "matches"
            )

        if isinstance(
            ioc_matches,
            list
        ):

            for match in ioc_matches:

                if not isinstance(
                    match,
                    dict
                ):

                    continue

                result = self.add_detection({

                    "type": "IOC",

                    "source":
                        source,

                    "value":
                        match.get(
                            "value"
                        ),

                    "indicator":
                        match.get(
                            "type"
                        ),

                    "severity":
                        match.get(
                            "severity",
                            "HIGH"
                        ),

                    "score":
                        match.get(
                            "score",
                            70
                        ),

                    "description":
                        match.get(
                            "description",
                            "Совпадение с IOC."
                        ),

                    "metadata":
                        match,

                    "event":
                        event,

                })

                if result:

                    detections.append(
                        result
                    )

        # ------------------------------------------------------
        # Suspicious
        # ------------------------------------------------------

        if (
            event.get(
                "suspicious"
            )


is True
        ):

            result = self.add_detection({

                "type":
                    "SUSPICIOUS",

                "source":
                    source,

                "value":
                    event.get(
                        "value"
                    ),

                "indicator":
                    event.get(
                        "indicator"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "HIGH"
                    ),

                "score":
                    event.get(
                        "score",
                        40
                    ),

                "description":
                    event.get(
                        "description",
                        "Обнаружено подозрительное событие."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # Behavior
        # ------------------------------------------------------

        if (
            event.get(
                "behavior"
            )
            or event.get(
                "behavior_event"
            )
        ):

            behavior = event.get(
                "behavior"
            )

            if not isinstance(
                behavior,
                dict
            ):

                behavior = event.get(
                    "behavior_event"
                )

            if not isinstance(
                behavior,
                dict
            ):

                behavior = event

            result = self.add_detection({

                "type":
                    "BEHAVIOR",

                "source":
                    source,

                "value":
                    behavior.get(
                        "value"
                    ),

                "indicator":
                    behavior.get(
                        "indicator"
                    ),

                "severity":
                    behavior.get(
                        "severity",
                        "MEDIUM"
                    ),

                "score":
                    behavior.get(
                        "score",
                        30
                    ),

                "description":
                    behavior.get(
                        "description",
                        "Обнаружено поведенческое событие."
                    ),

                "metadata":
                    behavior,

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # Process
        # ------------------------------------------------------

        if (
            event.get(
                "process"
            )
            or event.get(
                "pid"
            ) is not None
        ):

            process = event.get(
                "process"
            )

            if not process:

                process = event.get(
                    "name"
                )

            result = self.add_detection({

                "type":
                    "PROCESS",

                "source":
                    source,

                "value":
                    process,

                "indicator":
                    event.get(
                        "pid"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "LOW"
                    ),

                "score":
                    event.get(
                        "score",
                        0
                    ),


"description":
                    event.get(
                        "description",
                        "Событие процесса."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # Network
        # ------------------------------------------------------

        if (
            event.get(
                "remote_address"
            )
            or event.get(
                "remote_ip"
            )
            or event.get(
                "local_address"
            )
        ):

            value = (
                event.get(
                    "remote_address"
                )
                or event.get(
                    "remote_ip"
                )
                or event.get(
                    "local_address"
                )
            )

            result = self.add_detection({

                "type":
                    "NETWORK",

                "source":
                    source,

                "value":
                    value,

                "indicator":
                    event.get(
                        "remote_port"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "LOW"
                    ),

                "score":
                    event.get(
                        "score",
                        0
                    ),

                "description":
                    event.get(
                        "description",
                        "Сетевое событие."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # File
        # ------------------------------------------------------

        if (
            event.get(
                "file"
            )
            or event.get(
                "file_path"
            )
            or event.get(
                "filename"
            )
        ):

            value = (
                event.get(
                    "file_path"
                )
                or event.get(
                    "filename"
                )
                or event.get(
                    "file"
                )
            )

            result = self.add_detection({

                "type":
                    "FILE",

                "source":
                    source,

                "value":
                    value,

                "indicator":
                    event.get(
                        "hash"
                    )
                    or event.get(
                        "sha256"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "LOW"
                    ),

                "score":
                    event.get(
                        "score",
                        0
                    ),

                "description":
                    event.get(
                        "description",
                        "Событие файла."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # Startup
        # ------------------------------------------------------

        if (
            event.get(
                "startup"
            )
            or event.get(
                "autostart"
            )
        ):

            result = self.add_detection({

                "type":


"STARTUP",

                "source":
                    source,

                "value":
                    event.get(
                        "name"
                    )
                    or event.get(
                        "command"
                    ),

                "indicator":
                    event.get(
                        "command"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "LOW"
                    ),

                "score":
                    event.get(
                        "score",
                        0
                    ),

                "description":
                    event.get(
                        "description",
                        "Событие автозагрузки."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        # ------------------------------------------------------
        # USB
        # ------------------------------------------------------

        if (
            event.get(
                "usb"
            )
            or event.get(
                "device"
            )
        ):

            result = self.add_detection({

                "type":
                    "USB",

                "source":
                    source,

                "value":
                    event.get(
                        "device"
                    )
                    or event.get(
                        "name"
                    ),

                "indicator":
                    event.get(
                        "serial"
                    ),

                "severity":
                    event.get(
                        "severity",
                        "LOW"
                    ),

                "score":
                    event.get(
                        "score",
                        0
                    ),

                "description":
                    event.get(
                        "description",
                        "USB-событие."
                    ),

                "event":
                    event,

            })

            if result:

                detections.append(
                    result
                )

        self.last_detections = self._copy(
            detections
        )

        self.last_result = {

            "detections":
                len(
                    detections
                ),

            "processed":
                self.total_processed,

        }

        return self._copy(
            detections
        )

    # ==========================================================
    # ОБРАБОТКА СПИСКА СОБЫТИЙ
    # ==========================================================

    def process_events(
        self,
        events,
        source="events"
    ):

        if events is None:

            return []

        if isinstance(
            events,
            dict
        ):

            events = [
                events
            ]

        if not isinstance(
            events,
            (list, tuple)
        ):

            return []

        results = []

        for event in events:

            results.extend(
                self.process_event(
                    event,
                    source
                )
            )

        return self._copy(
            results
        )

    # ==========================================================
    # ОБРАБОТКА РЕЗУЛЬТАТОВ СКАНЕРОВ
    # ==========================================================

    def process_scan_results(
        self,
        results,
        source="scanner"
    ):

        if results is None:

            return []

        if isinstance(
            results,
            dict
        ):

            results = [
                results
            ]


        if not isinstance(
            results,
            (list, tuple)
        ):

            return []

        detections = []

        for item in results:

            if not isinstance(
                item,
                dict
            ):

                continue

            detections.extend(
                self.process_event(
                    item,
                    source
                )
            )

        return self._copy(
            detections
        )

    # ==========================================================
    # УДАЛЕНИЕ СТАРЫХ ЗАПИСЕЙ
    # ==========================================================

    def _enforce_limit(
        self
    ):

        if len(
            self.detections
        ) <= self.max_detections:

            return

        excess = (
            len(
                self.detections
            )
            - self.max_detections
        )

        if excess > 0:

            del self.detections[
                0:excess
            ]

    # ==========================================================
    # ПОЛУЧЕНИЕ DETECTIONS
    # ==========================================================

    def get_detections(
        self,
        detection_type=None,
        severity=None,
        limit=None
    ):

        normalized_type = None

        if detection_type is not None:

            normalized_type = (
                self.normalize_type(
                    detection_type
                )
            )

        normalized_severity = None

        if severity is not None:

            normalized_severity = (
                self.normalize_severity(
                    severity
                )
            )

        results = []

        for detection in self.detections:

            if (
                normalized_type is not None
                and detection.get(
                    "type"
                ) != normalized_type
            ):

                continue

            if (
                normalized_severity is not None
                and detection.get(
                    "severity"
                ) != normalized_severity
            ):

                continue

            results.append(
                self._copy(
                    detection
                )
            )

        if limit is not None:

            try:

                limit = int(
                    limit
                )

            except (
                TypeError,
                ValueError
            ):

                limit = None

        if limit is not None:

            if limit <= 0:

                return []

            results = results[
                -limit:
            ]

        return results

    # ==========================================================
    # ПОСЛЕДНИЕ DETECTIONS
    # ==========================================================

    def get_last_detections(
        self
    ):

        return self._copy(
            self.last_detections
        )

    # ==========================================================
    # КРИТИЧЕСКИЕ
    # ==========================================================

    def get_critical(
        self
    ):

        return self.get_detections(
            severity="CRITICAL"
        )

    # ==========================================================
    # ВЫСОКИЙ РИСК
    # ==========================================================

    def get_high(
        self
    ):

        return self.get_detections(
            severity="HIGH"
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПО ТИПУ
    # ==========================================================

    def get_by_type(
        self,
        detection_type
    ):

        return self.get_detections(
            detection_type=detection_type
        )

    # ==========================================================
    # ПОИСК
    # ==========================================================


    def find(
        self,
        value
    ):

        if value is None:

            return []

        value = str(
            value
        ).lower()

        results = []

        for detection in self.detections:

            current = str(
                detection.get(
                    "value",
                    ""
                )
            ).lower()

            indicator = str(
                detection.get(
                    "indicator",
                    ""
                )
            ).lower()

            if (
                value == current
                or value == indicator
            ):

                results.append(
                    self._copy(
                        detection
                    )
                )

        return results

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self
    ):

        statistics = {

            "total":
                len(
                    self.detections
                ),

            "total_detections":
                self.total_detections,

            "total_processed":
                self.total_processed,

            "types": {},

            "severities": {},

        }

        for detection in self.detections:

            detection_type = (
                detection.get(
                    "type",
                    "UNKNOWN"
                )
            )

            severity = (
                detection.get(
                    "severity",
                    "LOW"
                )
            )

            statistics[
                "types"
            ][detection_type] = (
                statistics[
                    "types"
                ].get(
                    detection_type,
                    0
                ) + 1
            )

            statistics[
                "severities"
            ][severity] = (
                statistics[
                    "severities"
                ].get(
                    severity,
                    0
                ) + 1
            )

        return statistics

    # ==========================================================
    # КОЛИЧЕСТВО
    # ==========================================================

    def count(
        self,
        detection_type=None
    ):

        return len(
            self.get_detections(
                detection_type
            )
        )

    # ==========================================================
    # ПРОВЕРКА НАЛИЧИЯ
    # ==========================================================

    def has_detections(
        self
    ):

        return bool(
            self.detections
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):

        removed = len(
            self.detections
        )

        self.detections.clear()

        self.last_detections = []

        self.last_result = {

            "detections": 0,

            "processed":
                self.total_processed,

        }

        self.log(
            "Detection Engine очищен. "
            f"Удалено обнаружений: {removed}"
        )

        return removed

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(
        self
    ):

        return self._copy(
            self.last_result
        )

    # ==========================================================
    # СВОДКА
    # ==========================================================

    def get_summary(
        self
    ):

        statistics = (
            self.get_statistics()
        )

        return {

            "detections":
                statistics[
                    "total"


],

            "processed":
                statistics[
                    "total_processed"
                ],

            "types":
                statistics[
                    "types"
                ],

            "severities":
                statistics[
                    "severities"
                ],

            "last_detections":
                len(
                    self.last_detections
                ),

            "max_detections":
                self.max_detections,

        }

    # ==========================================================
    # ДАННЫЕ ДЛЯ CORRELATION ENGINE
    # ==========================================================

    def get_correlation_data(
        self
    ):

        return self._copy(
            self.detections
        )

    # ==========================================================
    # ДАННЫЕ ДЛЯ RISK ENGINE
    # ==========================================================

    def get_risk_data(
        self
    ):

        return self._copy(
            self.detections
        )

    # ==========================================================
    # ДАННЫЕ ДЛЯ INCIDENT MANAGER
    # ==========================================================

    def get_incident_data(
        self
    ):

        incidents = []

        for detection in self.detections:

            severity = detection.get(
                "severity",
                "LOW"
            )

            if severity in (
                "HIGH",
                "CRITICAL"
            ):

                incidents.append(
                    self._copy(
                        detection
                    )
                )

        return incidents

    # ==========================================================
    # LEN
    # ==========================================================

    def __len__(
        self
    ):

        return len(
            self.detections
        )

    # ==========================================================
    # REPR
    # ==========================================================

    def __repr__(
        self
    ):

        return (
            f"DetectionEngine("
            f"detections="
            f"{len(self.detections)}, "
            f"max_detections="
            f"{self.max_detections})"
        )


# ==============================================================
# АЛИАСЫ
# ==============================================================

DetectionManager = DetectionEngine
DetectionStore = DetectionEngine