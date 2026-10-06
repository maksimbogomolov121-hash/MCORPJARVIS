"""
incident_manager.py

JARVIS Security Core V3.3

Менеджер инцидентов.

Назначение:
- создание инцидентов;
- регистрация обнаруженных цепочек угроз;
- присвоение уровня риска;
- изменение статуса инцидента;
- добавление событий и доказательств;
- получение инцидентов;
- фильтрация по статусу и уровню;
- закрытие и повторное открытие инцидентов;
- хранение истории изменений;
- формирование сводной статистики.

Модуль не выполняет защитных действий над системой.
Он только управляет данными об инцидентах.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
import uuid


class IncidentManager:

    # ==========================================================
    # ДОПУСТИМЫЕ СТАТУСЫ
    # ==========================================================

    STATUSES = {
        "NEW",
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
        "CLOSED",
    }

    # ==========================================================
    # УРОВНИ РИСКА
    # ==========================================================

    LEVELS = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3,
    }

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None
    ):

        self.logger = logger

        self.incidents = {}

        self.last_incident_id = None

        self.last_result = {
            "count": 0,
            "incidents": [],
        }

        self.log(
            "Incident Manager V3.3 инициализирован."
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

    def _timestamp(self):

        return datetime.now().isoformat(
            timespec="seconds"
        )

    # ==========================================================
    # СОЗДАНИЕ ID
    # ==========================================================

    def _generate_id(self):

        return (
            "INC-"
            + uuid.uuid4().hex[:12].upper()
        )

    # ==========================================================
    # НОРМАЛИЗАЦИЯ УРОВНЯ
    # ==========================================================

    def _normalize_level(
        self,
        level
    ):

        if level is None:

            return "LOW"

        value = str(
            level
        ).upper().strip()

        if value not in self.LEVELS:

            return "LOW"

        return value

    # ==========================================================
    # НОРМАЛИЗАЦИЯ СТАТУСА
    # ==========================================================

    def _normalize_status(
        self,
        status
    ):

        if status is None:

            return "NEW"

        value = str(
            status
        ).upper().strip()

        if value not in self.STATUSES:

            return "NEW"

        return value

    # ==========================================================
    # КОПИЯ ИНЦИДЕНТА
    # ==========================================================

    def _copy_incident(
        self,
        incident
    ):

        if not isinstance(
            incident,


dict
        ):

            return {}

        result = dict(
            incident
        )

        for key in (
            "events",
            "chains",
            "indicators",
            "evidence",
            "history",
        ):

            value = incident.get(
                key
            )

            if isinstance(
                value,
                list
            ):

                result[key] = list(
                    value
                )

        return result

    # ==========================================================
    # СОЗДАНИЕ ИНЦИДЕНТА
    # ==========================================================

    def create_incident(
        self,
        title="Security Incident",
        description="",
        level="LOW",
        source="Security Core",
        events=None,
        chains=None,
        indicators=None,
        evidence=None,
        incident_id=None,
    ):

        incident_id = (
            incident_id
            or self._generate_id()
        )

        if incident_id in self.incidents:

            return self._copy_incident(
                self.incidents[
                    incident_id
                ]
            )

        normalized_level = (
            self._normalize_level(
                level
            )
        )

        now = self._timestamp()

        incident = {

            "id": incident_id,

            "title": str(
                title
                or "Security Incident"
            ),

            "description": str(
                description
                or ""
            ),

            "level": normalized_level,

            "status": "NEW",

            "source": str(
                source
                or "Security Core"
            ),

            "created_at": now,

            "updated_at": now,

            "closed_at": None,

            "events": (
                list(events)
                if isinstance(
                    events,
                    (list, tuple)
                )
                else []
            ),

            "chains": (
                list(chains)
                if isinstance(
                    chains,
                    (list, tuple)
                )
                else []
            ),

            "indicators": (
                list(indicators)
                if isinstance(
                    indicators,
                    (list, tuple, set)
                )
                else []
            ),

            "evidence": (
                list(evidence)
                if isinstance(
                    evidence,
                    (list, tuple)
                )
                else []
            ),

            "history": [],

        }

        incident["history"].append(
            {
                "timestamp": now,
                "action": "CREATED",
                "status": "NEW",
                "level": normalized_level,
            }
        )

        self.incidents[
            incident_id
        ] = incident

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        self.log(
            "Создан инцидент "
            f"{incident_id}. "
            f"Level: {normalized_level}"
        )

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ИНЦИДЕНТА
    # ==========================================================

    def get_incident(
        self,
        incident_id
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ВСЕХ ИНЦИДЕНТОВ
    # ==========================================================

    def get_incidents(
        self,
        status=None,


level=None
    ):

        normalized_status = None
        normalized_level = None

        if status is not None:

            normalized_status = (
                self._normalize_status(
                    status
                )
            )

        if level is not None:

            normalized_level = (
                self._normalize_level(
                    level
                )
            )

        result = []

        for incident in self.incidents.values():

            if (
                normalized_status is not None
                and incident.get(
                    "status"
                ) != normalized_status
            ):

                continue

            if (
                normalized_level is not None
                and incident.get(
                    "level"
                ) != normalized_level
            ):

                continue

            result.append(
                self._copy_incident(
                    incident
                )
            )

        return result

    # ==========================================================
    # ОБНОВЛЕНИЕ РЕЗУЛЬТАТА
    # ==========================================================

    def _update_result(
        self
    ):

        self.last_result = {

            "count": len(
                self.incidents
            ),

            "incidents": self.get_incidents(),

        }

    # ==========================================================
    # ИЗМЕНЕНИЕ СТАТУСА
    # ==========================================================

    def update_status(
        self,
        incident_id,
        status
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        normalized_status = (
            self._normalize_status(
                status
            )
        )

        old_status = incident.get(
            "status",
            "NEW"
        )

        now = self._timestamp()

        incident["status"] = (
            normalized_status
        )

        incident["updated_at"] = now

        if normalized_status == "CLOSED":

            incident["closed_at"] = now

        elif old_status == "CLOSED":

            incident["closed_at"] = None

        incident["history"].append(
            {
                "timestamp": now,
                "action": "STATUS_CHANGED",
                "from": old_status,
                "to": normalized_status,
            }
        )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        self.log(
            f"Инцидент {incident_id}: "
            f"{old_status} → {normalized_status}"
        )

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ИЗМЕНЕНИЕ УРОВНЯ
    # ==========================================================

    def update_level(
        self,
        incident_id,
        level
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        normalized_level = (
            self._normalize_level(
                level
            )
        )

        old_level = incident.get(
            "level",
            "LOW"
        )

        now = self._timestamp()

        incident["level"] = (
            normalized_level
        )

        incident["updated_at"] = now

        incident["history"].append(
            {
                "timestamp": now,
                "action": "LEVEL_CHANGED",
                "from": old_level,
                "to": normalized_level,
            }
        )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        self.log(
            f"Инцидент {incident_id}: "
            f"Level {old_level} → "
            f"{normalized_level}"
        )

        return self._copy_incident(


incident
        )

    # ==========================================================
    # ДОБАВЛЕНИЕ СОБЫТИЯ
    # ==========================================================

    def add_event(
        self,
        incident_id,
        event
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        if event is None:

            return self._copy_incident(
                incident
            )

        incident["events"].append(
            event
        )

        now = self._timestamp()

        incident["updated_at"] = now

        incident["history"].append(
            {
                "timestamp": now,
                "action": "EVENT_ADDED",
            }
        )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ДОБАВЛЕНИЕ ЦЕПОЧКИ УГРОЗ
    # ==========================================================

    def add_chain(
        self,
        incident_id,
        chain
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        if chain is None:

            return self._copy_incident(
                incident
            )

        incident["chains"].append(
            chain
        )

        chain_level = None

        if isinstance(
            chain,
            dict
        ):

            chain_level = chain.get(
                "level"
            )

        if chain_level:

            current_level = self.LEVELS.get(
                incident.get(
                    "level",
                    "LOW"
                ),
                0
            )

            new_level = self.LEVELS.get(
                self._normalize_level(
                    chain_level
                ),
                0
            )

            if new_level > current_level:

                incident["level"] = (
                    self._normalize_level(
                        chain_level
                    )
                )

        now = self._timestamp()

        incident["updated_at"] = now

        incident["history"].append(
            {
                "timestamp": now,
                "action": "CHAIN_ADDED",
            }
        )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ДОБАВЛЕНИЕ ИНДИКАТОРА
    # ==========================================================

    def add_indicator(
        self,
        incident_id,
        indicator
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        if indicator is None:

            return self._copy_incident(
                incident
            )

        if indicator not in incident[
            "indicators"
        ]:

            incident[
                "indicators"
            ].append(
                indicator
            )

            now = self._timestamp()

            incident[
                "updated_at"
            ] = now

            incident[
                "history"
            ].append(
                {
                    "timestamp": now,
                    "action": "INDICATOR_ADDED",
                }
            )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ДОБАВЛЕНИЕ ДОКАЗАТЕЛЬСТВА
    # ==========================================================

    def add_evidence(
        self,
        incident_id,


evidence
    ):

        incident = self.incidents.get(
            incident_id
        )

        if incident is None:

            return None

        if evidence is None:

            return self._copy_incident(
                incident
            )

        incident[
            "evidence"
        ].append(
            evidence
        )

        now = self._timestamp()

        incident[
            "updated_at"
        ] = now

        incident[
            "history"
        ].append(
            {
                "timestamp": now,
                "action": "EVIDENCE_ADDED",
            }
        )

        self.last_incident_id = (
            incident_id
        )

        self._update_result()

        return self._copy_incident(
            incident
        )

    # ==========================================================
    # ОТКРЫТИЕ ИНЦИДЕНТА
    # ==========================================================

    def open_incident(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "OPEN"
        )

    # ==========================================================
    # НАЧАЛО РАССЛЕДОВАНИЯ
    # ==========================================================

    def investigate(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "INVESTIGATING"
        )

    # ==========================================================
    # СДЕРЖИВАНИЕ
    # ==========================================================

    def contain(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "CONTAINED"
        )

    # ==========================================================
    # РЕШЕНИЕ
    # ==========================================================

    def resolve(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "RESOLVED"
        )

    # ==========================================================
    # ЗАКРЫТИЕ
    # ==========================================================

    def close(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "CLOSED"
        )

    # ==========================================================
    # ПОВТОРНОЕ ОТКРЫТИЕ
    # ==========================================================

    def reopen(
        self,
        incident_id
    ):

        return self.update_status(
            incident_id,
            "OPEN"
        )

    # ==========================================================
    # УДАЛЕНИЕ ИНЦИДЕНТА
    # ==========================================================

    def delete_incident(
        self,
        incident_id
    ):

        if incident_id not in self.incidents:

            return False

        del self.incidents[
            incident_id
        ]

        if self.last_incident_id == incident_id:

            self.last_incident_id = None

        self._update_result()

        self.log(
            f"Инцидент {incident_id} удалён."
        )

        return True

    # ==========================================================
    # ПОСЛЕДНИЙ ИНЦИДЕНТ
    # ==========================================================

    def get_last_incident(
        self
    ):

        if not self.last_incident_id:

            return None

        return self.get_incident(
            self.last_incident_id
        )

    # ==========================================================
    # КОЛИЧЕСТВО
    # ==========================================================

    def count(
        self
    ):

        return len(
            self.incidents
        )

    # ==========================================================
    # КОЛИЧЕСТВО ОТКРЫТЫХ
    # ==========================================================

    def open_count(
        self
    ):

        count = 0

        for incident in self.incidents.values():

            if incident.get(
                "status"
            ) not in {
                "RESOLVED",
                "CLOSED",
            }:

                count += 1

        return count

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self
    ):

        statistics = {

            "total": len(
                self.incidents
            ),

            "open": 0,

            "new": 0,

            "investigating": 0,

            "contained": 0,

            "resolved": 0,

            "closed": 0,

            "low": 0,

            "medium": 0,

            "high": 0,

            "critical": 0,

        }

        for incident in self.incidents.values():

            status = str(
                incident.get(
                    "status",
                    "NEW"
                )
            ).lower()

            level = str(
                incident.get(
                    "level",
                    "LOW"
                )
            ).lower()

            if status == "new":

                statistics["new"] += 1

            elif status == "open":

                statistics["open"] += 1

            elif status == "investigating":

                statistics[
                    "investigating"
                ] += 1

            elif status == "contained":

                statistics[
                    "contained"
                ] += 1

            elif status == "resolved":

                statistics[
                    "resolved"
                ] += 1

            elif status == "closed":

                statistics[
                    "closed"
                ] += 1

            if level in statistics:

                statistics[
                    level
                ] += 1

        return statistics

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

            "total": statistics[
                "total"
            ],

            "open": self.open_count(),

            "new": statistics[
                "new"
            ],

            "investigating": statistics[
                "investigating"
            ],

            "contained": statistics[
                "contained"
            ],

            "resolved": statistics[
                "resolved"
            ],

            "closed": statistics[
                "closed"
            ],

            "low": statistics[
                "low"
            ],

            "medium": statistics[
                "medium"
            ],

            "high": statistics[
                "high"
            ],

            "critical": statistics[
                "critical"
            ],

        }

    # ==========================================================
    # ПОИСК
    # ==========================================================

    def search(
        self,
        query
    ):

        if query is None:

            return []

        query = str(
            query
        ).lower().strip()

        if not query:

            return self.get_incidents()

        results = []

        for incident in self.incidents.values():

            searchable = " ".join(
                [
                    str(
                        incident.get(
                            "id",
                            ""
                        )
                    ),

                    str(
                        incident.get(
                            "title",
                            ""
                        )
                    ),

                    str(
                        incident.get(
                            "description",


""
                        )
                    ),

                    str(
                        incident.get(
                            "level",
                            ""
                        )
                    ),

                    str(
                        incident.get(
                            "status",
                            ""
                        )
                    ),

                ]
            ).lower()

            if query in searchable:

                results.append(
                    self._copy_incident(
                        incident
                    )
                )

        return results

    # ==========================================================
    # ОБЪЯСНЕНИЕ
    # ==========================================================

    def explain_incident(
        self,
        incident_id
    ):

        incident = self.get_incident(
            incident_id
        )

        if incident is None:

            return (
                "Инцидент не найден."
            )

        return (
            f"Инцидент {incident['id']}. "
            f"{incident['title']}. "
            f"Статус: "
            f"{incident['status']}. "
            f"Уровень: "
            f"{incident['level']}. "
            f"Событий: "
            f"{len(incident['events'])}. "
            f"Цепочек: "
            f"{len(incident['chains'])}. "
            f"Индикаторов: "
            f"{len(incident['indicators'])}. "
            f"Доказательств: "
            f"{len(incident['evidence'])}."
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):

        self.incidents.clear()

        self.last_incident_id = None

        self._update_result()

        self.log(
            "Incident Manager очищен."
        )

        return self.get_summary()

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(
        self
    ):

        return {
            "count": self.last_result.get(
                "count",
                0
            ),
            "incidents": self.get_incidents(),
        }