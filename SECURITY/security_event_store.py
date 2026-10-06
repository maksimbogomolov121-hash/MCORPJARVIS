"""
security_event_store.py

JARVIS Security Core V3.4

Хранилище событий Security Core.

Назначение:
- хранение событий безопасности;
- добавление одного или нескольких событий;
- получение событий;
- получение последних событий;
- поиск;
- фильтрация;
- ограничение размера хранилища;
- удаление событий;
- очистка;
- статистика;
- экспорт событий.

Модуль не выполняет анализ угроз.
Он отвечает только за управление сохранёнными событиями.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
import copy
import json


class SecurityEventStore:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None,
        max_events=10000
    ):

        self.logger = logger

        try:
            max_events = int(
                max_events
            )
        except (
            TypeError,
            ValueError
        ):

            max_events = 10000

        if max_events < 1:

            max_events = 10000

        self.max_events = max_events

        self.events = []

        self.total_added = 0

        self.last_event = None

        self.last_result = {

            "count": 0,

            "total_added": 0,

        }

        self.log(
            "Security Event Store V3.4 инициализирован."
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
    # НОРМАЛИЗАЦИЯ СОБЫТИЯ
    # ==========================================================

    def _normalize_event(
        self,
        event
    ):

        if not isinstance(
            event,
            dict
        ):

            return None

        normalized = self._copy(
            event
        )

        if not normalized.get(
            "timestamp"
        ):

            normalized[
                "timestamp"
            ] = self._timestamp()

        if "type" not in normalized:

            normalized[
                "type"
            ] = "security_event"

        return normalized

    # ==========================================================
    # ОБНОВЛЕНИЕ СОСТОЯНИЯ
    # ==========================================================

    def _update_state(
        self
    ):

        self.last_result = {


"count": len(
                self.events
            ),

            "total_added": self.total_added,

        }

    # ==========================================================
    # ОГРАНИЧЕНИЕ РАЗМЕРА
    # ==========================================================

    def _enforce_limit(
        self
    ):

        if len(
            self.events
        ) <= self.max_events:

            return

        excess = (
            len(self.events)
            - self.max_events
        )

        if excess > 0:

            del self.events[
                0:excess
            ]

    # ==========================================================
    # ДОБАВЛЕНИЕ СОБЫТИЯ
    # ==========================================================

    def add_event(
        self,
        event
    ):

        normalized = (
            self._normalize_event(
                event
            )
        )

        if normalized is None:

            return None

        self.events.append(
            normalized
        )

        self.total_added += 1

        self.last_event = self._copy(
            normalized
        )

        self._enforce_limit()

        self._update_state()

        return self._copy(
            normalized
        )

    # ==========================================================
    # ДОБАВЛЕНИЕ НЕСКОЛЬКИХ СОБЫТИЙ
    # ==========================================================

    def add_events(
        self,
        events
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

        added = []

        for event in events:

            result = self.add_event(
                event
            )

            if result is not None:

                added.append(
                    result
                )

        self._update_state()

        return self._copy(
            added
        )

    # ==========================================================
    # АЛИАСЫ
    # ==========================================================

    def store(
        self,
        event
    ):

        return self.add_event(
            event
        )

    def save(
        self,
        event
    ):

        return self.add_event(
            event
        )

    def append(
        self,
        event
    ):

        return self.add_event(
            event
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ВСЕХ СОБЫТИЙ
    # ==========================================================

    def get_events(
        self,
        limit=None
    ):

        events = list(
            self.events
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

            events = events[
                -limit:
            ]

        return self._copy(
            events
        )

    # ==========================================================
    # ПОСЛЕДНЕЕ СОБЫТИЕ
    # ==========================================================

    def get_last_event(
        self
    ):

        if not self.events:

            return None

        return self._copy(
            self.events[-1]
        )

    # ==========================================================
    # ПОСЛЕДНИЕ N СОБЫТИЙ
    # ==========================================================

    def get_recent(
        self,
        count=10
    ):

        return self.get_events(
            limit=count
        )

    # ==========================================================
    # КОЛИЧЕСТВО СОБЫТИЙ
    # ==========================================================

    def count(
        self
    ):

        return len(
            self.events
        )

    # ==========================================================
    # ОБЩЕЕ КОЛИЧЕСТВО ДОБАВЛЕННЫХ СОБЫТИЙ
    # ==========================================================

    def get_total_added(
        self
    ):

        return self.total_added

    # ==========================================================
    # ФИЛЬТРАЦИЯ
    # ==========================================================

    def filter(
        self,
        event_type=None,
        level=None,
        source=None,
        pid=None,
        status=None
    ):

        results = []

        normalized_type = (
            str(event_type).lower()
            if event_type is not None
            else None
        )

        normalized_level = (
            str(level).lower()
            if level is not None
            else None
        )

        normalized_source = (
            str(source).lower()
            if source is not None
            else None
        )

        normalized_status = (
            str(status).lower()
            if status is not None
            else None
        )

        normalized_pid = (
            str(pid)
            if pid is not None
            else None
        )

        for event in self.events:

            if normalized_type is not None:

                value = str(
                    event.get(
                        "type",
                        ""
                    )
                ).lower()

                if value != normalized_type:

                    continue

            if normalized_level is not None:

                value = str(
                    event.get(
                        "level",
                        ""
                    )
                ).lower()

                if value != normalized_level:

                    continue

            if normalized_source is not None:

                value = str(
                    event.get(
                        "source",
                        ""
                    )
                ).lower()

                if value != normalized_source:

                    continue

            if normalized_status is not None:

                value = str(
                    event.get(
                        "status",
                        ""
                    )
                ).lower()

                if value != normalized_status:

                    continue

            if normalized_pid is not None:

                value = event.get(
                    "pid"
                )

                if value is None:

                    continue

                if str(
                    value
                ) != normalized_pid:

                    continue

            results.append(
                self._copy(
                    event
                )
            )

        return results

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

            return self.get_events()

        results = []

        for event in self.events:

            try:

                text = json.dumps(
                    event,
                    ensure_ascii=False,
                    default=str
                ).lower()

            except (
                TypeError,
                ValueError
            ):

                text = str(
                    event
                ).lower()

            if query in text:

                results.append(
                    self._copy(
                        event
                    )
                )

        return results


    # ==========================================================
    # ПОЛУЧЕНИЕ ПО ИДЕНТИФИКАТОРУ
    # ==========================================================

    def get_by_id(
        self,
        event_id
    ):

        if event_id is None:

            return None

        for event in self.events:

            for key in (
                "id",
                "event_id",
                "uid"
            ):

                if (
                    key in event
                    and str(
                        event.get(
                            key
                        )
                    ) == str(
                        event_id
                    )
                ):

                    return self._copy(
                        event
                    )

        return None

    # ==========================================================
    # УДАЛЕНИЕ ПО ИНДЕКСУ
    # ==========================================================

    def remove_at(
        self,
        index
    ):

        try:

            index = int(
                index
            )

        except (
            TypeError,
            ValueError
        ):

            return None

        if index < 0:

            index = len(
                self.events
            ) + index

        if (
            index < 0
            or index >= len(
                self.events
            )
        ):

            return None

        removed = self.events.pop(
            index
        )

        self._update_state()

        return self._copy(
            removed
        )

    # ==========================================================
    # УДАЛЕНИЕ ПО ID
    # ==========================================================

    def remove_by_id(
        self,
        event_id
    ):

        if event_id is None:

            return False

        for index, event in enumerate(
            self.events
        ):

            for key in (
                "id",
                "event_id",
                "uid"
            ):

                if (
                    key in event
                    and str(
                        event.get(
                            key
                        )
                    ) == str(
                        event_id
                    )
                ):

                    self.events.pop(
                        index
                    )

                    self._update_state()

                    return True

        return False

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):

        removed = len(
            self.events
        )

        self.events.clear()

        self.last_event = None

        self._update_state()

        self.log(
            "Security Event Store очищен. "
            f"Удалено событий: {removed}"
        )

        return removed

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self
    ):

        statistics = {

            "total": len(
                self.events
            ),

            "total_added": self.total_added,

            "types": {},

            "levels": {},

            "sources": {},

        }

        for event in self.events:

            event_type = str(
                event.get(
                    "type",
                    "unknown"
                )
            )

            level = str(
                event.get(
                    "level",
                    "unknown"
                )
            )

            source = str(
                event.get(
                    "source",
                    "unknown"
                )
            )

            statistics[
                "types"
            ][event_type] = (
                statistics[


            "types"
                ].get(
                    event_type,
                    0
                ) + 1
            )

            statistics[
                "levels"
            ][level] = (
                statistics[
                    "levels"
                ].get(
                    level,
                    0
                ) + 1
            )

            statistics[
                "sources"
            ][source] = (
                statistics[
                    "sources"
                ].get(
                    source,
                    0
                ) + 1
            )

        return statistics

    # ==========================================================
    # ЭКСПОРТ В JSON-СТРОКУ
    # ==========================================================

    def export_json(
        self,
        indent=2
    ):

        try:

            return json.dumps(
                self.events,
                ensure_ascii=False,
                indent=indent,
                default=str
            )

        except (
            TypeError,
            ValueError
        ):

            return "[]"

    # ==========================================================
    # ИМПОРТ ИЗ JSON
    # ==========================================================

    def import_json(
        self,
        data,
        replace=False
    ):

        if not isinstance(
            data,
            str
        ):

            return []

        try:

            parsed = json.loads(
                data
            )

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError
        ):

            return []

        if isinstance(
            parsed,
            dict
        ):

            parsed = [
                parsed
            ]

        if not isinstance(
            parsed,
            list
        ):

            return []

        if replace:

            self.events.clear()

        added = self.add_events(
            parsed
        )

        self._update_state()

        return added

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(
        self
    ):

        return {

            "count": len(
                self.events
            ),

            "total_added": self.total_added,

            "last_event": self._copy(
                self.last_event
            ),

        }

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

            "events": statistics[
                "total"
            ],

            "total_added": statistics[
                "total_added"
            ],

            "max_events": self.max_events,

            "types": statistics[
                "types"
            ],

            "levels": statistics[
                "levels"
            ],

            "sources": statistics[
                "sources"
            ],

        }

    # ==========================================================
    # ИЗМЕНЕНИЕ ЛИМИТА
    # ==========================================================

    def set_max_events(
        self,
        max_events
    ):

        try:

            max_events = int(
                max_events
            )

        except (
            TypeError,
            ValueError
        ):

            return self.max_events

        if max_events < 1:

            return self.max_events

        self.max_events = max_events

        self._enforce_limit()

        self._update_state()

        return self.max_events

    # ==========================================================
    # ПРОВЕРКА НАЛИЧИЯ СОБЫТИЙ
    # ==========================================================


    def has_events(
        self
    ):

        return bool(
            self.events
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ СЫРОГО КОЛИЧЕСТВА
    # ==========================================================

    def __len__(
        self
    ):

        return len(
            self.events
        )

    # ==========================================================
    # ПРЕДСТАВЛЕНИЕ
    # ==========================================================

    def __repr__(
        self
    ):

        return (
            f"SecurityEventStore("
            f"events={len(self.events)}, "
            f"max_events={self.max_events})"
        )