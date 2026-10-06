"""
threat_chain.py

JARVIS Security Core V3.2

Модуль построения цепочек атак.

Назначение:
- принимает события Security Core / Correlation Engine;
- ищет связанные события;
- группирует их в цепочки;
- определяет стадии потенциальной атаки;
- рассчитывает оценку цепочки;
- определяет уровень цепочки;
- формирует описание;
- хранит последние найденные цепочки.

Модуль является аналитическим.
Он не выполняет никаких действий над системой.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


class ThreatChain:

    # ==========================================================
    # СТАДИИ ПОТЕНЦИАЛЬНОЙ АТАКИ
    # ==========================================================

    STAGES = {

        "reconnaissance": {
            "weight": 10,
            "names": {
                "scan",
                "network_scan",
                "port_scan",
                "discovery",
                "reconnaissance",
                "enumeration",
            },
        },

        "execution": {
            "weight": 25,
            "names": {
                "execution",
                "execute",
                "command",
                "script",
                "powershell",
                "cmd",
                "process_execution",
            },
        },

        "persistence": {
            "weight": 30,
            "names": {
                "persistence",
                "startup",
                "startup_change",
                "autorun",
                "scheduled_task",
                "service",
                "registry_run",
            },
        },

        "privilege_escalation": {
            "weight": 35,
            "names": {
                "privilege_escalation",
                "elevation",
                "admin",
                "administrator",
                "privilege",
            },
        },

        "defense_evasion": {
            "weight": 35,
            "names": {
                "defense_evasion",
                "evasion",
                "disable_security",
                "security_disabled",
                "tampering",
            },
        },

        "credential_access": {
            "weight": 40,
            "names": {
                "credential_access",
                "credential",
                "password",
                "token",
                "credential_dump",
            },
        },

        "discovery": {
            "weight": 15,
            "names": {
                "discovery",
                "system_discovery",
                "process_discovery",
                "file_discovery",
                "network_discovery",
            },
        },

        "lateral_movement": {
            "weight": 40,
            "names": {
                "lateral_movement",
                "remote_access",
                "remote_execution",
                "smb",
                "rdp",
                "winrm",
            },
        },

        "collection": {
            "weight": 25,
            "names": {
                "collection",
                "data_collection",
                "archive",
                "staging",
            },
        },

        "command_and_control": {
            "weight": 45,
            "names": {
                "command_and_control",
                "c2",
                "beacon",
                "external_connection",
                "network_connection",
            },
        },

        "exfiltration": {
            "weight": 50,
            "names": {
                "exfiltration",
                "data_exfiltration",
                "upload",
                "outbound_transfer",
            },
        },

        "impact": {
            "weight": 70,
            "names": {
                "impact",
                "ransomware",
                "encryption",
                "destruction",
                "delete",
                "wipe",
            },
        },
    }


    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None
    ):

        self.logger = logger

        self.last_chains = []

        self.last_events = []

        self.last_result = {

            "chains": [],

            "count": 0,

            "events": 0,

        }

        self.log(
            "Threat Chain V3.2 инициализирован."
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
    # НОРМАЛИЗАЦИЯ СОБЫТИЙ
    # ==========================================================

    def _normalize_events(
        self,
        events
    ):

        if events is None:

            return []

        if isinstance(
            events,
            dict
        ):

            return [
                dict(events)
            ]

        if not isinstance(
            events,
            (list, tuple)
        ):

            return []

        normalized = []

        for event in events:

            if not isinstance(
                event,
                dict
            ):

                continue

            normalized.append(
                dict(event)
            )

        return normalized

    # ==========================================================
    # ПОЛУЧЕНИЕ СТРОКОВЫХ ЗНАЧЕНИЙ СОБЫТИЯ
    # ==========================================================

    def _event_strings(
        self,
        event
    ):

        values = []

        if not isinstance(
            event,
            dict
        ):

            return values

        for key in (
            "type",
            "event_type",
            "action",
            "category",
            "indicator",
            "stage",
            "level",
            "name",
        ):

            value = event.get(
                key
            )

            if isinstance(
                value,
                str
            ):

                values.append(
                    value.lower().strip()
                )

        indicators = event.get(
            "indicators"
        )

        if isinstance(
            indicators,
            (list, tuple, set)
        ):

            for value in indicators:

                if isinstance(
                    value,
                    str
                ):

                    values.append(
                        value.lower().strip()
                    )

        return values

    # ==========================================================
    # ОПРЕДЕЛЕНИЕ СТАДИЙ
    # ==========================================================

    def _detect_stages(
        self,
        event
    ):

        detected = []

        values = self._event_strings(
            event
        )

        for stage_name, stage_data in self.STAGES.items():

            names = stage_data.get(
                "names",
                set()
            )

            for value in values:

                if value in names:

                    if stage_name not in detected:

                        detected.append(
                            stage_name
                        )

                    break

        return detected

    # ==========================================================
    # ИНДИКАТОР СВЯЗИ СОБЫТИЙ
    # ==========================================================

    def _get_identifier(
        self,
        event
    ):

        if not isinstance(
            event,
            dict
        ):

            return None

        for key in (
            "chain_id",
            "correlation_id",
            "session_id",
            "connection_id",
            "process_id",
            "pid",
            "file_hash",
            "hash",
        ):

            value = event.get(
                key
            )

            if value is not None:

                return (
                    key,
                    str(value)
                )

        return None

    # ==========================================================
    # ПОИСК ОБЩЕГО ИДЕНТИФИКАТОРА
    # ==========================================================

    def _same_identifier(
        self,
        first,
        second
    ):

        first_id = self._get_identifier(
            first
        )

        second_id = self._get_identifier(
            second
        )

        if first_id is None:

            return False

        if second_id is None:

            return False

        return first_id == second_id

    # ==========================================================
    # ПОЛУЧЕНИЕ ВРЕМЕНИ СОБЫТИЯ
    # ==========================================================

    def _event_time(
        self,
        event
    ):

        if not isinstance(
            event,
            dict
        ):

            return None

        for key in (
            "timestamp",
            "time",
            "created_at",
            "datetime",
        ):

            value = event.get(
                key
            )

            if isinstance(
                value,
                datetime
            ):

                return value

            if isinstance(
                value,
                str
            ):

                try:

                    return datetime.fromisoformat(
                        value.replace(
                            "Z",
                            "+00:00"
                        )
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    continue

        return None

    # ==========================================================
    # ПРОВЕРКА ВРЕМЕННОЙ БЛИЗОСТИ
    # ==========================================================

    def _events_are_close(
        self,
        first,
        second,
        max_seconds=300
    ):

        first_time = self._event_time(
            first
        )

        second_time = self._event_time(
            second
        )

        if first_time is None:

            return True

        if second_time is None:

            return True

        try:

            difference = abs(
                (
                    second_time
                    - first_time
                ).total_seconds()
            )

        except (
            TypeError,
            ValueError
        ):

            return True

        return difference <= max_seconds

    # ==========================================================
    # СВЯЗАННОСТЬ СОБЫТИЙ
    # ==========================================================

    def _events_related(
        self,
        first,
        second
    ):

        if self._same_identifier(
            first,
            second
        ):

            return True

        if not self._events_are_close(
            first,
            second
        ):

            return False

        first_stages = set(
            self._detect_stages(
                first
            )
        )

        second_stages = set(
            self._detect_stages(
                second
            )
        )

        if first_stages.intersection(
            second_stages
        ):

            return True

        return False


    # ==========================================================
    # СОЗДАНИЕ ГРУПП СОБЫТИЙ
    # ==========================================================

    def _build_groups(
        self,
        events
    ):

        groups = []

        for event in events:

            placed = False

            for group in groups:

                for existing in group:

                    if self._events_related(
                        existing,
                        event
                    ):

                        group.append(
                            event
                        )

                        placed = True

                        break

                if placed:

                    break

            if not placed:

                groups.append(
                    [event]
                )

        return groups

    # ==========================================================
    # ПОДПОРЯДОЧИВАНИЕ СОБЫТИЙ
    # ==========================================================

    def _sort_events(
        self,
        events
    ):

        try:

            return sorted(
                events,
                key=lambda event: (
                    self._event_time(
                        event
                    )
                    or datetime.min
                )
            )

        except (
            TypeError,
            ValueError
        ):

            return list(
                events
            )

    # ==========================================================
    # РАСЧЁТ SCORE ЦЕПОЧКИ
    # ==========================================================

    def _calculate_chain_score(
        self,
        stages
    ):

        score = 0

        for stage in stages:

            stage_data = self.STAGES.get(
                stage,
                {}
            )

            score += int(
                stage_data.get(
                    "weight",
                    0
                )
            )

        # Дополнительный вес за
        # наличие нескольких стадий.

        if len(stages) >= 3:

            score += 10

        if len(stages) >= 5:

            score += 15

        if len(stages) >= 7:

            score += 20

        return max(
            0,
            min(
                100,
                score
            )
        )

    # ==========================================================
    # ОПРЕДЕЛЕНИЕ УРОВНЯ
    # ==========================================================

    def _get_level(
        self,
        score
    ):

        if score >= 70:

            return "CRITICAL"

        if score >= 40:

            return "HIGH"

        if score >= 20:

            return "MEDIUM"

        return "LOW"

    # ==========================================================
    # СОЗДАНИЕ ОДНОЙ ЦЕПОЧКИ
    # ==========================================================

    def _create_chain(
        self,
        events,
        chain_number
    ):

        ordered_events = self._sort_events(
            events
        )

        stages = []

        for event in ordered_events:

            detected = self._detect_stages(
                event
            )

            for stage in detected:

                if stage not in stages:

                    stages.append(
                        stage
                    )

        score = self._calculate_chain_score(
            stages
        )

        level = self._get_level(
            score
        )

        identifier = None

        for event in ordered_events:

            event_identifier = (
                self._get_identifier(
                    event
                )
            )

            if event_identifier:

                identifier = (
                    f"{event_identifier[0]}:"
                    f"{event_identifier[1]}"
                )

                break

        return {

            "chain_id": (
                identifier


            or f"chain-{chain_number}"
            ),

            "events": list(
                ordered_events
            ),

            "event_count": len(
                ordered_events
            ),

            "stages": list(
                stages
            ),

            "stage_count": len(
                stages
            ),

            "score": score,

            "level": level,

        }

    # ==========================================================
    # ОСНОВНОЙ МЕТОД
    # ==========================================================

    def build(
        self,
        events
    ):

        normalized_events = (
            self._normalize_events(
                events
            )
        )

        self.last_events = list(
            normalized_events
        )

        self.log(
            "Начало построения цепочек атак. "
            f"Событий: {len(normalized_events)}"
        )

        if not normalized_events:

            self.last_chains = []

            self.last_result = {

                "chains": [],

                "count": 0,

                "events": 0,

            }

            self.log(
                "Цепочки атак не обнаружены."
            )

            return []

        groups = self._build_groups(
            normalized_events
        )

        chains = []

        for index, group in enumerate(
            groups,
            start=1
        ):

            # Цепочкой считаем группу,
            # в которой есть хотя бы
            # две разные стадии.

            chain = self._create_chain(
                group,
                index
            )

            if chain["stage_count"] >= 2:

                chains.append(
                    chain
                )

        self.last_chains = list(
            chains
        )

        self.last_result = {

            "chains": list(
                chains
            ),

            "count": len(
                chains
            ),

            "events": len(
                normalized_events
            ),

        }

        self.log(
            "Построение цепочек завершено. "
            f"Найдено цепочек: {len(chains)}"
        )

        return list(
            chains
        )

    # ==========================================================
    # АЛЬТЕРНАТИВНЫЕ API
    # ==========================================================

    def analyze(
        self,
        events
    ):

        return self.build(
            events
        )

    def detect(
        self,
        events
    ):

        return self.build(
            events
        )

    def build_chains(
        self,
        events
    ):

        return self.build(
            events
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНИХ ЦЕПОЧЕК
    # ==========================================================

    def get_last_chains(
        self
    ):

        return list(
            self.last_chains
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ПОСЛЕДНЕГО РЕЗУЛЬТАТА
    # ==========================================================

    def get_last_result(
        self
    ):

        return {

            "chains": list(
                self.last_result.get(
                    "chains",
                    []
                )
            ),

            "count": self.last_result.get(
                "count",
                0
            ),

            "events": self.last_result.get(
                "events",
                0
            ),

        }

    # ==========================================================
    # КОЛИЧЕСТВО ЦЕПОЧЕК
    # ==========================================================

    def count(
        self
    ):

        return len(
            self.last_chains
        )

    # ==========================================================
    # НАИБОЛЕЕ ОПАСНАЯ ЦЕПОЧКА
    # ==========================================================

    def get_highest_risk_chain(
        self
    ):

        if not self.last_chains:

            return None

        return max(
            self.last_chains,
            key=lambda chain: chain.get(
                "score",
                0
            )
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):

        self.last_chains = []

        self.last_events = []

        self.last_result = {

            "chains": [],

            "count": 0,

            "events": 0,

        }

        self.log(
            "Threat Chain очищен."
        )

        return self.get_last_result()

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self
    ):

        statistics = {

            "total": len(
                self.last_chains
            ),

            "low": 0,

            "medium": 0,

            "high": 0,

            "critical": 0,

        }

        for chain in self.last_chains:

            level = str(
                chain.get(
                    "level",
                    "LOW"
                )
            ).upper()

            if level == "LOW":

                statistics["low"] += 1

            elif level == "MEDIUM":

                statistics["medium"] += 1

            elif level == "HIGH":

                statistics["high"] += 1

            elif level == "CRITICAL":

                statistics["critical"] += 1

        return statistics

    # ==========================================================
    # ОБЪЯСНЕНИЕ ЦЕПОЧКИ
    # ==========================================================

    def explain_chain(
        self,
        chain
    ):

        if not isinstance(
            chain,
            dict
        ):

            return (
                "Цепочка недоступна."
            )

        chain_id = chain.get(
            "chain_id",
            "unknown"
        )

        score = chain.get(
            "score",
            0
        )

        level = chain.get(
            "level",
            "LOW"
        )

        stages = chain.get(
            "stages",
            []
        )

        if not stages:

            return (
                f"Цепочка {chain_id}: "
                f"значимых стадий не обнаружено."
            )

        return (
            f"Цепочка {chain_id}. "
            f"Уровень: {level}. "
            f"Score: {score}/100. "
            f"Стадии: "
            f"{' → '.join(stages)}."
        )

    # ==========================================================
    # ОБЩЕЕ ОБЪЯСНЕНИЕ
    # ==========================================================

    def get_explanation(
        self
    ):

        if not self.last_chains:

            return (
                "Threat Chain: "
                "цепочки атак не обнаружены."
            )

        explanations = []

        for chain in self.last_chains:

            explanations.append(
                self.explain_chain(
                    chain
                )
            )

        return " ".join(
            explanations
        )