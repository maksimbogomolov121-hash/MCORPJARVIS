"""
ioc_engine.py

JARVIS Security Core V3.5

IOC Engine — работа с Indicators of Compromise.

Назначение:
- хранение IOC;
- добавление IOC;
- удаление IOC;
- поиск IOC;
- проверка событий на совпадения;
- проверка IP;
- проверка доменов;
- проверка хэшей;
- проверка имён файлов;
- получение совпадений;
- статистика;
- экспорт и импорт JSON.

Модуль не выполняет сетевое сканирование.
Он работает только с IOC, которые были переданы ему Security Core.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
import copy
import hashlib
import ipaddress
import json
import re


class IOCError(Exception):
    """Базовая ошибка IOC Engine."""


class IOCEngine:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        logger=None,
        max_iocs=10000
    ):

        self.logger = logger

        try:
            max_iocs = int(
                max_iocs
            )
        except (
            TypeError,
            ValueError
        ):

            max_iocs = 10000

        if max_iocs < 1:

            max_iocs = 10000

        self.max_iocs = max_iocs

        self.iocs = []

        self.total_added = 0

        self.total_matches = 0

        self.last_matches = []

        self.last_result = {

            "matches": 0,

            "total_iocs": 0,

        }

        self.log(
            "IOC Engine V3.5 инициализирован."
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
    # ВРЕМЯ
    # ==========================================================

    def _timestamp(
        self
    ):

        return datetime.now().isoformat(
            timespec="seconds"
        )

    # ==========================================================
    # ОПРЕДЕЛЕНИЕ ТИПА IOC
    # ==========================================================

    def detect_type(
        self,
        value
    ):

        if value is None:

            return "unknown"

        value = str(
            value
        ).strip()

        if not value:

            return "unknown"

        # ------------------------------------------------------
        # IPv4 / IPv6
        # ------------------------------------------------------

        try:

            ipaddress.ip_address(
                value
            )

            return "ip"

        except ValueError:

            pass

        # ------------------------------------------------------
        # MD5
        # ------------------------------------------------------

        if re.fullmatch(
            r"[a-fA-F0-9]{32}",
            value
        ):

            return "hash_md5"

        # ------------------------------------------------------
        # SHA1
        # ------------------------------------------------------

        if re.fullmatch(
            r"[a-fA-F0-9]{40}",
            value
        ):

            return "hash_sha1"

        # ------------------------------------------------------
        # SHA256
        # ------------------------------------------------------

        if re.fullmatch(
            r"[a-fA-F0-9]{64}",
            value
        ):

            return "hash_sha256"

        # ------------------------------------------------------
        # SHA512
        # ------------------------------------------------------

        if re.fullmatch(
            r"[a-fA-F0-9]{128}",
            value
        ):

            return "hash_sha512"

        # ------------------------------------------------------
        # DOMAIN
        # ------------------------------------------------------

        domain_pattern = (
            r"^(?=.{1,253}$)"
            r"(?:[a-zA-Z0-9]"
            r"(?:[a-zA-Z0-9-]{0,61}"
            r"[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,63}$"
        )

        if re.fullmatch(
            domain_pattern,
            value
        ):

            return "domain"

        # ------------------------------------------------------
        # URL
        # ------------------------------------------------------

        if re.match(
            r"^https?://",
            value,
            re.IGNORECASE
        ):

            return "url"

        # ------------------------------------------------------
        # EMAIL
        # ------------------------------------------------------

        if re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value
        ):

            return "email"

        return "string"

    # ==========================================================
    # НОРМАЛИЗАЦИЯ ТИПА
    # ==========================================================

    def _normalize_type(
        self,
        ioc_type
    ):

        if ioc_type is None:

            return None

        value = str(
            ioc_type
        ).strip().lower()

        aliases = {

            "ipv4": "ip",
            "ipv6": "ip",
            "ip_address": "ip",
            "ip-address": "ip",

            "md5": "hash_md5",

            "sha1": "hash_sha1",

            "sha-1": "hash_sha1",

            "sha256": "hash_sha256",

            "sha-256": "hash_sha256",

            "sha512": "hash_sha512",

            "sha-512": "hash_sha512",

            "hostname": "domain",

            "uri": "url",

        }

        return aliases.get(
            value,
            value
        )

    # ==========================================================
    # НОРМАЛИЗАЦИЯ ЗНАЧЕНИЯ
    # ==========================================================

    def _normalize_value(
        self,
        value,
        ioc_type=None
    ):

        if value is None:

            return ""

        value = str(
            value
        ).strip()

        normalized_type = (
            self._normalize_type(
                ioc_type
            )
        )

        if normalized_type in (
            "hash_md5",
            "hash_sha1",
            "hash_sha256",
            "hash_sha512"
        ):

            return value.lower()

        if normalized_type in (
            "domain",
            "url",
            "email"
        ):

            return value.lower()

        return value

    # ==========================================================
    # ПРОВЕРКА IOC
    # ==========================================================

    def validate_ioc(
        self,
        value,
        ioc_type=None
    ):

        if value is None:

            return False


            value = str(
            value
        ).strip()

        if not value:

            return False

        detected = self.detect_type(
            value
        )

        normalized_type = (
            self._normalize_type(
                ioc_type
            )
        )

        if normalized_type is None:

            return True

        if normalized_type == "ip":

            try:

                ipaddress.ip_address(
                    value
                )

                return True

            except ValueError:

                return False

        if normalized_type == "hash_md5":

            return bool(
                re.fullmatch(
                    r"[a-fA-F0-9]{32}",
                    value
                )
            )

        if normalized_type == "hash_sha1":

            return bool(
                re.fullmatch(
                    r"[a-fA-F0-9]{40}",
                    value
                )
            )

        if normalized_type == "hash_sha256":

            return bool(
                re.fullmatch(
                    r"[a-fA-F0-9]{64}",
                    value
                )
            )

        if normalized_type == "hash_sha512":

            return bool(
                re.fullmatch(
                    r"[a-fA-F0-9]{128}",
                    value
                )
            )

        if normalized_type == "domain":

            return detected == "domain"

        if normalized_type == "url":

            return bool(
                re.match(
                    r"^https?://",
                    value,
                    re.IGNORECASE
                )
            )

        if normalized_type == "email":

            return bool(
                re.fullmatch(
                    r"[^@\s]+@[^@\s]+\.[^@\s]+",
                    value
                )
            )

        return True

    # ==========================================================
    # ДОБАВЛЕНИЕ IOC
    # ==========================================================

    def add_ioc(
        self,
        value,
        ioc_type=None,
        source="manual",
        severity="medium",
        description="",
        tags=None,
        metadata=None
    ):

        if value is None:

            return None

        value = str(
            value
        ).strip()

        if not value:

            return None

        if ioc_type is None:

            ioc_type = self.detect_type(
                value
            )

        ioc_type = self._normalize_type(
            ioc_type
        )

        if not self.validate_ioc(
            value,
            ioc_type
        ):

            self.log(
                f"Некорректный IOC: {value}"
            )

            return None

        normalized_value = (
            self._normalize_value(
                value,
                ioc_type
            )
        )

        # ------------------------------------------------------
        # Защита от дубликатов
        # ------------------------------------------------------

        for existing in self.iocs:

            if (
                existing.get(
                    "type"
                ) == ioc_type
                and existing.get(
                    "value"
                ) == normalized_value
            ):

                return self._copy(
                    existing
                )

        if tags is None:

            tags = []

        if not isinstance(
            tags,
            list
        ):

            tags = [
                str(tags)
            ]

        if metadata is None:

            metadata = {}

        if not isinstance(
            metadata,
            dict
        ):

            metadata = {}

        ioc = {

            "id": self._generate_id(
                normalized_value,
                ioc_type
            ),

            "value": normalized_value,

            "type": ioc_type,

            "source": str(


source
            ),

            "severity": str(
                severity
            ).lower(),

            "description": str(
                description
            ),

            "tags": self._copy(
                tags
            ),

            "metadata": self._copy(
                metadata
            ),

            "created_at": self._timestamp(),

        }

        self.iocs.append(
            ioc
        )

        self.total_added += 1

        self._enforce_limit()

        return self._copy(
            ioc
        )

    # ==========================================================
    # ГЕНЕРАЦИЯ ID
    # ==========================================================

    def _generate_id(
        self,
        value,
        ioc_type
    ):

        raw = (
            f"{ioc_type}:{value}"
        )

        return hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

    # ==========================================================
    # ДОБАВЛЕНИЕ СПИСКА IOC
    # ==========================================================

    def add_iocs(
        self,
        iocs
    ):

        if iocs is None:

            return []

        if isinstance(
            iocs,
            dict
        ):

            iocs = [
                iocs
            ]

        if not isinstance(
            iocs,
            (list, tuple)
        ):

            return []

        added = []

        for item in iocs:

            if isinstance(
                item,
                dict
            ):

                value = item.get(
                    "value"
                )

                result = self.add_ioc(

                    value,

                    item.get(
                        "type"
                    ),

                    item.get(
                        "source",
                        "manual"
                    ),

                    item.get(
                        "severity",
                        "medium"
                    ),

                    item.get(
                        "description",
                        ""
                    ),

                    item.get(
                        "tags"
                    ),

                    item.get(
                        "metadata"
                    )

                )

            else:

                result = self.add_ioc(
                    item
                )

            if result is not None:

                added.append(
                    result
                )

        return self._copy(
            added
        )

    # ==========================================================
    # АЛИАСЫ
    # ==========================================================

    def add(
        self,
        value,
        ioc_type=None,
        **kwargs
    ):

        return self.add_ioc(
            value,
            ioc_type,
            **kwargs
        )

    def register(
        self,
        value,
        ioc_type=None,
        **kwargs
    ):

        return self.add_ioc(
            value,
            ioc_type,
            **kwargs
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ IOC
    # ==========================================================

    def get_iocs(
        self,
        ioc_type=None,
        limit=None
    ):

        normalized_type = (
            self._normalize_type(
                ioc_type
            )
        )

        results = []

        for ioc in self.iocs:

            if (
                normalized_type is not None
                and ioc.get(
                    "type"
                ) != normalized_type
            ):

                continue

            results.append(
                self._copy(
                    ioc
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
    # ПОЛУЧЕНИЕ ПО ID
    # ==========================================================

    def get_by_id(
        self,
        ioc_id
    ):

        if ioc_id is None:

            return None

        for ioc in self.iocs:

            if str(
                ioc.get(
                    "id"
                )
            ) == str(
                ioc_id
            ):

                return self._copy(
                    ioc
                )

        return None

    # ==========================================================
    # ПОИСК IOC
    # ==========================================================

    def find(
        self,
        value
    ):

        if value is None:

            return []

        normalized_value = str(
            value
        ).strip().lower()

        results = []

        for ioc in self.iocs:

            current = str(
                ioc.get(
                    "value",
                    ""
                )
            ).lower()

            if current == normalized_value:

                results.append(
                    self._copy(
                        ioc
                    )
                )

        return results

    # ==========================================================
    # УДАЛЕНИЕ IOC
    # ==========================================================

    def remove_ioc(
        self,
        value,
        ioc_type=None
    ):

        normalized_type = (
            self._normalize_type(
                ioc_type
            )
        )

        normalized_value = (
            self._normalize_value(
                value,
                normalized_type
            )
        )

        for index, ioc in enumerate(
            self.iocs
        ):

            if (
                ioc.get(
                    "value"
                ) == normalized_value
                and (
                    normalized_type is None
                    or ioc.get(
                        "type"
                    ) == normalized_type
                )
            ):

                self.iocs.pop(
                    index
                )

                return True

        return False

    def remove_by_id(
        self,
        ioc_id
    ):

        if ioc_id is None:

            return False

        for index, ioc in enumerate(
            self.iocs
        ):

            if str(
                ioc.get(
                    "id"
                )
            ) == str(
                ioc_id
            ):

                self.iocs.pop(
                    index
                )

                return True

        return False

    # ==========================================================
    # ПРОВЕРКА ЗНАЧЕНИЯ
    # ==========================================================

    def match(
        self,
        value,
        ioc_type=None
    ):

        if value is None:

            return []

        normalized_type = (
            self._normalize_type(
                ioc_type
            )
        )

        normalized_value = (
            self._normalize_value(
                value,
                normalized_type
            )
        )

        matches = []

        for ioc in self.iocs:

            if (
                ioc.get(
                    "value"
                ) != normalized_value
            ):

                continue

            if (
                normalized_type is not None
                and ioc.get(
                    "type"
                ) != normalized_type
            ):

                continue

            matches.append(


self._copy(
                    ioc
                )
            )

        return matches

    # ==========================================================
    # ПРОВЕРКА СОБЫТИЯ
    # ==========================================================

    def match_event(
        self,
        event
    ):

        if not isinstance(
            event,
            dict
        ):

            return []

        matches = []

        # ------------------------------------------------------
        # Явные IOC-поля
        # ------------------------------------------------------

        fields = (

            "ip",
            "source_ip",
            "destination_ip",
            "remote_ip",
            "local_ip",

            "domain",
            "hostname",

            "url",

            "md5",
            "sha1",
            "sha256",
            "sha512",

            "file_hash",
            "hash",

            "file_name",
            "filename",

        )

        for field in fields:

            if field not in event:

                continue

            value = event.get(
                field
            )

            if value is None:

                continue

            detected_type = None

            field_lower = field.lower()

            if "md5" in field_lower:

                detected_type = "hash_md5"

            elif "sha1" in field_lower:

                detected_type = "hash_sha1"

            elif "sha256" in field_lower:

                detected_type = "hash_sha256"

            elif "sha512" in field_lower:

                detected_type = "hash_sha512"

            elif "hash" in field_lower:

                detected_type = self.detect_type(
                    value
                )

            elif (
                "ip" in field_lower
            ):

                detected_type = "ip"

            elif (
                "domain" in field_lower
                or "hostname" in field_lower
            ):

                detected_type = "domain"

            elif field_lower == "url":

                detected_type = "url"

            elif (
                "file" in field_lower
                and (
                    "name" in field_lower
                    or "filename" in field_lower
                )
            ):

                detected_type = "string"

            field_matches = self.match(
                value,
                detected_type
            )

            for match in field_matches:

                result = self._copy(
                    match
                )

                result[
                    "matched_field"
                ] = field

                matches.append(
                    result
                )

        # ------------------------------------------------------
        # Поиск IOC внутри текста
        # ------------------------------------------------------

        text_parts = []

        for key, value in event.items():

            if isinstance(
                value,
                (str, int, float)
            ):

                text_parts.append(
                    str(value)
                )

        text = " ".join(
            text_parts
        ).lower()

        if text:

            for ioc in self.iocs:

                value = str(
                    ioc.get(
                        "value",
                        ""
                    )
                ).lower()

                if not value:

                    continue

                if value in text:

                    already_exists = False

                    for existing in matches:

                        if (
                            existing.get(
                                "id"
                            )
                            == ioc.get(
                                "id"
                            )
                        ):

                            already_exists = True

                            break

                        if not already_exists:


                         result = self._copy(
                            ioc
                        )

                        result[
                            "matched_field"
                        ] = "text"

                        matches.append(
                            result
                        )

        self.last_matches = self._copy(
            matches
        )

        self.total_matches += len(
            matches
        )

        self.last_result = {

            "matches": len(
                matches
            ),

            "total_iocs": len(
                self.iocs
            ),

        }

        return self._copy(
            matches
        )

    # ==========================================================
    # ПРОВЕРКА СПИСКА СОБЫТИЙ
    # ==========================================================

    def match_events(
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

        results = []

        for event in events:

            matches = self.match_event(
                event
            )

            if matches:

                results.append({

                    "event": self._copy(
                        event
                    ),

                    "matches": self._copy(
                        matches
                    ),

                })

        return results

    # ==========================================================
    # СПЕЦИАЛЬНАЯ ПРОВЕРКА IP
    # ==========================================================

    def check_ip(
        self,
        ip
    ):

        return self.match(
            ip,
            "ip"
        )

    # ==========================================================
    # СПЕЦИАЛЬНАЯ ПРОВЕРКА ДОМЕНА
    # ==========================================================

    def check_domain(
        self,
        domain
    ):

        return self.match(
            domain,
            "domain"
        )

    # ==========================================================
    # СПЕЦИАЛЬНАЯ ПРОВЕРКА ХЭША
    # ==========================================================

    def check_hash(
        self,
        file_hash
    ):

        detected_type = self.detect_type(
            file_hash
        )

        if not detected_type.startswith(
            "hash_"
        ):

            return []

        return self.match(
            file_hash,
            detected_type
        )

    # ==========================================================
    # СПЕЦИАЛЬНАЯ ПРОВЕРКА ФАЙЛА
    # ==========================================================

    def check_file(
        self,
        file_path,
        file_hash=None
    ):

        matches = []

        if file_hash:

            matches.extend(
                self.check_hash(
                    file_hash
                )
            )

        if file_path:

            path = str(
                file_path
            )

            filename = (
                path.replace(
                    "\\",
                    "/"
                ).split(
                    "/"
                )[-1]
            )

            for ioc in self.iocs:

                if ioc.get(
                    "value",
                    ""
                ).lower() == filename.lower():

                    result = self._copy(
                        ioc
                    )

                    result[
                        "matched_field"
                    ] = "file_name"

                    matches.append(
                        result
                    )

        return self._copy(
            matches
        )

    # ==========================================================
    # ПОСЛЕДНИЕ СОВПАДЕНИЯ
    # ==========================================================

    def get_last_matches(
        self
    ):

        return self._copy(
            self.last_matches
        )

    # ==========================================================
    # СТАТИСТИКА
    # ==========================================================

    def get_statistics(
        self
    ):

        statistics = {

            "total": len(
                self.iocs
            ),

            "total_added": self.total_added,

            "total_matches": self.total_matches,

            "types": {},

            "severities": {},

            "sources": {},

        }

        for ioc in self.iocs:

            ioc_type = str(
                ioc.get(
                    "type",
                    "unknown"
                )
            )

            severity = str(
                ioc.get(
                    "severity",
                    "unknown"
                )
            )

            source = str(
                ioc.get(
                    "source",
                    "unknown"
                )
            )

            statistics[
                "types"
            ][ioc_type] = (
                statistics[
                    "types"
                ].get(
                    ioc_type,
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
    # ОГРАНИЧЕНИЕ РАЗМЕРА
    # ==========================================================

    def _enforce_limit(
        self
    ):

        if len(
            self.iocs
        ) <= self.max_iocs:

            return

        excess = (
            len(
                self.iocs
            )
            - self.max_iocs
        )

        if excess > 0:

            del self.iocs[
                0:excess
            ]

    # ==========================================================
    # КОЛИЧЕСТВО IOC
    # ==========================================================

    def count(
        self,
        ioc_type=None
    ):

        return len(
            self.get_iocs(
                ioc_type
            )
        )

    # ==========================================================
    # ПРОВЕРКА НАЛИЧИЯ
    # ==========================================================

    def has_ioc(
        self,
        value,
        ioc_type=None
    ):

        return bool(
            self.match(
                value,
                ioc_type
            )
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(
        self
    ):

        removed = len(
            self.iocs
        )

        self.iocs.clear()

        self.last_matches = []

        self.last_result = {

            "matches": 0,

            "total_iocs": 0,

        }

        self.log(
            "IOC Engine очищен. "
            f"Удалено IOC: {removed}"
        )

        return removed

    # ==========================================================
    # ЭКСПОРТ JSON
    # ==========================================================

    def export_json(
        self,
        indent=2
    ):

        try:

            return json.dumps(
                self.iocs,
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
    # ИМПОРТ JSON
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

            self.iocs.clear()

        added = self.add_iocs(
            parsed
        )

        self._enforce_limit()

        return added

    # ==========================================================
    # ИЗМЕНЕНИЕ ЛИМИТА
    # ==========================================================

    def set_max_iocs(
        self,
        max_iocs
    ):

        try:

            max_iocs = int(
                max_iocs
            )

        except (
            TypeError,
            ValueError
        ):

            return self.max_iocs

        if max_iocs < 1:

            return self.max_iocs

        self.max_iocs = max_iocs

        self._enforce_limit()

        return self.max_iocs

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(
        self
    ):

        return {

            "matches": len(
                self.last_matches
            ),

            "total_iocs": len(
                self.iocs
            ),

            "total_matches": self.total_matches,

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

            "iocs": statistics[
                "total"
            ],

            "total_added": statistics[
                "total_added"
            ],

            "total_matches": statistics[
                "total_matches"
            ],

            "max_iocs": self.max_iocs,

            "types": statistics[
                "types"
            ],

            "severities": statistics[
                "severities"
            ],

            "sources": statistics[
                "sources"
            ],

            "last_matches": len(
                self.last_matches
            ),

        }

    # ==========================================================
    # ПРЕДСТАВЛЕНИЕ
    # ==========================================================

    def __len__(
        self
    ):

        return len(
            self.iocs
        )

    def __repr__(
        self
    ):

        return (
            f"IOCEngine("
            f"iocs={len(self.iocs)}, "
            f"max_iocs={self.max_iocs})"
        )


# ==============================================================
# АЛИАС
# ==============================================================

IOCManager = IOCEngine
IOCStore = IOCEngine