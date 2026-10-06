"""
behavior_engine.py
Поведенческий анализ JARVIS Security Core.

V2.0 — Behavior Engine.

Задача:
- принимать события поведения;
- начислять Risk Score;
- хранить историю событий;
- определять уровень риска;
- формировать объяснение, почему объект стал подозрительным.

Важно:
Behavior Engine сам ничего не удаляет, не блокирует
и не помещает в карантин.
"""


class BehaviorEngine:

    # ==========================================================
    # Уровни риска
    # ==========================================================

    LOW_SCORE = 0
    MEDIUM_SCORE = 30
    SUSPICIOUS_SCORE = 50
    HIGH_SCORE = 70

    def __init__(self, logger=None):

        self.logger = logger

        # ======================================================
        # История событий
        # ======================================================

        self.events = []

        # ======================================================
        # Состояние объектов
        #
        # Формат:
        # {
        #     "object": {
        #         "score": 20,
        #         "events": [...]
        #     }
        # }
        # ======================================================

        self.objects = {}

        self.log(
            "Behavior Engine инициализирован."
        )

    # ==========================================================
    # Добавление события
    # ==========================================================

    def add_event(
        self,
        object_name,
        event_type,
        description="",
        score=0,
        severity=None
    ):

        if not object_name:

            return None

        if not event_type:

            return None

        try:

            score = int(score)

        except (
            TypeError,
            ValueError
        ):

            score = 0

        if score < 0:

            score = 0

        # ======================================================
        # Формируем событие
        # ======================================================

        event = {

            "object":
                str(object_name),

            "event_type":
                str(event_type),

            "description":
                str(description),

            "score":
                score,

            "severity":
                severity,

        }

        # ======================================================
        # История
        # ======================================================

        self.events.append(
            event
        )

        # ======================================================
        # Создаём объект
        # ======================================================

        if object_name not in self.objects:

            self.objects[object_name] = {

                "score": 0,

                "events": []

            }

        # ======================================================
        # Добавляем событие объекту
        # ======================================================

        self.objects[
            object_name
        ]["events"].append(
            event
        )

        # ======================================================
        # Увеличиваем Risk Score
        # ======================================================

        self.objects[
            object_name
        ]["score"] += score

        # ======================================================
        # Определяем уровень
        # ======================================================

        current_score = (
            self.objects[
                object_name
            ]["score"]
        )

        level = self.get_risk_level(
            current_score
        )

        self.log(
            f"Behavior Event: "
            f"{object_name} | "
            f"{event_type} | "
            f"+{score} | "
            f"Risk Score: {current_score} | "
            f"Уровень: {level}"
        )

        return event


    # ==========================================================
    # Определение уровня риска
    # ==========================================================

    def get_risk_level(self, score):

        try:

            score = int(score)

        except (
            TypeError,
            ValueError
        ):

            score = 0

        if score >= self.HIGH_SCORE:

            return "ВЫСОКИЙ"

        if score >= self.SUSPICIOUS_SCORE:

            return "ПОДОЗРИТЕЛЬНЫЙ"

        if score >= self.MEDIUM_SCORE:

            return "СРЕДНИЙ"

        return "НИЗКИЙ"

    # ==========================================================
    # Получение Risk Score объекта
    # ==========================================================

    def get_score(self, object_name):

        if object_name not in self.objects:

            return 0

        return self.objects[
            object_name
        ].get(
            "score",
            0
        )

    # ==========================================================
    # Получение уровня объекта
    # ==========================================================

    def get_level(self, object_name):

        score = self.get_score(
            object_name
        )

        return self.get_risk_level(
            score
        )

    # ==========================================================
    # Получение событий объекта
    # ==========================================================

    def get_object_events(
        self,
        object_name
    ):

        if object_name not in self.objects:

            return []

        return list(
            self.objects[
                object_name
            ].get(
                "events",
                []
            )
        )

    # ==========================================================
    # Получение всех объектов
    # ==========================================================

    def get_objects(self):

        return list(
            self.objects.keys()
        )

    # ==========================================================
    # Получение подозрительных объектов
    # ==========================================================

    def get_suspicious_objects(
        self,
        minimum_score=50
    ):

        suspicious = []

        for object_name, data in (
            self.objects.items()
        ):

            score = data.get(
                "score",
                0
            )

            if score >= minimum_score:

                suspicious.append({

                    "object":
                        object_name,

                    "score":
                        score,

                    "level":
                        self.get_risk_level(
                            score
                        ),

                    "events":
                        list(
                            data.get(
                                "events",
                                []
                            )
                        )

                })

        return suspicious

    # ==========================================================
    # Получение объектов высокого риска
    # ==========================================================

    def get_high_risk_objects(self):

        return self.get_suspicious_objects(
            self.HIGH_SCORE
        )

    # ==========================================================
    # Анализ объекта
    # ==========================================================

    def analyze_object(
        self,
        object_name
    ):

        if object_name not in self.objects:

            return {

                "object":
                    object_name,

                "score":
                    0,

                "level":
                    "НИЗКИЙ",

                "events":
                    [],

                "reasons":
                    []

            }

        data = self.objects[
            object_name


]

        events = list(
            data.get(
                "events",
                []
            )
        )

        reasons = []

        for event in events:

            description = event.get(
                "description",
                ""
            )

            event_type = event.get(
                "event_type",
                ""
            )

            if description:

                reasons.append(
                    description
                )

            elif event_type:

                reasons.append(
                    event_type
                )

        return {

            "object":
                object_name,

            "score":
                data.get(
                    "score",
                    0
                ),

            "level":
                self.get_risk_level(
                    data.get(
                        "score",
                        0
                    )
                ),

            "events":
                events,

            "reasons":
                reasons

        }

    # ==========================================================
    # Анализ всех объектов
    # ==========================================================

    def analyze_all(self):

        results = []

        for object_name in (
            self.objects
        ):

            results.append(
                self.analyze_object(
                    object_name
                )
            )

        return results

    # ==========================================================
    # Общая статистика
    # ==========================================================

    def get_statistics(self):

        statistics = {

            "objects":
                len(self.objects),

            "events":
                len(self.events),

            "low":
                0,

            "medium":
                0,

            "suspicious":
                0,

            "high":
                0,

        }

        for object_name in (
            self.objects
        ):

            level = self.get_level(
                object_name
            )

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
    # Последние события
    # ==========================================================

    def get_events(
        self,
        limit=None
    ):

        if limit is None:

            return list(
                self.events
            )

        try:

            limit = int(limit)

        except (
            TypeError,
            ValueError
        ):

            return list(
                self.events
            )

        if limit <= 0:

            return []

        return list(
            self.events[-limit:]
        )

    # ==========================================================
    # Сброс конкретного объекта
    # ==========================================================

    def clear_object(
        self,
        object_name
    ):

        if object_name not in self.objects:

            return False

        del self.objects[
            object_name
        ]

        self.log(
            f"Поведенческий профиль "
            f"очищен: {object_name}"
        )

        return True

    # ==========================================================
    # Полный сброс
    # ==========================================================

    def clear(self):

        self.events.clear()

        self.objects.clear()

        self.log(
            "История Behavior Engine очищена."
        )

    # ==========================================================
    # Сводка
    # ==========================================================

    def get_summary(self):

        statistics = (
            self.get_statistics()
        )

        return {

            "objects":
                statistics["objects"],

            "events":
                statistics["events"],

            "low":
                statistics["low"],

            "medium":
                statistics["medium"],

            "suspicious":
                statistics["suspicious"],

            "high":
                statistics["high"],

        }

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

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