"""
decision_engine.py
JARVIS Security Core V4.1

Decision Engine — движок принятия решений.

Задача:
    Получить результаты анализа V3 и определить,
    какое действие должен выполнить Security Core.

Доступные решения:
    IGNORE
    NOTIFY
    ASK_SANDBOX
    QUARANTINE
    AUTO_DELETE
    BLOCK
    UNKNOWN
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class DecisionEngine:
    VERSION = "4.1"

    DECISION_IGNORE = "IGNORE"
    DECISION_NOTIFY = "NOTIFY"
    DECISION_ASK_SANDBOX = "ASK_SANDBOX"
    DECISION_QUARANTINE = "QUARANTINE"
    DECISION_AUTO_DELETE = "AUTO_DELETE"
    DECISION_BLOCK = "BLOCK"
    DECISION_UNKNOWN = "UNKNOWN"

    def __init__(self, logger=None):
        self.logger = logger

        self.last_input: Dict[str, Any] = {}
        self.last_decision: Dict[str, Any] = {
            "decision": self.DECISION_IGNORE,
            "reason": "Нет данных для анализа.",
            "confidence": 0,
            "requires_user": False,
            "automatic": False,
        }

        self.history: List[Dict[str, Any]] = []

        self.log("Decision Engine V4.1 инициализирован.")

    # ============================================================
    # LOGGING
    # ============================================================

    def log(self, message: str):
        if self.logger is not None:
            if hasattr(self.logger, "info"):
                self.logger.info(message)
                return

            if hasattr(self.logger, "log"):
                self.logger.log(message)
                return

        print(f"[SECURITY DECISION] {message}")

    # ============================================================
    # MAIN
    # ============================================================

    def decide(self, analysis_result: Any) -> Dict[str, Any]:
        """
        Основной метод принятия решения.

        analysis_result может содержать результаты:
        Detection Engine
        IOC Engine
        Correlation Engine
        Threat Chain
        Risk Engine
        """

        self.log("Начало принятия решения.")

        normalized = self._normalize_input(analysis_result)
        self.last_input = dict(normalized)

        decision = self._make_decision(normalized)

        self.last_decision = dict(decision)

        self.history.append(dict(decision))

        # Защита от бесконечного роста памяти.
        if len(self.history) > 100:
            self.history = self.history[-100:]

        self.log(
            f"Решение: {decision['decision']} | "
            f"Причина: {decision['reason']}"
        )

        return dict(decision)

    # ============================================================
    # INPUT NORMALIZATION
    # ============================================================

    @staticmethod
    def _normalize_input(data: Any) -> Dict[str, Any]:

        if data is None:
            return {
                "risk": {},
                "detection": [],
                "ioc": [],
                "correlation": [],
                "threat_chain": [],
                "raw": None,
            }

        if not isinstance(data, dict):
            return {
                "risk": {},
                "detection": [],
                "ioc": [],
                "correlation": [],
                "threat_chain": [],
                "raw": data,
            }

        return {
            "risk": data.get("risk", {}),
            "detection": DecisionEngine._ensure_list(
                data.get("detection", [])
            ),
            "ioc": DecisionEngine._ensure_list(
                data.get("ioc", [])
            ),
            "correlation": DecisionEngine._ensure_list(
                data.get("correlation", [])
            ),
            "threat_chain": DecisionEngine._ensure_list(
                data.get("threat_chain", [])
            ),
            "raw": data,
        }

    @staticmethod
    def _ensure_list(value: Any) -> List[Any]:

        if value is None:
            return []

        if isinstance(value, dict):
            if "results" in value:
                results = value.get("results")

                if isinstance(results, list):
                    return list(results)

                if results is None:
                    return []

                return [results]

            return [value]

        if isinstance(value, (list, tuple)):
            return list(value)

        return [value]

    # ============================================================
    # DECISION LOGIC
    # ============================================================

    def _make_decision(
        self,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:

        risk = data.get("risk", {})

        score = self._get_risk_score(risk)
        level = self._get_risk_level(risk, score)

        detections = data.get("detection", [])
        iocs = data.get("ioc", [])
        correlations = data.get("correlation", [])
        threat_chains = data.get("threat_chain", [])

        malicious = self._contains_malicious_indicator(
            detections,
            iocs,
            correlations,
            threat_chains,
        )

        suspicious = self._contains_suspicious_indicator(
            detections,
            iocs,
            correlations,
            threat_chains,
        )

        file_related = self._is_file_related(
            detections,
            iocs,
            correlations,
            threat_chains,
        )

        # --------------------------------------------------------
        # 1. Подтверждённая вредоносность
        # --------------------------------------------------------

        if malicious:

            if file_related:
                return self._decision(
                    decision=self.DECISION_AUTO_DELETE,
                    reason=(
                        "Угроза подтверждена результатами анализа. "
                        "Файл может быть автоматически удалён "
                        "после прохождения разрешённой политики."
                    ),
                    confidence=100,
                    automatic=True,
                    requires_user=False,
                )

            return self._decision(
                decision=self.DECISION_BLOCK,
                reason=(
                    "Обнаружена подтверждённая вредоносная активность."
                ),
                confidence=100,
                automatic=True,
                requires_user=False,
            )

        # --------------------------------------------------------
        # 2. Подозрительный файл
        # --------------------------------------------------------

        if suspicious and file_related:

            return self._decision(
                decision=self.DECISION_ASK_SANDBOX,
                reason=(
                    "Файл вызывает подозрение, но вредоносность "
                    "ещё не подтверждена. Необходимо предложить "
                    "проверку в Sandbox."
                ),
                confidence=80,
                automatic=False,
                requires_user=True,
            )

        # --------------------------------------------------------
        # 3. Критический риск
        # --------------------------------------------------------

        if level == "CRITICAL" or score >= 70:

            return self._decision(
                decision=self.DECISION_NOTIFY,
                reason=(
                    "Обнаружен критический уровень риска. "
                    "Требуется уведомить пользователя."
                ),
                confidence=90,
                automatic=False,
                requires_user=True,
            )

        # --------------------------------------------------------
        # 4. Высокий риск
        # --------------------------------------------------------

        if level == "HIGH" or score >= 40:


             return self._decision(
                decision=self.DECISION_NOTIFY,
                reason=(
                    "Обнаружен высокий уровень риска. "
                    "Пользователь должен быть уведомлён."
                ),
                confidence=80,
                automatic=False,
                requires_user=True,
            )

        # --------------------------------------------------------
        # 5. Средний риск
        # --------------------------------------------------------

        if level == "MEDIUM" or score >= 20:

            return self._decision(
                decision=self.DECISION_NOTIFY,
                reason=(
                    "Обнаружен средний уровень риска. "
                    "Необходимо уведомить пользователя."
                ),
                confidence=70,
                automatic=False,
                requires_user=True,
            )

        # --------------------------------------------------------
        # 6. Низкий риск
        # --------------------------------------------------------

        return self._decision(
            decision=self.DECISION_IGNORE,
            reason=(
                "Значимой угрозы не обнаружено."
            ),
            confidence=95,
            automatic=False,
            requires_user=False,
        )

    # ============================================================
    # RISK
    # ============================================================

    @staticmethod
    def _get_risk_score(risk: Any) -> int:

        if not isinstance(risk, dict):
            return 0

        try:
            score = int(risk.get("score", 0))
        except (TypeError, ValueError):
            score = 0

        return max(0, min(100, score))

    @staticmethod
    def _get_risk_level(
        risk: Any,
        score: int,
    ) -> str:

        if isinstance(risk, dict):

            level = risk.get("level")

            if isinstance(level, str) and level:
                return level.upper()

        if score >= 70:
            return "CRITICAL"

        if score >= 40:
            return "HIGH"

        if score >= 20:
            return "MEDIUM"

        return "LOW"

    # ============================================================
    # INDICATOR ANALYSIS
    # ============================================================

    @classmethod
    def _contains_malicious_indicator(
        cls,
        detections: List[Any],
        iocs: List[Any],
        correlations: List[Any],
        threat_chains: List[Any],
    ) -> bool:

        all_data = (
            detections
            + iocs
            + correlations
            + threat_chains
        )

        malicious_words = (
            "malicious",
            "malware",
            "confirmed_malware",
            "confirmed malicious",
            "trojan",
            "ransomware",
            "virus",
            "backdoor",
            "rootkit",
            "worm",
            "exploit",
            "confirmed_threat",
        )

        for item in all_data:

            text = cls._item_to_text(item)

            for word in malicious_words:

                if word in text:
                    return True

        return False

    @classmethod
    def _contains_suspicious_indicator(
        cls,
        detections: List[Any],
        iocs: List[Any],
        correlations: List[Any],
        threat_chains: List[Any],
    ) -> bool:

        all_data = (
            detections
            + iocs
            + correlations
            + threat_chains
        )

        suspicious_words = (
            "suspicious",
            "potential",
            "possible",
            "unknown",
            "anomaly",
            "risk",
            "threat",
            "indicator",
            "untrusted",
        )

        for item in all_data:
            text = cls._item_to_text(item)

            for word in suspicious_words:
                if word in text:
                    return True

        return False

    @staticmethod
    def _item_to_text(item: Any) -> str:

        if isinstance(item, dict):

            parts = []

            for key, value in item.items():

                parts.append(str(key).lower())
                parts.append(str(value).lower())

            return " ".join(parts)

        return str(item).lower()

    # ============================================================
    # FILE DETECTION
    # ============================================================

    @classmethod
    def _is_file_related(
        cls,
        detections: List[Any],
        iocs: List[Any],
        correlations: List[Any],
        threat_chains: List[Any],
    ) -> bool:

        all_data = (
            detections
            + iocs
            + correlations
            + threat_chains
        )

        file_words = (
            "file",
            "filepath",
            "file_path",
            "filename",
            "path",
            ".exe",
            ".dll",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
            ".scr",
            ".msi",
            ".sys",
        )

        for item in all_data:

            text = cls._item_to_text(item)

            for word in file_words:

                if word in text:
                    return True

        return False

    # ============================================================
    # DECISION BUILDER
    # ============================================================

    def _decision(
        self,
        decision: str,
        reason: str,
        confidence: int,
        automatic: bool,
        requires_user: bool,
    ) -> Dict[str, Any]:

        return {
            "decision": decision,
            "reason": reason,
            "confidence": max(0, min(100, confidence)),
            "requires_user": bool(requires_user),
            "automatic": bool(automatic),
            "timestamp": datetime.now().isoformat(),
            "engine_version": self.VERSION,
        }

    # ============================================================
    # ACCESSORS
    # ============================================================

    def get_last_decision(self) -> Dict[str, Any]:
        return dict(self.last_decision)

    def get_last_input(self) -> Dict[str, Any]:
        return dict(self.last_input)

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self.history)

    def get_version(self) -> str:
        return self.VERSION

    def clear(self):
        self.last_input = {}

        self.last_decision = {
            "decision": self.DECISION_IGNORE,
            "reason": "Нет данных для анализа.",
            "confidence": 0,
            "requires_user": False,
            "automatic": False,
        }

        self.history = []

        self.log("История Decision Engine очищена.")

    # ============================================================
    # CONVENIENCE METHODS
    # ============================================================

    def should_ask_sandbox(self) -> bool:
        return (
            self.last_decision.get("decision")
            == self.DECISION_ASK_SANDBOX
        )

    def should_auto_delete(self) -> bool:
        return (
            self.last_decision.get("decision")
            == self.DECISION_AUTO_DELETE
        )

    def requires_user_confirmation(self) -> bool:
        return bool(
            self.last_decision.get(
                "requires_user",
                False,
            )
        )

    def is_automatic(self) -> bool:
        return bool(
            self.last_decision.get(
                "automatic",
                False,
            )
        )


DecisionEngineV4 = DecisionEngine


if __name__ == "__main__":

    print("=" * 60)
    print("JARVIS DECISION ENGINE V4.1 TEST")
    print("=" * 60)

    engine = DecisionEngine()

    # Тест 1 — пустые данные
    print("\\n[1] Пустые данные")


    result = engine.decide({})

    print(result)

    # Тест 2 — подозрительный файл
    print("\\n[2] Подозрительный файл")

    result = engine.decide({
        "risk": {
            "score": 45,
            "level": "HIGH",
        },
        "detection": [
            {
                "type": "suspicious_file",
                "path": "test.exe",
            }
        ],
    })

    print(result)

    # Тест 3 — подтверждённый malware
    print("\\n[3] Подтверждённый malware")

    result = engine.decide({
        "risk": {
            "score": 95,
            "level": "CRITICAL",
        },
        "detection": [
            {
                "type": "confirmed_malware",
                "path": "malware.exe",
            }
        ],
    })

    print(result)

    print("\\n[4] Последнее решение")
    print(engine.get_last_decision())

    print("\\n[5] Версия")
    print(engine.get_version())

    print("=" * 60)