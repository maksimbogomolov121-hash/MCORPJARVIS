"""
security_policy.py
JARVIS Security Core V4.3

Security Policy — политики безопасности.

Задача:
    Определять, разрешено ли выполнение действия,
    которое предложил Decision Engine.

ВАЖНО:
    Этот модуль НЕ выполняет действия.
    Он только принимает решение:
        ALLOW
        ASK_USER
        DENY

Реальное выполнение находится в Response Engine.
"""


from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional


class SecurityPolicy:
    VERSION = "4.3"

    # ============================================================
    # POLICY RESULTS
    # ============================================================

    ALLOW = "ALLOW"
    ASK_USER = "ASK_USER"
    DENY = "DENY"

    # ============================================================
    # ACTIONS
    # ============================================================

    IGNORE = "IGNORE"
    NOTIFY = "NOTIFY"
    ASK_SANDBOX = "ASK_SANDBOX"
    QUARANTINE = "QUARANTINE"
    AUTO_DELETE = "AUTO_DELETE"
    BLOCK = "BLOCK"
    UNKNOWN = "UNKNOWN"

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(self, logger=None):

        self.logger = logger

        self.last_check: Dict[str, Any] = {}

        self.history: List[Dict[str, Any]] = []

        self.log(
            "Security Policy V4.3 инициализирован."
        )

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

        print(
            f"[SECURITY POLICY] {message}"
        )

    # ============================================================
    # MAIN POLICY CHECK
    # ============================================================

    def check(
        self,
        decision: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.log(
            "Проверка Security Policy."
        )

        context = context or {}

        normalized = self._normalize_decision(
            decision
        )

        action = normalized["decision"]

        result = self._evaluate_action(
            action,
            normalized,
            context,
        )

        self.last_check = dict(result)

        self.history.append(
            dict(result)
        )

        if len(self.history) > 100:
            self.history = self.history[-100:]

        self.log(
            f"Policy result: {result['policy']}"
        )

        return dict(result)

    # ============================================================
    # DECISION NORMALIZATION
    # ============================================================

    @staticmethod
    def _normalize_decision(
        decision: Any,
    ) -> Dict[str, Any]:

        if decision is None:

            return {
                "decision": SecurityPolicy.UNKNOWN,
                "reason": "Решение отсутствует.",
                "confidence": 0,
                "automatic": False,
                "requires_user": False,
            }

        if isinstance(decision, str):

            return {
                "decision": decision.upper(),
                "reason": "",
                "confidence": 0,
                "automatic": False,
                "requires_user": False,
            }

        if not isinstance(
            decision,
            dict,
        ):

            return {
                "decision": SecurityPolicy.UNKNOWN,
                "reason": (
                    "Некорректный формат решения."
                ),
                "confidence": 0,
                "automatic": False,
                "requires_user": False,
            }

        result = dict(decision)

        result["decision"] = str(
            result.get(
                "decision",
                SecurityPolicy.UNKNOWN,
            )
        ).upper()

        result.setdefault(
            "reason",
            "",
        )

        result.setdefault(
            "confidence",
            0,
        )

        result.setdefault(
            "automatic",
            False,
        )

        result.setdefault(
            "requires_user",
            False,
        )

        return result

    # ============================================================
    # ACTION EVALUATION
    # ============================================================

    def _evaluate_action(
        self,
        action: str,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        # --------------------------------------------------------
        # IGNORE
        # --------------------------------------------------------

        if action == self.IGNORE:

            return self._result(
                policy=self.ALLOW,
                action=action,
                reason=(
                    "Игнорирование события разрешено."
                ),
                automatic=False,
                requires_user=False,
            )

        # --------------------------------------------------------
        # NOTIFY
        # --------------------------------------------------------

        if action == self.NOTIFY:

            return self._result(
                policy=self.ALLOW,
                action=action,
                reason=(
                    "Уведомление пользователя разрешено."
                ),
                automatic=False,
                requires_user=False,
            )

        # --------------------------------------------------------
        # ASK SANDBOX
        # --------------------------------------------------------

        if action == self.ASK_SANDBOX:

            return self._check_sandbox_policy(
                decision,
                context,
            )

        # --------------------------------------------------------
        # QUARANTINE
        # --------------------------------------------------------

        if action == self.QUARANTINE:

            return self._check_quarantine_policy(
                decision,
                context,
            )

        # --------------------------------------------------------
        # AUTO DELETE
        # --------------------------------------------------------

        if action == self.AUTO_DELETE:

            return self._check_delete_policy(
                decision,
                context,
            )

        # --------------------------------------------------------
        # BLOCK
        # --------------------------------------------------------

        if action == self.BLOCK:

            return self._check_block_policy(
                decision,
                context,
            )

        # --------------------------------------------------------
        # UNKNOWN
        # --------------------------------------------------------

        return self._result(
            policy=self.DENY,
            action=action,
            reason=(
                "Неизвестное действие запрещено."
            ),
            automatic=False,
            requires_user=False,
        )

    # ============================================================
    # SANDBOX POLICY
    # ============================================================

    def _check_sandbox_policy(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:

            return self._result(
                policy=self.DENY,
                action=self.ASK_SANDBOX,
                reason=(
                    "Проверка Sandbox невозможна: "
                    "путь к файлу отсутствует."
                ),
                automatic=False,
                requires_user=False,
            )

        return self._result(
            policy=self.ASK_USER,
            action=self.ASK_SANDBOX,
            reason=(
                "Проверка подозрительного файла "
                "в Sandbox требует подтверждения пользователя."
            ),
            automatic=False,
            requires_user=True,
            file_path=file_path,
        )

    # ============================================================
    # QUARANTINE POLICY
    # ============================================================

    def _check_quarantine_policy(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:

            return self._result(
                policy=self.DENY,
                action=self.QUARANTINE,
                reason=(
                    "Карантин невозможен: "
                    "путь к файлу отсутствует."
                ),
                automatic=False,
                requires_user=False,
            )

        confidence = self._confidence(
            decision
        )

        if confidence < 70:

            return self._result(
                policy=self.ASK_USER,
                action=self.QUARANTINE,
                reason=(
                    "Уверенность анализа слишком низкая "
                    "для автоматического помещения файла "
                    "в карантин."
                ),
                automatic=False,
                requires_user=True,
                file_path=file_path,
            )

        return self._result(
            policy=self.ALLOW,
            action=self.QUARANTINE,
            reason=(
                "Помещение подозрительного объекта "
                "в карантин разрешено."
            ),
            automatic=True,
            requires_user=False,
            file_path=file_path,
        )

    # ============================================================
    # DELETE POLICY
    # ============================================================

    def _check_delete_policy(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:

            return self._result(
                policy=self.DENY,
                action=self.AUTO_DELETE,
                reason=(
                    "Удаление невозможно: "
                    "путь к файлу отсутствует."
                ),
                automatic=False,
                requires_user=False,
            )

        # --------------------------------------------------------
        # Automatic flag MUST be true.
        # --------------------------------------------------------

        if not bool(
            decision.get(
                "automatic",
                False,
            )
        ):

            return self._result(
                policy=self.DENY,
                action=self.AUTO_DELETE,
                reason=(
                    "Decision Engine не разрешил "
                    "автоматическое удаление."
                ),
                automatic=False,
                requires_user=False,
                file_path=file_path,
            )

        # --------------------------------------------------------
        # Confidence
        # --------------------------------------------------------

        confidence = self._confidence(
            decision
        )

        if confidence < 90:

            return self._result(
                policy=self.ASK_USER,
                action=self.AUTO_DELETE,
                reason=(
                    "Уверенность недостаточна "
                    "для автоматического удаления."
                ),
                automatic=False,
                requires_user=True,
                file_path=file_path,
            )

        # --------------------------------------------------------
        # Sandbox confirmation
        # --------------------------------------------------------

        sandbox_confirmed = bool(
            context.get(
                "sandbox_confirmed",
                False,
            )
        )

        if not sandbox_confirmed:

            return self._result(
                policy=self.DENY,
                action=self.AUTO_DELETE,
                reason=(
                    "Автоматическое удаление файла "
                    "запрещено без подтверждения Sandbox."
                ),
                automatic=False,
                requires_user=False,
                file_path=file_path,
            )

        # --------------------------------------------------------
        # Sandbox verdict
        # --------------------------------------------------------

        sandbox_verdict = str(
            context.get(
                "sandbox_verdict",
                "",
            )
        ).upper()

        if sandbox_verdict != "MALICIOUS":

            return self._result(
                policy=self.DENY,
                action=self.AUTO_DELETE,
                reason=(
                    "Sandbox не подтвердил "
                    "вредоносность файла."
                ),
                automatic=False,
                requires_user=False,
                file_path=file_path,
                sandbox_verdict=sandbox_verdict,
            )

        # --------------------------------------------------------
        # Protected path
        # --------------------------------------------------------

        if self._is_protected_path(
            file_path
        ):

            return self._result(
                policy=self.DENY,
                action=self.AUTO_DELETE,
                reason=(
                    "Удаление защищённого системного "
                    "пути запрещено."
                ),
                automatic=False,
                requires_user=False,
                file_path=file_path,
            )

        # --------------------------------------------------------
        # FINAL ALLOW
        # --------------------------------------------------------

        return self._result(
            policy=self.ALLOW,
            action=self.AUTO_DELETE,
            reason=(
                "Автоматическое удаление разрешено: "
                "решение подтверждено, уверенность высокая "
                "и Sandbox подтвердил вредоносность."
            ),
            automatic=True,
            requires_user=False,
            file_path=file_path,
            sandbox_confirmed=True,
            sandbox_verdict="MALICIOUS",
        )

    # ============================================================
    # BLOCK POLICY
    # ============================================================

    def _check_block_policy(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        confidence = self._confidence(
            decision
        )

        if confidence < 80:

            return self._result(
                policy=self.ASK_USER,
                action=self.BLOCK,
                reason=(
                    "Уверенность недостаточна "
                    "для автоматической блокировки."
                ),
                automatic=False,
                requires_user=True,
            )

        if not bool(
            decision.get(
                "automatic",
                False,
            )
        ):

            return self._result(
                policy=self.DENY,
                action=self.BLOCK,
                reason=(
                    "Автоматическая блокировка "
                    "не разрешена Decision Engine."
                ),

                automatic=False,
                requires_user=False,
            )

        return self._result(
            policy=self.ALLOW,
            action=self.BLOCK,
            reason=(
                "Автоматическая блокировка разрешена."
            ),
            automatic=True,
            requires_user=False,
        )

    # ============================================================
    # CONFIDENCE
    # ============================================================

    @staticmethod
    def _confidence(
        decision: Dict[str, Any],
    ) -> int:

        try:

            value = int(
                decision.get(
                    "confidence",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            value = 0

        return max(
            0,
            min(
                100,
                value,
            ),
        )

    # ============================================================
    # FILE PATH
    # ============================================================

    @staticmethod
    def _extract_file_path(
        context: Dict[str, Any],
    ) -> Optional[str]:

        if not isinstance(
            context,
            dict,
        ):
            return None

        keys = (
            "file_path",
            "filepath",
            "path",
            "filename",
        )

        for key in keys:

            value = context.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip()

        return None

    # ============================================================
    # PROTECTED PATHS
    # ============================================================

    @staticmethod
    def _is_protected_path(
        file_path: str,
    ) -> bool:

        try:

            import os

            normalized = os.path.abspath(
                file_path
            ).lower()

        except Exception:

            return True

        protected = []

        if os.name == "nt":

            windows_dir = os.environ.get(
                "WINDIR",
                r"C:\Windows",
            )

            system_drive = os.environ.get(
                "SystemDrive",
                "C:",
            )

            protected.extend(
                [
                    os.path.abspath(
                        windows_dir
                    ).lower(),
                    (
                        system_drive
                        + r"\bootmgr"
                    ).lower(),
                    (
                        system_drive
                        + r"\pagefile.sys"
                    ).lower(),
                ]
            )

        else:

            protected.extend(
                [
                    "/",
                    "/bin",
                    "/boot",
                    "/dev",
                    "/etc",
                    "/lib",
                    "/lib64",
                    "/proc",
                    "/root",
                    "/sbin",
                    "/sys",
                    "/usr",
                ]
            )

        for path in protected:

            if normalized == path:

                return True

            if normalized.startswith(
                path.rstrip("\\/")
                + os.sep
            ):

                return True

        return False

    # ============================================================
    # RESULT BUILDER
    # ============================================================

    def _result(
        self,
        policy: str,
        action: str,
        reason: str,
        automatic: bool,
        requires_user: bool,
        **extra,
    ) -> Dict[str, Any]:

        result = {
            "policy": policy,
            "action": action,
            "reason": reason,
            "automatic": bool(
                automatic
            ),
            "requires_user": bool(
                requires_user
            ),
            "timestamp": datetime.now().isoformat(),
            "policy_version": self.VERSION,
        }

        result.update(extra)

        return result

    # ============================================================
    # ACCESSORS
    # ============================================================

    def get_last_check(
        self,
    ) -> Dict[str, Any]:

        return dict(
            self.last_check
        )

    def get_history(
        self,
    ) -> List[Dict[str, Any]]:

        return list(
            self.history
        )

    def get_version(
        self,
    ) -> str:

        return self.VERSION

    def clear(
        self,
    ):

        self.last_check = {}

        self.history = []

        self.log(
            "История Security Policy очищена."
        )


SecurityPolicyV4 = SecurityPolicy


# ================================================================
# STANDALONE TEST
# ================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("JARVIS SECURITY POLICY V4.3 TEST")
    print("=" * 60)

    policy = SecurityPolicy()

    # ------------------------------------------------------------
    # TEST 1
    # ------------------------------------------------------------

    print("\n[1] IGNORE")

    result = policy.check(
        {
            "decision": "IGNORE",
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 2
    # ------------------------------------------------------------

    print("\n[2] NOTIFY")

    result = policy.check(
        {
            "decision": "NOTIFY",
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 3
    # ------------------------------------------------------------

    print("\n[3] ASK_SANDBOX")

    result = policy.check(
        {
            "decision": "ASK_SANDBOX",
            "confidence": 80,
        },
        {
            "file_path": (
                "test_suspicious.exe"
            ),
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 4
    # ------------------------------------------------------------

    print("\n[4] AUTO_DELETE без Sandbox")

    result = policy.check(
        {
            "decision": "AUTO_DELETE",
            "confidence": 100,
            "automatic": True,
        },
        {
            "file_path": (
                "test_malware.exe"
            ),
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 5
    # ------------------------------------------------------------

    print(
        "\n[5] AUTO_DELETE "
        "с неподтверждённым Sandbox"
    )

    result = policy.check(
        {
            "decision": "AUTO_DELETE",
            "confidence": 100,
            "automatic": True,
        },
        {
            "file_path": (
                "test_malware.exe"
            ),
            "sandbox_confirmed": True,
            "sandbox_verdict": "SAFE",
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 6
    # ------------------------------------------------------------

    print(
        "\n[6] AUTO_DELETE "
        "с подтверждённым Sandbox"
    )

    result = policy.check(
        {
            "decision": "AUTO_DELETE",
            "confidence": 100,
            "automatic": True,
        },
        {
            "file_path": (
                "test_malware.exe"
            ),
            "sandbox_confirmed": True,
            "sandbox_verdict": "MALICIOUS",
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 7
    # ------------------------------------------------------------

    print("\n[7] BLOCK")

    result = policy.check(
        {
            "decision": "BLOCK",
            "confidence": 100,
            "automatic": True,
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 8
    # ------------------------------------------------------------

    print("\n[8] UNKNOWN")

    result = policy.check(
        {
            "decision": "SOMETHING_UNKNOWN",
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 9
    # ------------------------------------------------------------

    print("\n[9] Последняя проверка")

    print(
        policy.get_last_check()
    )

    # ------------------------------------------------------------
    # TEST 10
    # ------------------------------------------------------------

    print("\n[10] Версия")

    print(
        policy.get_version()
    )

    print("\n" + "=" * 60)
    print("SECURITY POLICY V4.3 TEST COMPLETED")
    print("=" * 60)