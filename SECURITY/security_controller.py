from datetime import datetime
from typing import Any, Dict, Optional


class SecurityController:
    """
    Security Controller V4.4

    Центральный контроллер Security-системы.

    Цепочка:
        SecurityPipeline
            ↓
        DecisionEngine
            ↓
        SecurityPolicy
            ↓
        ResponseEngine
    """

    VERSION = "4.4"

    # Статусы контроллера
    STATUS_IDLE = "IDLE"
    STATUS_RUNNING = "RUNNING"
    STATUS_SUCCESS = "SUCCESS"
    STATUS_BLOCKED = "BLOCKED"
    STATUS_REQUIRES_USER = "REQUIRES_USER"
    STATUS_FAILED = "FAILED"

    def __init__(
        self,
        pipeline=None,
        decision_engine=None,
        policy=None,
        response_engine=None,
        logger=None,
    ):
        self.pipeline = pipeline
        self.decision_engine = decision_engine
        self.policy = policy
        self.response_engine = response_engine
        self.logger = logger

        self.status = self.STATUS_IDLE
        self.last_result = None
        self.history = []

    # =========================================================
    # MAIN
    # =========================================================

    def run(
        self,
        data: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:
            # -------------------------------------------------
            # Проверяем компоненты
            # -------------------------------------------------

            component_check = self._check_components()

            if not component_check["success"]:
                return self._fail_result(
                    "Security components are not available",
                    started_at,
                    component_check,
                )

            # -------------------------------------------------
            # 1. SECURITY PIPELINE
            # -------------------------------------------------

            pipeline_result = self.pipeline.run(data)

            if pipeline_result is None:
                return self._fail_result(
                    "Security pipeline returned no result",
                    started_at,
                )

            # -------------------------------------------------
            # 2. DECISION ENGINE
            # -------------------------------------------------

            decision = self.decision_engine.decide(
                pipeline_result
            )

            if decision is None:
                return self._fail_result(
                    "Decision engine returned no decision",
                    started_at,
                )

            # -------------------------------------------------
            # 3. SECURITY POLICY
            # -------------------------------------------------

            policy_result = self.policy.check(
                decision,
                context or {},
            )

            if policy_result is None:
                return self._fail_result(
                    "Security policy returned no result",
                    started_at,
                )

            policy_status = self._get_policy_status(
                policy_result
            )

            # -------------------------------------------------
            # 4. POLICY: DENY
            # -------------------------------------------------

            if policy_status == "DENY":

                self.status = self.STATUS_BLOCKED

                result = self._build_result(
                    status=self.STATUS_BLOCKED,
                    started_at=started_at,
                    pipeline_result=pipeline_result,
                    decision=decision,
                    policy_result=policy_result,
                    response_result=None,
                )

                self._store_result(result)

                return result

            # -------------------------------------------------
            # 5. POLICY: ASK_USER
            # -------------------------------------------------

            if policy_status == "ASK_USER":

                self.status = self.STATUS_REQUIRES_USER

                result = self._build_result(
                    status=self.STATUS_REQUIRES_USER,
                    started_at=started_at,
                    pipeline_result=pipeline_result,
                    decision=decision,
                    policy_result=policy_result,
                    response_result=None,
                )

                self._store_result(result)

                return result

            # -------------------------------------------------
            # 6. POLICY: ALLOW
            # -------------------------------------------------

            if policy_status == "ALLOW":

                response_result = self.response_engine.respond(
                    decision,
                    context or {},
                )

                self.status = self.STATUS_SUCCESS

                result = self._build_result(
                    status=self.STATUS_SUCCESS,
                    started_at=started_at,
                    pipeline_result=pipeline_result,
                    decision=decision,
                    policy_result=policy_result,
                    response_result=response_result,
                )

                self._store_result(result)

                return result

            # -------------------------------------------------
            # UNKNOWN POLICY
            # -------------------------------------------------

            return self._fail_result(
                f"Unknown security policy status: {policy_status}",
                started_at,
                {
                    "policy_result": policy_result,
                },
            )

        except Exception as exc:

            self.status = self.STATUS_FAILED

            result = {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": str(exc),
                "timestamp": datetime.now().isoformat(),
            }

            self._store_result(result)

            self._log(
                "SecurityController error: "
                f"{exc}"
            )

            return result

    # =========================================================
    # USER RESPONSE
    # =========================================================

    def user_response(
        self,
        approved: bool,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        if self.status != self.STATUS_REQUIRES_USER:

            return {
                "success": False,
                "status": self.status,
                "error": "Controller is not waiting for user approval",
            }

        try:

            if not approved:

                self.status = self.STATUS_BLOCKED

                result = {
                    "success": False,
                    "status": self.STATUS_BLOCKED,
                    "action": "BLOCK",
                    "reason": "User denied the operation",
                    "timestamp": datetime.now().isoformat(),
                }

                self._store_result(result)

                return result

            # Пользователь разрешил действие.
            # Передаём решение непосредственно ResponseEngine.

            if not self.last_result:

                return {
                    "success": False,
                    "status": self.STATUS_FAILED,
                    "error": "No pending security decision",
                }

            decision = self.last_result.get(
                "decision"
            )

            if decision is None:

                return {
                    "success": False,
                    "status": self.STATUS_FAILED,
                    "error": "Pending decision is missing",
                }

            response_result = self.response_engine.respond(
                decision,
                context or {},
            )

            self.status = self.STATUS_SUCCESS

            result = {
                "success": True,
                "status": self.STATUS_SUCCESS,
                "decision": decision,
                "response": response_result,
                "timestamp": datetime.now().isoformat(),
            }

            self._store_result(result)

            return result

        except Exception as exc:

            self.status = self.STATUS_FAILED

            result = {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": str(exc),
                "timestamp": datetime.now().isoformat(),
            }

            self._store_result(result)

            return result

    # =========================================================
    # COMPONENT CHECK
    # =========================================================

    def _check_components(self) -> Dict[str, Any]:

        components = {
            "pipeline": self.pipeline,
            "decision_engine": self.decision_engine,
            "policy": self.policy,
            "response_engine": self.response_engine,
        }

        missing = [
            name
            for name, component in components.items()
            if component is None
        ]

        return {
            "success": len(missing) == 0,
            "missing": missing,
        }

    # =========================================================
    # POLICY STATUS
    # =========================================================

    @staticmethod
    def _get_policy_status(
        policy_result: Any,
    ) -> str:

        if isinstance(policy_result, str):
            return policy_result.upper()

        if isinstance(policy_result, dict):

            status = policy_result.get(
                "status"
            )

            if status is None:
                status = policy_result.get(
                    "result"
                )

            if status is None:
                status = policy_result.get(
                    "policy"
                )

            if status is not None:
                return str(status).upper()

        return "UNKNOWN"

    # =========================================================
    # RESULT BUILDER
    # =========================================================

    def _build_result(
        self,
        status: str,
        started_at: str,
        pipeline_result: Any,
        decision: Any,
        policy_result: Any,
        response_result: Any,
    ) -> Dict[str, Any]:

        return {
            "success": status == self.STATUS_SUCCESS,
            "status": status,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
            "pipeline": pipeline_result,
            "decision": decision,
            "policy": policy_result,
            "response": response_result,
        }

    # =========================================================
    # FAIL RESULT
    # =========================================================

    def _fail_result(
        self,
        message: str,
        started_at: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_FAILED

        result = {
            "success": False,
            "status": self.STATUS_FAILED,
            "error": message,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
        }

        if details:
            result["details"] = details

        self._store_result(result)

        return result

    # =========================================================
    # HISTORY
    # =========================================================

    def _store_result(
        self,
        result: Dict[str, Any],
    ) -> None:

        self.last_result = result

        self.history.append(result)

    def get_last_result(self):

        return self.last_result

    def get_history(self):

        return list(self.history)

    def clear_history(self):

        self.history.clear()

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self) -> str:

        return self.status

    def is_running(self) -> bool:

        return self.status == self.STATUS_RUNNING

    def is_success(self) -> bool:

        return self.status == self.STATUS_SUCCESS

    def is_blocked(self) -> bool:

        return self.status == self.STATUS_BLOCKED

    def requires_user(self) -> bool:

        return self.status == self.STATUS_REQUIRES_USER

    def has_failed(self) -> bool:

        return self.status == self.STATUS_FAILED

    # =========================================================
    # LOGGER
    # =========================================================

    def _log(self, message: str) -> None:

        if self.logger is None:
            return

        try:

            if hasattr(self.logger, "log"):
                self.logger.log(message)

            elif hasattr(self.logger, "info"):
                self.logger.info(message)

        except Exception:
            pass