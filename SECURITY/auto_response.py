"""
JARVIS SECURITY
V6.1 - Automatic Response Engine

Выполняет автоматические действия, выбранные
Security Decision Engine и Security Policy.

Поддерживаемые действия:

    IGNORE
    NOTIFY
    QUARANTINE
    AUTO_DELETE
    BLOCK
    UNKNOWN

Sandbox намеренно отсутствует.
"""

from __future__ import annotations

import os
import shutil
import stat
from datetime import datetime
from typing import Any, Dict, Optional, List


class AutoResponse:
    """
    Движок автоматического реагирования Security.

    ВАЖНО:
    AutoResponse не определяет, является ли объект вредоносным.
    Решение приходит сверху:

        Detection
            ↓
        DecisionEngine
            ↓
        SecurityPolicy
            ↓
        AutoResponse
    """

    VERSION = "6.1"

    # =========================================================
    # ACTIONS
    # =========================================================

    ACTION_IGNORE = "IGNORE"
    ACTION_NOTIFY = "NOTIFY"
    ACTION_QUARANTINE = "QUARANTINE"
    ACTION_AUTO_DELETE = "AUTO_DELETE"
    ACTION_BLOCK = "BLOCK"
    ACTION_UNKNOWN = "UNKNOWN"

    # =========================================================
    # STATUSES
    # =========================================================

    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_UNKNOWN = "UNKNOWN"

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        quarantine=None,
        notifier=None,
        logger=None,
    ):
        """
        :param quarantine:
            Объект Quarantine из V1.5.

        :param notifier:
            Необязательный объект уведомлений.

        :param logger:
            Необязательный Security logger.
        """

        self.quarantine = quarantine
        self.notifier = notifier
        self.logger = logger

        self.history = []

    # =========================================================
    # MAIN RESPONSE
    # =========================================================

    def respond(
        self,
        decision: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Выполняет действие на основе Security Decision.
        """

        context = context or {}

        started_at = datetime.now().isoformat()

        try:

            action = self._extract_action(decision)

            target = self._extract_target(
                decision,
                context,
            )

            # -------------------------------------------------
            # IGNORE
            # -------------------------------------------------

            if action == self.ACTION_IGNORE:

                result = self._build_result(
                    action=action,
                    status=self.STATUS_SUCCESS,
                    target=target,
                    started_at=started_at,
                    message="Threat ignored by security decision",
                )

                self._store(result)

                return result

            # -------------------------------------------------
            # NOTIFY
            # -------------------------------------------------

            if action == self.ACTION_NOTIFY:

                notification_result = (
                    self._notify(
                        decision,
                        context,
                    )
                )

                result = self._build_result(
                    action=action,
                    status=self.STATUS_SUCCESS,
                    target=target,
                    started_at=started_at,
                    message="Security notification sent",
                    details={
                        "notification": notification_result,
                    },
                )

                self._store(result)

                return result

            # -------------------------------------------------
            # QUARANTINE
            # -------------------------------------------------

            if action == self.ACTION_QUARANTINE:

                quarantine_result = (
                    self._quarantine(
                        target,
                        decision,
                        context,
                    )
                )

                result = self._build_result(
                    action=action,
                    status=(
                        self.STATUS_SUCCESS
                        if quarantine_result.get("success")
                        else self.STATUS_FAILED
                    ),
                    target=target,
                    started_at=started_at,
                    message="Quarantine action executed",
                    details=quarantine_result,
                )

                self._store(result)

                return result

            # -------------------------------------------------
            # AUTO DELETE
            # -------------------------------------------------

            if action == self.ACTION_AUTO_DELETE:

                delete_result = (
                    self._delete(
                        target,
                    )
                )

                result = self._build_result(
                    action=action,
                    status=(
                        self.STATUS_SUCCESS
                        if delete_result.get("success")
                        else self.STATUS_FAILED
                    ),
                    target=target,
                    started_at=started_at,
                    message="Automatic deletion executed",
                    details=delete_result,
                )

                self._store(result)

                return result

            # -------------------------------------------------
            # BLOCK
            # -------------------------------------------------

            if action == self.ACTION_BLOCK:

                block_result = (
                    self._block(
                        target,
                        decision,
                        context,
                    )
                )

                result = self._build_result(
                    action=action,
                    status=(
                        self.STATUS_SUCCESS
                        if block_result.get("success")
                        else self.STATUS_FAILED
                    ),
                    target=target,
                    started_at=started_at,
                    message="Block action executed",
                    details=block_result,
                )

                self._store(result)

                return result

            # -------------------------------------------------
            # UNKNOWN
            # -------------------------------------------------

            result = self._build_result(
                action=self.ACTION_UNKNOWN,
                status=self.STATUS_UNKNOWN,
                target=target,
                started_at=started_at,
                message=f"Unknown security action: {action}",
            )

            self._store(result)

            return result

        except Exception as exc:

            result = self._build_result(
                action=self.ACTION_UNKNOWN,
                status=self.STATUS_FAILED,
                target=None,
                started_at=started_at,
                message="Automatic response failed",
                error=str(exc),
            )

            self._store(result)

            self._log(
                f"AutoResponse error: {exc}"
            )

            return result

    # =========================================================
    # EXTRACT ACTION
    # =========================================================

    @staticmethod
    def _extract_action(
        decision: Any,
    ) -> str:

        if isinstance(decision, str):

            return decision.upper()

        if isinstance(decision, dict):

            for key in (
                "action",
                "response",
                "recommended_action",
                "decision",
            ):

                value = decision.get(key)

                if value is not None:

                    if isinstance(value, dict):

                        nested = (
                            value.get("action")
                            or value.get("response")
                        )

                        if nested is not None:
                            return str(nested).upper()

                    return str(value).upper()

        return "UNKNOWN"

    # =========================================================
    # EXTRACT TARGET
    # =========================================================

    @staticmethod
    def _extract_target(
        decision: Any,
        context: Dict[str, Any],
    ) -> Optional[str]:

        # Сначала смотрим context.

        for key in (
            "target",
            "file",
            "file_path",
            "path",
            "filepath",
        ):

            value = context.get(key)

            if value:

                return str(value)

        # Затем decision.

        if isinstance(decision, dict):

            for key in (
                "target",
                "file",
                "file_path",
                "path",
                "filepath",
            ):

                value = decision.get(key)

                if value:

                    return str(value)

        return None

    # =========================================================
    # NOTIFY
    # =========================================================

    def _notify(
        self,
        decision: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        message = (
            context.get("message")
            or "Security event detected"
        )

        if self.notifier is None:

            self._log(
                f"Security notification: {message}"
            )

            return {
                "success": True,
                "method": "LOGGER",
                "message": message,
            }

        try:

            if hasattr(
                self.notifier,
                "notify",
            ):

                result = self.notifier.notify(
                    message,
                    decision,
                )

                return {
                    "success": True,
                    "method": "NOTIFY",
                    "result": result,
                }

            if hasattr(
                self.notifier,
                "send",
            ):

                result = self.notifier.send(
                    message,
                )

                return {
                    "success": True,
                    "method": "SEND",
                    "result": result,
                }

        except Exception as exc:

            return {
                "success": False,
                "error": str(exc),
            }

        return {
            "success": False,
            "error": "Notifier has no supported method",
        }

    # =========================================================
    # QUARANTINE
    # =========================================================

    def _quarantine(
        self,
        target: Optional[str],
        decision: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not target:

            return {
                "success": False,
                "error": "No target specified",
            }

        if not os.path.exists(target):

            return {
                "success": False,
                "error": "Target does not exist",
                "target": target,
            }

        # -----------------------------------------------------
        # Используем существующий Quarantine из V1.5
        # -----------------------------------------------------

        if self.quarantine is not None:

            try:

                if hasattr(
                    self.quarantine,
                    "quarantine",
                ):

                    result = (
                        self.quarantine.quarantine(
                            target
                        )
                    )

                    return {
                        "success": True,
                        "method": "QUARANTINE_MODULE",
                        "result": result,
                    }

                if hasattr(
                    self.quarantine,
                    "move_to_quarantine",
                ):

                    result = (
                        self.quarantine.move_to_quarantine(
                            target
                        )
                    )

                    return {
                        "success": True,
                        "method": "QUARANTINE_MODULE",
                        "result": result,
                    }

            except Exception as exc:

                return {
                    "success": False,
                    "method": "QUARANTINE_MODULE",
                    "error": str(exc),
                }

        # -----------------------------------------------------
        # Fallback
        # -----------------------------------------------------

        return {
            "success": False,
            "error": (
                "Quarantine module is not configured"
            ),
        }

    # =========================================================
    # DELETE
    # =========================================================

    def _delete(
        self,
        target: Optional[str],
    ) -> Dict[str, Any]:

        if not target:

            return {
                "success": False,
                "error": "No target specified",
            }

        if not os.path.exists(target):

            return {
                "success": False,
                "error": "Target does not exist",
                "target": target,
            }

        try:

            if os.path.isdir(target):

                shutil.rmtree(
                    target,
                    onerror=self._remove_readonly,
                )

            else:

                os.chmod(
                    target,
                    stat.S_IWRITE,
                )

                os.remove(target)

            self._log(
                f"Security automatically deleted: {target}"
            )

            return {
                "success": True,
                "target": target,
                "action": self.ACTION_AUTO_DELETE,
            }

        except Exception as exc:

            return {
                "success": False,
                "target": target,
                "error": str(exc),
            }

    # =========================================================
    # BLOCK
    # =========================================================

    def _block(
        self,
        target: Optional[str],
        decision: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        """
        Блокировка объекта.

        На этом уровне мы НЕ удаляем файл.

        Реальная блокировка может быть реализована
        отдельным модулем в дальнейшем.

        Сейчас фиксируем событие и пытаемся
        использовать переданный blocker.
        """

        blocker = context.get("blocker")

        if blocker is not None:

            try:

                if hasattr(
                    blocker,
                    "block",
                ):

                    result = blocker.block(
                        target,
                        decision,
                    )

                    return {
                        "success": True,
                        "method": "BLOCKER",
                        "result": result,
                    }

            except Exception as exc:

                return {
                    "success": False,
                    "error": str(exc),
                }

        self._log(
            f"Security block requested: {target}"
        )

        return {
            "success": True,
            "method": "SECURITY_EVENT",
            "target": target,
            "message": (
                "Block action recorded; "
                "no destructive operation performed"
            ),
        }

    # =========================================================
    # READONLY FILE HANDLER
    # =========================================================

    @staticmethod
    def _remove_readonly(
        func,
        path,
        exc_info,
    ) -> None:

        try:

            os.chmod(
                path,
                stat.S_IWRITE,
            )

            func(
                path,
            )

        except Exception:

            raise

    # =========================================================
    # RESULT
    # =========================================================

    def _build_result(
        self,
        action: str,
        status: str,
        target: Optional[str],
        started_at: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:

        result = {
            "success": status == self.STATUS_SUCCESS,
            "status": status,
            "action": action,
            "target": target,
            "message": message,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
        }

        if details is not None:
            result["details"] = details

        if error is not None:
            result["error"] = error

        return result

    # =========================================================
    # HISTORY
    # =========================================================

    def _store(
        self,
        result: Dict[str, Any],
    ) -> None:

        self.history.append(result)

        if len(self.history) > 1000:

            del self.history[
                :-1000
            ]

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:

        if limit is None:
            return list(self.history)

        try:

            limit = int(limit)

        except (TypeError, ValueError):

            return list(self.history)

        if limit <= 0:
            return []

        return self.history[-limit:]

    def clear_history(self) -> None:

        self.history.clear()

    # =========================================================
    # LAST RESULT
    # =========================================================

    def get_last_result(
        self,
    ) -> Optional[Dict[str, Any]]:

        if not self.history:
            return None

        return self.history[-1]

    # =========================================================
    # LOGGER
    # =========================================================

    def _log(
        self,
        message: str,
    ) -> None:

        if self.logger is None:
            return

        try:

            if hasattr(
                self.logger,
                "log",
            ):

                self.logger.log(message)

            elif hasattr(
                self.logger,
                "info",
            ):

                self.logger.info(message)

        except Exception:
            pass