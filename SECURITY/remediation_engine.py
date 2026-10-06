"""
JARVIS SECURITY
V6.2 - Remediation Engine

Система устранения последствий обнаруженных угроз.

RemediationEngine отвечает за:
- удаление вредоносных объектов;
- восстановление файлов;
- откат изменений;
- очистку следов угроз;
- выполнение заранее разрешённых remediation-действий;
- журналирование результатов.

ВАЖНО:
RemediationEngine не определяет наличие угрозы.
Решение о необходимости remediation приходит сверху.

Архитектура:

    Detection
        ↓
    RiskEngine
        ↓
    DecisionEngine
        ↓
    AutoResponse
        ↓
    RemediationEngine
"""

from __future__ import annotations

import os
import shutil
import stat
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class RemediationEngine:
    """
    Движок устранения последствий угроз.
    """

    VERSION = "6.2"

    # =========================================================
    # ACTIONS
    # =========================================================

    ACTION_DELETE = "DELETE"
    ACTION_RESTORE = "RESTORE"
    ACTION_REMOVE = "REMOVE"
    ACTION_CLEAN = "CLEAN"
    ACTION_ROLLBACK = "ROLLBACK"
    ACTION_CUSTOM = "CUSTOM"

    # =========================================================
    # STATUSES
    # =========================================================

    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"
    STATUS_SKIPPED = "SKIPPED"
    STATUS_NOT_FOUND = "NOT_FOUND"
    STATUS_UNKNOWN = "UNKNOWN"

    # =========================================================
    # INIT
    # =========================================================

    def __init__(
        self,
        quarantine=None,
        logger=None,
    ):
        """
        :param quarantine:
            Объект Quarantine из V1.5.

        :param logger:
            Необязательный Security logger.
        """

        self.quarantine = quarantine
        self.logger = logger

        self.history: List[Dict[str, Any]] = []

        self.custom_actions: Dict[
            str,
            Callable[..., Any]
        ] = {}

    # =========================================================
    # MAIN
    # =========================================================

    def remediate(
        self,
        action: str,
        target: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Выполняет remediation-действие.

        :param action:
            Тип действия.

        :param target:
            Объект, над которым выполняется действие.

        :param context:
            Дополнительный контекст.
        """

        context = context or {}

        action = str(action).upper()

        started_at = datetime.now().isoformat()

        try:

            # -------------------------------------------------
            # DELETE
            # -------------------------------------------------

            if action == self.ACTION_DELETE:

                result = self.delete(
                    target
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # REMOVE
            # -------------------------------------------------

            if action == self.ACTION_REMOVE:

                result = self.delete(
                    target
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # RESTORE
            # -------------------------------------------------

            if action == self.ACTION_RESTORE:

                result = self.restore(
                    target,
                    context,
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # CLEAN
            # -------------------------------------------------

            if action == self.ACTION_CLEAN:

                result = self.clean(
                    target,
                    context,
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # ROLLBACK
            # -------------------------------------------------

            if action == self.ACTION_ROLLBACK:

                result = self.rollback(
                    target,
                    context,
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # CUSTOM
            # -------------------------------------------------

            if action == self.ACTION_CUSTOM:

                custom_name = context.get(
                    "custom_action"
                )

                result = self.run_custom(
                    custom_name,
                    target,
                    context,
                )

                return self._finalize(
                    action,
                    target,
                    started_at,
                    result,
                )

            # -------------------------------------------------
            # UNKNOWN
            # -------------------------------------------------

            result = {
                "success": False,
                "status": self.STATUS_UNKNOWN,
                "error": (
                    f"Unknown remediation action: "
                    f"{action}"
                ),
            }

            return self._finalize(
                action,
                target,
                started_at,
                result,
            )

        except Exception as exc:

            result = {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": str(exc),
            }

            return self._finalize(
                action,
                target,
                started_at,
                result,
            )

    # =========================================================
    # DELETE
    # =========================================================

    def delete(
        self,
        target: Any,
    ) -> Dict[str, Any]:
        """
        Удаляет файл или директорию.
        """

        if not target:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No target specified",
            }

        target = os.path.abspath(
            str(target)
        )

        if not os.path.exists(target):

            return {
                "success": False,
                "status": self.STATUS_NOT_FOUND,
                "target": target,
                "error": "Target does not exist",
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
                f"Remediation deleted: {target}"
            )

            return {
                "success": True,
                "status": self.STATUS_SUCCESS,
                "target": target,
                "action": self.ACTION_DELETE,
            }

        except Exception as exc:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "target": target,
                "error": str(exc),
            }

    # =========================================================
    # RESTORE
    # =========================================================

    def restore(
        self,
        target: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Восстанавливает объект из резервной копии.

        Ожидается:

            context["backup_path"]

        """

        if not target:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No target specified",
            }

        backup_path = context.get(
            "backup_path"
        )

        if not backup_path:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No backup path specified",
            }

        target = os.path.abspath(
            str(target)
        )

        backup_path = os.path.abspath(
            str(backup_path)
        )

        if not os.path.exists(
            backup_path
        ):

            return {
                "success": False,
                "status": self.STATUS_NOT_FOUND,
                "backup": backup_path,
                "error": "Backup does not exist",
            }

        try:

            target_parent = os.path.dirname(
                target
            )

            if target_parent:

                os.makedirs(
                    target_parent,
                    exist_ok=True,
                )

            if os.path.isdir(
                backup_path
            ):

                if os.path.exists(target):

                    if os.path.isdir(target):

                        shutil.rmtree(target)

                    else:

                        os.remove(target)

                shutil.copytree(
                    backup_path,
                    target,
                )

            else:

                shutil.copy2(
                    backup_path,
                    target,
                )

            self._log(
                f"Remediation restored: {target}"
            )

            return {
                "success": True,
                "status": self.STATUS_SUCCESS,
                "target": target,
                "backup": backup_path,
                "action": self.ACTION_RESTORE,
            }

        except Exception as exc:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "target": target,
                "backup": backup_path,
                "error": str(exc),
            }

    # =========================================================
    # CLEAN
    # =========================================================

    def clean(
        self,
        target: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Очистка объекта.

        По умолчанию безопасно удаляет указанный объект.

        Дополнительные операции могут передаваться
        через context.
        """

        if not target:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No target specified",
            }

        clean_mode = context.get(
            "clean_mode",
            "delete",
        )

        if clean_mode == "delete":

            return self.delete(
                target
            )

        return {
            "success": False,
            "status": self.STATUS_UNKNOWN,
            "error": (
                f"Unknown clean mode: "
                f"{clean_mode}"
            ),
        }

    # =========================================================
    # ROLLBACK
    # =========================================================

    def rollback(
        self,
        target: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Выполняет откат изменения.

        Сейчас rollback использует backup_path,
        если он указан.

        В дальнейшем сюда можно добавить
        полноценный журнал изменений.
        """

        backup_path = context.get(
            "backup_path"
        )

        if not backup_path:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No backup path specified",
            }

        return self.restore(
            target,
            context,
        )

    # =========================================================
    # CUSTOM ACTIONS
    # =========================================================

    def register_custom_action(
        self,
        name: str,
        callback: Callable[..., Any],
    ) -> bool:
        """
        Регистрирует пользовательское remediation-действие.
        """

        if not name:

            raise ValueError(
                "Action name cannot be empty"
            )

        if not callable(callback):

            raise TypeError(
                "Callback must be callable"
            )

        self.custom_actions[
            str(name).upper()
        ] = callback

        self._log(
            f"Custom remediation registered: {name}"
        )

        return True

    def unregister_custom_action(
        self,
        name: str,
    ) -> bool:

        key = str(name).upper()

        if key not in self.custom_actions:

            return False

        del self.custom_actions[key]

        return True

    def run_custom(
        self,
        name: Optional[str],
        target: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Выполняет зарегистрированное действие.
        """

        if not name:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "error": "No custom action specified",
            }

        key = str(name).upper()

        callback = self.custom_actions.get(
            key
        )

        if callback is None:

            return {
                "success": False,
                "status": self.STATUS_NOT_FOUND,
                "error": (
                    f"Custom action not found: "
                    f"{name}"
                ),
            }

        try:

            result = callback(
                target,
                context,
            )

            return {
                "success": True,
                "status": self.STATUS_SUCCESS,
                "action": key,
                "result": result,
            }

        except Exception as exc:

            return {
                "success": False,
                "status": self.STATUS_FAILED,
                "action": key,
                "error": str(exc),
            }

    # =========================================================
    # FINALIZE
    # =========================================================

    def _finalize(
        self,
        action: str,
        target: Any,
        started_at: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:

        final_result = {
            "success": result.get(
                "success",
                False,
            ),
            "status": result.get(
                "status",
                self.STATUS_FAILED,
            ),
            "action": action,
            "target": target,
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
        }

        for key, value in result.items():

            if key not in final_result:

                final_result[key] = value

        self._store(
            final_result
        )

        return final_result

    # =========================================================
    # HISTORY
    # =========================================================

    def _store(
        self,
        result: Dict[str, Any],
    ) -> None:

        self.history.append(
            result
        )

        if len(self.history) > 1000:

            del self.history[
                :-1000
            ]

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:

        if limit is None:

            return list(
                self.history
            )

        try:

            limit = int(limit)

        except (TypeError, ValueError):

            return list(
                self.history
            )

        if limit <= 0:

            return []

        return self.history[-limit:]

    def get_last_result(
        self,
    ) -> Optional[Dict[str, Any]]:

        if not self.history:

            return None

        return self.history[-1]

    def clear_history(self) -> None:

        self.history.clear()

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

                self.logger.log(
                    message
                )

            elif hasattr(
                self.logger,
                "info",
            ):

                self.logger.info(
                    message
                )

        except Exception:
            pass

    # =========================================================
    # READONLY HANDLER
    # =========================================================

    @staticmethod
    def _remove_readonly(
        func,
        path,
        exc_info,
    ) -> None:

        os.chmod(
            path,
            stat.S_IWRITE,
        )

        func(
            path,
        )

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self) -> str:

        return "READY"

    def get_statistics(
        self,
    ) -> Dict[str, Any]:

        successful = sum(
            1
            for item in self.history
            if item.get("success")
        )

        failed = sum(
            1
            for item in self.history
            if not item.get("success")
        )

        return {
            "version": self.VERSION,
            "status": self.get_status(),
            "total_operations": len(
                self.history
            ),
            "successful_operations": successful,
            "failed_operations": failed,
            "custom_actions": len(
                self.custom_actions
            ),
        }





