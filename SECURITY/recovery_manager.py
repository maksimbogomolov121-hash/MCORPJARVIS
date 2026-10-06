"""
JARVIS SECURITY
V6.3 - Recovery Manager

Управление восстановлением системы и объектов
после действий безопасности.

Отвечает за:
- восстановление файлов из резервных копий;
- откат изменений;
- восстановление после remediation;
- регистрацию операций восстановления;
- проверку доступности восстановления;
- историю восстановлений.

Sandbox не используется.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import os
import shutil


class RecoveryManager:
    """
    Recovery Manager V6.3.

    Управляет операциями восстановления после
    автоматических действий системы безопасности.
    """

    VERSION = "6.3"

    STATUS_IDLE = "IDLE"
    STATUS_RUNNING = "RUNNING"
    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"

    def __init__(
        self,
        logger: Optional[Any] = None,
        quarantine: Optional[Any] = None,
        remediation_engine: Optional[Any] = None,
    ):
        self.logger = logger
        self.quarantine = quarantine
        self.remediation_engine = remediation_engine

        self.status = self.STATUS_IDLE
        self.last_result: Optional[Dict[str, Any]] = None
        self.history: List[Dict[str, Any]] = []

    # ============================================================
    # ОСНОВНАЯ ОПЕРАЦИЯ ВОССТАНОВЛЕНИЯ
    # ============================================================

    def recover(
        self,
        target: str,
        backup_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Восстанавливает объект.

        Если указан backup_path:
            восстанавливает объект из резервной копии.

        Если backup_path не указан:
            пытается использовать quarantine.

        Parameters:
            target:
                Путь к объекту, который нужно восстановить.

            backup_path:
                Путь к резервной копии.

            context:
                Дополнительный контекст операции.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:
            if not target:
                return self._failure(
                    "Recovery target is not specified.",
                    started_at,
                )

            # ----------------------------------------------------
            # Восстановление из резервной копии
            # ----------------------------------------------------

            if backup_path:
                result = self._restore_from_backup(
                    target,
                    backup_path,
                    context,
                )

                if result.get("success"):
                    return self._success(
                        "Object successfully restored from backup.",
                        target,
                        started_at,
                        result,
                    )

                return self._failure(
                    result.get("message", "Backup restoration failed."),
                    started_at,
                    target=target,
                    details=result,
                )

            # ----------------------------------------------------
            # Восстановление из карантина
            # ----------------------------------------------------

            if self.quarantine is not None:
                result = self._restore_from_quarantine(
                    target,
                    context,
                )

                if result.get("success"):
                    return self._success(
                        "Object successfully restored from quarantine.",
                        target,
                        started_at,
                        result,
                    )

            # ----------------------------------------------------
            # Если источник восстановления отсутствует
            # ----------------------------------------------------

                    return self._failure(
                "No recovery source is available.",
                started_at,
                target=target,
            )

        except Exception as exc:
            return self._failure(
                f"Recovery failed: {exc}",
                started_at,
                target=target,
            )

    # ============================================================
    # ВОССТАНОВЛЕНИЕ ИЗ BACKUP
    # ============================================================

    def _restore_from_backup(
        self,
        target: str,
        backup_path: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        try:
            if not os.path.exists(backup_path):
                return {
                    "success": False,
                    "message": "Backup path does not exist.",
                }

            target_parent = os.path.dirname(target)

            if target_parent:
                os.makedirs(
                    target_parent,
                    exist_ok=True,
                )

            # ----------------------------------------------------
            # Если backup является директорией
            # ----------------------------------------------------

            if os.path.isdir(backup_path):

                if os.path.exists(target):

                    if os.path.isdir(target):
                        shutil.rmtree(target)

                    else:
                        os.remove(target)

                shutil.copytree(
                    backup_path,
                    target,
                )

            # ----------------------------------------------------
            # Если backup является файлом
            # ----------------------------------------------------

            else:

                shutil.copy2(
                    backup_path,
                    target,
                )

            self._log(
                "restore_from_backup",
                {
                    "target": target,
                    "backup": backup_path,
                    "context": context or {},
                },
            )

            return {
                "success": True,
                "target": target,
                "backup": backup_path,
            }

        except Exception as exc:

            return {
                "success": False,
                "message": str(exc),
            }

    # ============================================================
    # ВОССТАНОВЛЕНИЕ ИЗ КАРАНТИНА
    # ============================================================

    def _restore_from_quarantine(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        try:

            # ----------------------------------------------------
            # Пытаемся использовать стандартные методы quarantine
            # ----------------------------------------------------

            if hasattr(self.quarantine, "restore"):

                result = self.quarantine.restore(
                    target
                )

                if isinstance(result, dict):
                    return result

                return {
                    "success": bool(result),
                    "target": target,
                }

            # ----------------------------------------------------
            # Альтернативные имена методов
            # ----------------------------------------------------

            if hasattr(self.quarantine, "recover"):

                result = self.quarantine.recover(
                    target
                )

                if isinstance(result, dict):
                    return result

                return {
                    "success": bool(result),
                    "target": target,
                }

            return {
                "success": False,
                "message": "Quarantine does not support restoration.",
21:22
}

        except Exception as exc:

            return {
                "success": False,
                "message": str(exc),
            }

    # ============================================================
    # ВОССТАНОВЛЕНИЕ ЧЕРЕЗ REMEDIATION ENGINE
    # ============================================================

    def recover_from_remediation(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Пытается выполнить восстановление через
        Remediation Engine.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if self.remediation_engine is None:
                return self._failure(
                    "Remediation Engine is not available.",
                    started_at,
                    target=target,
                )

            # ----------------------------------------------------
            # Основной метод restore
            # ----------------------------------------------------

            if hasattr(
                self.remediation_engine,
                "restore",
            ):

                result = self.remediation_engine.restore(
                    target,
                    context=context,
                )

                if isinstance(result, dict):

                    if result.get("success"):
                        return self._success(
                            "Object restored through Remediation Engine.",
                            target,
                            started_at,
                            result,
                        )

                    return self._failure(
                        result.get(
                            "message",
                            "Remediation restoration failed.",
                        ),
                        started_at,
                        target=target,
                        details=result,
                    )

                if result:
                    return self._success(
                        "Object restored through Remediation Engine.",
                        target,
                        started_at,
                    )

            return self._failure(
                "Remediation Engine does not support restoration.",
                started_at,
                target=target,
            )

        except Exception as exc:

            return self._failure(
                f"Remediation recovery failed: {exc}",
                started_at,
                target=target,
            )

    # ============================================================
    # ПРОВЕРКА ВОЗМОЖНОСТИ ВОССТАНОВЛЕНИЯ
    # ============================================================

    def can_recover(
        self,
        target: str,
        backup_path: Optional[str] = None,
    ) -> bool:
        """
        Проверяет, существует ли источник восстановления.
        """

        try:

            if backup_path:
                return os.path.exists(
                    backup_path
                )

            if self.quarantine is not None:

                if hasattr(
                    self.quarantine,
                    "can_restore",
                ):
                    return bool(
                        self.quarantine.can_restore(
                            target
                        )
                    )

                if hasattr(
                    self.quarantine,
                    "exists",
                ):
                    return bool(
                        self.quarantine.exists(
                            target
                        )
                    )

            if self.remediation_engine is not None:

                if hasattr(
                    self.remediation_engine,
                    "can_restore",
                ):
                    return bool(

                self.remediation_engine.can_restore(
                            target
                        )
                    )

            return False

        except Exception:
            return False

    # ============================================================
    # СОЗДАНИЕ BACKUP
    # ============================================================

    def create_backup(
        self,
        source: str,
        backup_path: str,
    ) -> Dict[str, Any]:
        """
        Создаёт резервную копию объекта.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if not os.path.exists(source):

                return self._failure(
                    "Source object does not exist.",
                    started_at,
                    target=source,
                )

            backup_parent = os.path.dirname(
                backup_path
            )

            if backup_parent:
                os.makedirs(
                    backup_parent,
                    exist_ok=True,
                )

            # ----------------------------------------------------
            # Backup директории
            # ----------------------------------------------------

            if os.path.isdir(source):

                if os.path.exists(backup_path):
                    shutil.rmtree(
                        backup_path
                    )

                shutil.copytree(
                    source,
                    backup_path,
                )

            # ----------------------------------------------------
            # Backup файла
            # ----------------------------------------------------

            else:

                shutil.copy2(
                    source,
                    backup_path,
                )

            return self._success(
                "Backup created successfully.",
                source,
                started_at,
                {
                    "backup_path": backup_path,
                },
            )

        except Exception as exc:

            return self._failure(
                f"Backup creation failed: {exc}",
                started_at,
                target=source,
            )

    # ============================================================
    # УДАЛЕНИЕ BACKUP
    # ============================================================

    def delete_backup(
        self,
        backup_path: str,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if not os.path.exists(
                backup_path
            ):
                return self._failure(
                    "Backup does not exist.",
                    started_at,
                    target=backup_path,
                )

            if os.path.isdir(
                backup_path
            ):
                shutil.rmtree(
                    backup_path
                )
            else:
                os.remove(
                    backup_path
                )

            return self._success(
                "Backup deleted successfully.",
                backup_path,
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"Backup deletion failed: {exc}",
                started_at,
                target=backup_path,
            )

    # ============================================================
    # ВНУТРЕННИЕ RESULT BUILDERS
    # ============================================================

    def _success(
        self,
        message: str,
        target: Optional[str],
        started_at: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_SUCCESS

        result = {
            "success": True,
            "status": self.STATUS_SUCCESS,
            "message": message,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "started_at": started_at,
            "details": details or {},
        }

        self.last_result = result
        self.history.append(result)

        self._log(
            "recovery_success",
            result,
        )

        return result

    def _failure(
        self,
        message: str,
        started_at: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_FAILED

        result = {
            "success": False,
            "status": self.STATUS_FAILED,
            "message": message,
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "started_at": started_at,
            "details": details or {},
        }

        self.last_result = result
        self.history.append(result)

        self._log(
            "recovery_failed",
            result,
        )

        return result

    # ============================================================
    # LOGGING
    # ============================================================

    def _log(
        self,
        event: str,
        data: Dict[str, Any],
    ) -> None:

        try:

            if self.logger is None:
                return

            if hasattr(
                self.logger,
                "log",
            ):
                self.logger.log(
                    event,
                    data,
                )

            elif hasattr(
                self.logger,
                "info",
            ):
                self.logger.info(
                    f"{event}: {data}"
                )

        except Exception:
            pass

    # ============================================================
    # GETTERS
    # ============================================================

    def get_status(self) -> str:
        return self.status

    def get_last_result(
        self,
    ) -> Optional[Dict[str, Any]]:
        return self.last_result

    def get_history(
        self,
    ) -> List[Dict[str, Any]]:
        return list(
            self.history
        )

    def get_version(self) -> str:
        return self.VERSION

    # ============================================================
    # STATUS HELPERS
    # ============================================================

    def is_idle(self) -> bool:
        return self.status == self.STATUS_IDLE

    def is_running(self) -> bool:
        return self.status == self.STATUS_RUNNING

    def is_success(self) -> bool:
        return self.status == self.STATUS_SUCCESS

    def is_failed(self) -> bool:
        return self.status == self.STATUS_FAILED

    # ============================================================
    # HISTORY MANAGEMENT
    # ============================================================

    def clear_history(self) -> None:
        self.history.clear()

    def reset(self) -> None:
        self.status = self.STATUS_IDLE
        self.last_result = None

    # ============================================================
    # REPRESENTATION
    # ============================================================

    def __repr__(self) -> str:
        return (
            f"<RecoveryManager "
            f"version={self.VERSION} "
            f"status={self.status}>"
        )