"""
JARVIS SECURITY
V7.0 - Security API

Единая программная точка доступа к Security Core.

Предоставляет:
- запуск полного анализа;
- проверку файлов;
- проверку процессов;
- проверку автозагрузки;
- проверку USB;
- получение текущего статуса;
- получение последнего результата;
- получение истории;
- управление карантином;
- запуск remediation;
- восстановление объектов.

Sandbox не используется.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional


class SecurityAPI:
    """
    Security API V7.0.

    Единый интерфейс между Security Core
    и другими компонентами JARVIS.
    """

    VERSION = "7.0"

    STATUS_READY = "READY"
    STATUS_RUNNING = "RUNNING"
    STATUS_SUCCESS = "SUCCESS"
    STATUS_FAILED = "FAILED"

    def __init__(
        self,
        security_controller: Optional[Any] = None,
        security_core: Optional[Any] = None,
        security_orchestrator: Optional[Any] = None,
        remediation_engine: Optional[Any] = None,
        recovery_manager: Optional[Any] = None,
        logger: Optional[Any] = None,
    ):
        self.security_controller = security_controller
        self.security_core = security_core
        self.security_orchestrator = security_orchestrator
        self.remediation_engine = remediation_engine
        self.recovery_manager = recovery_manager
        self.logger = logger

        self.status = self.STATUS_READY
        self.last_result: Optional[Dict[str, Any]] = None
        self.history: List[Dict[str, Any]] = []

    # ============================================================
    # ОСНОВНОЙ SECURITY API
    # ============================================================

    def analyze(
        self,
        data: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Запускает полный анализ через Security Controller.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:
            if self.security_controller is not None:
                result = self.security_controller.run(
                    data=data,
                    context=context,
                )

                return self._store_result(
                    result,
                    started_at,
                )

            # ----------------------------------------------------
            # Резервный вариант через Security Core
            # ----------------------------------------------------

            if self.security_core is not None:

                if hasattr(
                    self.security_core,
                    "run",
                ):
                    result = self.security_core.run(
                        data
                    )

                    return self._store_result(
                        result,
                        started_at,
                    )

                if hasattr(
                    self.security_core,
                    "analyze",
                ):
                    result = self.security_core.analyze(
                        data
                    )

                    return self._store_result(
                        result,
                        started_at,
                    )

            # ----------------------------------------------------
            # Резервный вариант через Orchestrator
            # ----------------------------------------------------

            if self.security_orchestrator is not None:

                if hasattr(
                    self.security_orchestrator,
                    "run",
                ):
                    result = self.security_orchestrator.run(
                        data
                    )

                    return self._store_result(
                        result,
                        started_at,
                    )

                if hasattr(
                    self.security_orchestrator,

"analyze",
                ):
                    result = self.security_orchestrator.analyze(
                        data
                    )

                    return self._store_result(
                        result,
                        started_at,
                    )

            return self._failure(
                "No Security analysis engine is available.",
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"Security analysis failed: {exc}",
                started_at,
            )

    # ============================================================
    # ПРОВЕРКА ФАЙЛА
    # ============================================================

    def scan_file(
        self,
        file_path: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Проверяет конкретный файл.
        """

        return self.analyze(
            data={
                "type": "file",
                "target": file_path,
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА ПРОЦЕССА
    # ============================================================

    def scan_process(
        self,
        process: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Проверяет конкретный процесс.
        """

        return self.analyze(
            data={
                "type": "process",
                "target": process,
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА ПАПКИ
    # ============================================================

    def scan_folder(
                self,
                folder_path: str,
                context: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            """
            Проверяет конкретную папку.
            """

            return self.analyze(
                data={
                    "type": "folder",
                    "target": folder_path,
                },
                context=context,
            )

    # ============================================================
    # ПРОВЕРКА АВТОЗАПУСКА
    # ============================================================

    def scan_startup(
        self,
        startup_item: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Проверяет элемент автозагрузки.
        """

        return self.analyze(
            data={
                "type": "startup",
                "target": startup_item,
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА USB
    # ============================================================

    def scan_usb(
        self,
        usb_device: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Проверяет USB-устройство.
        """

        return self.analyze(
            data={
                "type": "usb",
                "target": usb_device,
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА СЕТИ
    # ============================================================

    def scan_network(
        self,
        target: Any = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Запускает сетевой анализ.
        """

        return self.analyze(
            data={
                "type": "network",
                "target": target,
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА FIREWALL
    # ============================================================

    def scan_firewall(
        self,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Запускает анализ Windows Firewall.
        """

        return self.analyze(
            data={
                "type": "firewall",
            },
            context=context,
        )

    # ============================================================
    # ПРОВЕРКА DNS
    # ============================================================

    def scan_dns(
        self,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
21:30
Запускает анализ DNS-конфигурации.
        """

        return self.analyze(
            data={
                "type": "dns",
            },
            context=context,
        )

    # ============================================================
    # USER RESPONSE
    # ============================================================

    def user_response(
        self,
        approved: bool,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Передаёт решение пользователя Security Controller.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if self.security_controller is None:

                return self._failure(
                    "Security Controller is not available.",
                    started_at,
                )

            if not hasattr(
                self.security_controller,
                "user_response",
            ):

                return self._failure(
                    "Security Controller does not support user response.",
                    started_at,
                )

            result = self.security_controller.user_response(
                approved=approved,
                context=context,
            )

            return self._store_result(
                result,
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"User response handling failed: {exc}",
                started_at,
            )

    # ============================================================
    # REMEDIATION
    # ============================================================

    def remediate(
        self,
        target: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Запускает Remediation Engine.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if self.remediation_engine is None:

                return self._failure(
                    "Remediation Engine is not available.",
                    started_at,
                )

            if not hasattr(
                self.remediation_engine,
                "remediate",
            ):

                return self._failure(
                    "Remediation Engine does not support remediate().",
                    started_at,
                )

            result = self.remediation_engine.remediate(
                target=target,
                action=action,
                context=context,
            )

            return self._store_result(
                result,
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"Remediation failed: {exc}",
                started_at,
            )

    # ============================================================
    # ВОССТАНОВЛЕНИЕ
    # ============================================================

    def recover(
        self,
        target: str,
        backup_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Восстанавливает объект через Recovery Manager.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if self.recovery_manager is None:

                return self._failure(
                    "Recovery Manager is not available.",
                    started_at,
                )

            if not hasattr(
                self.recovery_manager,
                "recover",
            ):

                return self._failure(
                    "Recovery Manager does not support recover().",
                    started_at,
                )

            result = self.recovery_manager.recover(
                target=target,
                backup_path=backup_path,
                context=context,
            )

            return self._store_result(
                result,
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"Recovery failed: {exc}",
                started_at,
            )

    # ============================================================
    # BACKUP
    # ============================================================

    def create_backup(
        self,
        source: str,
        backup_path: str,
    ) -> Dict[str, Any]:
        """
        Создаёт резервную копию.
        """

        self.status = self.STATUS_RUNNING

        started_at = datetime.now().isoformat()

        try:

            if self.recovery_manager is None:

                return self._failure(
                    "Recovery Manager is not available.",
                    started_at,
                )

            result = self.recovery_manager.create_backup(
                source=source,
                backup_path=backup_path,
            )

            return self._store_result(
                result,
                started_at,
            )

        except Exception as exc:

            return self._failure(
                f"Backup creation failed: {exc}",
                started_at,
            )

    # ============================================================
    # CAN RECOVER
    # ============================================================

    def can_recover(
        self,
        target: str,
        backup_path: Optional[str] = None,
    ) -> bool:
        """
        Проверяет возможность восстановления.
        """

        try:

            if self.recovery_manager is None:
                return False

            if not hasattr(
                self.recovery_manager,
                "can_recover",
            ):
                return False

            return bool(
                self.recovery_manager.can_recover(
                    target=target,
                    backup_path=backup_path,
                )
            )

        except Exception:
            return False

    # ============================================================
    # STATUS
    # ============================================================

    def get_status(self) -> str:
        return self.status

    def get_version(self) -> str:
        return self.VERSION

    # ============================================================
    # LAST RESULT
    # ============================================================

    def get_last_result(
        self,
    ) -> Optional[Dict[str, Any]]:
        return self.last_result

    # ============================================================
    # HISTORY
    # ============================================================

    def get_history(
        self,
    ) -> List[Dict[str, Any]]:
        return list(
            self.history
        )

    # ============================================================
    # COMPONENT STATUS
    # ============================================================

    def get_components_status(
        self,
    ) -> Dict[str, bool]:
        """
        Возвращает информацию о подключённых компонентах.
        """

        return {
            "security_controller": (
                self.security_controller is not None
            ),
            "security_core": (
                self.security_core is not None
            ),
            "security_orchestrator": (
                self.security_orchestrator is not None
            ),
            "remediation_engine": (
                self.remediation_engine is not None
            ),
            "recovery_manager": (
                self.recovery_manager is not None
            ),
            "logger": (
                self.logger is not None
            ),
        }

    # ============================================================
    # HEALTH CHECK
    # ============================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Проверяет работоспособность API.
        """

        components = self.get_components_status()

        available = any(
            [
                components["security_controller"],
                components["security_core"],
                components["security_orchestrator"],
            ]
        )

        result = {
            "healthy": available,
            "status": (
                self.STATUS_READY
                if available
                else self.STATUS_FAILED
            ),
            "version": self.VERSION,
            "components": components,
            "timestamp": datetime.now().isoformat(),
        }

        return result

    # ============================================================
    # INTERNAL RESULT STORAGE
    # ============================================================

    def _store_result(
        self,
        result: Any,
        started_at: str,
    ) -> Dict[str, Any]:

        if isinstance(result, dict):

            stored = dict(result)

        else:

            stored = {
                "success": bool(result),
                "result": result,
            }

        stored.setdefault(
            "timestamp",
            datetime.now().isoformat(),
        )

        stored.setdefault(
            "started_at",
            started_at,
        )

        self.last_result = stored
        self.history.append(stored)

        if stored.get("success"):

            self.status = self.STATUS_SUCCESS

        else:

            self.status = self.STATUS_FAILED

        self._log(
            "security_api_result",
            stored,
        )

        return stored

    # ============================================================
    # FAILURE
    # ============================================================

    def _failure(
        self,
        message: str,
        started_at: str,
    ) -> Dict[str, Any]:

        self.status = self.STATUS_FAILED

        result = {
            "success": False,
            "status": self.STATUS_FAILED,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "started_at": started_at,
        }

        self.last_result = result
        self.history.append(result)

        self._log(
            "security_api_failure",
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
    # RESET
    # ============================================================

    def clear_history(self) -> None:
        self.history.clear()

    def reset(self) -> None:
        self.status = self.STATUS_READY
        self.last_result = None

    # ============================================================
    # REPRESENTATION
    # ============================================================

    def __repr__(self) -> str:
        return (
            f"<SecurityAPI "
            f"version={self.VERSION} "
            f"status={self.status}>"
        )