# SECURITY/jarvis_security_bridge.py
# JARVIS V11 — Security Bridge
# V8.0

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
import threading


class JarvisSecurityBridge:
    """
    Мост между JARVIS V11 и Security System.

    Назначение:
    - предоставляет JARVIS единый интерфейс Security System;
    - передает команды в SecurityAPI;
    - получает и нормализует результаты;
    - предоставляет состояние безопасности;
    - предоставляет уведомления и события;
    - позволяет подписывать JARVIS на security-события.

    ВАЖНО:
    Bridge не содержит собственной логики обнаружения угроз.
    Все security-решения выполняются Security System.
    """

    VERSION = "8.0"

    STATUS_DISCONNECTED = "DISCONNECTED"
    STATUS_CONNECTED = "CONNECTED"
    STATUS_ERROR = "ERROR"

    def __init__(
        self,
        security_api: Optional[Any] = None,
        notifications: Optional[Any] = None,
        logger: Optional[Any] = None,
    ):
        self.security_api = security_api
        self.notifications = notifications
        self.logger = logger

        self.status = self.STATUS_DISCONNECTED

        self.last_result: Optional[Dict[str, Any]] = None
        self.last_error: Optional[str] = None

        self.history: List[Dict[str, Any]] = []

        self._subscribers: List[
            Callable[[Dict[str, Any]], None]
        ] = []

        self._lock = threading.RLock()

        if self.security_api is not None:
            self.connect()

        self._log("JarvisSecurityBridge initialized")

    # ============================================================
    # CONNECTION
    # ============================================================

    def connect(
        self,
        security_api: Optional[Any] = None,
    ) -> bool:
        """
        Подключить SecurityAPI.

        Если security_api передан, используется новый экземпляр.
        """

        with self._lock:

            if security_api is not None:
                self.security_api = security_api

            if self.security_api is None:
                self.status = self.STATUS_DISCONNECTED
                return False

            try:
                if hasattr(self.security_api, "health_check"):
                    health = self.security_api.health_check()

                    if isinstance(health, dict):
                        if health.get("healthy") is False:
                            self.status = self.STATUS_ERROR
                            self.last_error = str(
                                health.get("error", "Security API unhealthy")
                            )
                            return False

                self.status = self.STATUS_CONNECTED
                self.last_error = None

                self._log("SecurityAPI connected")

                return True

            except Exception as exc:

                self.status = self.STATUS_ERROR
                self.last_error = str(exc)

                self._log(
                    f"SecurityAPI connection error: {exc}",
                    level="ERROR",
                )

                return False

    # ------------------------------------------------------------

    def disconnect(self) -> None:
        """Отключить SecurityAPI."""

        with self._lock:
            self.status = self.STATUS_DISCONNECTED

        self._log("SecurityAPI disconnected")

    # ------------------------------------------------------------

    def is_connected(self) -> bool:
        """Проверить соединение."""

        return (
            self.status == self.STATUS_CONNECTED
            and self.security_api is not None
        )

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        data: Any = None,
        context: Optional[Dict[str, Any]] = None,

) -> Dict[str, Any]:
        """
        Главный универсальный запрос к SecurityAPI.
        """

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            result = self.security_api.analyze(
                data=data,
                context=context,
            )

            return self._process_result(
                result,
                operation="analyze",
            )

        except Exception as exc:
            return self._handle_error(
                "analyze",
                exc,
            )

    # ============================================================
    # FILE
    # ============================================================

    def scan_file(
        self,
        path: str,
    ) -> Dict[str, Any]:
        """Проверить файл."""

        return self._call_api(
            "scan_file",
            path,
        )

    # ============================================================
    # FOLDER
    # ============================================================

    def scan_folder(
        self,
        path: str,
    ) -> Dict[str, Any]:
        """Проверить папку."""

        return self._call_api(
            "scan_folder",
            path,
        )

    # ============================================================
    # PROCESS
    # ============================================================

    def scan_process(
        self,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Проверить процесс."""

        if process_name is not None:
            return self._call_api(
                "scan_process",
                process_name,
            )

        if pid is not None:
            return self._call_api(
                "scan_process",
                pid,
            )

        return self._failure(
            "process_name or pid is required"
        )

    # ============================================================
    # STARTUP
    # ============================================================

    def scan_startup(self) -> Dict[str, Any]:
        """Проверить автозагрузку."""

        return self._call_api(
            "scan_startup"
        )

    # ============================================================
    # USB
    # ============================================================

    def scan_usb(
        self,
        device: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Проверить USB."""

        if device is not None:
            return self._call_api(
                "scan_usb",
                device,
            )

        return self._call_api(
            "scan_usb"
        )

    # ============================================================
    # NETWORK
    # ============================================================

    def scan_network(self) -> Dict[str, Any]:
        """Проверить сетевые соединения."""

        return self._call_api(
            "scan_network"
        )

    # ============================================================
    # FIREWALL
    # ============================================================

    def scan_firewall(self) -> Dict[str, Any]:
        """Проверить Windows Firewall."""

        return self._call_api(
            "scan_firewall"
        )

    # ============================================================
    # DNS
    # ============================================================

    def scan_dns(self) -> Dict[str, Any]:
        """Проверить DNS."""

        return self._call_api(
            "scan_dns"
        )

    # ============================================================
    # QUICK / FULL SCAN
    # ============================================================

    def quick_scan(self) -> Dict[str, Any]:
        """
        Быстрая проверка.

        Если SecurityAPI не имеет quick_scan,
        используется общий analyze.
22:07
"""

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            if hasattr(self.security_api, "quick_scan"):
                result = self.security_api.quick_scan()

            else:
                result = self.security_api.analyze(
                    data={
                        "scan_type": "quick",
                    }
                )

            return self._process_result(
                result,
                operation="quick_scan",
            )

        except Exception as exc:
            return self._handle_error(
                "quick_scan",
                exc,
            )

    # ------------------------------------------------------------

    def full_scan(self) -> Dict[str, Any]:
        """
        Полная проверка.

        Если SecurityAPI не имеет full_scan,
        используется общий analyze.
        """

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            if hasattr(self.security_api, "full_scan"):
                result = self.security_api.full_scan()

            else:
                result = self.security_api.analyze(
                    data={
                        "scan_type": "full",
                    }
                )

            return self._process_result(
                result,
                operation="full_scan",
            )

        except Exception as exc:
            return self._handle_error(
                "full_scan",
                exc,
            )

    # ============================================================
    # USER RESPONSE
    # ============================================================

    def user_response(
        self,
        approved: bool,
    ) -> Dict[str, Any]:
        """
        Передать ответ пользователя Security System.

        Используется после ASK_USER.
        """

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            if hasattr(self.security_api, "user_response"):
                result = self.security_api.user_response(
                    approved
                )

                return self._process_result(
                    result,
                    operation="user_response",
                )

            return self._failure(
                "SecurityAPI does not support user_response"
            )

        except Exception as exc:
            return self._handle_error(
                "user_response",
                exc,
            )

    # ============================================================
    # REMEDIATION
    # ============================================================

    def remediate(
        self,
        target: Any,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Передать запрос на remediation.

        Bridge не решает, какую remediation выполнять.
        """

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            result = self.security_api.remediate(
                target=target,
                action=action,
                context=context,
            )

            return self._process_result(
                result,
                operation="remediate",
            )

        except TypeError:

            # Поддержка API с другой сигнатурой
            try:
                result = self.security_api.remediate(
                    target
                )

                return self._process_result(
                    result,
                    operation="remediate",
                )

            except Exception as exc:

                return self._handle_error(
                    "remediate",
                    exc,
                )

        except Exception as exc:
            return self._handle_error(
                "remediate",
                exc,
            )

    # ============================================================
    # RECOVERY
    # ============================================================

    def recover(
        self,
        target: Any,
        backup_path: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Восстановить объект."""

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            result = self.security_api.recover(
                target=target,
                backup_path=backup_path,
                context=context,
            )

            return self._process_result(
                result,
                operation="recover",
            )

        except TypeError:

            try:

                result = self.security_api.recover(
                    target
                )

                return self._process_result(
                    result,
                    operation="recover",
                )

            except Exception as exc:
                return self._handle_error(
                    "recover",
                    exc,
                )

        except Exception as exc:
            return self._handle_error(
                "recover",
                exc,
            )

    # ============================================================
    # SECURITY STATUS
    # ============================================================

    def get_security_status(self) -> Dict[str, Any]:
        """
        Получить общее состояние безопасности.
        """

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            if hasattr(self.security_api, "get_status"):
                result = self.security_api.get_status()

            elif hasattr(self.security_api, "health_check"):
                result = self.security_api.health_check()

            else:
                result = {
                    "status": "UNKNOWN",
                }

            return self._process_result(
                result,
                operation="get_security_status",
                store_history=False,
            )

        except Exception as exc:
            return self._handle_error(
                "get_security_status",
                exc,
            )

    # ============================================================
    # SECURITY SCORE
    # ============================================================

    def get_security_score(self) -> Optional[float]:
        """
        Получить Security Score.

        Сам Bridge его НЕ рассчитывает.
        """

        if not self._ensure_connection():
            return None

        try:

            # API может предоставлять score напрямую
            if hasattr(
                self.security_api,
                "get_security_score",
            ):
                result = self.security_api.get_security_score()

                return self._extract_score(result)

            # Или score может находиться в status
            status = self.security_api.get_status()

            return self._extract_score(status)

        except Exception as exc:

            self._log(
                f"Security score error: {exc}",
                level="ERROR",
            )

            return None

    # ============================================================
    # THREATS
    # ============================================================

    def get_threats(
        self,
    ) -> List[Dict[str, Any]]:
        """Получить список угроз."""

        if not self._ensure_connection():

           return []

        try:

            if hasattr(
                self.security_api,
                "get_threats",
            ):
                result = self.security_api.get_threats()

                return self._normalize_list(result)

            if isinstance(self.last_result, dict):

                threats = self.last_result.get(
                    "threats",
                    [],
                )

                return self._normalize_list(threats)

            return []

        except Exception as exc:

            self._log(
                f"Threat retrieval error: {exc}",
                level="ERROR",
            )

            return []

    # ============================================================
    # NOTIFICATIONS
    # ============================================================

    def get_notifications(
        self,
        unread_only: bool = False,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Получить security notifications.
        """

        if self.notifications is None:
            return []

        try:

            if unread_only and hasattr(
                self.notifications,
                "get_unread",
            ):
                return self.notifications.get_unread(
                    limit=limit
                )

            if hasattr(
                self.notifications,
                "get_all",
            ):
                return self.notifications.get_all(
                    limit=limit
                )

            return []

        except Exception as exc:

            self._log(
                f"Notification retrieval error: {exc}",
                level="ERROR",
            )

            return []

    # ------------------------------------------------------------

    def unread_notifications_count(self) -> int:
        """Количество непрочитанных уведомлений."""

        if self.notifications is None:
            return 0

        try:

            if hasattr(
                self.notifications,
                "unread_count",
            ):
                return int(
                    self.notifications.unread_count()
                )

        except Exception:
            pass

        return len(
            self.get_notifications(
                unread_only=True
            )
        )

    # ============================================================
    # EVENTS
    # ============================================================

    def subscribe(
        self,
        callback: Callable[[Dict[str, Any]], None],
    ) -> bool:
        """
        Подписать JARVIS на security-события.
        """

        if not callable(callback):
            return False

        with self._lock:

            if callback not in self._subscribers:
                self._subscribers.append(callback)

                self._log(
                    "JARVIS security subscriber added"
                )

                return True

        return False

    # ------------------------------------------------------------

    def unsubscribe(
        self,
        callback: Callable[[Dict[str, Any]], None],
    ) -> bool:
        """Удалить подписчика."""

        with self._lock:

            if callback in self._subscribers:
                self._subscribers.remove(callback)

                self._log(
                    "JARVIS security subscriber removed"
                )

                return True

        return False

    # ------------------------------------------------------------

    def _emit(
        self,
        event: Dict[str, Any],
    ) -> None:
        """Передать событие подписчикам."""

        subscribers = list(self._subscribers)

        for callback in subscribers:

            try:
                callback(event)

            except Exception as exc:

                self._log(
                    f"Bridge subscriber error: {exc}",
                    level="ERROR",
                )

    # ============================================================
    # NOTIFICATION BRIDGE
    # ============================================================

    def connect_notifications(self) -> bool:
        """
        Подключить SecurityNotifications к Bridge.

        После этого новые уведомления Security System
        будут автоматически передаваться подписчикам Bridge.
        """

        if self.notifications is None:
            return False

        try:

            if hasattr(
                self.notifications,
                "subscribe",
            ):
                self.notifications.subscribe(
                    self._notification_callback
                )

                self._log(
                    "SecurityNotifications connected"
                )

                return True

        except Exception as exc:

            self._log(
                f"Notification connection error: {exc}",
                level="ERROR",
            )

        return False

    # ------------------------------------------------------------

    def _notification_callback(
        self,
        notification: Dict[str, Any],
    ) -> None:
        """Получить notification от SecurityNotifications."""

        event = {
            "event": "security_notification",
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
            "notification": notification,
        }

        self._emit(event)

    # ============================================================
    # API CALL HELPER
    # ============================================================

    def _call_api(
        self,
        method_name: str,
        *args,
        **kwargs,
    ) -> Dict[str, Any]:
        """Безопасный вызов метода SecurityAPI."""

        if not self._ensure_connection():
            return self._failure(
                "SecurityAPI is not connected"
            )

        try:

            method = getattr(
                self.security_api,
                method_name,
                None,
            )

            if method is None:
                return self._failure(
                    f"SecurityAPI does not support "
                    f"{method_name}"
                )

            result = method(
                *args,
                **kwargs,
            )

            return self._process_result(
                result,
                operation=method_name,
            )

        except Exception as exc:

            return self._handle_error(
                method_name,
                exc,
            )

    # ============================================================
    # CONNECTION CHECK
    # ============================================================

    def _ensure_connection(self) -> bool:
        """Проверить подключение."""

        if self.security_api is None:
            self.status = self.STATUS_DISCONNECTED
            return False

        if self.status != self.STATUS_CONNECTED:

            if not self.connect():
                return False

        return True

    # ============================================================
    # RESULT PROCESSING
    # ============================================================

    def _process_result(
        self,
        result: Any,
        operation: str,
        store_history: bool = True,
    ) -> Dict[str, Any]:
        """
        Нормализовать результат SecurityAPI.
        """

        if isinstance(result, dict):
            normalized = dict(result)

        else:
            normalized = {
                "result": result,
            }

        normalized.setdefault(
            "operation",
            operation,
        )

        normalized.setdefault(
            "timestamp",
            datetime.now().isoformat(
                timespec="seconds"
            ),
        )

        normalized.setdefault(
            "bridge_version",
            self.VERSION,
        )

        normalized.setdefault(
            "success",
            True,
        )

        with self._lock:

            self.last_result = normalized
            self.last_error = None

            if store_history:
                self.history.append(
                    normalized
                )

                self._trim_history()

        self._emit(
            {
                "event": "security_result",
                "operation": operation,
                "result": normalized,
            }
        )

        self._log(
            f"Security operation completed: {operation}"
        )

        return normalized

    # ============================================================
    # FAILURE
    # ============================================================

    def _failure(
        self,
        message: str,
    ) -> Dict[str, Any]:
        """Создать результат ошибки."""

        result = {
            "success": False,
            "status": self.STATUS_ERROR,
            "error": message,

            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),

            "bridge_version": self.VERSION,
        }

        with self._lock:
            self.last_result = result
            self.last_error = message

        return result

    # ============================================================
    # ERROR HANDLING
    # ============================================================

    def _handle_error(
        self,
        operation: str,
        exc: Exception,
    ) -> Dict[str, Any]:
        """Обработать исключение."""

        message = str(exc)

        self.status = self.STATUS_ERROR
        self.last_error = message

        self._log(
            f"Security operation error "
            f"[{operation}]: {message}",
            level="ERROR",
        )

        return {
            "success": False,
            "status": self.STATUS_ERROR,

            "operation": operation,

            "error": message,

            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),

            "bridge_version": self.VERSION,
        }

    # ============================================================
    # NORMALIZATION HELPERS
    # ============================================================

    def _normalize_list(
        self,
        value: Any,
    ) -> List[Dict[str, Any]]:
        """Привести список результатов к единому виду."""

        if value is None:
            return []

        if isinstance(value, list):

            normalized = []

            for item in value:

                if isinstance(item, dict):
                    normalized.append(item)

                else:
                    normalized.append(
                        {
                            "value": item,
                        }
                    )

            return normalized

        if isinstance(value, dict):

            # Если API вернул {"threats": [...]}
            for key in (
                "threats",
                "items",
                "results",
                "data",
            ):

                if isinstance(
                    value.get(key),
                    list,
                ):
                    return self._normalize_list(
                        value.get(key)
                    )

            return [value]

        return [
            {
                "value": value,
            }
        ]

    # ------------------------------------------------------------

    def _extract_score(
        self,
        value: Any,
    ) -> Optional[float]:
        """Извлечь Security Score."""

        if value is None:
            return None

        if isinstance(value, (int, float)):
            return float(value)

        if isinstance(value, dict):

            for key in (
                "security_score",
                "score",
                "risk_score",
            ):

             if key in value:

                    try:
                        return float(
                            value[key]
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        return None

        return None

    # ============================================================
    # HISTORY
    # ============================================================

    def _trim_history(self) -> None:
        """Ограничить историю."""

        max_history = 500

        if len(self.history) > max_history:

            excess = (
                len(self.history)
                - max_history
            )

            del self.history[:excess]

    # ------------------------------------------------------------

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Получить историю операций."""

        with self._lock:

            items = list(
                reversed(self.history)
            )

            if limit is not None:
                items = items[
                    :max(0, int(limit))
                ]

            return items

    # ============================================================
    # STATUS
    # ============================================================

    def get_status(self) -> Dict[str, Any]:
        """Получить состояние Bridge."""

        with self._lock:

            return {
                "version": self.VERSION,

                "status": self.status,

                "connected": self.is_connected(),

                "security_api": (
                    self.security_api is not None
                ),

                "notifications": (
                    self.notifications is not None
                ),

                "subscribers": len(
                    self._subscribers
                ),

                "history_size": len(
                    self.history
                ),

                "unread_notifications": (
                    self.unread_notifications_count()
                ),

                "last_error": self.last_error,
            }

    # ============================================================
    # HEALTH CHECK
    # ============================================================

    def health_check(self) -> Dict[str, Any]:
        """Проверка работоспособности Bridge."""

        try:

            connected = self._ensure_connection()

            api_health = None

            if (
                connected
                and hasattr(
                    self.security_api,
                    "health_check",
                )
            ):
                api_health = (
                    self.security_api.health_check()
                )

            return {
                "healthy": connected,

                "bridge_version": self.VERSION,

                "status": self.status,

                "security_api": api_health,

                "error": self.last_error,
            }

        except Exception as exc:

            return {
                "healthy": False,

                "bridge_version": self.VERSION,

                "status": self.STATUS_ERROR,

                "error": str(exc),
            }

    # ============================================================
    # RESET
    # ============================================================

    def reset_history(self) -> None:
        """Очистить историю Bridge."""

        with self._lock:
            self.history.clear()

        self._log(
            "Bridge history cleared"
        )

    # ============================================================
    # LOGGER
    # ============================================================

    def _log(
        self,
        message: str,
        level: str = "INFO",
    ) -> None:
        """Безопасное логирование."""

        if self.logger is None:

            return

        try:

            if hasattr(
                self.logger,
                "log",
            ):
                self.logger.log(
                    level,
                    message,
                )

            elif (
                level == "ERROR"
                and hasattr(
                    self.logger,
                    "error",
                )
            ):
                self.logger.error(message)

            elif (
                level == "WARNING"
                and hasattr(
                    self.logger,
                    "warning",
                )
            ):
                self.logger.warning(message)

            elif hasattr(
                self.logger,
                "info",
            ):
                self.logger.info(message)

        except Exception:
            pass

    # ============================================================
    # REPRESENTATION
    # ============================================================

    def __repr__(self) -> str:
        return (
            f"<JarvisSecurityBridge "
            f"version={self.VERSION} "
            f"status={self.status}>"
        )


# ================================================================
# SINGLETON
# ================================================================

_bridge_instance: Optional[JarvisSecurityBridge] = None


def get_jarvis_security_bridge(
    security_api: Optional[Any] = None,
    notifications: Optional[Any] = None,
    logger: Optional[Any] = None,
) -> JarvisSecurityBridge:
    """
    Получить общий экземпляр JarvisSecurityBridge.
    """

    global _bridge_instance

    if _bridge_instance is None:

        _bridge_instance = JarvisSecurityBridge(
            security_api=security_api,
            notifications=notifications,
            logger=logger,
        )

    else:

        if (
            security_api is not None
            and _bridge_instance.security_api is None
        ):
            _bridge_instance.connect(
                security_api
            )

        if (
            notifications is not None
            and _bridge_instance.notifications is None
        ):
            _bridge_instance.notifications = (
                notifications
            )

        if (
            logger is not None
            and _bridge_instance.logger is None
        ):
            _bridge_instance.logger = logger

    return _bridge_instance