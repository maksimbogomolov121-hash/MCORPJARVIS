# SECURITY/security_notifications.py
# JARVIS V11 — Security Notifications
# V7.2

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
import threading
import time


class SecurityNotifications:
    """
    Менеджер уведомлений системы безопасности JARVIS.

    Отвечает за:
    - создание уведомлений;
    - уровни важности;
    - историю уведомлений;
    - unread/read состояние;
    - антиспам и cooldown;
    - объединение одинаковых уведомлений;
    - подписчиков;
    - передачу событий интерфейсу;
    - подготовку событий для голосового JARVIS.

    ВАЖНО:
    Этот класс НЕ принимает решения о безопасности.
    Он только сообщает пользователю о событиях,
    которые уже были сформированы Security Core / API.
    """

    VERSION = "7.2"

    # ============================================================
    # LEVELS
    # ============================================================

    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    LEVEL_PRIORITY = {
        INFO: 1,
        NOTICE: 2,
        WARNING: 3,
        HIGH: 4,
        CRITICAL: 5,
    }

    # ============================================================
    # NOTIFICATION TYPES
    # ============================================================

    TYPE_INFO = "INFO"
    TYPE_SCAN_STARTED = "SCAN_STARTED"
    TYPE_SCAN_COMPLETED = "SCAN_COMPLETED"
    TYPE_THREAT_DETECTED = "THREAT_DETECTED"
    TYPE_THREAT_BLOCKED = "THREAT_BLOCKED"
    TYPE_THREAT_QUARANTINED = "THREAT_QUARANTINED"
    TYPE_THREAT_REMOVED = "THREAT_REMOVED"
    TYPE_RECOVERY = "RECOVERY"
    TYPE_SYSTEM = "SYSTEM"
    TYPE_NETWORK = "NETWORK"
    TYPE_FIREWALL = "FIREWALL"
    TYPE_DNS = "DNS"
    TYPE_STARTUP = "STARTUP"
    TYPE_USB = "USB"
    TYPE_PROCESS = "PROCESS"
    TYPE_USER_ACTION = "USER_ACTION"
    TYPE_ERROR = "ERROR"

    # ============================================================
    # DEFAULT SETTINGS
    # ============================================================

    DEFAULT_COOLDOWN = 5.0
    DEFAULT_MAX_HISTORY = 500

    # ============================================================
    # INIT
    # ============================================================

    def __init__(
        self,
        logger: Optional[Any] = None,
        max_history: int = DEFAULT_MAX_HISTORY,
        cooldown: float = DEFAULT_COOLDOWN,
    ):
        self.logger = logger

        self.max_history = max(1, int(max_history))
        self.cooldown = max(0.0, float(cooldown))

        self.enabled = True

        # История уведомлений
        self.notifications: List[Dict[str, Any]] = []

        # Счетчик ID
        self._next_id = 1

        # Подписчики
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []

        # Последнее время уведомления
        self._last_notification_time: Dict[str, float] = {}

        # Счетчик повторений
        self._duplicate_counts: Dict[str, int] = {}

        # Блокировка для потокобезопасности
        self._lock = threading.RLock()

        # Статистика
        self.total_created = 0
        self.total_suppressed = 0
        self.total_critical = 0
        self.total_high = 0
        self.total_warning = 0
        self.total_info = 0

        self.last_notification: Optional[Dict[str, Any]] = None

        self._log("SecurityNotifications initialized")

    # ============================================================
    # CORE NOTIFICATION METHOD
    # ============================================================

    def notify(
        self,
        title: str,
        message: str,
        severity: str = INFO,
        notification_type: str = TYPE_INFO,
        target: Optional[str] = None,
        recommended_action: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        cooldown: Optional[float] = None,
        force: bool = False,
    ) -> Optional[Dict[str, Any]]:

        """
        Создает новое уведомление.

        Возвращает созданное уведомление или None,
        если уведомление было подавлено антиспамом.
        """

        with self._lock:

            if not self.enabled and not force:
                self.total_suppressed += 1
                return None

            severity = self._normalize_severity(severity)
            notification_type = self._normalize_type(notification_type)

            title = str(title or "Security Notification")
            message = str(message or "")

            notification_key = self._build_notification_key(
                title=title,
                message=message,
                severity=severity,
                notification_type=notification_type,
                target=target,
            )

            # ----------------------------------------------------
            # COOLDOWN
            # ----------------------------------------------------

            if not force:
                effective_cooldown = (
                    self.cooldown
                    if cooldown is None
                    else max(0.0, float(cooldown))
                )

                if self._is_in_cooldown(
                    notification_key,
                    effective_cooldown,
                ):
                    self.total_suppressed += 1

                    self._duplicate_counts[notification_key] = (
                        self._duplicate_counts.get(notification_key, 0) + 1
                    )

                    # Попробуем обновить уже существующее уведомление
                    self._update_duplicate(notification_key)

                    return None

            # ----------------------------------------------------
            # CREATE
            # ----------------------------------------------------

            notification = {
                "id": self._next_id,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "timestamp_unix": time.time(),

                "type": notification_type,
                "severity": severity,

                "title": title,
                "message": message,

                "target": target,

                "recommended_action": recommended_action,

                "metadata": dict(metadata or {}),

                "read": False,
                "acknowledged": False,

                "duplicate_count": 0,

                "notification_key": notification_key,
            }

            self._next_id += 1

            self.notifications.append(notification)

            self.total_created += 1

            self.last_notification = notification

            self._register_statistics(severity)

            self._last_notification_time[notification_key] = time.time()

            # Ограничиваем историю
            self._trim_history()

            # Логируем
            self._log(
                f"Notification created: "
                f"[{severity}] {title}"
            )

            # Уведомляем подписчиков
            self._emit(notification)

            return notification

    # ============================================================
    # CONVENIENCE METHODS
    # ============================================================

    def info(
        self,
        title: str,
        message: str,
        notification_type: str = TYPE_INFO,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Информационное уведомление."""

        return self.notify(
            title=title,
            message=message,
            severity=self.INFO,
            notification_type=notification_type,
            **kwargs,
        )

    # ------------------------------------------------------------

    def notice(
        self,
        title: str,
        message: str,
        notification_type: str = TYPE_INFO,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Обычное важное уведомление."""

        return self.notify(

            title=title,
            message=message,
            severity=self.NOTICE,
            notification_type=notification_type,
            **kwargs,
        )

    # ------------------------------------------------------------

    def warning(
        self,
        title: str,
        message: str,
        notification_type: str = TYPE_SYSTEM,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Предупреждение."""

        return self.notify(
            title=title,
            message=message,
            severity=self.WARNING,
            notification_type=notification_type,
            **kwargs,
        )

    # ------------------------------------------------------------

    def high(
        self,
        title: str,
        message: str,
        notification_type: str = TYPE_THREAT_DETECTED,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Высокоопасное событие."""

        return self.notify(
            title=title,
            message=message,
            severity=self.HIGH,
            notification_type=notification_type,
            **kwargs,
        )

    # ------------------------------------------------------------

    def critical(
        self,
        title: str,
        message: str,
        notification_type: str = TYPE_THREAT_DETECTED,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """Критическое событие."""

        return self.notify(
            title=title,
            message=message,
            severity=self.CRITICAL,
            notification_type=notification_type,
            **kwargs,
        )

    # ============================================================
    # SECURITY-SPECIFIC NOTIFICATIONS
    # ============================================================

    def threat_detected(
        self,
        threat_name: str,
        target: Optional[str] = None,
        severity: str = HIGH,
        details: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Уведомление об обнаруженной угрозе.
        """

        message = f"Обнаружена угроза: {threat_name}"

        if target:
            message += f"\nОбъект: {target}"

        if details:
            message += f"\n{details}"

        return self.notify(
            title="Обнаружена угроза",
            message=message,
            severity=severity,
            notification_type=self.TYPE_THREAT_DETECTED,
            target=target,
            recommended_action="Проверить и при необходимости поместить объект в карантин.",
            metadata={
                "threat_name": threat_name,
                **(metadata or {}),
            },
            cooldown=10.0,
        )

    # ------------------------------------------------------------

    def threat_blocked(
        self,
        threat_name: str,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление о блокировке угрозы."""

        message = f"Угроза заблокирована: {threat_name}"

        if target:
            message += f"\nОбъект: {target}"

        return self.notify(
            title="Угроза заблокирована",
            message=message,
            severity=self.HIGH,
            notification_type=self.TYPE_THREAT_BLOCKED,
            target=target,
            recommended_action="Проверить отчет безопасности.",
            metadata={
                "threat_name": threat_name,
                **(metadata or {}),
            },
            cooldown=5.0,
        )

    # ------------------------------------------------------------

    def threat_quarantined(
        self,
        threat_name: str,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление о помещении угрозы в карантин."""

        message = f"Объект помещен в карантин: {threat_name}"

        if target:

                    message += f"\nОбъект: {target}"

        return self.notify(
            title="Угроза помещена в карантин",
            message=message,
            severity=self.WARNING,
            notification_type=self.TYPE_THREAT_QUARANTINED,
            target=target,
            recommended_action="Открыть карантин и проверить объект.",
            metadata={
                "threat_name": threat_name,
                **(metadata or {}),
            },
            cooldown=3.0,
        )

    # ------------------------------------------------------------

    def threat_removed(
        self,
        threat_name: str,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление об удалении угрозы."""

        message = f"Угроза удалена: {threat_name}"

        if target:
            message += f"\nОбъект: {target}"

        return self.notify(
            title="Угроза удалена",
            message=message,
            severity=self.NOTICE,
            notification_type=self.TYPE_THREAT_REMOVED,
            target=target,
            metadata={
                "threat_name": threat_name,
                **(metadata or {}),
            },
            cooldown=3.0,
        )

    # ============================================================
    # SCAN NOTIFICATIONS
    # ============================================================

    def scan_started(
        self,
        scan_type: str = "quick",
        target: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Сканирование началось."""

        message = f"Начато сканирование: {scan_type}"

        if target:
            message += f"\nЦель: {target}"

        return self.notify(
            title="Сканирование запущено",
            message=message,
            severity=self.INFO,
            notification_type=self.TYPE_SCAN_STARTED,
            target=target,
            metadata={
                "scan_type": scan_type,
            },
            cooldown=1.0,
        )

    # ------------------------------------------------------------

    def scan_completed(
        self,
        scan_type: str = "quick",
        threats_found: int = 0,
        target: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Сканирование завершено."""

        if threats_found > 0:
            severity = self.WARNING
            title = "Сканирование завершено: обнаружены угрозы"
        else:
            severity = self.NOTICE
            title = "Сканирование завершено"

        message = (
            f"Тип сканирования: {scan_type}\n"
            f"Обнаружено угроз: {threats_found}"
        )

        if target:
            message += f"\nЦель: {target}"

        return self.notify(
            title=title,
            message=message,
            severity=severity,
            notification_type=self.TYPE_SCAN_COMPLETED,
            target=target,
            metadata={
                "scan_type": scan_type,
                "threats_found": threats_found,
            },
            cooldown=2.0,
        )

    # ============================================================
    # FIREWALL
    # ============================================================

    def firewall_alert(
            self,
            message: str,
            severity: str = "WARNING",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Событие Windows Firewall."""

        return self.notify(
            title="Предупреждение Firewall",
            message=message,
            severity=severity,
            notification_type=self.TYPE_FIREWALL,
            metadata=metadata,
            cooldown=10.0,
        )

    # ============================================================
    # NETWORK
    # ============================================================

    def network_alert(
            self,
            message: str,
            target: Optional[str] = None,
            severity: str = "WARNING",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Сетевое уведомление."""

        return self.notify(
            title="Сетевое событие",
            message=message,
            severity=severity,
            notification_type=self.TYPE_NETWORK,
            target=target,
            metadata=metadata,
            cooldown=10.0,
        )

    # ============================================================
    # DNS
    # ============================================================

    def dns_alert(
            self,
            message: str,
            severity: str = "WARNING",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление DNS."""

        return self.notify(
            title="Сетевое событие DNS",
            message=message,
            severity=severity,
            notification_type=self.TYPE_DNS,
            metadata=metadata,
            cooldown=10.0,
        )

    # ============================================================
    # STARTUP
    # ============================================================

    def startup_alert(
            self,
            message: str,
            target: Optional[str] = None,
            severity: str = "WARNING",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление об автозагрузке."""

        return self.notify(
            title="Событие автозагрузки",
            message=message,
            severity=severity,
            notification_type=self.TYPE_STARTUP,
            target=target,
            metadata=metadata,
            cooldown=10.0,
        )

    # ============================================================
    # USB
    # ============================================================

    def usb_alert(
            self,
            message: str,
            target: Optional[str] = None,
            severity: str = "NOTICE",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление USB."""

        return self.notify(
            title="USB событие",
            message=message,
            severity=severity,
            notification_type=self.TYPE_USB,
            target=target,
            metadata=metadata,
            cooldown=5.0,
        )

    # ============================================================
    # PROCESS
    # ============================================================

    def process_alert(
            self,
            message: str,
            target: Optional[str] = None,
            severity: str = "WARNING",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление процесса."""

        return self.notify(
            title="Событие процесса",
            message=message,
            severity=severity,
            notification_type=self.TYPE_PROCESS,
            target=target,
            metadata = metadata,
            cooldown = 10.0,
        )

    # ============================================================
    # RECOVERY
    # ============================================================

    def recovery_alert(
            self,
            message: str,
            target: Optional[str] = None,
            severity: str = "NOTICE",
            metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Уведомление о восстановлении."""

        return self.notify(
            title="Восстановление системы",
            message=message,
            severity=severity,
            notification_type=self.TYPE_RECOVERY,
            target=target,
            metadata=metadata,
            cooldown=5.0,
        )

    # ============================================================
    # ERROR
    # ============================================================

    def error(
        self,
        message: str,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Системная ошибка."""

        return self.notify(
            title="Ошибка Security System",
            message=message,
            severity=self.HIGH,
            notification_type=self.TYPE_ERROR,
            target=target,
            metadata=metadata,
            cooldown=5.0,
        )

    # ============================================================
    # SUBSCRIBERS
    # ============================================================

    def subscribe(
        self,
        callback: Callable[[Dict[str, Any]], None],
    ) -> bool:
        """
        Подписать внешний компонент на уведомления.

        Например:
            interface.subscribe(...)
            jarvis_voice.subscribe(...)
        """

        if not callable(callback):
            return False

        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)
                self._log("Notification subscriber added")
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
                self._log("Notification subscriber removed")
                return True

        return False

    # ------------------------------------------------------------

    def _emit(
        self,
        notification: Dict[str, Any],
    ) -> None:
        """Передать уведомление всем подписчикам."""

        subscribers = list(self._subscribers)

        for callback in subscribers:
            try:
                callback(notification)
            except Exception as exc:
                self._log(
                    f"Subscriber error: {exc}",
                    level="ERROR",
                )

    # ============================================================
    # READ / UNREAD
    # ============================================================

    def mark_read(
        self,
        notification_id: int,
    ) -> bool:
        """Пометить уведомление прочитанным."""

        with self._lock:

            notification = self.get_notification(notification_id)

            if notification is None:
                return False

            notification["read"] = True

            return True

    # ------------------------------------------------------------

    def mark_unread(
        self,
        notification_id: int,
    ) -> bool:
        """Пометить уведомление непрочитанным."""

        with self._lock:

            notification = self.get_notification(notification_id)

            if notification is None:
                return False

            notification["read"] = False

            return True

    # ------------------------------------------------------------

    def acknowledge(
        self,
        notification_id: int,
    ) -> bool:
        """Подтвердить получение уведомления."""

        with self._lock:

            notification = self.get_notification(notification_id)

            if notification is None:
                return False

            notification["acknowledged"] = True
            notification["read"] = True

            return True

    # ============================================================
    # GETTERS
    # ============================================================

    def get_notification(
        self,
        notification_id: int,
    ) -> Optional[Dict[str, Any]]:
        """Получить уведомление по ID."""

        for notification in self.notifications:
            if notification.get("id") == notification_id:
                return notification

        return None

    # ------------------------------------------------------------

    def get_all(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Получить историю уведомлений."""

        with self._lock:

            items = list(reversed(self.notifications))

            if limit is not None:
                items = items[:max(0, int(limit))]

            return items

    # ------------------------------------------------------------

    def get_unread(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Получить непрочитанные уведомления."""

        with self._lock:

            items = [
                notification
                for notification in reversed(self.notifications)
                if not notification.get("read", False)
            ]

            if limit is not None:
                items = items[:max(0, int(limit))]

            return items

    # ------------------------------------------------------------

    def get_by_severity(
        self,
        severity: str,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Получить уведомления определенной важности."""

        severity = self._normalize_severity(severity)

        with self._lock:

            items = [
                notification
                for notification in reversed(self.notifications)
                if notification.get("severity") == severity
            ]

            if limit is not None:
                items = items[:max(0, int(limit))]

            return items

    # ------------------------------------------------------------

    def get_by_type(
        self,
        notification_type: str,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Получить уведомления определенного типа."""

        notification_type = self._normalize_type(notification_type)

        with self._lock:

            items = [
                notification
                for notification in reversed(self.notifications)
                if notification.get("type") == notification_type
            ]

            if limit is not None:
                items = items[:max(0, int(limit))]

            return items

    # ============================================================
    # COUNTERS
    # ============================================================

    def unread_count(self) -> int:
        """Количество непрочитанных уведомлений."""

        with self._lock:
            return sum(
                1
                for notification in self.notifications
                if not notification.get("read", False)
            )

    # ------------------------------------------------------------

    def critical_count(self) -> int:
        """Количество критических уведомлений."""

        return self._count_severity(self.CRITICAL)

    # ------------------------------------------------------------

    def high_count(self) -> int:
        """Количество HIGH уведомлений."""

        return self._count_severity(self.HIGH)

    # ------------------------------------------------------------

    def warning_count(self) -> int:
        """Количество WARNING уведомлений."""

        return self._count_severity(self.WARNING)

    # ------------------------------------------------------------

    def _count_severity(
        self,
        severity: str,
    ) -> int:
        severity = self._normalize_severity(severity)

        with self._lock:
            return sum(
                1
                for notification in self.notifications
                if notification.get("severity") == severity
            )

    # ============================================================
    # SETTINGS
    # ============================================================

    def enable(self) -> None:
        """Включить уведомления."""

        with self._lock:
            self.enabled = True

        self._log("Notifications enabled")

    # ------------------------------------------------------------

    def disable(self) -> None:
        """Выключить уведомления."""

        with self._lock:
            self.enabled = False

        self._log("Notifications disabled")

    # ------------------------------------------------------------

    def is_enabled(self) -> bool:
        """Проверить состояние уведомлений."""

        return self.enabled

    # ------------------------------------------------------------

    def set_cooldown(
        self,
        seconds: float,
    ) -> None:
        """Изменить глобальный cooldown."""

        with self._lock:
            self.cooldown = max(0.0, float(seconds))

    # ============================================================
    # CLEAR
    # ============================================================

    def clear(
        self,
        keep_critical: bool = False,
    ) -> int:
        """
        Очистить историю.

        keep_critical=True оставляет CRITICAL уведомления.
        """

        with self._lock:

            before = len(self.notifications)

            if keep_critical:
                self.notifications = [
                    notification
                    for notification in self.notifications
                    if notification.get("severity") == self.CRITICAL
                ]
            else:
                self.notifications.clear()

            removed = before - len(self.notifications)

            self._log(
                f"Notification history cleared: {removed}"
            )

            return removed

    # ------------------------------------------------------------

    def clear_read(self) -> int:
        """Удалить только прочитанные уведомления."""

        with self._lock:

            before = len(self.notifications)

            self.notifications = [
                notification
                for notification in self.notifications
                if not notification.get("read", False)
            ]

            removed = before - len(self.notifications)

            return removed

    # ============================================================
    # ANTI-SPAM
    # ============================================================

    def _build_notification_key(
        self,
        title: str,
        message: str,
        severity: str,
        notification_type: str,
        target: Optional[str],
    ) -> str:
        """
        Формирует ключ для определения одинаковых уведомлений.
        """

        return "|".join(
            [
                notification_type,
                severity,
                title.strip().lower(),
                message.strip().lower(),
                str(target or "").strip().lower(),
            ]
        )

    # ------------------------------------------------------------

    def _is_in_cooldown(
        self,
        key: str,
        cooldown: float,
    ) -> bool:
        """Проверяет cooldown."""

        if cooldown <= 0:
            return False

        last_time = self._last_notification_time.get(key)

        if last_time is None:
            return False

        return (time.time() - last_time) < cooldown

    # ------------------------------------------------------------

    def _update_duplicate(
        self,
        key: str,
    ) -> None:
        """Обновить счетчик повторяющегося уведомления."""

        for notification in reversed(self.notifications):

            if notification.get("notification_key") == key:

                notification["duplicate_count"] = (
                    notification.get("duplicate_count", 0) + 1
                )

                return

    # ============================================================
    # NORMALIZATION
    # ============================================================

    def _normalize_severity(
        self,
        severity: str,
    ) -> str:
        """Нормализация уровня важности."""

        severity = str(severity or self.INFO).upper().strip()

        if severity not in self.LEVEL_PRIORITY:

         return self.INFO
               
        return severity

    # ------------------------------------------------------------

    def _normalize_type(
        self,
        notification_type: str,
    ) -> str:
        """Нормализация типа уведомления."""

        return str(
            notification_type or self.TYPE_INFO
        ).upper().strip()

    # ============================================================
    # STATISTICS
    # ============================================================

    def _register_statistics(
        self,
        severity: str,
    ) -> None:

        if severity == self.CRITICAL:
            self.total_critical += 1

        elif severity == self.HIGH:
            self.total_high += 1

        elif severity == self.WARNING:
            self.total_warning += 1

        else:
            self.total_info += 1

    # ============================================================
    # HISTORY
    # ============================================================

    def _trim_history(self) -> None:
        """Ограничивает размер истории."""

        if len(self.notifications) <= self.max_history:
            return

        excess = len(self.notifications) - self.max_history

        del self.notifications[:excess]

    # ============================================================
    # STATUS
    # ============================================================

    def get_status(self) -> Dict[str, Any]:
        """Получить состояние менеджера уведомлений."""

        with self._lock:

            return {
                "version": self.VERSION,
                "enabled": self.enabled,

                "total_created": self.total_created,
                "total_suppressed": self.total_suppressed,

                "total_notifications": len(self.notifications),
                "unread": self.unread_count(),

                "critical": self.critical_count(),
                "high": self.high_count(),
                "warning": self.warning_count(),

                "subscribers": len(self._subscribers),

                "cooldown": self.cooldown,
                "max_history": self.max_history,
            }

    # ------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Проверка работоспособности менеджера."""

        try:
            status = self.get_status()

            return {
                "healthy": True,
                "status": status,
                "error": None,
            }

        except Exception as exc:

            return {
                "healthy": False,
                "status": {},
                "error": str(exc),
            }

    # ============================================================
    # RESET
    # ============================================================

    def reset(self) -> None:
        """
        Полный сброс менеджера.

        Использовать осторожно:
        история уведомлений будет удалена.
        """

        with self._lock:

            self.notifications.clear()

            self._last_notification_time.clear()
            self._duplicate_counts.clear()

            self.total_created = 0
            self.total_suppressed = 0

            self.total_critical = 0
            self.total_high = 0
            self.total_warning = 0
            self.total_info = 0

            self.last_notification = None

            self._next_id = 1

        self._log("SecurityNotifications reset")

    # ============================================================
    # LOGGER
    # ============================================================

    def _log(
        self,
        message: str,
        level: str = "INFO",
    ) -> None:
        """Безопасная отправка сообщения в Security Logger."""

        if self.logger is None:
            return

        try:

            if hasattr(self.logger, "log"):
                self.logger.log(
                    level,
                    message,

)

            elif hasattr(self.logger, "info") and level == "INFO":
                self.logger.info(message)

            elif hasattr(self.logger, "warning") and level == "WARNING":
                self.logger.warning(message)

            elif hasattr(self.logger, "error") and level == "ERROR":
                self.logger.error(message)

        except Exception:
            pass

    # ============================================================
    # REPRESENTATION
    # ============================================================

    def __repr__(self) -> str:
        return (
            f"<SecurityNotifications "
            f"version={self.VERSION} "
            f"enabled={self.enabled} "
            f"notifications={len(self.notifications)}>"
        )

# ================================================================
# OPTIONAL SINGLETON
# ================================================================

_notifications_instance: Optional[SecurityNotifications] = None


def get_security_notifications(
    logger: Optional[Any] = None,
) -> SecurityNotifications:
    """
    Получить общий экземпляр SecurityNotifications.

    Удобно для компонентов JARVIS, которым нужен единый
    менеджер уведомлений.
    """

    global _notifications_instance

    if _notifications_instance is None:
        _notifications_instance = SecurityNotifications(
            logger=logger
        )

    elif logger is not None and _notifications_instance.logger is None:
        _notifications_instance.logger = logger

    return _notifications_instance
