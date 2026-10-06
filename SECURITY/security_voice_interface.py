"""
JARVIS Security Voice Interface
Version: 8.2

Voice layer for the JARVIS Security System.

Responsibilities:
- Convert recognized speech into security intents.
- Extract targets from natural language.
- Maintain short-term security command context.
- Handle confirmation / denial / cancellation.
- Forward structured commands to SecurityCommandHandler.
- Never execute dangerous security actions directly.
- Work with the existing JARVIS voice engine.
- Remain independent from TTS/STT implementation.

Architecture:

JARVIS Voice Engine
        ↓
SecurityVoiceInterface
        ↓
SecurityCommandHandler
        ↓
JarvisSecurityBridge
        ↓
SecurityAPI
        ↓
Security System
"""

from __future__ import annotations

import re
import threading
import time

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


class SecurityVoiceInterface:
    """
    V8.2 Security Voice Interface.

    Converts recognized Russian speech into structured security commands.
    """

    VERSION = "8.2"

    # ---------------------------------------------------------
    # COMMAND CATEGORIES
    # ---------------------------------------------------------

    CATEGORY_SCAN = "scan"
    CATEGORY_STATUS = "status"
    CATEGORY_THREATS = "threats"
    CATEGORY_QUARANTINE = "quarantine"
    CATEGORY_REMEDIATION = "remediation"
    CATEGORY_NETWORK = "network"
    CATEGORY_MONITORING = "monitoring"
    CATEGORY_REPORT = "report"
    CATEGORY_NOTIFICATION = "notification"
    CATEGORY_CONTROL = "control"

    # ---------------------------------------------------------
    # COMMAND NAMES
    # ---------------------------------------------------------

    CMD_QUICK_SCAN = "quick_scan"
    CMD_FULL_SCAN = "full_scan"

    CMD_SCAN_FILE = "scan_file"
    CMD_SCAN_FOLDER = "scan_folder"

    CMD_SCAN_PROCESSES = "scan_processes"
    CMD_SCAN_PROCESS = "scan_process"

    CMD_SCAN_STARTUP = "scan_startup"
    CMD_SCAN_USB = "scan_usb"

    CMD_SCAN_NETWORK = "scan_network"
    CMD_SCAN_FIREWALL = "scan_firewall"
    CMD_SCAN_DNS = "scan_dns"

    CMD_SECURITY_STATUS = "security_status"
    CMD_SECURITY_SCORE = "security_score"

    CMD_GET_THREATS = "get_threats"
    CMD_ANALYZE_THREAT = "analyze_threat"
    CMD_ANALYZE_OBJECT = "analyze_object"
    CMD_GET_SECURITY_EVENTS = "get_security_events"

    CMD_GET_QUARANTINE = "get_quarantine"

    CMD_QUARANTINE = "quarantine"
    CMD_REMOVE = "remove"
    CMD_BLOCK = "block"
    CMD_RECOVER = "recover"

    CMD_GET_REPORT = "get_report"

    CMD_GET_NOTIFICATIONS = "get_notifications"
    CMD_ACKNOWLEDGE_NOTIFICATIONS = "acknowledge_notifications"

    CMD_MONITORING_START = "monitoring_start"
    CMD_MONITORING_STOP = "monitoring_stop"
    CMD_MONITORING_STATUS = "monitoring_status"

    CMD_RESCAN = "rescan"

    CMD_HELP = "security_help"

    CMD_CONFIRM = "confirm"
    CMD_DENY = "deny"
    CMD_CANCEL = "cancel"

    # ---------------------------------------------------------
    # ACTIONS
    # ---------------------------------------------------------

    ACTION_QUARANTINE = "quarantine"
    ACTION_REMOVE = "remove"
    ACTION_BLOCK = "block"
    ACTION_RECOVER = "recover"

    # ---------------------------------------------------------
    # CONFIRMATION
    # ---------------------------------------------------------

    SAFE = False
    REQUIRES_CONFIRMATION = True

    # ---------------------------------------------------------
    # DATA STRUCTURES
    # ---------------------------------------------------------

    @dataclass
    class VoiceCommand:
        command: str
        category: str
        target: Optional[Any] = None

        action: Optional[str] = None

        requires_confirmation: bool = False

        source_text: str = ""

        confidence: float = 1.0

        timestamp: float = field(
            default_factory=time.time
        )

        metadata: Dict[str, Any] = field(
            default_factory=dict
        )

        def to_dict(self) -> Dict[str, Any]:
            return {
                "command": self.command,
                "category": self.category,
                "target": self.target,
                "action": self.action,
                "requires_confirmation": self.requires_confirmation,
                "confirmed": self.metadata.get("confirmed", False),
                "source_text": self.source_text,
                "confidence": self.confidence,
                "timestamp": self.timestamp,
                "metadata": self.metadata,
            }

    # ---------------------------------------------------------

    @dataclass
    class PendingConfirmation:
        command: "SecurityVoiceInterface.VoiceCommand"

        created_at: float = field(
            default_factory=time.time
        )

        expires_after: float = 60.0

        def expired(self) -> bool:
            return (
                time.time() - self.created_at
                > self.expires_after
            )

    # ---------------------------------------------------------

    class Context:
        """
        Short-term voice/security context.
        """

        def __init__(self) -> None:
            self.last_command: Optional[
                SecurityVoiceInterface.VoiceCommand
            ] = None

            self.last_target: Optional[Any] = None

            self.last_scan: Optional[Any] = None

            self.last_threat: Optional[Any] = None

            self.last_result: Optional[Any] = None

            self.last_report: Optional[Any] = None

            self.pending_confirmation: Optional[
                SecurityVoiceInterface.PendingConfirmation
            ] = None

            self.updated_at = time.time()

        def update(
            self,
            command: Optional[
                "SecurityVoiceInterface.VoiceCommand"
            ] = None,
            result: Any = None,
        ) -> None:

            if command is not None:
                self.last_command = command

                if command.target is not None:
                    self.last_target = command.target

            if result is not None:
                self.last_result = result

            self.updated_at = time.time()

        def clear_confirmation(self) -> None:
            self.pending_confirmation = None

        def clear(self) -> None:
            self.last_command = None
            self.last_target = None
            self.last_scan = None
            self.last_threat = None
            self.last_result = None
            self.last_report = None
            self.pending_confirmation = None
            self.updated_at = time.time()

        def to_dict(self) -> Dict[str, Any]:
            pending = self.pending_confirmation

            return {
                "last_command": (
                    self.last_command.to_dict()
                    if self.last_command
                    else None
                ),
                "last_target": self.last_target,
                "last_scan": self.last_scan,
                "last_threat": self.last_threat,
                "last_result": self.last_result,
                "last_report": self.last_report,
                "pending_confirmation": (
                    pending.command.to_dict()
                    if pending
                    else None
                ),
                "updated_at": self.updated_at,
            }

    # ---------------------------------------------------------
    # CONSTRUCTOR
    # ---------------------------------------------------------

    def __init__(
        self,
        command_handler: Any = None,
        notifications: Any = None,
        logger: Any = None,
        response_callback: Optional[
            Callable[[str], None]
        ] = None,
    ) -> None:

        self.command_handler = command_handler

        self.notifications = notifications

        self.logger = logger

        self.response_callback = response_callback

        self.context = self.Context()

        self._lock = threading.RLock()

        self._enabled = True

        self._history: List[
            SecurityVoiceInterface.VoiceCommand
        ] = []

        self._max_history = 100

        self._stats = {
            "total_commands": 0,
            "recognized_commands": 0,
            "unknown_commands": 0,
            "confirmations": 0,
            "denials": 0,
            "cancellations": 0,
            "errors": 0,
        }

    # =========================================================
    # MAIN ENTRY POINT
    # =========================================================

    def process(
        self,
        text: str,
    ) -> Dict[str, Any]:

        with self._lock:

            if not self._enabled:
                return self._result(
                    success=False,
                    message="Голосовой интерфейс безопасности отключён.",
                )

            if not text:
                return self._result(
                    success=False,
                    message="Пустая команда.",
                )

            normalized = self._normalize(text)

            self._stats["total_commands"] += 1

            # -------------------------------------------------
            # CONFIRMATION / DENIAL / CANCEL
            # -------------------------------------------------

            if self._is_confirmation(normalized):
                return self._handle_confirmation()

            if self._is_denial(normalized):
                return self._handle_denial()

            if self._is_cancel(normalized):
                return self._handle_cancel()

            # -------------------------------------------------
            # COMMAND RECOGNITION
            # -------------------------------------------------

            command = self._recognize(
                normalized,
                original=text,
            )

            if command is None:

                self._stats["unknown_commands"] += 1

                return self._result(
                    success=False,
                    message="Я не распознал команду безопасности.",
                    command=None,
                )

            self._stats["recognized_commands"] += 1

            self.context.update(command)

            self._remember(command)

            # -------------------------------------------------
            # CONFIRMATION GATE
            # -------------------------------------------------

            if command.requires_confirmation:

                self.context.pending_confirmation = (
                    self.PendingConfirmation(command)
                )

                return self._result(
                    success=True,
                    requires_confirmation=True,
                    command=command,
                    message=self._confirmation_message(
                        command
                    ),
                )

            # -------------------------------------------------
            # SAFE EXECUTION
            # -------------------------------------------------

            return self._dispatch(command)

    # =========================================================
    # NORMALIZATION
    # =========================================================

    @staticmethod
    def _normalize(text: str) -> str:

        text = text.lower().strip()

        replacements = {
            "фаервол": "firewall",
            "файрвол": "firewall",
            "fire wall": "firewall",
            "файр вол": "firewall",
            "юсб": "usb",
            "юэсби": "usb",
            "пи ай ди": "pid",
            "пид": "pid",
            "скор": "score",
        }

        for old, new in replacements.items():
            text = text.replace(old, new)

        text = re.sub(
            r"[!?.,;:]+",
            " ",
            text,
        )

        text = re.sub(
            r"\s+",
            " ",
            text,
        )

        return text.strip()

    # =========================================================
    # RECOGNITION
    # =========================================================

    def _recognize(
        self,
        text: str,
        original: str,
    ) -> Optional[VoiceCommand]:

        # -----------------------------------------------------
        # QUICK SCAN
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "быстро проверь",
                "быстрая проверка",
                "быстрый скан",
                "быстрое сканирование",
                "быстро просканируй",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_QUICK_SCAN,
                category=self.CATEGORY_SCAN,
                source_text=original,
            )

        # -----------------------------------------------------
        # FULL SCAN
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "полная проверка",
                "полное сканирование",
                "полный скан",
                "полностью проверь",
                "проверь весь компьютер",
                "просканируй весь компьютер",
                "полностью просканируй",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_FULL_SCAN,
                category=self.CATEGORY_SCAN,
                source_text=original,
            )

        # -----------------------------------------------------
        # FILE SCAN
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь файл",
                "просканируй файл",
                "сканируй файл",
                "проанализируй файл",
                "проверь этот файл",
            ],
        ):

            target = self._extract_file_target(text)

            return self.VoiceCommand(
                command=self.CMD_SCAN_FILE,
                category=self.CATEGORY_SCAN,
                target=target or self.context.last_target,
                source_text=original,
            )

        # -----------------------------------------------------
        # FOLDER SCAN
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь папку",
                "просканируй папку",
                "сканируй папку",
                "проверь эту папку",
            ],
        ):

            target = self._extract_path_target(
                text,
                keywords=[
                    "папку",
                    "папка",
                ],
            )

            return self.VoiceCommand(
                command=self.CMD_SCAN_FOLDER,
                category=self.CATEGORY_SCAN,
                target=target or self.context.last_target,
                source_text=original,
            )

        # -----------------------------------------------------
        # PROCESSES
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь процессы",
                "просканируй процессы",
                "проверь запущенные процессы",
                "проверь запущенные программы",
                "есть ли подозрительные процессы",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_PROCESSES,
                category=self.CATEGORY_SCAN,
                source_text=original,
            )

        # -----------------------------------------------------
        # SINGLE PROCESS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь процесс",
                "проанализируй процесс",
                "просканируй процесс",
            ],
        ):

            target = self._extract_process_target(text)

            return self.VoiceCommand(
                command=self.CMD_SCAN_PROCESS,
                category=self.CATEGORY_SCAN,
                target=target or self.context.last_target,
                source_text=original,
            )

        # -----------------------------------------------------
        # STARTUP
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь автозагрузку",
                "просканируй автозагрузку",
                "сканируй автозагрузку",
                "проверь запуск программ",
                "проверь программы при запуске",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_STARTUP,
                category=self.CATEGORY_SCAN,
                source_text=original,
            )

        # -----------------------------------------------------
        # USB
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь usb",
                "просканируй usb",
                "проверь флешки",
                "проверь флешку",
                "проверь подключённые usb",
                "проверь подключенные usb",
                "проверь usb устройства",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_USB,
                category=self.CATEGORY_SCAN,
                source_text=original,
            )

        # -----------------------------------------------------
        # NETWORK
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь сеть",
                "просканируй сеть",
                "проанализируй сеть",
                "проверь сетевые соединения",
                "проверь подключения",
                "есть ли подозрительные соединения",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_NETWORK,
                category=self.CATEGORY_NETWORK,
                source_text=original,
            )

        # -----------------------------------------------------
        # FIREWALL
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь firewall",
                "проверь брандмауэр",
                "проверь файрвол",
                "проверь настройки firewall",
                "проверь настройки брандмауэра",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_FIREWALL,
                category=self.CATEGORY_NETWORK,
                source_text=original,
            )

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь dns",
                "проанализируй dns",
                "проверь настройки dns",
                "есть ли проблемы с dns",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SCAN_DNS,
                category=self.CATEGORY_NETWORK,
                source_text=original,
            )

        # -----------------------------------------------------
        # SECURITY STATUS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "статус безопасности",
                "состояние безопасности",
                "состояние защиты",
                "как состояние безопасности",
                "всё нормально с безопасностью",
                "все нормально с безопасностью",
                "проверь состояние защиты",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SECURITY_STATUS,
                category=self.CATEGORY_STATUS,
                source_text=original,
            )

        # -----------------------------------------------------
        # SECURITY SCORE
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "security score",
                "securityscore",
                "оценка безопасности",
                "показатель безопасности",
                "какой показатель безопасности",
                "какая оценка безопасности",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_SECURITY_SCORE,
                category=self.CATEGORY_STATUS,
                source_text=original,
            )

        # -----------------------------------------------------
        # THREATS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "покажи угрозы",
                "покажи обнаруженные угрозы",
                "какие угрозы обнаружены",
                "есть ли угрозы",
                "обнаруженные угрозы",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_GET_THREATS,
                category=self.CATEGORY_THREATS,
                source_text=original,
            )

        # -----------------------------------------------------
        # THREAT ANALYSIS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проанализируй угрозу",
                "анализ угрозы",
                "что это за угроза",
                "насколько опасна угроза",
                "насколько это опасно",
            ],
        ):

            target = self.context.last_threat

            return self.VoiceCommand(
                command=self.CMD_ANALYZE_THREAT,
                category=self.CATEGORY_THREATS,
                target=target,
                source_text=original,
            )

        # -----------------------------------------------------
        # GENERIC OBJECT ANALYSIS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проанализируй этот объект",
                "проанализируй объект",
                "проанализируй его",
                "проанализируй это",
            ],
        ):

            return self.VoiceCommand(
                command=self.CMD_ANALYZE_OBJECT,
                category=self.CATEGORY_THREATS,
                target=self.context.last_target,
                source_text=original,
            )

        # -----------------------------------------------------
        # EVENTS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "покажи последние события",
                "последние события безопасности",
                "что происходило с безопасностью",
                "последние предупреждения",
                "покажи события безопасности",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_GET_SECURITY_EVENTS,
                category=self.CATEGORY_STATUS,
                source_text=original,
            )

        # -----------------------------------------------------
        # QUARANTINE LIST
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "покажи карантин",
                "что в карантине",
                "что находится в карантине",
                "покажи файлы в карантине",
                "есть ли что-нибудь в карантине",
                "есть ли что нибудь в карантине",

],
        ):
            return self.VoiceCommand(
                command=self.CMD_GET_QUARANTINE,
                category=self.CATEGORY_QUARANTINE,
                source_text=original,
            )

        # -----------------------------------------------------
        # REMOVE
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "удали угрозу",
                "удалить угрозу",
                "удали этот файл",
                "удалить этот файл",
                "удали его",
                "удалить его",
            ],
        ):

            target = self._extract_target_after_action(
                text,
                action_words=[
                    "удали",
                    "удалить",
                ],
            )

            if not target:
                target = (
                    self.context.last_threat
                    or self.context.last_target
                )

            return self.VoiceCommand(
                command=self.CMD_REMOVE,
                category=self.CATEGORY_REMEDIATION,
                action=self.ACTION_REMOVE,
                target=target,
                requires_confirmation=True,
                source_text=original,
            )

        # -----------------------------------------------------
        # QUARANTINE
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "помести в карантин",
                "отправь в карантин",
                "изолируй этот файл",
                "изолируй угрозу",
                "карантинизируй угрозу",
            ],
        ):

            target = (
                self.context.last_threat
                or self.context.last_target
            )

            return self.VoiceCommand(
                command=self.CMD_QUARANTINE,
                category=self.CATEGORY_REMEDIATION,
                action=self.ACTION_QUARANTINE,
                target=target,
                requires_confirmation=True,
                source_text=original,
            )

        # -----------------------------------------------------
        # BLOCK
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "заблокируй угрозу",
                "заблокируй этот объект",
                "заблокируй соединение",
                "заблокировать угрозу",
                "заблокировать соединение",
            ],
        ):

            target = (
                self.context.last_threat
                or self.context.last_target
            )

            return self.VoiceCommand(
                command=self.CMD_BLOCK,
                category=self.CATEGORY_REMEDIATION,
                action=self.ACTION_BLOCK,
                target=target,
                requires_confirmation=True,
                source_text=original,
            )

        # -----------------------------------------------------
        # RECOVER
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "восстанови файл",
                "восстановить файл",
                "восстанови объект",
                "восстановить объект",
                "верни файл из карантина",
                "восстанови из карантина",
            ],
        ):

            target = (
                self.context.last_target
                or self.context.last_threat
            )

            return self.VoiceCommand(
                command=self.CMD_RECOVER,
                category=self.CATEGORY_REMEDIATION,
                action=self.ACTION_RECOVER,
                target=target,
                requires_confirmation=True,
                source_text=original,
            )

        # -----------------------------------------------------
        # REPORT
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "покажи последний отчёт",
                "покажи последний отчет",
                "открой отчёт безопасности",
                "открой отчет безопасности",
                "покажи результаты последней проверки",
                "что показала последняя проверка",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_GET_REPORT,
                category=self.CATEGORY_REPORT,
                source_text=original,
            )

        # -----------------------------------------------------
        # NOTIFICATIONS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "покажи уведомления безопасности",
                "есть новые уведомления",
                "есть новые уведомления безопасности",
                "покажи непрочитанные уведомления",
                "что нового по безопасности",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_GET_NOTIFICATIONS,
                category=self.CATEGORY_NOTIFICATION,
                source_text=original,
            )

        # -----------------------------------------------------
        # ACKNOWLEDGE NOTIFICATIONS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "отметь уведомления прочитанными",
                "отметь уведомления прочитанными",
                "прочитай все уведомления",
                "очисти непрочитанные уведомления",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_ACKNOWLEDGE_NOTIFICATIONS,
                category=self.CATEGORY_NOTIFICATION,
                source_text=original,
            )

        # -----------------------------------------------------
        # MONITORING START
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "включи мониторинг безопасности",
                "запусти мониторинг безопасности",
                "включи мониторинг",
                "запусти мониторинг",
                "начни мониторинг",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_MONITORING_START,
                category=self.CATEGORY_MONITORING,
                source_text=original,
            )

        # -----------------------------------------------------
        # MONITORING STOP
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "отключи мониторинг безопасности",
                "останови мониторинг безопасности",
                "отключи мониторинг",
                "останови мониторинг",
                "остановить мониторинг",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_MONITORING_STOP,
                category=self.CATEGORY_MONITORING,
                source_text=original,
            )

        # -----------------------------------------------------
        # MONITORING STATUS
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "работает ли мониторинг",
                "статус мониторинга",
                "состояние мониторинга",
                "включён ли мониторинг",
                "включен ли мониторинг",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_MONITORING_STATUS,
                category=self.CATEGORY_MONITORING,
                source_text=original,
            )

        # -----------------------------------------------------
        # RESCAN
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "проверь ещё раз",
                "проверь еще раз",
                "повтори проверку",
                "запусти повторное сканирование",
                "повторное сканирование",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_RESCAN,
                category=self.CATEGORY_SCAN,
                target=self.context.last_target,
                source_text=original,
            )

        # -----------------------------------------------------
        # HELP
        # -----------------------------------------------------

        if self._contains(
            text,
            [
                "помощь по безопасности",
                "какие есть команды безопасности",
                "какие команды безопасности",
                "что ты умеешь в безопасности",
                "покажи команды security",
                "покажи команды безопасности",
            ],
        ):
            return self.VoiceCommand(
                command=self.CMD_HELP,
                category=self.CATEGORY_CONTROL,
                source_text=original,
            )

        return None

    # =========================================================
    # CONFIRMATION
    # =========================================================

    def _is_confirmation(
        self,
        text: str,
    ) -> bool:

        return self._contains(
            text,
            [
                "да",
                "подтверждаю",
                "подтверждаю действие",
                "выполняй",
                "выполнить",
                "разрешаю",
                "давай",
                "сделай",
                "подтверждено",
            ],
        )

    # =========================================================

    def _is_denial(
        self,
        text: str,
    ) -> bool:

        return self._contains(
            text,
            [
                "нет",
                "не надо",
                "не делай",
                "отказываюсь",
                "отмена действия",
                "не подтверждаю",
            ],
        )

    # =========================================================

    def _is_cancel(
        self,
        text: str,
    ) -> bool:

        return self._contains(
            text,
            [
                "отмена",
                "отменить",
                "отмени",
                "стоп",
                "остановись",
            ],
        )

    # =========================================================
    # CONFIRMATION HANDLERS
    # =========================================================

    def _handle_confirmation(self, text: str):
        if self.context.pending_confirmation is None:
            return {
                "success": False,
                "message": "Нет ожидающего действия для подтверждения."
            }

        pending = self.context.pending_confirmation

        if pending.is_expired():
            self.context.pending_confirmation = None

            return {
                "success": False,
                "message": "Подтверждение устарело. Повторите команду."
            }

        command = pending.command

        # Подтверждаем выполнение опасной команды
        command.requires_confirmation = False
        command.metadata["confirmed"] = True

        # Сохраняем информацию о подтверждении
        command.metadata["confirmation_text"] = text
        command.metadata["confirmed_at"] = time.time()

        # Убираем ожидание подтверждения
        self.context.pending_confirmation = None

        # Обновляем историю
        self.context.last_command = command.command
        self.context.last_target = command.target

        # Передаём уже подтверждённую команду V8.1
        result = self._dispatch(command)

        self.context.last_result = result

        return result

    # =========================================================

    def _handle_denial(
        self,
    ) -> Dict[str, Any]:

        pending = self.context.pending_confirmation

        if pending is None:

            self._stats["denials"] += 1

            return self._result(
                success=False,
                message="Нет операции, от которой можно отказаться.",
            )

        self.context.clear_confirmation()

        self._stats["denials"] += 1

        return self._result(

            success=True,
            message="Операция отменена пользователем.",
        )

    # =========================================================

    def _handle_cancel(
        self,
    ) -> Dict[str, Any]:

        self.context.clear_confirmation()

        self._stats["cancellations"] += 1

        return self._result(
            success=True,
            message="Операция отменена.",
        )

    # =========================================================
    # DISPATCH
    # =========================================================

    def _dispatch(
        self,
        command: VoiceCommand,
    ) -> Dict[str, Any]:

        if self.command_handler is None:

            return self._result(
                success=True,
                command=command,
                executed=False,
                message=(
                    "Команда распознана, "
                    "но Security Command Handler ещё не подключён."
                ),
            )

        try:

            handler = self.command_handler

            # -------------------------------------------------
            # Preferred interface
            # -------------------------------------------------

            if hasattr(handler, "handle"):

                result = handler.handle(
                    command.to_dict()
                )

                self.context.update(
                    command,
                    result,
                )

                return self._result(
                    success=True,
                    command=command,
                    executed=True,
                    result=result,
                    message=self._result_message(
                        command,
                        result,
                    ),
                )

            # -------------------------------------------------
            # Alternative interface
            # -------------------------------------------------

            if hasattr(handler, "execute"):

                result = handler.execute(
                    command.to_dict()
                )

                self.context.update(
                    command,
                    result,
                )

                return self._result(
                    success=True,
                    command=command,
                    executed=True,
                    result=result,
                    message=self._result_message(
                        command,
                        result,
                    ),
                )

            return self._result(
                success=False,
                command=command,
                message=(
                    "Security Command Handler "
                    "не предоставляет поддерживаемый интерфейс."
                ),
            )

        except Exception as exc:

            self._stats["errors"] += 1

            self._log(
                "error",
                f"Security Voice Interface error: {exc}",
            )

            return self._result(
                success=False,
                command=command,
                message="При выполнении команды произошла ошибка.",
                error=str(exc),
            )

    # =========================================================
    # MESSAGE GENERATION
    # =========================================================

    def _confirmation_message(
        self,
        command: VoiceCommand,
    ) -> str:

        target = self._target_description(
            command.target
        )

        if command.action == self.ACTION_REMOVE:
            return (
                f"Подтвердить удаление {target}? "
                f"Скажите «да» для подтверждения "
                f"или «нет» для отмены."
            )

        if command.action == self.ACTION_QUARANTINE:
            return (
                f"Поместить {target} в карантин? "
                f"Скажите «да» для подтверждения "
                f"или «нет» для отмены."

)

        if command.action == self.ACTION_BLOCK:
            return (
                f"Заблокировать {target}? "
                f"Скажите «да» для подтверждения "
                f"или «нет» для отмены."
            )

        if command.action == self.ACTION_RECOVER:
            return (
                f"Восстановить {target}? "
                f"Скажите «да» для подтверждения "
                f"или «нет» для отмены."
            )

        return (
            "Операция требует подтверждения. "
            "Выполнить её?"
        )

    # =========================================================

    def _result_message(
        self,
        command: VoiceCommand,
        result: Any,
    ) -> str:

        messages = {
            self.CMD_QUICK_SCAN:
                "Быстрая проверка завершена.",

            self.CMD_FULL_SCAN:
                "Полное сканирование завершено.",

            self.CMD_SCAN_FILE:
                "Проверка файла завершена.",

            self.CMD_SCAN_FOLDER:
                "Проверка папки завершена.",

            self.CMD_SCAN_PROCESSES:
                "Проверка процессов завершена.",

            self.CMD_SCAN_PROCESS:
                "Проверка процесса завершена.",

            self.CMD_SCAN_STARTUP:
                "Проверка автозагрузки завершена.",

            self.CMD_SCAN_USB:
                "Проверка USB завершена.",

            self.CMD_SCAN_NETWORK:
                "Проверка сети завершена.",

            self.CMD_SCAN_FIREWALL:
                "Проверка Firewall завершена.",

            self.CMD_SCAN_DNS:
                "Проверка DNS завершена.",

            self.CMD_SECURITY_STATUS:
                "Статус безопасности получен.",

            self.CMD_SECURITY_SCORE:
                "Security Score получен.",

            self.CMD_GET_THREATS:
                "Список угроз получен.",

            self.CMD_ANALYZE_THREAT:
                "Анализ угрозы завершён.",

            self.CMD_ANALYZE_OBJECT:
                "Анализ объекта завершён.",

            self.CMD_GET_SECURITY_EVENTS:
                "Список событий безопасности получен.",

            self.CMD_GET_QUARANTINE:
                "Список карантина получен.",

            self.CMD_REMOVE:
                "Операция удаления выполнена.",

            self.CMD_QUARANTINE:
                "Объект помещён в карантин.",

            self.CMD_BLOCK:
                "Объект заблокирован.",

            self.CMD_RECOVER:
                "Объект восстановлен.",

            self.CMD_GET_REPORT:
                "Последний отчёт получен.",

            self.CMD_GET_NOTIFICATIONS:
                "Уведомления безопасности получены.",

            self.CMD_ACKNOWLEDGE_NOTIFICATIONS:
                "Уведомления отмечены как прочитанные.",

            self.CMD_MONITORING_START:
                "Мониторинг безопасности запущен.",

            self.CMD_MONITORING_STOP:
                "Мониторинг безопасности остановлен.",

            self.CMD_MONITORING_STATUS:
                "Статус мониторинга получен.",

            self.CMD_RESCAN:
                "Повторная проверка завершена.",

            self.CMD_HELP:
                "Список команд безопасности готов.",
        }

        return messages.get(
            command.command,
            "Команда выполнена.",
        )

    # =========================================================
    # TARGET EXTRACTION
    # =========================================================

    @staticmethod
    def _extract_file_target(
        text: str,
    ) -> Optional[str]:

        patterns = [
            r"файл\s+(.+)$",
            r"файла\s+(.+)$",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                re.IGNORECASE,
            )

            if match:

                target = match.group(1).strip()

                if target in {
                    "этот",
                    "этот файл",
                    "файл",
                }:
                    return None

                return target

        return None

    # =========================================================

    @staticmethod
    def _extract_path_target(
        text: str,
        keywords: List[str],
    ) -> Optional[str]:

        for keyword in keywords:

            pattern = (
                rf"{re.escape(keyword)}"
                rf"\s+(.+)$"
            )

            match = re.search(
                pattern,
                text,
                re.IGNORECASE,
            )

            if match:

                target = match.group(1).strip()

                if target in {
                    "эту",
                    "эта",
                    "этот",
                }:
                    return None

                return target

        return None

    # =========================================================

    @staticmethod
    def _extract_process_target(
        text: str,
    ) -> Optional[Any]:

        pid_match = re.search(
            r"(?:pid\s*)?(\d{1,10})",
            text,
            re.IGNORECASE,
        )

        if pid_match:

            try:
                return {
                    "type": "pid",
                    "value": int(
                        pid_match.group(1)
                    ),
                }
            except ValueError:
                pass

        patterns = [
            r"процесс\s+([^\s]+)",
            r"процесса\s+([^\s]+)",
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                re.IGNORECASE,
            )

            if match:

                target = match.group(1).strip()

                if target not in {
                    "этот",
                    "этого",
                    "с",
                    "с",
                }:
                    return {
                        "type": "name",
                        "value": target,
                    }

        return None

    # =========================================================

    @staticmethod
    def _extract_target_after_action(
        text: str,
        action_words: List[str],
    ) -> Optional[str]:

        for word in action_words:

            pattern = (
                rf"{re.escape(word)}"
                rf"\s+(.+)$"
            )

            match = re.search(
                pattern,
                text,
                re.IGNORECASE,
            )

            if match:

                target = match.group(1).strip()

                if target in {
                    "его",
                    "этот",
                    "это",
                    "угрозу",
                    "этот файл",
                }:
                    return None

                return target

        return None

    # =========================================================
    # CONTEXT / HISTORY
    # =========================================================

    def _remember(
        self,
        command: VoiceCommand,
    ) -> None:

        self._history.append(command)

        if len(self._history) > self._max_history:

            self._history = (
                self._history[
                    -self._max_history:
                ]
            )

    # =========================================================
    # HELP
    # =========================================================

    def get_help(
        self,
    ) -> Dict[str, List[str]]:

        return {
            "scanning": [
                "быстро проверь компьютер",
                "запусти полное сканирование",
                "проверь файл",
                "проверь папку",
                "проверь процессы",
                "проверь процесс",
                "проверь автозагрузку",
                "проверь USB",
            ],

            "network": [
                "проверь сеть",

                "проверь Firewall",
                "проверь DNS",
            ],

            "status": [
                "покажи статус безопасности",
                "покажи Security Score",
                "покажи угрозы",
                "покажи последние события",
            ],

            "quarantine": [
                "покажи карантин",
                "помести угрозу в карантин",
                "восстанови файл",
            ],

            "remediation": [
                "удали угрозу",
                "заблокируй угрозу",
                "помести угрозу в карантин",
                "восстанови файл",
            ],

            "monitoring": [
                "включи мониторинг",
                "останови мониторинг",
                "статус мониторинга",
            ],

            "reports": [
                "покажи последний отчёт",
                "покажи уведомления",
            ],

            "control": [
                "помощь по безопасности",
                "отмена",
                "да",
                "нет",
            ],
        }

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(
        self,
    ) -> Dict[str, Any]:

        pending = self.context.pending_confirmation

        return {
            "version": self.VERSION,
            "enabled": self._enabled,
            "jarvis_active": self._jarvis_active,
            "voice_control_available": (
                    self._enabled and self._jarvis_active
            ),
            "handler_connected": (
                self.command_handler is not None
            ),
            "pending_confirmation": (
                pending.command.to_dict()
                if pending
                else None
            ),
            "statistics": dict(
                self._stats
            ),
            "history_size": len(
                self._history
            ),
        }

    # =========================================================
    # HISTORY
    # =========================================================

    def get_history(
        self,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:

        if limit < 1:
            limit = 1

        return [
            command.to_dict()
            for command in self._history[
                -limit:
            ]
        ]

    # =========================================================
    # CONTEXT
    # =========================================================

    def get_context(
        self,
    ) -> Dict[str, Any]:

        return self.context.to_dict()

    # =========================================================
    # ENABLE / DISABLE
    # =========================================================

    def enable(self) -> None:

        with self._lock:
            self._enabled = True

    # ---------------------------------------------------------
    # JARVIS CONNECTION STATE
    # ---------------------------------------------------------
    # Security работает независимо от JARVIS.
    # Голосовое управление разрешено ТОЛЬКО когда JARVIS активен.

            self._jarvis_active = False

    # =========================================================

    def disable(self) -> None:

        with self._lock:
            self._enabled = False

            self.context.clear_confirmation()

    # =========================================================

    def is_enabled(self) -> bool:

        return self._enabled

    # =========================================================
    # JARVIS ACTIVE STATE
    # =========================================================

    def set_jarvis_active(
            self,
            active: bool,
    ) -> None:
        """
        Подключает или отключает голосовое управление Security
        в зависимости от состояния JARVIS.

        Security при этом продолжает работать независимо от JARVIS.
        """

        with self._lock:

            self._jarvis_active = bool(active)

            # При отключении JARVIS обязательно
            # сбрасываем ожидающее опасное подтверждение.
            if not self._jarvis_active:
                self.context.clear_confirmation()

                self._log(
                    "info",
                    "Security voice control disabled: JARVIS inactive.",
                )

            else:

                self._log(
                    "info",
                    "Security voice control enabled: JARVIS active.",
                )

    def is_jarvis_active(self) -> bool:
        """
        Возвращает состояние подключения JARVIS
        к голосовому интерфейсу Security.
        """

        with self._lock:
            return self._jarvis_active

    # =========================================================
    # RESET
    # =========================================================

    def reset(
        self,
    ) -> None:

        with self._lock:

            self.context.clear()

            self._history.clear()

            self._stats = {
                "total_commands": 0,
                "recognized_commands": 0,
                "unknown_commands": 0,
                "confirmations": 0,
                "denials": 0,
                "cancellations": 0,
                "errors": 0,
            }

    # =========================================================
    # CONNECT HANDLER
    # =========================================================

    def set_command_handler(
        self,
        command_handler: Any,
    ) -> None:

        with self._lock:

            self.command_handler = (
                command_handler
            )

    # =========================================================
    # RESPONSE CALLBACK
    # =========================================================

    def set_response_callback(
        self,
        callback: Optional[
            Callable[[str], None]
        ],
    ) -> None:

        self.response_callback = callback

    # =========================================================
    # UTILITIES
    # =========================================================

    @staticmethod
    def _contains(
        text: str,
        phrases: List[str],
    ) -> bool:

        return any(
            phrase in text
            for phrase in phrases
        )

    # =========================================================

    @staticmethod
    def _target_description(
        target: Any,
    ) -> str:

        if target is None:
            return "объект"

        if isinstance(target, dict):

            value = target.get(
                "value",
                "объект",
            )

            target_type = target.get(
                "type",
                "объект",
            )

            if target_type == "pid":
                return (
                    f"процесс с PID {value}"
                )

            if target_type == "name":
                return (
                    f"процесс {value}"
                )

            return str(value)

        return str(target)

    # =========================================================

    @staticmethod
    def _result(
        success: bool,
        message: str,
        command: Optional[
            VoiceCommand
        ] = None,
        result: Any = None,
        executed: bool = False,
        requires_confirmation: bool = False,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:

        response = {
            "success": success,
            "message": message,
            "executed": executed,
            "requires_confirmation": (
                requires_confirmation
            ),
            "command": (
                command.to_dict()
                if command
                else None
            ),
            "result": result,
        }

        if error is not None:
            response["error"] = error

        return response

    # =========================================================

    def _log(
        self,
        level: str,
        message: str,
    ) -> None:

        if self.logger is None:
            return

        try:

            if hasattr(
                self.logger,
                level,
            ):
                getattr(
                    self.logger,
                    level,
                )(message)

            elif hasattr(
                self.logger,
                "log",
            ):
                self.logger.log(
                    level,
                    message,
                )

        except Exception:
            pass

    # =========================================================
    # HEALTH
    # =========================================================

    def health_check(
        self,
    ) -> Dict[str, Any]:

        checks = {
            "enabled": self._enabled,
            "jarvis_state": (
                isinstance(
                    self._jarvis_active,
                    bool,
                )
            ),
            "context": (
                self.context is not None
            ),
            "command_handler": (
                self.command_handler is not None
            ),
            "lock": (
                self._lock is not None
            ),
        }

        return {
            "healthy": all(
                checks.values()
            ),
            "version": self.VERSION,
            "checks": checks,
        }

    # =========================================================

    def __repr__(self) -> str:

        return (
            f"<SecurityVoiceInterface "
            f"version={self.VERSION!r} "
            f"enabled={self._enabled!r} "
            f"handler_connected="
            f"{self.command_handler is not None!r}>"
        )

# =============================================================
# SINGLETON
# =============================================================

_security_voice_interface: Optional[
    SecurityVoiceInterface
] = None

_security_voice_interface_lock = threading.Lock()


def get_security_voice_interface(
    command_handler: Any = None,
    notifications: Any = None,
    logger: Any = None,
    response_callback: Optional[
        Callable[[str], None]
    ] = None,
) -> SecurityVoiceInterface:

    global _security_voice_interface

    with _security_voice_interface_lock:

        if _security_voice_interface is None:

            _security_voice_interface = (
                SecurityVoiceInterface(
                    command_handler=command_handler,
                    notifications=notifications,
                    logger=logger,
                    response_callback=response_callback,
                )
            )

        else:

            if command_handler is not None:
                _security_voice_interface.set_command_handler(
                    command_handler
                )

            if notifications is not None:
                _security_voice_interface.notifications = (
                    notifications
                )

            if logger is not None:
                _security_voice_interface.logger = (
                    logger
                )

            if response_callback is not None:
                _security_voice_interface.set_response_callback(
                    response_callback
                )

        return _security_voice_interface