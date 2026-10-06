"""
JARVIS Security Command Handler
Version: 8.1

Central command dispatcher between:
    Security Voice Interface
            ↓
    Security Command Handler
            ↓
    Jarvis Security Bridge
            ↓
    Security API
            ↓
    Security System

Responsibilities:
- Accept structured security commands.
- Validate commands and targets.
- Route commands to JarvisSecurityBridge.
- Keep command execution separate from voice recognition.
- Support safe security operations.
- Support remediation operations after confirmation.
- Never perform security operations directly.
"""

from __future__ import annotations

import threading
import time

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


class SecurityCommandHandler:
    """
    V8.1 Security Command Handler.

    Receives structured commands from the voice interface
    or other JARVIS modules and routes them through
    JarvisSecurityBridge.
    """

    VERSION = "8.1"

    # =========================================================
    # COMMANDS
    # =========================================================

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
    CMD_ACKNOWLEDGE_NOTIFICATIONS = (
        "acknowledge_notifications"
    )

    CMD_MONITORING_START = "monitoring_start"
    CMD_MONITORING_STOP = "monitoring_stop"
    CMD_MONITORING_STATUS = "monitoring_status"

    CMD_RESCAN = "rescan"

    CMD_SECURITY_HELP = "security_help"

    # =========================================================
    # ACTIONS
    # =========================================================

    ACTION_QUARANTINE = "quarantine"
    ACTION_REMOVE = "remove"
    ACTION_BLOCK = "block"
    ACTION_RECOVER = "recover"

    # =========================================================
    # CATEGORIES
    # =========================================================

    CATEGORY_SCAN = "scan"
    CATEGORY_NETWORK = "network"
    CATEGORY_STATUS = "status"
    CATEGORY_THREATS = "threats"
    CATEGORY_QUARANTINE = "quarantine"
    CATEGORY_REMEDIATION = "remediation"
    CATEGORY_REPORT = "report"
    CATEGORY_NOTIFICATION = "notification"
    CATEGORY_MONITORING = "monitoring"
    CATEGORY_CONTROL = "control"

    # =========================================================
    # STATUS
    # =========================================================

    STATUS_IDLE = "idle"
    STATUS_RUNNING = "running"
    STATUS_SUCCESS = "success"
    STATUS_REQUIRES_USER = "requires_user"
    STATUS_BLOCKED = "blocked"
    STATUS_FAILED = "failed"

    # =========================================================
    # CONSTRUCTOR
    # =========================================================

    def __init__(
        self,
        security_bridge: Any = None,
        policy: Any = None,
        logger: Any = None,
        notifications: Any = None,
    ) -> None:

        self.security_bridge = security_bridge

        self.policy = policy

        self.logger = logger

        self.notifications = notifications

        self._lock = threading.RLock()

        self._status = self.STATUS_IDLE

        self._last_command: Optional[
            Dict[str, Any]
        ] = None

        self._last_result: Optional[Any] = None

        self._history: List[
            Dict[str, Any]
        ] = []

        self._max_history = 100

        self._stats = {
            "total_commands": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "blocked_commands": 0,
            "confirmation_required": 0,
        }

    # =========================================================
    # MAIN ENTRY POINT
    # =========================================================

    def handle(
        self,
        command: Dict[str, Any],
    ) -> Dict[str, Any]:

        with self._lock:

            self._stats["total_commands"] += 1

            self._status = self.STATUS_RUNNING

            self._last_command = dict(command)

            self._remember(command)

            try:

                normalized = self._normalize_command(
                    command
                )

                validation = self._validate_command(
                    normalized
                )

                if not validation["valid"]:

                    self._status = self.STATUS_FAILED

                    self._stats[
                        "failed_commands"
                    ] += 1

                    return self._result(
                        success=False,
                        command=normalized,
                        message=validation["message"],
                    )

                # -------------------------------------------------
                # POLICY / CONFIRMATION
                # -------------------------------------------------

                policy_result = self._check_policy(
                    normalized
                )

                if policy_result["blocked"]:

                    self._status = self.STATUS_BLOCKED

                    self._stats[
                        "blocked_commands"
                    ] += 1

                    return self._result(
                        success=False,
                        command=normalized,
                        message=(
                            policy_result["message"]
                        ),
                    )

                if policy_result[
                    "requires_confirmation"
                ]:

                    self._status = (
                        self.STATUS_REQUIRES_USER
                    )

                    self._stats[
                        "confirmation_required"
                    ] += 1

                    return self._result(
                        success=True,
                        command=normalized,
                        requires_confirmation=True,
                        message=(
                            policy_result["message"]
                        ),
                    )

                # -------------------------------------------------
                # EXECUTION
                # -------------------------------------------------

                result = self._execute(
                    normalized
                )

                self._last_result = result

                if self._operation_successful(
                    result
                ):

                    self._status = (
                        self.STATUS_SUCCESS
                    )

                    self._stats[
                        "successful_commands"
                    ] += 1

                    return self._result(
                        success=True,
                        command=normalized,
                        executed=True,
                        result=result,
                        message=(
                            "Команда успешно выполнена."
                        ),
                    )

                self._status = self.STATUS_FAILED

                self._stats[
                    "failed_commands"
                ] += 1

                return self._result(
                    success=False,
                    command=normalized,
                    executed=True,
                    result=result,
                    message=(
                        "Команда выполнена, "
                        "но операция завершилась с ошибкой."
                    ),
                )

            except Exception as exc:

                self._status = self.STATUS_FAILED

                self._stats[
                    "failed_commands"
                ] += 1

                self._log(
                    "error",
                    (
                        "SecurityCommandHandler "
                        f"error: {exc}"
                    ),
                )

                return self._result(
                    success=False,
                    command=command,
                    message=(
                        "Ошибка обработчика "
                        "команд безопасности."
                    ),
                    error=str(exc),
                )

    # =========================================================
    # NORMALIZATION
    # =========================================================

    def _normalize_command(
        self,
        command: Dict[str, Any],
    ) -> Dict[str, Any]:

        normalized = dict(command)

        normalized.setdefault(
            "command",
            None,
        )

        normalized.setdefault(
            "category",
            None,
        )

        normalized.setdefault(
            "target",
            None,
        )

        normalized.setdefault(
            "action",
            None,
        )

        normalized.setdefault(
            "requires_confirmation",
            False,
        )

        normalized.setdefault(
            "source_text",
            "",
        )

        return normalized

    # =========================================================
    # VALIDATION
    # =========================================================

    def _validate_command(
        self,
        command: Dict[str, Any],
    ) -> Dict[str, Any]:

        name = command.get("command")

        if not name:

            return {
                "valid": False,
                "message": (
                    "Команда безопасности не указана."
                ),
            }

        supported = {
            self.CMD_QUICK_SCAN,
            self.CMD_FULL_SCAN,

            self.CMD_SCAN_FILE,
            self.CMD_SCAN_FOLDER,

            self.CMD_SCAN_PROCESSES,
            self.CMD_SCAN_PROCESS,

            self.CMD_SCAN_STARTUP,
            self.CMD_SCAN_USB,

            self.CMD_SCAN_NETWORK,
            self.CMD_SCAN_FIREWALL,
            self.CMD_SCAN_DNS,

            self.CMD_SECURITY_STATUS,
            self.CMD_SECURITY_SCORE,

            self.CMD_GET_THREATS,
            self.CMD_ANALYZE_THREAT,
            self.CMD_ANALYZE_OBJECT,

            self.CMD_GET_SECURITY_EVENTS,

            self.CMD_GET_QUARANTINE,

            self.CMD_QUARANTINE,
            self.CMD_REMOVE,
            self.CMD_BLOCK,
            self.CMD_RECOVER,

            self.CMD_GET_REPORT,

            self.CMD_GET_NOTIFICATIONS,
            self.CMD_ACKNOWLEDGE_NOTIFICATIONS,

            self.CMD_MONITORING_START,
            self.CMD_MONITORING_STOP,
            self.CMD_MONITORING_STATUS,

            self.CMD_RESCAN,

            self.CMD_SECURITY_HELP,
        }

        if name not in supported:

            return {
                "valid": False,
                "message": (
                    f"Неподдерживаемая команда: {name}"
                ),
            }

        # -----------------------------------------------------
        # TARGET REQUIREMENTS
        # -----------------------------------------------------

        target_required = {
            self.CMD_SCAN_FILE,
            self.CMD_SCAN_FOLDER,
            self.CMD_SCAN_PROCESS,
        }

        if name in target_required:

         if command.get("target") is None:

                return {
                    "valid": False,
                    "message": (
                        "Для этой команды "
                        "не указан объект."
                    ),
                }

        # -----------------------------------------------------
        # REMEDIATION VALIDATION
        # -----------------------------------------------------

        remediation_commands = {
            self.CMD_QUARANTINE:
                self.ACTION_QUARANTINE,

            self.CMD_REMOVE:
                self.ACTION_REMOVE,

            self.CMD_BLOCK:
                self.ACTION_BLOCK,

            self.CMD_RECOVER:
                self.ACTION_RECOVER,
        }

        if name in remediation_commands:

            expected_action = (
                remediation_commands[name]
            )

            if command.get("action") is None:

                command["action"] = expected_action

            elif command.get("action") != (
                expected_action
            ):

                return {
                    "valid": False,
                    "message": (
                        "Действие команды "
                        "не соответствует операции."
                    ),
                }

        return {
            "valid": True,
            "message": "Команда корректна.",
        }

    # =========================================================
    # POLICY
    # =========================================================

    def _check_policy(
        self,
        command: Dict[str, Any],
    ) -> Dict[str, Any]:

        name = command.get("command")

        dangerous = {
            self.CMD_REMOVE,
            self.CMD_BLOCK,
            self.CMD_QUARANTINE,
            self.CMD_RECOVER,
        }

        # -----------------------------------------------------
        # ALWAYS REQUIRE CONFIRMATION FOR REMEDIATION
        # -----------------------------------------------------

        if name in dangerous:

            if command.get(
                "confirmed",
                False,
            ):

                return {
                    "blocked": False,
                    "requires_confirmation": False,
                    "message": (
                        "Операция подтверждена."
                    ),
                }

            return {
                "blocked": False,
                "requires_confirmation": True,
                "message": (
                    "Операция требует "
                    "подтверждения пользователя."
                ),
            }

        # -----------------------------------------------------
        # EXTERNAL POLICY
        # -----------------------------------------------------

        if self.policy is None:

            return {
                "blocked": False,
                "requires_confirmation": False,
                "message": "Политика не подключена.",
            }

        try:

            if hasattr(
                self.policy,
                "check",
            ):

                policy_result = self.policy.check(
                    command,
                    command,
                )

                return self._normalize_policy_result(
                    policy_result
                )

        except Exception as exc:

            self._log(
                "error",
                (
                    "Security policy error: "
                    f"{exc}"
                ),
            )

            # Fail-safe:
            return {
                "blocked": True,
                "requires_confirmation": False,
                "message": (
                    "Не удалось проверить "
                    "политику безопасности."
                ),
            }

        return {
            "blocked": False,
            "requires_confirmation": False,
            "message": "Политика разрешает операцию.",
        }

    # =========================================================
    # POLICY NORMALIZATION
    # =========================================================

    def _normalize_policy_result(
        self,
        result: Any,
    ) -> Dict[str, Any]:

        if result is None:

            return {
                "blocked": True,
                "requires_confirmation": False,
                "message": (
                    "Политика безопасности "
                    "не вернула решение."
                ),
            }

        if isinstance(result, bool):

            return {
                "blocked": not result,
                "requires_confirmation": False,
                "message": (
                    "Операция разрешена."
                    if result
                    else "Операция запрещена."
                ),
            }

        if isinstance(result, dict):

            action = str(
                result.get(
                    "action",
                    "",
                )
            ).lower()

            allowed = result.get(
                "allowed",
                None,
            )

            requires_confirmation = bool(
                result.get(
                    "requires_confirmation",
                    False,
                )
            )

            if action in {
                "deny",
                "blocked",
                "block",
            }:

                return {
                    "blocked": True,
                    "requires_confirmation": False,
                    "message": result.get(
                        "message",
                        "Операция запрещена политикой.",
                    ),
                }

            if action in {
                "ask_user",
                "confirm",
                "confirmation",
            }:

                return {
                    "blocked": False,
                    "requires_confirmation": True,
                    "message": result.get(
                        "message",
                        "Требуется подтверждение.",
                    ),
                }

            if allowed is False:

                return {
                    "blocked": True,
                    "requires_confirmation": False,
                    "message": result.get(
                        "message",
                        "Операция запрещена политикой.",
                    ),
                }

            return {
                "blocked": False,
                "requires_confirmation": (
                    requires_confirmation
                ),
                "message": result.get(
                    "message",
                    "Операция разрешена.",
                ),
            }

        # Unknown policy result:
        # fail-safe.
        return {
            "blocked": True,
            "requires_confirmation": False,
            "message": (
                "Неизвестный результат "
                "политики безопасности."
            ),
        }

    # =========================================================
    # EXECUTION
    # =========================================================

    def _execute(
        self,
        command: Dict[str, Any],
    ) -> Any:

        bridge = self.security_bridge

        if bridge is None:

            return {
                "success": False,
                "error": (
                    "Jarvis Security Bridge "
                    "не подключён."
                ),
            }

        name = command.get("command")

        target = command.get("target")

        # -----------------------------------------------------
        # QUICK SCAN
        # -----------------------------------------------------

        if name == self.CMD_QUICK_SCAN:

            return bridge.quick_scan()

        # -----------------------------------------------------
        # FULL SCAN
        # -----------------------------------------------------

        if name == self.CMD_FULL_SCAN:

            return bridge.full_scan()

        # -----------------------------------------------------
        # FILE
        # -----------------------------------------------------

        if name == self.CMD_SCAN_FILE:

            return bridge.scan_file(
                target
            )

        # -----------------------------------------------------
        # FOLDER
        # -----------------------------------------------------

        if name == self.CMD_SCAN_FOLDER:

            return bridge.scan_folder(
                target
            )

        # -----------------------------------------------------
        # PROCESSES
        # -----------------------------------------------------

        if name == self.CMD_SCAN_PROCESSES:
            return self._bridge_call(
                [
                    "scan_processes",
                    "scan_all_processes",
                ],
                fallback={
                    "scan_type": "processes",
                },
            )

        # -----------------------------------------------------
        # PROCESS
        # -----------------------------------------------------

        if name == self.CMD_SCAN_PROCESS:

            if isinstance(
                target,
                dict,
            ):

                target_type = target.get(
                    "type"
                )

                target_value = target.get(
                    "value"
                )

                if target_type == "pid":

                    return bridge.scan_process(
                        pid=target_value
                    )

                if target_type == "name":

                    return bridge.scan_process(
                        name=target_value
                    )

            if isinstance(
                target,
                int,
            ):

                return bridge.scan_process(
                    pid=target
                )

            return bridge.scan_process(
                name=str(target)
            )

        # -----------------------------------------------------
        # STARTUP
        # -----------------------------------------------------

        if name == self.CMD_SCAN_STARTUP:

            return bridge.scan_startup()

        # -----------------------------------------------------
        # USB
        # -----------------------------------------------------

        if name == self.CMD_SCAN_USB:

            return bridge.scan_usb()

        # -----------------------------------------------------
        # NETWORK
        # -----------------------------------------------------

        if name == self.CMD_SCAN_NETWORK:

            return bridge.scan_network()

        # -----------------------------------------------------
        # FIREWALL
        # -----------------------------------------------------

        if name == self.CMD_SCAN_FIREWALL:

            return bridge.scan_firewall()

        # -----------------------------------------------------
        # DNS
        # -----------------------------------------------------

        if name == self.CMD_SCAN_DNS:

            return bridge.scan_dns()

        # -----------------------------------------------------
        # SECURITY STATUS
        # -----------------------------------------------------

        if name == self.CMD_SECURITY_STATUS:

            return bridge.get_security_status()

        # -----------------------------------------------------
        # SECURITY SCORE
        # -----------------------------------------------------

        if name == self.CMD_SECURITY_SCORE:

            return bridge.get_security_score()

        # -----------------------------------------------------
        # THREATS
        # -----------------------------------------------------

        if name == self.CMD_GET_THREATS:

            return bridge.get_threats()

        # -----------------------------------------------------
        # THREAT ANALYSIS
        # -----------------------------------------------------

        if name == self.CMD_ANALYZE_THREAT:

            if hasattr(
                bridge,

                        "analyze",
            ):

                return bridge.analyze(
                    {
                        "type": "threat",
                        "target": target,
                    }
                )

            return {
                "success": False,
                "error": (
                    "Bridge не поддерживает "
                    "анализ угроз."
                ),
            }

        # -----------------------------------------------------
        # OBJECT ANALYSIS
        # -----------------------------------------------------

        if name == self.CMD_ANALYZE_OBJECT:

            if hasattr(
                bridge,
                "analyze",
            ):

                return bridge.analyze(
                    {
                        "type": "object",
                        "target": target,
                    }
                )

            return {
                "success": False,
                "error": (
                    "Bridge не поддерживает "
                    "анализ объектов."
                ),
            }

        # -----------------------------------------------------
        # SECURITY EVENTS
        # -----------------------------------------------------

        if name == self.CMD_GET_SECURITY_EVENTS:

            return self._bridge_call(
                bridge,
                [
                    "get_security_events",
                    "get_events",
                ],
            )

        # -----------------------------------------------------
        # QUARANTINE
        # -----------------------------------------------------

        if name == self.CMD_GET_QUARANTINE:

            return self._bridge_call(
                bridge,
                [
                    "get_quarantine",
                    "get_quarantine_items",
                ],
            )

        # -----------------------------------------------------
        # QUARANTINE OBJECT
        # -----------------------------------------------------

        if name == self.CMD_QUARANTINE:

            return bridge.remediate(
                action=self.ACTION_QUARANTINE,
                target=target,
            )

        # -----------------------------------------------------
        # REMOVE
        # -----------------------------------------------------

        if name == self.CMD_REMOVE:

            return bridge.remediate(
                action=self.ACTION_REMOVE,
                target=target,
            )

        # -----------------------------------------------------
        # BLOCK
        # -----------------------------------------------------

        if name == self.CMD_BLOCK:

            return bridge.remediate(
                action=self.ACTION_BLOCK,
                target=target,
            )

        # -----------------------------------------------------
        # RECOVER
        # -----------------------------------------------------

        if name == self.CMD_RECOVER:

            return bridge.recover(
                target
            )

        # -----------------------------------------------------
        # REPORT
        # -----------------------------------------------------

        if name == self.CMD_GET_REPORT:

            return self._bridge_call(
                bridge,
                [
                    "get_report",
                    "get_last_report",
                ],
            )

        # -----------------------------------------------------
        # NOTIFICATIONS
        # -----------------------------------------------------

        if name == self.CMD_GET_NOTIFICATIONS:

            return bridge.get_notifications()

        # -----------------------------------------------------
        # ACKNOWLEDGE
        # -----------------------------------------------------

        if name == (
            self.CMD_ACKNOWLEDGE_NOTIFICATIONS
        ):

            return self._bridge_call(
                bridge,

[
                    "acknowledge_notifications",
                    "mark_notifications_read",
                ],
            )

        # -----------------------------------------------------
        # MONITORING START
        # -----------------------------------------------------

        if name == self.CMD_MONITORING_START:

            return self._bridge_call(
                bridge,
                [
                    "start_monitoring",
                    "monitoring_start",
                ],
            )

        # -----------------------------------------------------
        # MONITORING STOP
        # -----------------------------------------------------

        if name == self.CMD_MONITORING_STOP:

            return self._bridge_call(
                bridge,
                [
                    "stop_monitoring",
                    "monitoring_stop",
                ],
            )

        # -----------------------------------------------------
        # MONITORING STATUS
        # -----------------------------------------------------

        if name == self.CMD_MONITORING_STATUS:

            return self._bridge_call(
                bridge,
                [
                    "get_monitoring_status",
                    "monitoring_status",
                ],
            )

        # -----------------------------------------------------
        # RESCAN
        # -----------------------------------------------------

        if name == self.CMD_RESCAN:

            last_command = (
                self._history[-1]
                if self._history
                else None
            )

            if last_command is None:

                return {
                    "success": False,
                    "error": (
                        "Нет предыдущей команды "
                        "для повторного выполнения."
                    ),
                }

            previous_name = last_command.get(
                "command"
            )

            if previous_name == self.CMD_QUICK_SCAN:

                return bridge.quick_scan()

            if previous_name == self.CMD_FULL_SCAN:

                return bridge.full_scan()

            if previous_name == self.CMD_SCAN_FILE:

                return bridge.scan_file(
                    last_command.get("target")
                )

            if previous_name == self.CMD_SCAN_FOLDER:

                return bridge.scan_folder(
                    last_command.get("target")
                )

            if previous_name == self.CMD_SCAN_PROCESSES:

                return bridge.scan_processes()

            if previous_name == self.CMD_SCAN_PROCESS:

                return bridge.scan_process(
                    name=last_command.get(
                        "target"
                    )
                )

            if previous_name == self.CMD_SCAN_STARTUP:

                return bridge.scan_startup()

            if previous_name == self.CMD_SCAN_USB:

                return bridge.scan_usb()

            if previous_name == self.CMD_SCAN_NETWORK:

                return bridge.scan_network()

            if previous_name == self.CMD_SCAN_FIREWALL:

                return bridge.scan_firewall()

            if previous_name == self.CMD_SCAN_DNS:

                return bridge.scan_dns()

            return {
                "success": False,
                "error": (
                    "Предыдущую операцию "
                    "нельзя повторить."
                ),
            }

        # -----------------------------------------------------
        # HELP
        # -----------------------------------------------------

        if name == self.CMD_SECURITY_HELP:

            return self.get_help()

        return {
            "success": False,
            "error": (
                "Команда не имеет обработчика."
            ),
        }

    # =========================================================
    # BRIDGE CALL
    # =========================================================

    @staticmethod
    def _bridge_call(
        bridge: Any,
        method_names: List[str],
        *args: Any,
        **kwargs: Any,
    ) -> Any:

        for method_name in method_names:

            if hasattr(
                bridge,
                method_name,
            ):

                method = getattr(
                    bridge,
                    method_name,
                )

                return method(
                    *args,
                    **kwargs,
                )

        return {
            "success": False,
            "error": (
                "Bridge не поддерживает "
                "данную операцию."
            ),
        }

    # =========================================================
    # RESULT VALIDATION
    # =========================================================

    @staticmethod
    def _operation_successful(
        result: Any,
    ) -> bool:

        if result is None:
            return False

        if isinstance(
            result,
            bool,
        ):
            return result

        if isinstance(
            result,
            dict,
        ):

            if result.get(
                "success"
            ) is False:
                return False

            if result.get(
                "error"
            ):
                return False

            return True

        return True

    # =========================================================
    # RESULT BUILDER
    # =========================================================

    @staticmethod
    def _result(
        success: bool,
        command: Optional[
            Dict[str, Any]
        ],
        message: str,
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
            "command": command,
            "result": result,
        }

        if error is not None:
            response["error"] = error

        return response

    # =========================================================
    # HISTORY
    # =========================================================

    def _remember(
        self,
        command: Dict[str, Any],
    ) -> None:

        self._history.append(
            dict(command)
        )

        if len(
            self._history
        ) > self._max_history:

            self._history = (
                self._history[
                    -self._max_history:
                ]
            )

    # =========================================================
    # GET HISTORY
    # =========================================================

    def get_history(
        self,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:

        if limit < 1:
            limit = 1

        return [
            dict(command)
            for command in self._history[
                -limit:
            ]
        ]

    # =========================================================
    # GET STATUS
    # =========================================================

    def get_status(
        self,
    ) -> Dict[str, Any]:

        return {
            "version": self.VERSION,
            "status": self._status,
            "bridge_connected": (
                self.security_bridge is not None
            ),
            "policy_connected": (
                self.policy is not None
            ),
            "last_command": self._last_command,
            "last_result": self._last_result,
            "statistics": dict(
                self._stats
            ),
            "history_size": len(
                self._history
            ),
        }

    # =========================================================
    # HELP
    # =========================================================

    def get_help(
        self,
    ) -> Dict[str, List[str]]:

        return {
            "scanning": [
                self.CMD_QUICK_SCAN,
                self.CMD_FULL_SCAN,
                self.CMD_SCAN_FILE,
                self.CMD_SCAN_FOLDER,
                self.CMD_SCAN_PROCESSES,
                self.CMD_SCAN_PROCESS,
                self.CMD_SCAN_STARTUP,
                self.CMD_SCAN_USB,
            ],

            "network": [
                self.CMD_SCAN_NETWORK,
                self.CMD_SCAN_FIREWALL,
                self.CMD_SCAN_DNS,
            ],

            "status": [
                self.CMD_SECURITY_STATUS,
                self.CMD_SECURITY_SCORE,
                self.CMD_GET_THREATS,
                self.CMD_GET_SECURITY_EVENTS,
            ],

            "remediation": [
                self.CMD_QUARANTINE,
                self.CMD_REMOVE,
                self.CMD_BLOCK,
                self.CMD_RECOVER,
            ],

            "monitoring": [
                self.CMD_MONITORING_START,
                self.CMD_MONITORING_STOP,
                self.CMD_MONITORING_STATUS,
            ],

            "information": [
                self.CMD_GET_QUARANTINE,
                self.CMD_GET_REPORT,
                self.CMD_GET_NOTIFICATIONS,
                self.CMD_ACKNOWLEDGE_NOTIFICATIONS,
                self.CMD_ANALYZE_THREAT,
                self.CMD_ANALYZE_OBJECT,
            ],

            "control": [
                self.CMD_RESCAN,
                self.CMD_SECURITY_HELP,
            ],
        }

    # =========================================================
    # CONNECT BRIDGE
    # =========================================================

    def set_security_bridge(
        self,
        security_bridge: Any,
    ) -> None:

        with self._lock:

            self.security_bridge = (
                security_bridge
            )

    # =========================================================
    # CONNECT POLICY
    # =========================================================

    def set_policy(
        self,
        policy: Any,
    ) -> None:

        with self._lock:

            self.policy = policy

    # =========================================================
    # ENABLE / DISABLE
    # =========================================================

    def enable(self) -> None:

        with self._lock:

            if self._status == self.STATUS_BLOCKED:
                self._status = self.STATUS_IDLE

    # =========================================================

    def disable(self) -> None:

        with self._lock:

            self._status = self.STATUS_BLOCKED

    # =========================================================
    # HEALTH CHECK
    # =========================================================

    def health_check(
        self,
    ) -> Dict[str, Any]:

        checks = {
            "bridge": (
                self.security_bridge is not None
            ),
            "lock": (
                self._lock is not None
            ),
            "history": (
                self._history is not None
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
    # RESET
    # =========================================================

    def reset(
        self,
    ) -> None:

        with self._lock:

            self._status = self.STATUS_IDLE

            self._last_command = None

            self._last_result = None

            self._history.clear()

            self._stats = {
                "total_commands": 0,
                "successful_commands": 0,
                "failed_commands": 0,
                "blocked_commands": 0,
                "confirmation_required": 0,
            }

    # =========================================================
    # LOGGER
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
    # REPRESENTATION
    # =========================================================

    def __repr__(self) -> str:

        return (
            f"<SecurityCommandHandler "
            f"version={self.VERSION!r} "
            f"status={self._status!r} "
            f"bridge_connected="
            f"{self.security_bridge is not None!r}>"
        )


# =============================================================
# SINGLETON
# =============================================================

_security_command_handler: Optional[
    SecurityCommandHandler
] = None

_security_command_handler_lock = (
    threading.Lock()
)


def get_security_command_handler(
    security_bridge: Any = None,
    policy: Any = None,
    logger: Any = None,
    notifications: Any = None,
) -> SecurityCommandHandler:

    global _security_command_handler

    with _security_command_handler_lock:

        if _security_command_handler is None:

            _security_command_handler = (
                SecurityCommandHandler(
                    security_bridge=security_bridge,
                    policy=policy,
                    logger=logger,
                    notifications=notifications,
                )
            )

        else:

            if security_bridge is not None:

                _security_command_handler.set_security_bridge(
                    security_bridge
                )

            if policy is not None:

                _security_command_handler.set_policy(
                    policy
                )

            if logger is not None:

                _security_command_handler.logger = (
                    logger
                )

            if notifications is not None:

                _security_command_handler.notifications = (
                    notifications
                )

        return _security_command_handler