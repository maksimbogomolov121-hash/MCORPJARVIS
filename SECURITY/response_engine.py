"""
response_engine.py
JARVIS Security Core V4.2

Response Engine — движок выполнения реакций Security Core.

Задача:
    Получить решение Decision Engine и выполнить разрешённое действие.

Основные решения:
    IGNORE
    NOTIFY
    ASK_SANDBOX
    QUARANTINE
    AUTO_DELETE
    BLOCK
    UNKNOWN

ВАЖНО:
    Response Engine не принимает решение о том,
    является ли объект вредоносным.

    Решение приходит извне, например от Decision Engine
    и в дальнейшем будет дополнительно контролироваться
    Security Policy.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class ResponseEngine:
    VERSION = "4.2"

    RESPONSE_SUCCESS = "SUCCESS"
    RESPONSE_FAILED = "FAILED"
    RESPONSE_SKIPPED = "SKIPPED"
    RESPONSE_REQUIRES_USER = "REQUIRES_USER"

    DECISION_IGNORE = "IGNORE"
    DECISION_NOTIFY = "NOTIFY"
    DECISION_ASK_SANDBOX = "ASK_SANDBOX"
    DECISION_QUARANTINE = "QUARANTINE"
    DECISION_AUTO_DELETE = "AUTO_DELETE"
    DECISION_BLOCK = "BLOCK"
    DECISION_UNKNOWN = "UNKNOWN"

    def __init__(
        self,
        logger=None,
        notifier: Optional[Callable[[str], Any]] = None,
        sandbox_handler: Optional[Callable[[str], Any]] = None,
    ):
        self.logger = logger
        self.notifier = notifier
        self.sandbox_handler = sandbox_handler

        self.last_decision: Dict[str, Any] = {}
        self.last_response: Dict[str, Any] = {}

        self.history: List[Dict[str, Any]] = []

        self.pending_sandbox: Optional[str] = None

        self.log("Response Engine V4.2 инициализирован.")

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

        print(f"[SECURITY RESPONSE] {message}")

    # ============================================================
    # MAIN RESPONSE
    # ============================================================

    def respond(
        self,
        decision: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.log("Начало выполнения Security Response.")

        normalized_decision = self._normalize_decision(decision)
        context = context or {}

        self.last_decision = dict(normalized_decision)

        decision_type = normalized_decision["decision"]

        try:

            if decision_type == self.DECISION_IGNORE:
                result = self._handle_ignore()

            elif decision_type == self.DECISION_NOTIFY:
                result = self._handle_notify(
                    normalized_decision,
                    context,
                )

            elif decision_type == self.DECISION_ASK_SANDBOX:
                result = self._handle_ask_sandbox(
                    normalized_decision,
                    context,
                )

            elif decision_type == self.DECISION_QUARANTINE:
                result = self._handle_quarantine(
                    normalized_decision,
                    context,
                )

            elif decision_type == self.DECISION_AUTO_DELETE:
                result = self._handle_auto_delete(
                    normalized_decision,
                    context,
                )

            elif decision_type == self.DECISION_BLOCK:
                result = self._handle_block(
                    normalized_decision,
                    context,
                )

            else:
                result = self._handle_unknown(
                    normalized_decision,
                    context,
                )

        except Exception as error:


            self.log(
                f"Ошибка выполнения реакции: {error}"
                )

            result = self._response(
                status=self.RESPONSE_FAILED,
                action=decision_type,
                message="Ошибка выполнения реакции.",
                error=str(error),
            )

        self.last_response = dict(result)

        self.history.append(dict(result))

        if len(self.history) > 100:
            self.history = self.history[-100:]

        self.log(
            f"Response завершён. "
            f"Status: {result.get('status')}, "
            f"Action: {result.get('action')}"
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
                "decision": ResponseEngine.DECISION_UNKNOWN,
                "reason": "Решение отсутствует.",
                "confidence": 0,
                "requires_user": False,
                "automatic": False,
            }

        if isinstance(decision, str):

            return {
                "decision": decision.upper(),
                "reason": "",
                "confidence": 0,
                "requires_user": False,
                "automatic": False,
            }

        if not isinstance(decision, dict):

            return {
                "decision": ResponseEngine.DECISION_UNKNOWN,
                "reason": "Некорректный формат решения.",
                "confidence": 0,
                "requires_user": False,
                "automatic": False,
            }

        result = dict(decision)

        result["decision"] = str(
            result.get(
                "decision",
                ResponseEngine.DECISION_UNKNOWN,
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
            "requires_user",
            False,
        )

        result.setdefault(
            "automatic",
            False,
        )

        return result

    # ============================================================
    # IGNORE
    # ============================================================

    def _handle_ignore(
        self,
    ) -> Dict[str, Any]:

        self.log(
            "Решение IGNORE. Действий не требуется."
        )

        return self._response(
            status=self.RESPONSE_SKIPPED,
            action=self.DECISION_IGNORE,
            message="Действий не требуется.",
        )

    # ============================================================
    # NOTIFY
    # ============================================================

    def _handle_notify(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        message = self._build_notification(
            decision,
            context,
        )

        self._notify(message)

        return self._response(
            status=self.RESPONSE_SUCCESS,
            action=self.DECISION_NOTIFY,
            message=message,
        )

    # ============================================================
    # ASK SANDBOX
    # ============================================================

    def _handle_ask_sandbox(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:
            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_ASK_SANDBOX,
                message=(
                    "Не удалось определить путь "
                    "подозрительного файла."


),
            )

        self.pending_sandbox = file_path

        message = (
            "Обнаружен подозрительный файл.\n"
            f"Файл: {file_path}\n"
            "Рекомендуется проверить его в Sandbox."
        )

        self._notify(message)

        return self._response(
            status=self.RESPONSE_REQUIRES_USER,
            action=self.DECISION_ASK_SANDBOX,
            message=message,
            file_path=file_path,
        )

    # ============================================================
    # SANDBOX USER RESPONSE
    # ============================================================

    def sandbox_user_response(
        self,
        approved: bool,
    ) -> Dict[str, Any]:

        if not self.pending_sandbox:

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_ASK_SANDBOX,
                message=(
                    "Нет файла, ожидающего "
                    "решения пользователя."
                ),
            )

        file_path = self.pending_sandbox

        if not approved:

            self.pending_sandbox = None

            message = (
                "Проверка файла в Sandbox "
                "отменена пользователем."
            )

            self._notify(message)

            return self._response(
                status=self.RESPONSE_SUCCESS,
                action="SANDBOX_CANCELLED",
                message=message,
                file_path=file_path,
            )

        self.log(
            f"Пользователь разрешил Sandbox: {file_path}"
        )

        if self.sandbox_handler is None:

            return self._response(
                status=self.RESPONSE_FAILED,
                action="SANDBOX",
                message=(
                    "Sandbox Handler не подключён."
                ),
                file_path=file_path,
            )

        try:

            sandbox_result = self.sandbox_handler(
                file_path
            )

        except Exception as error:

            return self._response(
                status=self.RESPONSE_FAILED,
                action="SANDBOX",
                message=(
                    "Ошибка запуска Sandbox."
                ),
                error=str(error),
                file_path=file_path,
            )

        verdict = self._extract_sandbox_verdict(
            sandbox_result
        )

        # --------------------------------------------------------
        # SAFE
        # --------------------------------------------------------

        if verdict == "SAFE":

            self.pending_sandbox = None

            message = (
                "Sandbox-анализ завершён.\n"
                f"Файл: {file_path}\n"
                "Угрозы не обнаружено."
            )

            self._notify(message)

            return self._response(
                status=self.RESPONSE_SUCCESS,
                action="SANDBOX_SAFE",
                message=message,
                file_path=file_path,
                sandbox_result=sandbox_result,
            )

        # --------------------------------------------------------
        # MALICIOUS
        # --------------------------------------------------------

        if verdict == "MALICIOUS":

            self.pending_sandbox = None

            message = (
                "Sandbox-анализ завершён.\n"
                f"Файл: {file_path}\n"
                "Файл признан вредоносным.\n"
                "Запрашивается автоматическое удаление."
            )

            self._notify(message)

            delete_decision = {
                "decision": self.DECISION_AUTO_DELETE,
                "reason": (
                    "Sandbox подтвердил вредоносность файла."
                ),
                "confidence": 100,
                "automatic": True,
                "requires_user": False,
            }

            return self._handle_auto_delete(
                delete_decision,


{
                    "file_path": file_path,
                    "sandbox_result": sandbox_result,
                },
            )

        # --------------------------------------------------------
        # UNKNOWN
        # --------------------------------------------------------

        message = (
            "Sandbox не смог однозначно определить "
            "безопасность файла.\n"
            f"Файл: {file_path}\n"
            "Автоматическое удаление отменено."
        )

        self._notify(message)

        return self._response(
            status=self.RESPONSE_REQUIRES_USER,
            action="SANDBOX_UNKNOWN",
            message=message,
            file_path=file_path,
            sandbox_result=sandbox_result,
        )

    # ============================================================
    # QUARANTINE
    # ============================================================

    def _handle_quarantine(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_QUARANTINE,
                message=(
                    "Путь к файлу не указан."
                ),
            )

        quarantine_dir = context.get(
            "quarantine_dir"
        )

        if not quarantine_dir:

            quarantine_dir = os.path.join(
                os.path.expanduser("~"),
                "JARVIS_Quarantine",
            )

        try:

            os.makedirs(
                quarantine_dir,
                exist_ok=True,
            )

            filename = os.path.basename(
                file_path
            )

            destination = os.path.join(
                quarantine_dir,
                filename,
            )

            destination = self._unique_path(
                destination
            )

            shutil.move(
                file_path,
                destination,
            )

            message = (
                "Файл помещён в карантин.\n"
                f"Источник: {file_path}\n"
                f"Карантин: {destination}"
            )

            self._notify(message)

            return self._response(
                status=self.RESPONSE_SUCCESS,
                action=self.DECISION_QUARANTINE,
                message=message,
                file_path=file_path,
                quarantine_path=destination,
            )

        except Exception as error:

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_QUARANTINE,
                message=(
                    "Не удалось переместить "
                    "файл в карантин."
                ),
                error=str(error),
                file_path=file_path,
            )

    # ============================================================
    # AUTO DELETE
    # ============================================================

    def _handle_auto_delete(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        file_path = self._extract_file_path(
            context
        )

        if not file_path:

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_AUTO_DELETE,
                message=(
                    "Невозможно удалить файл: "
                    "путь не указан."
                ),
            )

        if not bool(
            decision.get(
                "automatic",
                False,
            )
        ):

            return self._response(
                status=self.RESPONSE_SKIPPED,
                action=self.DECISION_AUTO_DELETE,
                message=(
                    "Автоматическое удаление "


"не разрешено текущим решением."
                ),
                file_path=file_path,
            )

        if not os.path.isfile(file_path):

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_AUTO_DELETE,
                message=(
                    "Файл не найден."
                ),
                file_path=file_path,
            )

        # --------------------------------------------------------
        # Защита от очевидно опасных путей.
        # --------------------------------------------------------

        if self._is_protected_path(
            file_path
        ):

            self.log(
                "Удаление защищённого пути заблокировано."
            )

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_AUTO_DELETE,
                message=(
                    "Удаление защищённого системного "
                    "пути заблокировано."
                ),
                file_path=file_path,
            )

        try:

            os.remove(
                file_path
            )

            message = (
                "Вредоносный файл удалён.\n"
                f"Файл: {file_path}"
            )

            self._notify(message)

            return self._response(
                status=self.RESPONSE_SUCCESS,
                action=self.DECISION_AUTO_DELETE,
                message=message,
                file_path=file_path,
            )

        except Exception as error:

            return self._response(
                status=self.RESPONSE_FAILED,
                action=self.DECISION_AUTO_DELETE,
                message=(
                    "Не удалось удалить "
                    "вредоносный файл."
                ),
                error=str(error),
                file_path=file_path,
            )

    # ============================================================
    # BLOCK
    # ============================================================

    def _handle_block(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        message = (
            "Обнаружена вредоносная активность.\n"
            "Требуется блокировка объекта."
        )

        self._notify(message)

        # Реальная блокировка будет подключаться
        # отдельным безопасным обработчиком.

        return self._response(
            status=self.RESPONSE_SUCCESS,
            action=self.DECISION_BLOCK,
            message=message,
        )

    # ============================================================
    # UNKNOWN
    # ============================================================

    def _handle_unknown(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:

        message = (
            "Security Core получил неизвестное "
            "решение. Действие не выполнено."
        )

        self._notify(message)

        return self._response(
            status=self.RESPONSE_SKIPPED,
            action=self.DECISION_UNKNOWN,
            message=message,
        )

    # ============================================================
    # NOTIFICATION
    # ============================================================

    def _notify(
        self,
        message: str,
    ):

        if self.notifier is not None:

            try:
                self.notifier(message)
            except Exception as error:
                self.log(
                    f"Ошибка уведомления: {error}"
                )

        self.log(message)

    def _build_notification(
        self,
        decision: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:

        reason = decision.get(
            "reason",
            "Причина не указана.",
        )

        score = decision.get(
            "confidence",
            0,
        )

        return (


"Security Core обнаружил событие.\n"
            f"Причина: {reason}\n"
            f"Уверенность решения: {score}%"
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

        possible_keys = (
            "file_path",
            "filepath",
            "path",
            "filename",
        )

        for key in possible_keys:

            value = context.get(key)

            if isinstance(
                value,
                str,
            ) and value.strip():

                return os.path.abspath(
                    value.strip()
                )

        return None

    # ============================================================
    # SANDBOX VERDICT
    # ============================================================

    @staticmethod
    def _extract_sandbox_verdict(
        result: Any,
    ) -> str:

        if isinstance(result, str):

            text = result.lower()

            if (
                "malicious" in text
                or "malware" in text
                or "infected" in text
            ):
                return "MALICIOUS"

            if (
                "safe" in text
                or "clean" in text
                or "benign" in text
            ):
                return "SAFE"

            return "UNKNOWN"

        if isinstance(result, dict):

            verdict = result.get(
                "verdict",
                result.get(
                    "result",
                    result.get(
                        "status",
                        "",
                    ),
                ),
            )

            text = str(
                verdict
            ).upper()

            if text in (
                "MALICIOUS",
                "MALWARE",
                "INFECTED",
            ):
                return "MALICIOUS"

            if text in (
                "SAFE",
                "CLEAN",
                "BENIGN",
            ):
                return "SAFE"

        return "UNKNOWN"

    # ============================================================
    # PATH PROTECTION
    # ============================================================

    @staticmethod
    def _is_protected_path(
        file_path: str,
    ) -> bool:

        try:

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
    # UNIQUE PATH
    # ============================================================

    @staticmethod
    def _unique_path(
        path: str,
    ) -> str:

        if not os.path.exists(path):
            return path

        directory = os.path.dirname(
            path
        )

        filename = os.path.basename(
            path
        )

        name, extension = os.path.splitext(
            filename
        )

        counter = 1

        while True:

            candidate = os.path.join(
                directory,
                f"{name}_{counter}{extension}",
            )

            if not os.path.exists(
                candidate
            ):
                return candidate

            counter += 1

    # ============================================================
    # RESPONSE BUILDER
    # ============================================================

    def _response(
        self,
        status: str,
        action: str,
        message: str,
        **extra,
    ) -> Dict[str, Any]:

        result = {
            "status": status,
            "action": action,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "engine_version": self.VERSION,
        }

        result.update(extra)

        return result

    # ============================================================
    # ACCESSORS
    # ============================================================

    def get_last_response(
        self,
    ) -> Dict[str, Any]:

        return dict(
            self.last_response
        )

    def get_last_decision(
        self,
    ) -> Dict[str, Any]:

        return dict(
            self.last_decision
        )

    def get_history(
        self,
    ) -> List[Dict[str, Any]]:

        return list(
            self.history
        )

    def get_pending_sandbox(
        self,
    ) -> Optional[str]:

        return self.pending_sandbox

    def get_version(
        self,
    ) -> str:

        return self.VERSION

    def clear(
        self,
    ):

        self.last_decision = {}
        self.last_response = {}
        self.history = []
        self.pending_sandbox = None

        self.log(
            "История Response Engine очищена."
        )


ResponseEngineV4 = ResponseEngine


# ================================================================
# STANDALONE TEST
# ================================================================

if __name__ == "__main__":

    print("=" * 60)
    print("JARVIS RESPONSE ENGINE V4.2 TEST")
    print("=" * 60)

    notifications = []

    def test_notifier(message):
        notifications.append(message)
        print(
            "\n[NOTIFICATION]"
        )
        print(message)

    def test_sandbox(file_path):

        print(
            f"\n[SANDBOX] Анализ: {file_path}"
        )

        return {
            "verdict": "SAFE",
            "file": file_path,
        }

    engine = ResponseEngine(
        notifier=test_notifier,
        sandbox_handler=test_sandbox,
    )

    # ------------------------------------------------------------
    # TEST 1
    # ------------------------------------------------------------

    print("\n[1] IGNORE")

    result = engine.respond(
        {
            "decision": "IGNORE",
            "reason": "Тестовое событие.",
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 2
    # ------------------------------------------------------------

    print("\n[2] NOTIFY")

    result = engine.respond(
        {
            "decision": "NOTIFY",
            "reason": "Обнаружен тестовый риск.",
            "confidence": 75,
        }
    )

    print(result)


    # ------------------------------------------------------------
    # TEST 3
    # ------------------------------------------------------------

    print("\n[3] ASK_SANDBOX")

    result = engine.respond(
        {
            "decision": "ASK_SANDBOX",
            "reason": "Подозрительный файл.",
            "confidence": 80,
            "requires_user": True,
        },
        {
            "file_path": "test_suspicious.exe",
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 4
    # ------------------------------------------------------------

    print("\n[4] Отказ пользователя")

    result = engine.sandbox_user_response(
        False
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 5
    # ------------------------------------------------------------

    print("\n[5] ASK_SANDBOX снова")

    result = engine.respond(
        {
            "decision": "ASK_SANDBOX",
            "reason": "Подозрительный файл.",
            "confidence": 80,
            "requires_user": True,
        },
        {
            "file_path": "test_suspicious.exe",
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 6
    # ------------------------------------------------------------

    print("\n[6] Пользователь разрешает Sandbox")

    result = engine.sandbox_user_response(
        True
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 7
    # ------------------------------------------------------------

    print("\n[7] Проверка AUTO_DELETE без файла")

    result = engine.respond(
        {
            "decision": "AUTO_DELETE",
            "reason": (
                "Sandbox подтвердил вредоносность."
            ),
            "confidence": 100,
            "automatic": True,
        },
        {
            "file_path": "not_existing_test_file.exe",
        },
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 8
    # ------------------------------------------------------------

    print("\n[8] Проверка BLOCK")

    result = engine.respond(
        {
            "decision": "BLOCK",
            "reason": (
                "Подтверждённая вредоносная активность."
            ),
            "confidence": 100,
            "automatic": True,
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 9
    # ------------------------------------------------------------

    print("\n[9] Проверка UNKNOWN")

    result = engine.respond(
        {
            "decision": "SOMETHING_UNKNOWN",
        }
    )

    print(result)

    # ------------------------------------------------------------
    # TEST 10
    # ------------------------------------------------------------

    print("\n[10] Последний результат")

    print(
        engine.get_last_response()
    )

    # ------------------------------------------------------------
    # TEST 11
    # ------------------------------------------------------------

    print("\n[11] Версия")

    print(
        engine.get_version()
    )

    # ------------------------------------------------------------
    # FINAL
    # ------------------------------------------------------------

    print("\n" + "=" * 60)
    print("RESPONSE ENGINE V4.2 TEST COMPLETED")
    print("=" * 60)