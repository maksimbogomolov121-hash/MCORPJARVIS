"""
JARVIS V11 - SYNC LOGGER
Версия: 1.0.0

Отдельный журнал системы SYNC.

Назначение:
- логирование событий синхронизации;
- логирование операций с файлами;
- логирование конфликтов;
- логирование ошибок;
- чтение и экспорт журнала;
- автономный self-test.

SYNC Logger не зависит от:
- main.py
- Voice
- GUI
- SyncEngine
- SyncManager

Он может использоваться любым модулем SYNC.
"""

from __future__ import annotations

import json
import tempfile
import threading
import uuid

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# КОНСТАНТЫ
# ============================================================

MODULE_VERSION = "1.0.0"
LOGGER_VERSION = 1

DEFAULT_LOG_DIR = "SYNC/logs"
DEFAULT_LOG_FILENAME = "sync.log"

ENCODING = "utf-8"

# Уровни логирования
LEVEL_DEBUG = "DEBUG"
LEVEL_INFO = "INFO"
LEVEL_WARNING = "WARNING"
LEVEL_ERROR = "ERROR"
LEVEL_CRITICAL = "CRITICAL"

VALID_LEVELS = {
    LEVEL_DEBUG,
    LEVEL_INFO,
    LEVEL_WARNING,
    LEVEL_ERROR,
    LEVEL_CRITICAL,
}

# Приоритеты уровней
LEVEL_PRIORITY = {
    LEVEL_DEBUG: 10,
    LEVEL_INFO: 20,
    LEVEL_WARNING: 30,
    LEVEL_ERROR: 40,
    LEVEL_CRITICAL: 50,
}


# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def _now() -> str:
    """Возвращает текущее UTC-время в ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _safe_value(value: Any) -> Any:
    """Преобразует объект в JSON-совместимый вид."""

    if isinstance(value, Path):
        return str(value)

    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:
            pass

    if hasattr(value, "__dataclass_fields__"):
        try:
            from dataclasses import asdict

            return asdict(value)
        except Exception:
            pass

    if isinstance(value, dict):
        return {
            str(key): _safe_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _safe_value(item)
            for item in value
        ]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


# ============================================================
# LOG ENTRY
# ============================================================

@dataclass
class LogEntry:
    """
    Одна запись журнала.
    """

    entry_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    timestamp: str = field(
        default_factory=_now
    )

    level: str = LEVEL_INFO

    event: str = ""

    message: str = ""

    source_device: str = ""

    target_device: str = ""

    session_id: str = ""

    path: str = ""

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        """Преобразует запись в словарь."""

        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "level": self.level,
            "event": self.event,
            "message": self.message,
            "source_device": self.source_device,
            "target_device": self.target_device,
            "session_id": self.session_id,
            "path": self.path,
            "metadata": _safe_value(self.metadata),
        }

    def to_json(self) -> str:
        """Возвращает JSON-представление записи."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
        )


# ============================================================
# SYNC LOGGER
# ============================================================

class SyncLogger:
    """
    Основной Logger системы SYNC.

    По умолчанию:

        JARVIS_V11/
        └── SYNC/

Максим (11:18):
└── logs/
                └── sync.log
    """

    def __init__(
        self,
        root_path: Optional[str | Path] = None,
        log_dir: Optional[str | Path] = None,
        log_filename: str = DEFAULT_LOG_FILENAME,
        min_level: str = LEVEL_DEBUG,
        console: bool = True,
    ):
        # ----------------------------------------------------
        # ROOT
        # ----------------------------------------------------

        if root_path is None:
            self.root_path = (
                Path(__file__)
                .resolve()
                .parent
                .parent
            )
        else:
            self.root_path = Path(
                root_path
            ).resolve()

        # ----------------------------------------------------
        # LOG DIRECTORY
        # ----------------------------------------------------

        if log_dir is None:
            self.log_dir = (
                self.root_path
                / DEFAULT_LOG_DIR
            )
        else:
            self.log_dir = Path(
                log_dir
            ).resolve()

        self.log_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # LOG FILE
        # ----------------------------------------------------

        self.log_file = (
            self.log_dir
            / log_filename
        )

        # ----------------------------------------------------
        # SETTINGS
        # ----------------------------------------------------

        min_level = str(
            min_level
        ).upper()

        if min_level not in VALID_LEVELS:
            raise ValueError(
                f"Неизвестный уровень логирования: "
                f"{min_level}"
            )

        self.min_level = min_level
        self.console = bool(console)

        self._lock = threading.RLock()

        self.entries_written = 0

    # ========================================================
    # INTERNAL
    # ========================================================

    def _should_log(
        self,
        level: str,
    ) -> bool:
        """Проверяет, нужно ли записывать уровень."""

        level = str(level).upper()

        return (
            LEVEL_PRIORITY[level]
            >= LEVEL_PRIORITY[self.min_level]
        )

    def _format_line(
        self,
        entry: LogEntry,
    ) -> str:
        """
        Формат обычной строки журнала.
        """

        parts = [
            entry.timestamp,
            f"[{entry.level}]",
        ]

        if entry.event:
            parts.append(
                f"[{entry.event}]"
            )

        if entry.session_id:
            parts.append(
                f"[session={entry.session_id}]"
            )

        if (
            entry.source_device
            or entry.target_device
        ):
            parts.append(
                "["
                f"{entry.source_device or '-'}"
                "→"
                f"{entry.target_device or '-'}"
                "]"
            )

        if entry.path:
            parts.append(
                f"[path={entry.path}]"
            )

        parts.append(
            entry.message
        )

        return " ".join(parts)

    def _write_entry(
        self,
        entry: LogEntry,
    ) -> Optional[LogEntry]:
        """
        Записывает запись в файл.
        """

        if not self._should_log(
            entry.level
        ):
            return None

        line = (
            self._format_line(entry)
            + "\n"
        )

        with self._lock:
            with open(
                self.log_file,
                "a",
                encoding=ENCODING,
            ) as file:
                file.write(line)

            self.entries_written += 1

        if self.console:
            print(
                f"[SyncLogger] {line.rstrip()}"
            )

        return entry

    # ========================================================
    # GENERAL LOGGING
    # ========================================================

    def log(
        self,
        level: str,
        message: str,
        event: str = "",
        source_device: str = "",
        target_device: str = "",
        session_id: str = "",
        path: str = "",
        metadata: Optional[
            dict[str, Any]
        ] = None,
    ) -> Optional[LogEntry]:
        """
        Универсальная запись.
        """

        level = str(
            level
        ).upper()

        if level not in VALID_LEVELS:
            raise ValueError(
                f"Неизвестный уровень: {level}"
            )

        entry = LogEntry(
            level=level,
            event=str(event),
            message=str(message),
            source_device=str(
                source_device
            ),
            target_device=str(
                target_device
            ),
            session_id=str(
                session_id
            ),
            path=str(path),
            metadata=(
                _safe_value(metadata)
                if metadata
                else {}
            ),
        )

        return self._write_entry(
            entry
        )

    # ========================================================
    # LEVEL HELPERS
    # ========================================================

    def debug(
        self,
        message: str,
        event: str = "",
        **kwargs: Any,
    ) -> Optional[LogEntry]:
        return self.log(
            LEVEL_DEBUG,
            message,
            event=event,
            **kwargs,
        )

    def info(
        self,
        message: str,
        event: str = "",
        **kwargs: Any,
    ) -> Optional[LogEntry]:
        return self.log(
            LEVEL_INFO,
            message,
            event=event,
            **kwargs,
        )

    def warning(
        self,
        message: str,
        event: str = "",
        **kwargs: Any,
    ) -> Optional[LogEntry]:
        return self.log(
            LEVEL_WARNING,
            message,
            event=event,
            **kwargs,
        )

    def error(
        self,
        message: str,
        event: str = "",
        **kwargs: Any,
    ) -> Optional[LogEntry]:
        return self.log(
            LEVEL_ERROR,
            message,
            event=event,
            **kwargs,
        )

    def critical(
        self,
        message: str,
        event: str = "",
        **kwargs: Any,
    ) -> Optional[LogEntry]:
        return self.log(
            LEVEL_CRITICAL,
            message,
            event=event,
            **kwargs,
        )

    # ========================================================
    # SYNC EVENTS
    # ========================================================

    def sync_started(
        self,
        session_id: str,
        source_device: str,
        target_device: str,
    ) -> Optional[LogEntry]:
        """Логирует начало синхронизации."""

        return self.info(
            "Синхронизация запущена.",
            event="SYNC_STARTED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
        )

    def sync_completed(
        self,
        session_id: str,
        source_device: str,
        target_device: str,
        success: bool = True,
    ) -> Optional[LogEntry]:
        """Логирует завершение синхронизации."""

        level = (
            LEVEL_INFO
            if success
            else LEVEL_ERROR
        )

        message = (
            "Синхронизация завершена успешно."
            if success
            else "Синхронизация завершена с ошибками."
        )

        return self.log(
            level,
            message,
            event="SYNC_COMPLETED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
            metadata={
                "success": success,
            },
        )

    def sync_failed(
        self,
        session_id: str,
        source_device: str,
        target_device: str,
        error: str,
    ) -> Optional[LogEntry]:
        """Логирует провал синхронизации."""

        return self.error(
            str(error),
            event="SYNC_FAILED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
        )

    def sync_cancelled(
        self,
        session_id: str,
        source_device: str = "",
        target_device: str = "",
        reason: str = "",
    ) -> Optional[LogEntry]:
        """Логирует отмену."""

        return self.warning(
            reason or "Синхронизация отменена.",
            event="SYNC_CANCELLED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
        )

    # ========================================================
    # ANALYSIS
    # ========================================================

    def analysis_started(
        self,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            "Анализ изменений запущен.",
            event="ANALYSIS_STARTED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
        )

    def analysis_completed(
        self,
        operations: int,
        conflicts: int,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            (
                "Анализ завершён: "
                f"{operations} операций, "
                f"{conflicts} конфликтов."
            ),
            event="ANALYSIS_COMPLETED",
            source_device=source_device,
            target_device=target_device,
            session_id=session_id,
            metadata={
                "operations": operations,
                "conflicts": conflicts,
            },
        )

    # ========================================================
    # FILE OPERATIONS
    # ========================================================

    def file_copied(
        self,
        path: str,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            "Файл скопирован.",
            event="FILE_COPIED",
            path=path,
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
        )

    def file_updated(
        self,
        path: str,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            "Файл обновлён.",
            event="FILE_UPDATED",
            path=path,
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
        )

    def file_deleted(
        self,
        path: str,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> Optional[LogEntry]:
        return self.warning(
            "Файл удалён.",
            event="FILE_DELETED",
            path=path,
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
        )

    def file_skipped(
        self,
        path: str,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
        reason: str = "",
    ) -> Optional[LogEntry]:
        return self.debug(
            reason or "Файл пропущен.",
            event="FILE_SKIPPED",
            path=path,
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
        )

    # ========================================================
    # BACKUP / VERIFY
    # ========================================================

    def backup_started(
        self,
        session_id: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            "Создание backup запущено.",
            event="BACKUP_STARTED",
            session_id=session_id,
        )

    def backup_completed(
        self,
        session_id: str = "",
        files: int = 0,
    ) -> Optional[LogEntry]:
        return self.info(
            (
                "Backup завершён: "
                f"{files} файлов."
            ),
            event="BACKUP_COMPLETED",
            session_id=session_id,
            metadata={
                "files": files,
            },
        )

    def verification_started(
        self,
        session_id: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            "Проверка результатов запущена.",
            event="VERIFICATION_STARTED",
            session_id=session_id,
        )

    def verification_completed(
        self,
        session_id: str = "",
        errors: int = 0,
    ) -> Optional[LogEntry]:
        level = (
            LEVEL_INFO
            if errors == 0
            else LEVEL_ERROR
        )

        message = (
            "Проверка завершена успешно."
            if errors == 0
            else (
                "Проверка завершена с ошибками: "
                f"{errors}."
            )
        )

        return self.log(
            level,
            message,
            event="VERIFICATION_COMPLETED",
            session_id=session_id,
            metadata={
                "errors": errors,
            },
        )

    # ========================================================
    # CONFLICTS
    # ========================================================

    def conflict_detected(
        self,
        path: str,
        session_id: str = "",
        source_device: str = "",
        target_device: str = "",
        message: str = "",
    ) -> Optional[LogEntry]:
        return self.warning(
            message or "Обнаружен конфликт.",
            event="CONFLICT_DETECTED",
            path=path,
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
        )

    def conflict_resolved(
        self,
        path: str,
        resolution: str,
        session_id: str = "",
    ) -> Optional[LogEntry]:
        return self.info(
            (
                "Конфликт разрешён: "
                f"{resolution}."
            ),
            event="CONFLICT_RESOLVED",
            path=path,
            session_id=session_id,
            metadata={
                "resolution": resolution,
            },
        )

    # ========================================================
    # ERRORS
    # ========================================================

    def exception(
        self,
        error: Exception,
        event: str = "EXCEPTION",
        session_id: str = "",
        path: str = "",
    ) -> Optional[LogEntry]:
        return self.error(
            (
                f"{type(error).__name__}: "
                f"{error}"
            ),
            event=event,
            session_id=session_id,
            path=path,
            metadata={
                "exception_type": type(error).__name__,
            },
        )

    # ========================================================
    # READING
    # ========================================================

    def read_lines(
        self,
        limit: Optional[int] = None,
    ) -> list[str]:
        """
        Читает строки журнала.

        limit:
            None — весь журнал;
            число — последние N строк.
        """

        if not self.log_file.exists():
            return []

        with self._lock:
            with open(

        self.log_file,
                "r",
                encoding=ENCODING,
            ) as file:
                lines = file.readlines()

        lines = [
            line.rstrip("\n\r")
            for line in lines
        ]

        if limit is not None:
            limit = max(
                0,
                int(limit),
            )

            if limit == 0:
                return []

            return lines[-limit:]

        return lines

    def read_entries(
        self,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Читает журнал.

        Поскольку основной log-файл человекочитаемый,
        здесь записи восстанавливаются в компактном виде.
        """

        lines = self.read_lines(limit)

        entries: list[dict[str, Any]] = []

        for line in lines:
            entries.append(
                {
                    "line": line,
                }
            )

        return entries

    # ========================================================
    # SEARCH
    # ========================================================

    def search(
        self,
        text: str,
        limit: Optional[int] = None,
    ) -> list[str]:
        """Ищет текст в журнале."""

        text = str(text).lower()

        lines = self.read_lines()

        matches = [
            line
            for line in lines
            if text in line.lower()
        ]

        if limit is not None:
            limit = max(
                0,
                int(limit),
            )

            matches = matches[-limit:]

        return matches

    def search_level(
        self,
        level: str,
        limit: Optional[int] = None,
    ) -> list[str]:
        """Ищет записи определённого уровня."""

        level = str(
            level
        ).upper()

        if level not in VALID_LEVELS:
            raise ValueError(
                f"Неизвестный уровень: {level}"
            )

        return self.search(
            f"[{level}]",
            limit=limit,
        )

    # ========================================================
    # CLEAR
    # ========================================================

    def clear(self) -> None:
        """Полностью очищает журнал."""

        with self._lock:
            with open(
                self.log_file,
                "w",
                encoding=ENCODING,
            ):
                pass

            self.entries_written = 0

    # ========================================================
    # EXPORT
    # ========================================================

    def export_text(
        self,
        destination: str | Path,
    ) -> Path:
        """Экспортирует журнал в текстовый файл."""

        destination = Path(
            destination
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lines = self.read_lines()

        with open(
            destination,
            "w",
            encoding=ENCODING,
        ) as file:
            file.write(
                "\n".join(lines)
            )

        return destination

    def export_json(
        self,
        destination: str | Path,
        limit: Optional[int] = None,
    ) -> Path:
        """
        Экспортирует строки журнала в JSON.
        """

        destination = Path(
            destination
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        data = {
            "logger_version": LOGGER_VERSION,
            "module_version": MODULE_VERSION,
            "exported_at": _now(),
            "entries": self.read_entries(
                limit=limit
            ),
        }

        with open(
            destination,
            "w",
            encoding=ENCODING,
        ) as file:
            json.dump(
                data,
                file,
                ensure_ascii=False,
                indent=2,
)

        return destination

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:
        """Возвращает состояние Logger."""

        try:
            size = self.log_file.stat().st_size
        except Exception:
            size = 0

        try:
            line_count = len(
                self.read_lines()
            )
        except Exception:
            line_count = 0

        return {
            "module": "SyncLogger",
            "module_version": MODULE_VERSION,
            "logger_version": LOGGER_VERSION,
            "root_path": str(
                self.root_path
            ),
            "log_dir": str(
                self.log_dir
            ),
            "log_file": str(
                self.log_file
            ),
            "log_exists": self.log_file.exists(),
            "log_size": size,
            "line_count": line_count,
            "entries_written": (
                self.entries_written
            ),
            "min_level": self.min_level,
            "console": self.console,
        }

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self) -> tuple[bool, list[str]]:
        """Проверяет состояние Logger."""

        errors: list[str] = []

        if not self.root_path.exists():
            errors.append(
                "Корневой путь не существует."
            )

        if not self.log_dir.exists():
            errors.append(
                "Каталог логов не существует."
            )

        if not self.log_dir.is_dir():
            errors.append(
                "Путь логов не является каталогом."
            )

        if not self.log_file.parent.exists():
            errors.append(
                "Родительский каталог "
                "log-файла не существует."
            )

        return (
            len(errors) == 0,
            errors,
        )

    # ========================================================
    # SELF TEST
    # ========================================================

    @staticmethod
    def self_test() -> bool:
        """
        Полный автономный тест SyncLogger.
        """

        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)

                logger = SyncLogger(
                    root_path=root,
                    console=False,
                    min_level=LEVEL_DEBUG,
                )

                # ------------------------------------------------
                # 1. Проверяем структуру
                # ------------------------------------------------

                valid, errors = (
                    logger.validate()
                )

                if not valid:
                    print(
                        "[SelfTest] Initial "
                        "validation failed:",
                        errors,
                    )
                    return False

                # ------------------------------------------------
                # 2. Обычные уровни
                # ------------------------------------------------

                logger.debug(
                    "Debug message.",
                    event="TEST_DEBUG",
                )

                logger.info(
                    "Info message.",
                    event="TEST_INFO",
                )

                logger.warning(
                    "Warning message.",
                    event="TEST_WARNING",
                )

                logger.error(
                    "Error message.",
                    event="TEST_ERROR",
                )

                logger.critical(
                    "Critical message.",
                    event="TEST_CRITICAL",
                )

                # ------------------------------------------------
                # 3. Sync events
                # ------------------------------------------------

                session_id = (
                    "TEST-SESSION"
                )

                logger.sync_started(
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.analysis_started(
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.analysis_completed(
                    operations=3,
                    conflicts=1,
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                # ------------------------------------------------
                # 4. File operations
                # ------------------------------------------------

                logger.file_copied(
                    path="CONFIG/settings.json",
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.file_updated(
                    path="DATA/user.json",
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.file_deleted(
                    path="DATA/old.json",
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.file_skipped(
                    path="CACHE/temp.tmp",
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                    reason="Файл игнорируется правилами.",
                )

                # ------------------------------------------------
                # 5. Backup / verify
                # ------------------------------------------------

                logger.backup_started(
                    session_id=session_id,
                )

                logger.backup_completed(
                    session_id=session_id,
                    files=2,
                )

                logger.verification_started(
                    session_id=session_id,
                )

                logger.verification_completed(
                    session_id=session_id,
                    errors=0,
                )

                # ------------------------------------------------
                # 6. Conflict
                # ------------------------------------------------

                logger.conflict_detected(
                    path="CONFIG/test.json",
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                )

                logger.conflict_resolved(
                    path="CONFIG/test.json",
                    resolution="pc_wins",
                    session_id=session_id,
                )

                # ------------------------------------------------
                # 7. Completion
                # ------------------------------------------------

                logger.sync_completed(
                    session_id=session_id,
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                    success=True,
                )

                # ------------------------------------------------
                # 8. Проверяем файл
                # ------------------------------------------------

                if not logger.log_file.exists():
                    print(
                        "[SelfTest] Log file missing"
                    )
                    return False

                lines = logger.read_lines()

                if not lines:
                    print(
                        "[SelfTest] Log is empty"
                    )
                    return False

                # ------------------------------------------------
                # 9. Проверяем количество
                # ------------------------------------------------

                if len(lines) < 10:
                    print(
                        "[SelfTest] Too few log lines:",
                        len(lines),
                    )
                    return False

                # ------------------------------------------------
                # 10. Поиск
                # ------------------------------------------------

                copied = logger.search(
                    "FILE_COPIED"
                )

                if not copied:
                    print(
                        "[SelfTest] FILE_COPIED "
                        "search failed"
                    )
                    return False

                conflicts = (
                    logger.search_level(
                        LEVEL_WARNING
                    )
                )

                if not conflicts:
                    print(
                        "[SelfTest] WARNING "
                        "search failed"
                    )
                    return False

                # ------------------------------------------------
                # 11. Export text
                # ------------------------------------------------

                exported_txt = (
                    root
                    / "exported.log"
                )

                logger.export_text(
                    exported_txt
                )

                if not exported_txt.exists():
                    print(
                        "[SelfTest] Text export missing"
                    )
                    return False

                # ------------------------------------------------
                # 12. Export JSON
                # ------------------------------------------------

                exported_json = (
                    root
                    / "exported.json"
                )

                logger.export_json(
                    exported_json
                )

                if not exported_json.exists():
                    print(
                        "[SelfTest] JSON export missing"
                    )
                    return False

                with open(
                    exported_json,
                    "r",
                    encoding=ENCODING,
                ) as file:
                    exported_data = json.load(
                        file
                    )

                if "entries" not in exported_data:
                    print(
                        "[SelfTest] JSON entries missing"
                    )
                    return False

                # ------------------------------------------------
                # 13. Status
                # ------------------------------------------------

                status = logger.status()

                if not status["log_exists"]:
                    print(
                        "[SelfTest] Status "
                        "log_exists failed"
                    )
                    return False

                if status["line_count"] <= 0:
                    print(
                        "[SelfTest] Status "
                        "line_count failed"
                    )
                    return False

                # ------------------------------------------------
                # 14. Final validation
                # ------------------------------------------------

                valid, errors = (
                    logger.validate()
                )

                if not valid:
                    print(
                        "[SelfTest] Final "
                        "validation failed:",
                        errors,
                    )
                    return False

                # ------------------------------------------------
                # 15. Print diagnostics
                # ------------------------------------------------

                print(
                    "[SelfTest] Log file =",
                    logger.log_file,
                )

                print(
                    "[SelfTest] Lines =",
                    len(lines),
                )

                print(
                    "[SelfTest] Copied entries =",
                    len(copied),
                )

                print(
                    "[SelfTest] WARNING entries =",
                    len(conflicts),
                )

                print(
                    "[SelfTest] Export TXT =",
                    exported_txt.exists(),
                )

                print(
                    "[SelfTest] Export JSON =",
                    exported_json.exists(),
                )

                print(
                    "[SelfTest] All checks passed"
                )

                return True

        except Exception as exc:
            print(
                "[SelfTest] Exception:",
                repr(exc),
            )
            return False


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":
    print(
        f"[SyncLogger] Version: {MODULE_VERSION}"
    )

    if SyncLogger.self_test():
        print("[+] Self-test: OK")
        print("[+] SyncLogger: OK")
    else:
        print("[-] Self-test: FAILED")
        print("[-] SyncLogger: FAILED")
        raise SystemExit(1)