"""
JARVIS V11 - SYNC REPORT
Версия: 1.0.0

Формирует отчёты о синхронизации:
- статус
- устройства
- операции
- изменения файлов
- конфликты
- ошибки
- время выполнения
- экспорт JSON
"""

from __future__ import annotations

import json
import tempfile
import uuid

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


MODULE_VERSION = "1.0.0"
REPORT_VERSION = 1

DEFAULT_REPORT_DIR = "SYNC"
DEFAULT_REPORT_PREFIX = "sync_report"


# ============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================

def _now() -> str:
    """UTC timestamp в ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


def _safe_json(data: Any) -> Any:
    """
    Преобразует dataclass / Path / прочие объекты
    в безопасный для JSON формат.
    """
    if hasattr(data, "to_dict"):
        return data.to_dict()

    if isinstance(data, Path):
        return str(data)

    if hasattr(data, "__dataclass_fields__"):
        return asdict(data)

    if isinstance(data, dict):
        return {
            str(key): _safe_json(value)
            for key, value in data.items()
        }

    if isinstance(data, (list, tuple)):
        return [_safe_json(value) for value in data]

    return data


# ============================================================
# SYNC REPORT
# ============================================================

@dataclass
class SyncReport:
    """
    Полный результат одной синхронизации.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    report_version: int = REPORT_VERSION
    module_version: str = MODULE_VERSION

    status: str = "unknown"
    success: bool = False

    source_device: str = ""
    target_device: str = ""

    started_at: str = field(default_factory=_now)
    completed_at: Optional[str] = None

    duration_seconds: float = 0.0

    files_total: int = 0
    files_copied: int = 0
    files_updated: int = 0
    files_deleted: int = 0
    files_skipped: int = 0

    operations_total: int = 0

    conflicts: int = 0
    errors: int = 0

    messages: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)

    operations: list[dict[str, Any]] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        """Завершает отчёт и рассчитывает длительность."""
        self.completed_at = _now()

        try:
            started = datetime.fromisoformat(self.started_at)
            completed = datetime.fromisoformat(self.completed_at)

            self.duration_seconds = max(
                0.0,
                (completed - started).total_seconds()
            )

        except Exception:
            self.duration_seconds = 0.0

    def add_operation(
        self,
        path: str,
        action: str,
        change_type: Optional[str] = None,
        success: bool = True,
        message: str = "",
        **metadata: Any,
    ) -> None:
        """Добавляет одну операцию в отчёт."""

        operation = {
            "path": str(path),
            "action": str(action),
            "change_type": change_type,
            "success": bool(success),
            "message": message,
            "metadata": _safe_json(metadata),
        }

        self.operations.append(operation)
        self.operations_total = len(self.operations)

        action_lower = str(action).lower()

        if action_lower == "copy":
            self.files_copied += 1

        elif action_lower == "update":
            self.files_updated += 1

        elif action_lower == "delete":
            self.files_deleted += 1

        elif action_lower == "skip":
            self.files_skipped += 1

        if not success:
            self.errors += 1

            if message:
                self.error_messages.append(message)

    def add_conflict(
        self,
        path: str,
        message: str = "",
        **metadata: Any,
    ) -> None:
        """Добавляет конфликт."""

        self.conflicts += 1

        conflict = {
            "path": str(path),
            "message": message,
            "metadata": _safe_json(metadata),
        }

        self.metadata.setdefault("conflict_details", [])
        self.metadata["conflict_details"].append(conflict)

    def add_error(
        self,
        message: str,
        **metadata: Any,
    ) -> None:
        """Добавляет ошибку."""

        self.errors += 1
        self.error_messages.append(str(message))

        if metadata:
            self.metadata.setdefault("error_details", [])
            self.metadata["error_details"].append(
                _safe_json(metadata)
            )

    def add_message(self, message: str) -> None:
        """Добавляет информационное сообщение."""
        self.messages.append(str(message))

    def set_status(
        self,
        status: str,
        success: Optional[bool] = None,
    ) -> None:
        """Устанавливает статус отчёта."""

        self.status = str(status)

        if success is not None:
            self.success = bool(success)

    def to_dict(self) -> dict[str, Any]:
        """Преобразует отчёт в словарь."""

        return _safe_json(asdict(self))

    def to_json(self, indent: int = 2) -> str:
        """Возвращает JSON-строку."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
        )


# ============================================================
# REPORT MANAGER
# ============================================================

class SyncReportManager:
    """
    Управляет созданием и сохранением отчётов SYNC.
    """

    def __init__(
        self,
        root_path: Optional[str | Path] = None,
        report_dir: Optional[str | Path] = None,
    ):
        if root_path is None:
            root = Path(__file__).resolve().parent.parent
        else:
            root = Path(root_path).resolve()

        self.root_path = root

        if report_dir is None:
            self.report_dir = self.root_path / DEFAULT_REPORT_DIR
        else:
            self.report_dir = Path(report_dir).resolve()

        self.report_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.current_report: Optional[SyncReport] = None

    # --------------------------------------------------------
    # СОЗДАНИЕ
    # --------------------------------------------------------

    def create_report(
        self,
        source_device: str = "",
        target_device: str = "",
        status: str = "started",
    ) -> SyncReport:
        """Создаёт новый отчёт."""

        report = SyncReport(
            source_device=str(source_device),
            target_device=str(target_device),
            status=str(status),
        )

        self.current_report = report

        return report

    def get_current_report(self) -> Optional[SyncReport]:
        """Возвращает текущий отчёт."""
        return self.current_report

    # --------------------------------------------------------
    # ФИНАЛИЗАЦИЯ
    # --------------------------------------------------------

    def finish_report(
        self,
        report: Optional[SyncReport] = None,
        success: bool = True,
        status: str = "completed",
    ) -> SyncReport:
        """
        Завершает отчёт.
        """

        if report is None:
            report = self.current_report

        if report is None:
            raise RuntimeError(
                "Нет активного отчёта для завершения."
            )

        report.success = bool(success)
        report.status = str(status)

        report.finish()

        self.current_report = report

        return report

    # --------------------------------------------------------
    # СОХРАНЕНИЕ
    # --------------------------------------------------------

    def save_report(
        self,
        report: Optional[SyncReport] = None,
        filename: Optional[str] = None,
    ) -> Path:
        """
        Сохраняет отчёт атомарно.
        """

        if report is None:
            report = self.current_report

        if report is None:
            raise RuntimeError(
                "Нет отчёта для сохранения."
            )

        if filename is None:
            timestamp = datetime.now().strftime(
                "%Y-%m-%d_%H-%M-%S"
            )

            filename = (
                f"{DEFAULT_REPORT_PREFIX}_"
                f"{timestamp}_"
                f"{report.report_id[:8]}.json"
            )

        filename = Path(filename)

        if not filename.is_absolute():
            filename = self.report_dir / filename

        filename.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temp_path = filename.with_suffix(
            filename.suffix + ".tmp"
        )

        with open(
            temp_path,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report.to_dict(),
                file,
                ensure_ascii=False,
                indent=2,
            )

        temp_path.replace(filename)

        return filename

    # --------------------------------------------------------
    # ЗАГРУЗКА
    # --------------------------------------------------------

    def load_report(
        self,
        path: str | Path,
    ) -> SyncReport:
        """Загружает отчёт из JSON."""

        path = Path(path)

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        report = SyncReport(
            report_id=data.get(
                "report_id",
                str(uuid.uuid4()),
            ),
            report_version=data.get(
                "report_version",
                REPORT_VERSION,
            ),
            module_version=data.get(
                "module_version",
                MODULE_VERSION,
            ),
            status=data.get(
                "status",
                "unknown",
            ),
            success=bool(
                data.get("success", False)
            ),
            source_device=data.get(
                "source_device",
                "",
            ),
            target_device=data.get(
                "target_device",
                "",
            ),
            started_at=data.get(
                "started_at",
                _now(),
            ),
            completed_at=data.get(
                "completed_at",
            ),
            duration_seconds=float(
                data.get(
                    "duration_seconds",
                    0.0,
                )
            ),
            files_total=int(
                data.get(
                    "files_total",
                    0,
                )
            ),
            files_copied=int(
                data.get(
                    "files_copied",
                    0,
                )
            ),
            files_updated=int(
                data.get(
                    "files_updated",
                    0,
                )
            ),
            files_deleted=int(
                data.get(
                    "files_deleted",
                    0,
                )
            ),
            files_skipped=int(
                data.get(
                    "files_skipped",
                    0,
                )
            ),
            operations_total=int(
                data.get(
                    "operations_total",
                    0,
                )
            ),
            conflicts=int(
                data.get(
                    "conflicts",
                    0,
                )
            ),
            errors=int(
                data.get(
                    "errors",
                    0,
                )
            ),
            messages=list(
                data.get(
                    "messages",
                    [],
                )
            ),
            error_messages=list(
                data.get(
                    "error_messages",
                    [],
                )
            ),
            operations=list(
                data.get(
                    "operations",
                    [],
                )
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
            ),
        )

        return report

    # --------------------------------------------------------
    # СПИСОК ОТЧЁТОВ
    # --------------------------------------------------------

    def list_reports(self) -> list[Path]:
        """Возвращает список JSON-отчётов."""

        if not self.report_dir.exists():
            return []

        return sorted(
            self.report_dir.glob(
                f"{DEFAULT_REPORT_PREFIX}_*.json"
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

    def get_latest_report(self) -> Optional[SyncReport]:
        """Возвращает последний сохранённый отчёт."""

        reports = self.list_reports()

        if not reports:
            return None

        return self.load_report(reports[0])

    # --------------------------------------------------------
    # ЭКСПОРТ
    # --------------------------------------------------------

    def export_report(
        self,
        report: Optional[SyncReport] = None,
    ) -> dict[str, Any]:
        """Экспортирует отчёт в словарь."""

        if report is None:
            report = self.current_report

        if report is None:
            return {}

        return report.to_dict()

    # --------------------------------------------------------
    # СТАТУС
    # --------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Возвращает состояние Report Manager."""

        current = self.current_report

        return {
            "module": "SyncReportManager",
            "module_version": MODULE_VERSION,
            "report_version": REPORT_VERSION,
            "root_path": str(self.root_path),
            "report_dir": str(self.report_dir),
            "reports_count": len(
                self.list_reports()
            ),
            "has_current_report": current is not None,
            "current_report_id": (
                current.report_id
                if current
                else None
            ),
        }

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    def validate(self) -> tuple[bool, list[str]]:
        """Проверяет состояние Report Manager."""

        errors: list[str] = []

        if not self.root_path.exists():
            errors.append(
                "Корневой путь не существует."
            )

        if not self.report_dir.exists():
            errors.append(
                "Каталог отчётов не существует."
            )

        if not self.report_dir.is_dir():
            errors.append(
                "Путь отчётов не является каталогом."
            )

        return (
            len(errors) == 0,
            errors,
        )

    # --------------------------------------------------------
    # SELF TEST
    # --------------------------------------------------------

    @staticmethod
    def self_test() -> bool:
        """
        Полный автономный тест Report Manager.
        """

        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)

                report_dir = (
                    root / "SYNC"
                )

                manager = SyncReportManager(
                    root_path=root,
                    report_dir=report_dir,
                )

                # Создание
                report = manager.create_report(
                    source_device="PC_TEST",
                    target_device="USB_TEST",
                    status="analyzing",
                )

                if not report.report_id:
                    print(
                        "[SelfTest] Report ID missing"
                    )
                    return False

                # Операции
                report.add_operation(
                    path="CONFIG/settings.json",
                    action="copy",
                    change_type="added",
                    success=True,
                    message="Файл скопирован.",
                )

                report.add_operation(
                    path="DATA/user.json",
                    action="update",
                    change_type="modified",
                    success=True,
                    message="Файл обновлён.",
                )

                report.add_operation(
                    path="DATA/cache.tmp",
                    action="skip",
                    change_type="unchanged",
                    success=True,
                    message="Файл пропущен.",
                )

                report.files_total = 3

                # Конфликт
                report.add_conflict(
                    path="CONFIG/conflict.json",
                    message="Требуется ручное разрешение.",
                )

                # Завершение
                manager.finish_report(
                    report,
                    success=True,
                    status="completed",
                )

                # Проверки счётчиков
                if report.files_total != 3:
                    print(
                        "[SelfTest] files_total failed"
                    )
                    return False

                if report.files_copied != 1:
                    print(
                        "[SelfTest] files_copied failed"
                    )
                    return False

                if report.files_updated != 1:
                    print(
                        "[SelfTest] files_updated failed"
                    )
                    return False

                if report.files_skipped != 1:
                    print(
                        "[SelfTest] files_skipped failed"
                    )
                    return False

                if report.conflicts != 1:
                    print(
                        "[SelfTest] conflicts failed"
                    )
                    return False

                if report.operations_total != 3:
                    print(
                        "[SelfTest] operations_total failed"
                    )
                    return False

                if not report.success:
                    print(
                        "[SelfTest] success failed"
                    )
                    return False

                if report.completed_at is None:
                    print(
                        "[SelfTest] completed_at missing"
                    )
                    return False

                # Сохранение
                saved = manager.save_report(
                    report
                )

                if not saved.exists():
                    print(
                        "[SelfTest] Report file missing"
                    )
                    return False

                # Загрузка
                loaded = manager.load_report(
                    saved
                )

                if (
                    loaded.report_id
                    != report.report_id
                ):
                    print(
                        "[SelfTest] report ID mismatch"
                    )
                    return False

                if (
                    loaded.files_copied
                    != 1
):
                    print(
                        "[SelfTest] loaded data mismatch"
                    )
                    return False

                if (
                    loaded.conflicts
                    != 1
                ):
                    print(
                        "[SelfTest] loaded conflicts mismatch"
                    )
                    return False

                # Latest
                latest = (
                    manager.get_latest_report()
                )

                if latest is None:
                    print(
                        "[SelfTest] latest report missing"
                    )
                    return False

                if (
                    latest.report_id
                    != report.report_id
                ):
                    print(
                        "[SelfTest] latest report mismatch"
                    )
                    return False

                # Validation
                valid, errors = (
                    manager.validate()
                )

                if not valid:
                    print(
                        "[SelfTest] validation failed:",
                        errors,
                    )
                    return False

                print(
                    "[SelfTest] Report ID =",
                    report.report_id,
                )

                print(
                    "[SelfTest] Status =",
                    report.status,
                )

                print(
                    "[SelfTest] Operations =",
                    report.operations_total,
                )

                print(
                    "[SelfTest] Copied =",
                    report.files_copied,
                )

                print(
                    "[SelfTest] Updated =",
                    report.files_updated,
                )

                print(
                    "[SelfTest] Skipped =",
                    report.files_skipped,
                )

                print(
                    "[SelfTest] Conflicts =",
                    report.conflicts,
                )

                print(
                    "[SelfTest] Report saved =",
                    saved,
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
        f"[SyncReport] Version: {MODULE_VERSION}"
    )

    if SyncReportManager.self_test():
        print("[+] Self-test: OK")
        print("[+] SyncReportManager: OK")
    else:
        print("[-] Self-test: FAILED")
        print("[-] SyncReportManager: FAILED")
        raise SystemExit(1)