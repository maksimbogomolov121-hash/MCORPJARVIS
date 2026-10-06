"""
JARVIS V11
SYNC / SYNC MANAGER
Version: 1.0

Назначение:
    Управление процессом синхронизации между устройствами.

SyncManager отвечает за:
    - запуск синхронизации;
    - выбор source / target устройств;
    - управление жизненным циклом sync-сессии;
    - управление SyncState;
    - запуск SyncEngine;
    - обработку ошибок;
    - регистрацию результата;
    - историю запусков;
    - получение общего статуса.

SyncManager НЕ выполняет:
    - копирование файлов;
    - удаление файлов;
    - создание backup напрямую;
    - проверку hash напрямую;
    - работу с manifest напрямую;
    - регистрацию версий напрямую.

Этим занимается SyncEngine.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from sync_rules import SyncRules


# ============================================================
# IMPORTS
# ============================================================

try:
    from .device_manager import (
        DeviceManager,
    )

    from .sync_engine import (
        SyncEngine,
        SyncPlan,
        SyncResult,
    )

    from .sync_state import (
        SyncState,
        SyncSession,

        STATUS_IDLE,
        STATUS_ANALYZING,
        STATUS_BACKING_UP,
        STATUS_APPLYING,
        STATUS_VERIFYING,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CONFLICT,
    )

except ImportError:
    from device_manager import (
        DeviceManager,
    )

    from sync_engine import (
        SyncEngine,
        SyncPlan,
        SyncResult,
    )

    from sync_state import (
        SyncState,
        SyncSession,

        STATUS_IDLE,
        STATUS_ANALYZING,
        STATUS_BACKING_UP,
        STATUS_APPLYING,
        STATUS_VERIFYING,
        STATUS_COMPLETED,
        STATUS_FAILED,
        STATUS_CONFLICT,
    )


# ============================================================
# CONSTANTS
# ============================================================

MANAGER_VERSION = 1

MANAGER_IDLE = "idle"
MANAGER_ANALYZING = "analyzing"
MANAGER_BACKING_UP = "backing_up"
MANAGER_APPLYING = "applying"
MANAGER_VERIFYING = "verifying"
MANAGER_COMPLETED = "completed"
MANAGER_FAILED = "failed"
MANAGER_CONFLICT = "conflict"

DIRECTION_PC_TO_USB = "pc_to_usb"
DIRECTION_USB_TO_PC = "usb_to_pc"

DEFAULT_SYNC_ROOT = "SYNC"
DEFAULT_STATE_FILENAME = "sync_state.json"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """
    Возвращает текущее UTC-время в ISO 8601.
    """
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ManagerResult:
    """
    Результат работы SyncManager.
    """

    session_id: str

    success: bool

    status: str

    started_at: str

    completed_at: Optional[str]

    source_device: str

    target_device: str

    files_added: int = 0

    files_modified: int = 0

    files_deleted: int = 0

    files_unchanged: int = 0

    files_skipped: int = 0

    conflicts: int = 0

    errors: int = 0

    error_messages: list[str] = field(
        default_factory=list
    )

    operations: list[dict[str, Any]] = field(
        default_factory=list
    )

    plan_id: Optional[str] = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> dict[str, Any]:
        """
        Возвращает JSON-compatible словарь.
        """

        return {
            "session_id": self.session_id,
            "success": self.success,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,

            "source_device": self.source_device,
            "target_device": self.target_device,


            "files_added": self.files_added,
            "files_modified": self.files_modified,
            "files_deleted": self.files_deleted,
            "files_unchanged": self.files_unchanged,
            "files_skipped": self.files_skipped,

            "conflicts": self.conflicts,
            "errors": self.errors,

            "error_messages": list(
                self.error_messages
            ),

            "operations": [
                dict(operation)
                for operation
                in self.operations
            ],

            "plan_id": self.plan_id,

            "metadata": dict(
                self.metadata
            ),
        }


# ============================================================
# SYNC MANAGER
# ============================================================

class SyncManager:
    """
    Главный менеджер синхронизации.

    Архитектура:

        SyncManager
             │
             ├── DeviceManager
             │
             ├── SyncState
             │
             └── SyncEngine
                    │
                    ├── ChangeDetector
                    ├── SyncRules
                    ├── HashManager
                    ├── ManifestManager
                    ├── ConflictManager
                    └── VersionManager

    Manager отвечает за orchestration.
    Engine отвечает за саму синхронизацию.
    """

    # ========================================================
    # INIT
    # ========================================================

    def __init__(
        self,
        root_path: str | Path | None = None,
        device_manager: DeviceManager | None = None,
        sync_state: SyncState | None = None,
    ) -> None:

        # ----------------------------------------------------
        # ROOT
        # ----------------------------------------------------

        if root_path is None:

            root_path = (
                Path(__file__)
                .resolve()
                .parent
                .parent
            )

        self.root_path = Path(
            root_path
        ).resolve()

        # ----------------------------------------------------
        # MANAGERS
        # ----------------------------------------------------

        self.device_manager = (
            device_manager
            if device_manager is not None
            else DeviceManager()
        )

        self.sync_state = (
            sync_state
            if sync_state is not None
            else SyncState(
                self.root_path
                / DEFAULT_SYNC_ROOT
                / DEFAULT_STATE_FILENAME
            )
        )

        # ----------------------------------------------------
        # RUNTIME
        # ----------------------------------------------------

        self.status = MANAGER_IDLE

        self.current_engine: Optional[
            SyncEngine
        ] = None

        self.current_plan: Optional[
            SyncPlan
        ] = None

        self.last_result: Optional[
            ManagerResult
        ] = None

    # ========================================================
    # LOG
    # ========================================================

    def _log(
        self,
        message: str,
    ) -> None:
        """
        Временный вывод Manager.

        Позже может быть подключён SyncLogger.
        """

        print(
            f"[SyncManager] {message}"
        )

    # ========================================================
    # DEVICE HELPERS
    # ========================================================

    def _get_device(
        self,
        device_id: str,
    ) -> Any:
        """
        Получает устройство через DeviceManager.
        """

        device = (
            self.device_manager
            .get_device(
                device_id
            )
        )

        if device is None:

            raise ValueError(
                f"Устройство не найдено: "
                f"{device_id}"
)

        return device

    # ========================================================
    # DEVICE ROOT
    # ========================================================

    def _get_device_root(
        self,
        device_id: str,
    ) -> Path:
        """
        Получает root_path устройства.
        """

        device = self._get_device(
            device_id
        )

        # ----------------------------------------------------
        # DeviceInfo object
        # ----------------------------------------------------

        if hasattr(
            device,
            "root_path",
        ):

            root = device.root_path

            if root:
                return Path(root).resolve()

        # ----------------------------------------------------
        # Dictionary
        # ----------------------------------------------------

        if isinstance(
            device,
            dict,
        ):

            root = device.get(
                "root_path"
            )

            if root:
                return Path(root).resolve()

        raise ValueError(
            f"У устройства "
            f"{device_id} отсутствует root_path."
        )

    # ========================================================
    # DEVICE VALIDATION
    # ========================================================

    def _validate_devices(
        self,
        source_device: str,
        target_device: str,
    ) -> tuple[Path, Path]:
        """
        Проверяет source / target устройства.
        """

        if (
            not source_device
            or not target_device
        ):

            raise ValueError(
                "Source и target устройства "
                "должны быть указаны."
            )

        if source_device == target_device:

            raise ValueError(
                "Source и target устройства "
                "не могут совпадать."
            )

        source_root = (
            self._get_device_root(
                source_device
            )
        )

        target_root = (
            self._get_device_root(
                target_device
            )
        )

        if not source_root.exists():

            raise FileNotFoundError(
                f"Source root не существует: "
                f"{source_root}"
            )

        if not target_root.exists():

            raise FileNotFoundError(
                f"Target root не существует: "
                f"{target_root}"
            )

        return (
            source_root,
            target_root,
        )

    # ========================================================
    # STATE
    # ========================================================

    def _save_state(self) -> None:
        """
        Сохраняет SyncState.
        """

        self.sync_state.save()

    # ========================================================
    # SESSION START
    # ========================================================

    def _start_session(
        self,
        source_device: str,
        target_device: str,
    ) -> SyncSession:

        session_id = str(
            uuid.uuid4()
        )

        session = (
            self.sync_state.start_session(
                session_id=session_id,
                source_device=source_device,
                target_device=target_device,
            )
        )

        self._save_state()

        self._log(
            f"Session started: "
            f"{session.session_id}"
        )

        return session

    # ========================================================
    # SESSION STATUS
    # ========================================================

    def _set_status(
        self,
        status: str,
    ) -> None:
        """
        Синхронно обновляет статус Manager
        и SyncState.
        """

        self.status = status

        self.sync_state.set_status(
            status
        )

        self._save_state()

        self._log(

f"Status: {status}"
        )

    # ========================================================
    # UPDATE SESSION
    # ========================================================

    def _update_session_from_result(
        self,
        result: SyncResult,
    ) -> None:
        """
        Переносит статистику Engine
        в активную SyncSession.
        """

        self.sync_state.update_active_session(

            files_added=(
                result.files_added
            ),

            files_modified=(
                result.files_modified
            ),

            files_deleted=(
                result.files_deleted
            ),

            files_unchanged=(
                result.files_unchanged
            ),

            conflicts=(
                result.conflicts
            ),

            errors=(
                result.errors
            ),

            error_messages=list(
                result.error_messages
            ),
        )

        self._save_state()

    # ========================================================
    # CREATE ENGINE
    # ========================================================

    def _create_engine(
            self,
            source_root: Path,
            target_root: Path,
            source_device: str,
            target_device: str,
    ) -> SyncEngine:
        """
        Создаёт SyncEngine для текущей операции.
        """

        sync_rules = SyncRules()
        sync_rules.set_direction(
            "bidirectional"
        )

        engine = SyncEngine(
            source_root=source_root,
            target_root=target_root,
            source_device_id=source_device,
            target_device_id=target_device,
            sync_rules=sync_rules,
        )

        self.current_engine = engine

        return engine

    # ========================================================
    # PLAN
    # ========================================================

    def analyze(
        self,
        source_device: str,
        target_device: str,
    ) -> SyncPlan:
        """
        Только анализ.

        Никаких изменений файлов не выполняется.
        """

        source_root, target_root = (
            self._validate_devices(
                source_device,
                target_device,
            )
        )

        engine = self._create_engine(

            source_root=source_root,

            target_root=target_root,

            source_device=source_device,

            target_device=target_device,
        )

        self._set_status(
            STATUS_ANALYZING
        )

        plan = engine.analyze()

        self.current_plan = plan

        return plan

    # ========================================================
    # SYNC
    # ========================================================

    def sync(
        self,
        source_device: str,
        target_device: str,
    ) -> ManagerResult:
        """
        Полная синхронизация.

        Workflow:

            START
              ↓
            ANALYZE
              ↓
            BACKUP
              ↓
            APPLY
              ↓
            VERIFY
              ↓
            COMPLETE
        """

        started_at = utc_now()

        session: Optional[
            SyncSession
        ] = None

        try:

            # ------------------------------------------------
            # VALIDATE
            # ------------------------------------------------

            (
                source_root,
                target_root,
            ) = self._validate_devices(
                source_device,
                target_device,
            )

            # ------------------------------------------------
            # CHECK ACTIVE SESSION
            # ------------------------------------------------

            active = (
                self.sync_state
                .get_active_session()
            )

            if active is not None:

                raise RuntimeError(

                    "В SyncState уже существует "
                    "активная sync-сессия."
                )

            # ------------------------------------------------
            # START
            # ------------------------------------------------

            session = self._start_session(
                source_device=source_device,
                target_device=target_device,
            )

            self._log(
                f"Synchronizing "
                f"{source_device} → "
                f"{target_device}"
            )

            # ------------------------------------------------
            # ENGINE
            # ------------------------------------------------

            engine = self._create_engine(

                source_root=source_root,

                target_root=target_root,

                source_device=source_device,

                target_device=target_device,
            )

            # ------------------------------------------------
            # ANALYZE
            # ------------------------------------------------

            self._set_status(
                STATUS_ANALYZING
            )

            plan = engine.analyze()

            self.current_plan = plan

            # ------------------------------------------------
            # UPDATE SESSION COUNTS
            # ------------------------------------------------

            added = 0
            modified = 0
            deleted = 0
            unchanged = 0
            conflicts = len(
                plan.conflicts
            )
            skipped = len(
                plan.skipped
            )

            for operation in (
                plan.operations
            ):

                change_type = (
                    operation.change_type
                )

                if change_type == "added":
                    added += 1

                elif change_type == "modified":
                    modified += 1

                elif change_type == "deleted":
                    deleted += 1

                elif change_type == "unchanged":
                    unchanged += 1

            self.sync_state.update_active_session(

                files_added=added,

                files_modified=modified,

                files_deleted=deleted,

                files_unchanged=unchanged,

                conflicts=conflicts,
            )

            self._save_state()

            # ------------------------------------------------
            # CONFLICT CHECK
            # ------------------------------------------------

            if conflicts > 0:

                self._set_status(
                    STATUS_CONFLICT
                )

                manager_result = (
                    ManagerResult(

                        session_id=(
                            session.session_id
                        ),

                        success=False,

                        status=(
                            STATUS_CONFLICT
                        ),

                        started_at=started_at,

                        completed_at=utc_now(),

                        source_device=(
                            source_device
                        ),

                        target_device=(
                            target_device
                        ),

                        files_added=added,

                        files_modified=modified,

                        files_deleted=deleted,

                        files_unchanged=unchanged,

                        files_skipped=skipped,

                        conflicts=conflicts,

                        errors=0,

                        operations=[
                            operation.__dict__.copy()
                            for operation
                            in plan.operations
                        ],

                        plan_id=plan.plan_id,

                        metadata={
                            "reason":
                            "Unresolved conflicts",
                        },
                    )
                )

                self.last_result = (
                    manager_result
                )

                self.sync_state.update_active_session(

                    conflicts=conflicts
                )

                self.sync_state.complete_session(
                    STATUS_CONFLICT
                )

                self._save_state()

                return manager_result

            # ------------------------------------------------
            # APPLY
            # ------------------------------------------------

            self._set_status(
                STATUS_APPLYING
            )

            result = engine.apply(
                plan
            )

            # ------------------------------------------------
            # ENGINE RESULT → STATE
            # ------------------------------------------------

            self._update_session_from_result(
                result
            )

            # ------------------------------------------------
            # ENGINE FAILED
            # ------------------------------------------------

            if result.status == STATUS_FAILED:

                self._set_status(
                    STATUS_FAILED
                )

                completed = (
                    self.sync_state
                    .complete_session(
                        STATUS_FAILED
                    )
                )

                self._save_state()

                manager_result = (
                    self._result_from_engine(
                        result=result,
                        source_device=source_device,
                        target_device=target_device,
                        session=completed,
                        plan=plan,
                    )
                )

                self.last_result = (
                    manager_result
                )

                return manager_result

            # ------------------------------------------------
            # ENGINE CONFLICT
            # ------------------------------------------------

            if result.status == STATUS_CONFLICT:

                self._set_status(
                    STATUS_CONFLICT
                )

                completed = (
                    self.sync_state
                    .complete_session(
                        STATUS_CONFLICT
                    )
                )

                self._save_state()

                manager_result = (
                    self._result_from_engine(
                        result=result,
                        source_device=source_device,
                        target_device=target_device,
                        session=completed,
                        plan=plan,
                    )
                )

                self.last_result = (
                    manager_result
                )

                return manager_result

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            if result.success:

                self._set_status(
                    STATUS_COMPLETED
                )

                # --------------------------------------------
                # Increase global sync version
                # --------------------------------------------

                new_version = (
                    self.sync_state
                    .increment_sync_version()
                )

                # --------------------------------------------
                # Update devices
                # --------------------------------------------

                try:

                    self.sync_state.update_device(

                        source_device,

                        last_sync_at=utc_now(),

                        sync_version=new_version,
                    )

                except Exception:
                    pass

                try:

                    self.sync_state.update_device(

                        target_device,

                        last_sync_at=utc_now(),

                        sync_version=new_version,

                        files_synced=(
                            result.files_added
                            + result.files_modified
                        ),
                    )

                except Exception:
                    pass

                self._save_state()

                # --------------------------------------------
                # Complete session
                # --------------------------------------------

                completed = (
                    self.sync_state
                    .complete_session(
                        STATUS_COMPLETED
                    )
                )

                self._save_state()

                manager_result = (
                    self._result_from_engine(
                        result=result,
                        source_device=source_device,
                        target_device=target_device,
                        session=completed,
                        plan=plan,
                    )
                )

                manager_result.metadata[
                    "sync_version"
                ] = new_version

                self.last_result = (
                    manager_result
                )

                self._log(
                    "Synchronization completed."
                )

                return manager_result

            # ------------------------------------------------
            # UNKNOWN RESULT
            # ------------------------------------------------

            raise RuntimeError(
                "SyncEngine вернул неизвестный "
                f"результат: {result.status}"
            )

        # ====================================================
        # ERROR HANDLING
        # ====================================================

        except Exception as exc:

            error_message = str(
                exc
            )

            self._log(
                f"Synchronization failed: "
                f"{error_message}"
            )

            self.status = (
                MANAGER_FAILED
            )

            # ------------------------------------------------
            # Active session exists?
            # ------------------------------------------------

            try:

                active = (
                    self.sync_state
                    .get_active_session()
                )

                if active is not None:

                    self.sync_state.cancel_session(
                        error_message
                    )

                else:

                    self.sync_state.set_status(
                        STATUS_FAILED
                    )

                self._save_state()

            except Exception as state_exc:

                self._log(
                    f"State update failed: "
                    f"{state_exc}"
                )

            # ------------------------------------------------
            # Result
            # ------------------------------------------------

            session_id = (
                session.session_id
                if session is not None
                else str(uuid.uuid4())
            )

            manager_result = (
                ManagerResult(

                    session_id=session_id,

                    success=False,

                    status=STATUS_FAILED,

                    started_at=started_at,

                    completed_at=utc_now(),

                    source_device=(
                        source_device
                    ),

                    target_device=(
                        target_device
                    ),

                    errors=1,

                    error_messages=[


error_message
                    ],

                    plan_id=(
                        self.current_plan.plan_id
                        if self.current_plan
                        else None
                    ),

                    metadata={
                        "exception": (
                            type(exc).__name__
                        )
                    },
                )
            )

            self.last_result = (
                manager_result
            )

            return manager_result

    # ========================================================
    # SYNC TO
    # ========================================================

    def sync_to(
        self,
        target_device: str,
        source_device: str = "PC",
    ) -> ManagerResult:
        """
        Синхронизация из source в target.

        Например:

            sync_to("USB")
        """

        return self.sync(
            source_device=source_device,
            target_device=target_device,
        )

    # ========================================================
    # SYNC FROM
    # ========================================================

    def sync_from(
        self,
        source_device: str,
        target_device: str = "PC",
    ) -> ManagerResult:
        """
        Синхронизация из source в target.

        Например:

            sync_from("USB")
        """

        return self.sync(
            source_device=source_device,
            target_device=target_device,
        )

    # ========================================================
    # PC → USB
    # ========================================================

    def sync_pc_to_usb(
        self,
        usb_device: str = "USB",
    ) -> ManagerResult:
        """
        Удобный метод PC → USB.
        """

        return self.sync(
            source_device="PC",
            target_device=usb_device,
        )

    # ========================================================
    # USB → PC
    # ========================================================

    def sync_usb_to_pc(
        self,
        usb_device: str = "USB",
    ) -> ManagerResult:
        """
        Удобный метод USB → PC.
        """

        return self.sync(
            source_device=usb_device,
            target_device="PC",
        )

    # ========================================================
    # RESULT CONVERSION
    # ========================================================

    def _result_from_engine(
        self,
        result: SyncResult,
        source_device: str,
        target_device: str,
        session: Optional[SyncSession],
        plan: Optional[SyncPlan],
    ) -> ManagerResult:
        """
        Преобразует SyncResult в ManagerResult.
        """

        manager_result = (
            ManagerResult(

                session_id=(
                    session.session_id
                    if session is not None
                    else result.session_id
                ),

                success=result.success,

                status=result.status,

                started_at=result.started_at,

                completed_at=result.completed_at,

                source_device=(
                    source_device
                ),

                target_device=(
                    target_device
                ),

                files_added=(
                    result.files_added
                ),

                files_modified=(
                    result.files_modified
                ),

                files_deleted=(
                    result.files_deleted
                ),

                files_unchanged=(
                    result.files_unchanged
                ),

                files_skipped=(
                    result.files_skipped
                ),

                conflicts=(
                    result.conflicts
                ),

                errors=(
                    result.errors
                ),

                error_messages=list(
                    result.error_messages
                ),

                operations=[
                    dict(operation)
                    for operation
                    in result.operations
                ],

                plan_id=(
                    plan.plan_id
                    if plan is not None
                    else None
                ),
            )
        )

        return manager_result

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(
        self,
    ) -> dict[str, Any]:
        """
        Возвращает полный статус Manager.
        """

        engine_status = None

        if self.current_engine is not None:

            try:

                engine_status = (
                    self.current_engine
                    .get_status()
                )

            except Exception as exc:

                engine_status = {
                    "error": str(exc)
                }

        state_status = None

        try:

            state_status = (
                self.sync_state
                .status()
            )

        except Exception as exc:

            state_status = {
                "error": str(exc)
            }

        return {

            "manager_version": (
                MANAGER_VERSION
            ),

            "status": self.status,

            "root_path": str(
                self.root_path
            ),

            "has_engine": (
                self.current_engine
                is not None
            ),

            "has_plan": (
                self.current_plan
                is not None
            ),

            "last_result": (
                self.last_result.to_dict()
                if self.last_result
                else None
            ),

            "engine": engine_status,

            "sync_state": state_status,
        }

    # ========================================================
    # LAST RESULT
    # ========================================================

    def get_last_result(
        self,
    ) -> Optional[ManagerResult]:
        """
        Возвращает последний результат.
        """

        return self.last_result

    # ========================================================
    # CURRENT PLAN
    # ========================================================

    def get_current_plan(
        self,
    ) -> Optional[SyncPlan]:
        """
        Возвращает текущий план.
        """

        return self.current_plan

    # ========================================================
    # EXPORT PLAN
    # ========================================================

    def export_plan(
        self,
    ) -> dict[str, Any]:
        """
        Экспорт текущего плана.
        """

        if self.current_engine is None:

            return {}

        return (
            self.current_engine
            .export_plan(
                self.current_plan
            )
        )

    # ========================================================
    # EXPORT RESULT
    # ========================================================

    def export_result(
        self,
    ) -> dict[str, Any]:
        """
        Экспорт последнего результата.
        """

        if self.last_result is None:

            return {}

        return (
            self.last_result
            .to_dict()
        )

    # ========================================================
    # HISTORY
    # ========================================================

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> list[SyncSession]:
        """
        Возвращает историю синхронизаций.
        """

        return (
            self.sync_state
            .get_history(
                limit
            )
        )

    # ========================================================
    # LAST SYNC
    # ========================================================

    def get_last_sync(
        self,
    ) -> Optional[SyncSession]:
        """
        Возвращает последнюю синхронизацию.
        """

        return (
            self.sync_state
            .get_last_sync()
        )

    # ========================================================
    # CANCEL
    # ========================================================

    def cancel(
        self,
        reason: str = (
            "Синхронизация отменена."
        ),
    ) -> bool:
        """
        Отменяет активную сессию.

        Важно:
            Engine не поддерживает отдельную
            операцию cancellation, поэтому здесь
            отменяется состояние Manager/State.
        """

        active = (
            self.sync_state
            .get_active_session()
        )

        if active is None:

            return False

        try:

            self.sync_state.cancel_session(
                reason
            )

            self.status = (
                MANAGER_FAILED
            )

            self._save_state()

            self._log(
                f"Session cancelled: "
                f"{active.session_id}"
            )

            return True

        except Exception as exc:

            self._log(
                f"Cancel failed: {exc}"
            )

            return False

    # ========================================================
    # DEVICE REGISTRATION
    # ========================================================

    def register_device_in_state(
        self,
        device_id: str,
        device_type: str,
        name: str = "",
    ) -> None:
        """
        Регистрирует устройство в SyncState.

        DeviceManager при этом остаётся
        главным источником информации
        об устройстве.
        """

        existing = (
            self.sync_state
            .get_device(
                device_id
            )
        )

        if existing is None:

            self.sync_state.register_device(

                device_id=device_id,

                device_type=device_type,

                name=name,
            )

        else:

            self.sync_state.update_device(

                device_id,

                device_type=device_type,

                name=name,

                active=True,
            )

        self._save_state()

    # ========================================================
    # VALIDATE STATE
    # ========================================================

    def validate_state(
        self,
    ) -> tuple[bool, list[str]]:
        """
        Проверяет SyncState.
        """

        return (
            self.sync_state
            .validate()
        )

    # ========================================================
    # RESET RUNTIME
    # ========================================================

    def reset_runtime(
        self,
    ) -> None:
        """
        Сбрасывает только runtime-ссылки Manager.

        Файлы и SyncState не удаляются.
        """

        self.status = (
            MANAGER_IDLE
        )

        self.current_engine = None

        self.current_plan = None

        self.last_result = None

    # ========================================================
    # SELF TEST
    # ========================================================

    @staticmethod
    def self_test() -> bool:
        """
        Автономный тест SyncManager.

        Тест НЕ должен изменять реальные файлы JARVIS.
        """

        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:

            root = Path(
                temp_dir
            )

            # ------------------------------------------------
            # Create fake devices
            # ------------------------------------------------

            pc_root = (
                root / "PC"
            )

            usb_root = (
                root / "USB"
            )

            pc_root.mkdir(
                parents=True
            )

            usb_root.mkdir(
                parents=True
            )

            (
                pc_root / "CONFIG"
            ).mkdir()

            (
                usb_root / "CONFIG"
            ).mkdir()

            # ------------------------------------------------
            # Source file
            # ------------------------------------------------

            source_file = (
                pc_root
                / "CONFIG"
                / "settings.json"
            )

            source_file.write_text(
                '{"manager_test": 123}',
                encoding="utf-8",
            )

            # ------------------------------------------------
            # Fake DeviceManager
            # ------------------------------------------------

            class FakeDeviceManager:

                def __init__(self):

                    self.devices = {

                        "PC": {
                            "device_id": "PC",
                            "device_type": "PC",
                            "name": "Test PC",
                            "root_path": str(
                                pc_root
                            ),
                        },

                        "USB": {
                            "device_id": "USB",
                            "device_type": "USB",
                            "name": "Test USB",
                            "root_path": str(
                                usb_root
                            ),
                        },
                    }

                def get_device(
                    self,
                    device_id,
                ):

                    return self.devices.get(
                        device_id
                    )

            # ------------------------------------------------
            # State
            # ------------------------------------------------

            state = SyncState(

                state_path=(
                    root
                    / "SYNC"
                    / "sync_state.json"
                )
            )

            # ------------------------------------------------
            # Manager
            # ------------------------------------------------

            manager = SyncManager(

                root_path=root,
                device_manager=(
                    FakeDeviceManager()
                ),

                sync_state=state,
            )

            # ------------------------------------------------
            # Register devices
            # ------------------------------------------------

            manager.register_device_in_state(

                "PC",

                "PC",

                "Test PC",
            )

            manager.register_device_in_state(

                "USB",

                "USB",

                "Test USB",
            )

            # ------------------------------------------------
            # SYNC
            # ------------------------------------------------

            result = manager.sync(

                source_device="PC",

                target_device="USB",
            )

            # ------------------------------------------------
            # Check result
            # ------------------------------------------------

            if not result.success:

                print(
                    "[SelfTest] FAIL: "
                    f"{result.error_messages}"
                )

                return False

            if (
                result.status
                != STATUS_COMPLETED
            ):

                print(
                    "[SelfTest] FAIL: "
                    f"wrong status: "
                    f"{result.status}"
                )

                return False

            # ------------------------------------------------
            # Target file
            # ------------------------------------------------

            target_file = (
                usb_root
                / "CONFIG"
                / "settings.json"
            )

            if not target_file.exists():

                print(
                    "[SelfTest] FAIL: "
                    "target file missing"
                )

                return False

            content = (
                target_file.read_text(
                    encoding="utf-8"
                )
            )

            if content != (
                '{"manager_test": 123}'
            ):

                print(
                    "[SelfTest] FAIL: "
                    "target content mismatch"
                )

                return False

            # ------------------------------------------------
            # Last sync
            # ------------------------------------------------

            last_sync = (
                manager.get_last_sync()
            )

            if last_sync is None:

                print(
                    "[SelfTest] FAIL: "
                    "last sync missing"
                )

                return False

            if (
                last_sync.status
                != STATUS_COMPLETED
            ):

                print(
                    "[SelfTest] FAIL: "
                    "last sync status mismatch"
                )

                return False

            # ------------------------------------------------
            # History
            # ------------------------------------------------

            history = (
                manager.get_history()
            )

            if len(history) != 1:

                print(
                    "[SelfTest] FAIL: "
                    "history count mismatch"
                )

                return False

            # ------------------------------------------------
            # State validation
            # ------------------------------------------------

            valid, errors = (
                manager.validate_state()
            )

            if not valid:

                print(
                    "[SelfTest] FAIL: "
                    f"state invalid: {errors}"
                )

                return False

            # ------------------------------------------------
            # Status
            # ------------------------------------------------

            status = (
                manager.get_status()
            )

            if status["status"] != (
                STATUS_COMPLETED
            ):

                print(
                    "[SelfTest] FAIL: "
                    "manager status mismatch"
                )

                return False

            # ------------------------------------------------
            # Export
            # ------------------------------------------------

            exported = (
                manager.export_result()
            )

            if not isinstance(
                exported,
                dict,
            ):

                print(
                    "[SelfTest] FAIL: "
                    "result export"
                )

                return False

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            print(
                "[+] Self-test: OK"
            )

            return True


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    if SyncManager.self_test():

        print(
            "[+] SyncManager: OK"
        )

    else:

        print(
            "[-] SyncManager: FAILED"
        )