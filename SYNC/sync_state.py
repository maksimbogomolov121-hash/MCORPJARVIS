"""
JARVIS V11
SYNC / SYNC STATE
Version: 1.0

Назначение:
    Хранение состояния последней синхронизации между устройствами.

Модуль отвечает за:
    - состояние синхронизации;
    - общую sync-версию;
    - устройства-участники;
    - время последней синхронизации;
    - количество изменений;
    - конфликты;
    - ошибки;
    - историю синхронизаций.

Модуль НЕ выполняет саму синхронизацию.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONSTANTS
# ============================================================

STATE_VERSION = 1
STATE_FILENAME = "sync_state.json"

STATUS_IDLE = "idle"
STATUS_ANALYZING = "analyzing"
STATUS_BACKING_UP = "backing_up"
STATUS_APPLYING = "applying"
STATUS_VERIFYING = "verifying"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CONFLICT = "conflict"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """
    Возвращает текущее UTC-время в ISO 8601.
    """
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# DATA CLASS
# ============================================================

@dataclass
class SyncSession:
    """
    Информация об одной синхронизации.
    """

    session_id: str
    source_device: str
    target_device: str
    started_at: str
    completed_at: Optional[str]
    status: str

    files_added: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    files_unchanged: int = 0

    conflicts: int = 0
    errors: int = 0

    sync_version_before: int = 0
    sync_version_after: int = 0

    error_messages: list[str] | None = None

    def __post_init__(self) -> None:
        if self.error_messages is None:
            self.error_messages = []

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SyncSession":
        return cls(
            session_id=str(data["session_id"]),
            source_device=str(data["source_device"]),
            target_device=str(data["target_device"]),
            started_at=str(data["started_at"]),
            completed_at=data.get("completed_at"),
            status=str(data.get("status", STATUS_IDLE)),

            files_added=int(data.get("files_added", 0)),
            files_modified=int(
                data.get("files_modified", 0)
            ),
            files_deleted=int(
                data.get("files_deleted", 0)
            ),
            files_unchanged=int(
                data.get("files_unchanged", 0)
            ),

            conflicts=int(
                data.get("conflicts", 0)
            ),
            errors=int(
                data.get("errors", 0)
            ),

            sync_version_before=int(
                data.get(
                    "sync_version_before",
                    0,
                )
            ),
            sync_version_after=int(
                data.get(
                    "sync_version_after",
                    0,
                )
            ),

            error_messages=list(
                data.get(
                    "error_messages",
                    [],
                )
            ),
        )


# ============================================================
# SYNC STATE
# ============================================================

class SyncState:
    """
    Менеджер состояния синхронизации.

    Хранит информацию о последнем состоянии
    и истории синхронизаций.
    """

    def __init__(
        self,
        state_path: Optional[Path | str] = None,
    ):
        if state_path is None:
            state_path = (


     Path(__file__).resolve().parent
                / STATE_FILENAME
            )

        self.state_path = Path(
            state_path
        ).resolve()

        self.state: dict[str, Any] = {}

        if self.state_path.exists():
            self.load()
        else:
            self.create_empty()

    # ========================================================
    # LOG
    # ========================================================

    def _log(
        self,
        message: str,
    ) -> None:
        print(
            f"[SyncState] {message}"
        )

    # ========================================================
    # CREATE
    # ========================================================

    def create_empty(
        self,
    ) -> dict[str, Any]:
        """
        Создаёт новое пустое состояние.
        """

        now = utc_now()

        self.state = {
            "state_version": STATE_VERSION,

            "created_at": now,
            "updated_at": now,

            "last_sync": None,

            "sync_version": 0,

            "current_status": STATUS_IDLE,

            "active_session": None,

            "devices": {},

            "history": [],
        }

        return self.state

    # ========================================================
    # STRUCTURE
    # ========================================================

    def _ensure_structure(
        self,
    ) -> None:
        """
        Гарантирует наличие всех обязательных полей.
        """

        if "state_version" not in self.state:
            self.state[
                "state_version"
            ] = STATE_VERSION

        if "created_at" not in self.state:
            self.state[
                "created_at"
            ] = utc_now()

        if "updated_at" not in self.state:
            self.state[
                "updated_at"
            ] = utc_now()

        if "last_sync" not in self.state:
            self.state[
                "last_sync"
            ] = None

        if "sync_version" not in self.state:
            self.state[
                "sync_version"
            ] = 0

        if "current_status" not in self.state:
            self.state[
                "current_status"
            ] = STATUS_IDLE

        if "active_session" not in self.state:
            self.state[
                "active_session"
            ] = None

        if "devices" not in self.state:
            self.state[
                "devices"
            ] = {}

        if "history" not in self.state:
            self.state[
                "history"
            ] = []

        if not isinstance(
            self.state["devices"],
            dict,
        ):
            raise ValueError(
                "devices должен быть объектом."
            )

        if not isinstance(
            self.state["history"],
            list,
        ):
            raise ValueError(
                "history должен быть списком."
            )

    # ========================================================
    # LOAD
    # ========================================================

    def load(
        self,
    ) -> dict[str, Any]:
        """
        Загружает состояние из JSON.
        """

        if not self.state_path.exists():
            return self.create_empty()

        try:
            with self.state_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            if not isinstance(
                data,
                dict,
            ):
                raise ValueError(
                    "sync_state должен быть JSON-объектом."
                )

            self.state = data

            self._ensure_structure()

            return self.state

        except Exception as exc:
            raise RuntimeError(
                f"Не удалось загрузить sync_state: {exc}"
            ) from exc

    # ========================================================
    # SAVE
    # ========================================================

    def save(
        self,
    ) -> Path:
        """
        Безопасно сохраняет состояние.
        """

        self.state_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.state[
            "updated_at"
        ] = utc_now()

        fd, temp_name = tempfile.mkstemp(
            prefix=".sync_state_",
            suffix=".tmp",
            dir=str(
                self.state_path.parent
            ),
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    self.state,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

                file.flush()
                os.fsync(
                    file.fileno()
                )

            os.replace(
                temp_name,
                self.state_path,
            )

        except Exception:
            try:
                os.unlink(
                    temp_name
                )
            except OSError:
                pass

            raise

        return self.state_path

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(
        self,
    ) -> str:
        return str(
            self.state.get(
                "current_status",
                STATUS_IDLE,
            )
        )

    def set_status(
        self,
        status: str,
    ) -> None:
        """
        Устанавливает текущий статус.

        Разрешены только известные статусы.
        """

        allowed = {
            STATUS_IDLE,
            STATUS_ANALYZING,
            STATUS_BACKING_UP,
            STATUS_APPLYING,
            STATUS_VERIFYING,
            STATUS_COMPLETED,
            STATUS_FAILED,
            STATUS_CONFLICT,
        }

        if status not in allowed:
            raise ValueError(
                f"Неизвестный статус: {status}"
            )

        self.state[
            "current_status"
        ] = status

        self.state[
            "updated_at"
        ] = utc_now()

    # ========================================================
    # SYNC VERSION
    # ========================================================

    def get_sync_version(
        self,
    ) -> int:
        return int(
            self.state.get(
                "sync_version",
                0,
            )
        )

    def set_sync_version(
        self,
        version: int,
    ) -> None:
        if version < 0:
            raise ValueError(
                "sync_version не может быть отрицательной."
            )

        self.state[
            "sync_version"
        ] = int(version)

        self.state[
            "updated_at"
        ] = utc_now()

    def increment_sync_version(
        self,
    ) -> int:
        version = (
            self.get_sync_version()
            + 1
        )

        self.set_sync_version(
            version
        )

        return version

    # ========================================================
    # ACTIVE SESSION
    # ========================================================

    def start_session(
        self,
        session_id: str,
        source_device: str,
        target_device: str,
    ) -> SyncSession:
        """
        Создаёт активную sync-сессию.
        """

        if self.state[
            "active_session"
        ] is not None:
            raise RuntimeError(
                "Синхронизация уже выполняется."
            )

        session = SyncSession(
            session_id=session_id,
            source_device=source_device,
            target_device=target_device,
            started_at=utc_now(),
            completed_at=None,
            status=STATUS_ANALYZING,
            sync_version_before=(
                self.get_sync_version()
            ),
        )

        self.state[
            "active_session"
        ] = session.to_dict()

        self.set_status(
            STATUS_ANALYZING
        )

        return session

    def get_active_session(
        self,
    ) -> Optional[SyncSession]:
        """
        Возвращает активную сессию.
        """

        data = self.state.get(
            "active_session"
        )

        if data is None:
            return None

        return SyncSession.from_dict(
            data
        )

    def update_active_session(
        self,
        **updates: Any,
    ) -> Optional[SyncSession]:
        """
        Обновляет активную сессию.

        Пример:

            update_active_session(
                files_modified=3
            )
        """

        session = (
            self.get_active_session()
        )

        if session is None:
            return None

        for key, value in updates.items():

            if not hasattr(
                session,
                key,
            ):
                raise ValueError(
                    f"Неизвестное поле сессии: {key}"
                )

            setattr(
                session,
                key,
                value,
            )

        self.state[
            "active_session"
        ] = session.to_dict()

        self.state[
            "updated_at"
        ] = utc_now()

        return session

    # ========================================================
    # COMPLETE SESSION
    # ========================================================

    def complete_session(
        self,
        status: str = STATUS_COMPLETED,
    ) -> Optional[SyncSession]:
        """
        Завершает активную сессию.
        """

        session = (
            self.get_active_session()
        )

        if session is None:
            return None

        if status not in {
            STATUS_COMPLETED,
            STATUS_FAILED,
            STATUS_CONFLICT,
        }:
            raise ValueError(
                "Недопустимый финальный статус."
            )

        session.status = status
        session.completed_at = utc_now()

        if status == STATUS_COMPLETED:

            session.sync_version_after = (
                self.get_sync_version()
            )

        self.state[
            "last_sync"
        ] = session.to_dict()

        self.state[
            "history"
        ].append(
            session.to_dict()
        )

        self.state[
            "active_session"
        ] = None

        self.set_status(
            status
        )

        return session

    # ========================================================
    # CANCEL SESSION
    # ========================================================

    def cancel_session(
        self,
        reason: str = "Синхронизация отменена.",
    ) -> Optional[SyncSession]:
        """
        Завершает активную сессию как failed.
        """

        session = (
            self.get_active_session()
        )

        if session is None:
            return None

        session.errors += 1
        session.error_messages.append(
            reason
        )

        session.status = STATUS_FAILED
        session.completed_at = utc_now()

        self.state[
            "last_sync"
        ] = session.to_dict()

        self.state[
            "history"
        ].append(
            session.to_dict()
        )

        self.state[
            "active_session"
        ] = None

        self.set_status(
            STATUS_FAILED
        )

        return session

    # ========================================================
    # DEVICE STATE
    # ========================================================

    def register_device(
        self,
        device_id: str,
        device_type: str,
        name: str = "",
    ) -> None:
        """
        Добавляет устройство в состояние.
        """
        self.state[
            "devices"
        ][device_id] = {
            "device_id": device_id,
            "device_type": device_type,
            "name": name,
            "last_sync_at": None,
            "sync_version": 0,
            "files_synced": 0,
            "active": True,
        }

        self.state[
            "updated_at"
        ] = utc_now()

    def update_device(
        self,
        device_id: str,
        **updates: Any,
    ) -> bool:
        """
        Обновляет информацию об устройстве.
        """

        device = self.state[
            "devices"
        ].get(
            device_id
        )

        if device is None:
            return False

        device.update(
            updates
        )

        self.state[
            "updated_at"
        ] = utc_now()

        return True

    def get_device(
        self,
        device_id: str,
    ) -> Optional[dict[str, Any]]:
        device = self.state[
            "devices"
        ].get(
            device_id
        )

        if device is None:
            return None

        return dict(device)

    def list_devices(
        self,
    ) -> list[dict[str, Any]]:
        return [
            dict(device)
            for device in self.state[
                "devices"
            ].values()
        ]

    # ========================================================
    # HISTORY
    # ========================================================

    def get_history(
        self,
        limit: Optional[int] = None,
    ) -> list[SyncSession]:
        """
        Возвращает историю синхронизаций.

        limit:
            количество последних записей.
        """

        history = [
            SyncSession.from_dict(
                item
            )
            for item in self.state[
                "history"
            ]
        ]

        if limit is not None:

            if limit < 0:
                raise ValueError(
                    "limit не может быть отрицательным."
                )

            history = history[
                -limit:
            ]

        return history

    def clear_history(
        self,
    ) -> None:
        self.state[
            "history"
        ] = []

        self.state[
            "updated_at"
        ] = utc_now()

    # ========================================================
    # LAST SYNC
    # ========================================================

    def get_last_sync(
        self,
    ) -> Optional[SyncSession]:
        data = self.state.get(
            "last_sync"
        )

        if data is None:
            return None

        return SyncSession.from_dict(
            data
        )

    # ========================================================
    # EXPORT
    # ========================================================

    def export(
        self,
    ) -> dict[str, Any]:
        """
        Возвращает независимую копию состояния.
        """

        return json.loads(
            json.dumps(
                self.state,
                ensure_ascii=False,
            )
        )

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(
        self,
    ) -> tuple[bool, list[str]]:
        """
        Проверяет целостность sync_state.
        """

        errors: list[str] = []

        if not isinstance(
            self.state,
            dict,
        ):
            errors.append(
                "state должен быть объектом."
            )

            return False, errors

        required = [
            "state_version",
            "created_at",
            "updated_at",
            "last_sync",
            "sync_version",
            "current_status",
            "active_session",
            "devices",
            "history",
        ]

        for field in required:
            if field not in self.state:
                errors.append(


f"Отсутствует поле: {field}"
                )

        try:
            if int(
                self.state.get(
                    "sync_version",
                    0,
                )
            ) < 0:
                errors.append(
                    "sync_version не может быть отрицательной."
                )
        except (
            TypeError,
            ValueError,
        ):
            errors.append(
                "Некорректная sync_version."
            )

        allowed_statuses = {
            STATUS_IDLE,
            STATUS_ANALYZING,
            STATUS_BACKING_UP,
            STATUS_APPLYING,
            STATUS_VERIFYING,
            STATUS_COMPLETED,
            STATUS_FAILED,
            STATUS_CONFLICT,
        }

        if self.state.get(
            "current_status"
        ) not in allowed_statuses:
            errors.append(
                "Некорректный current_status."
            )

        if not isinstance(
            self.state.get(
                "devices"
            ),
            dict,
        ):
            errors.append(
                "devices должен быть объектом."
            )

        if not isinstance(
            self.state.get(
                "history"
            ),
            list,
        ):
            errors.append(
                "history должен быть списком."
            )

        active = self.state.get(
            "active_session"
        )

        if active is not None:

            if not isinstance(
                active,
                dict,
            ):
                errors.append(
                    "active_session должен быть объектом или null."
                )
            else:

                required_session_fields = [
                    "session_id",
                    "source_device",
                    "target_device",
                    "started_at",
                    "status",
                ]

                for field in required_session_fields:

                    if field not in active:
                        errors.append(
                            "active_session: "
                            f"отсутствует {field}"
                        )

        return (
            len(errors) == 0,
            errors,
        )

    # ========================================================
    # STATUS REPORT
    # ========================================================

    def status(
        self,
    ) -> dict[str, Any]:
        """
        Возвращает краткий статус.
        """

        valid, errors = self.validate()

        active = (
            self.get_active_session()
        )

        last_sync = (
            self.get_last_sync()
        )

        return {
            "state_path": str(
                self.state_path
            ),
            "exists": self.state_path.exists(),

            "state_version": self.state.get(
                "state_version"
            ),

            "sync_version": self.get_sync_version(),

            "current_status": self.get_status(),

            "active_session": (
                active.to_dict()
                if active
                else None
            ),

            "last_sync": (
                last_sync.to_dict()
                if last_sync
                else None
            ),

            "device_count": len(
                self.state[
                    "devices"
                ]
            ),

            "history_count": len(
                self.state[
                    "history"
                ]
            ),

            "valid": valid,
            "errors": errors,

            "created_at": self.state.get(
                "created_at"
            ),

            "updated_at": self.state.get(
                "updated_at"
            ),
        }

    # ========================================================
    # SELF TEST
    # ========================================================

    @staticmethod

    def self_test() -> bool:
        """
        Полный автономный тест SyncState.
        """

        test_dir = Path(
            tempfile.mkdtemp(
                prefix="jarvis_sync_state_test_"
            )
        )

        state_path = (
            test_dir
            / STATE_FILENAME
        )

        try:
            # --------------------------------------------
            # 1. CREATE
            # --------------------------------------------

            manager = SyncState(
                state_path=state_path
            )

            assert (
                manager.get_status()
                == STATUS_IDLE
            )

            assert (
                manager.get_sync_version()
                == 0
            )

            # --------------------------------------------
            # 2. DEVICES
            # --------------------------------------------

            manager.register_device(
                device_id="PC-001",
                device_type="PC",
                name="Test PC",
            )

            manager.register_device(
                device_id="USB-001",
                device_type="USB",
                name="Test USB",
            )

            assert (
                len(
                    manager.list_devices()
                )
                == 2
            )

            # --------------------------------------------
            # 3. UPDATE DEVICE
            # --------------------------------------------

            updated = manager.update_device(
                "USB-001",
                sync_version=5,
                files_synced=10,
            )

            assert updated

            usb = manager.get_device(
                "USB-001"
            )

            assert usb is not None
            assert usb[
                "sync_version"
            ] == 5
            assert usb[
                "files_synced"
            ] == 10

            # --------------------------------------------
            # 4. START SESSION
            # --------------------------------------------

            session = manager.start_session(
                session_id="TEST-SESSION-001",
                source_device="PC-001",
                target_device="USB-001",
            )

            assert (
                session.status
                == STATUS_ANALYZING
            )

            assert (
                manager.get_status()
                == STATUS_ANALYZING
            )

            assert (
                manager.get_active_session()
                is not None
            )

            # --------------------------------------------
            # 5. UPDATE SESSION
            # --------------------------------------------

            manager.update_active_session(
                files_added=2,
                files_modified=3,
                files_deleted=1,
                files_unchanged=10,
            )

            active = (
                manager.get_active_session()
            )

            assert active is not None

            assert (
                active.files_added == 2
            )

            assert (
                active.files_modified == 3
            )

            assert (
                active.files_deleted == 1
            )

            assert (
                active.files_unchanged == 10
            )

            # --------------------------------------------
            # 6. VERSION
            # --------------------------------------------

            version = (
                manager.increment_sync_version()
            )

            assert version == 1

            # --------------------------------------------
            # 7. COMPLETE
            # --------------------------------------------

            completed = (
                manager.complete_session()
            )

            assert completed is not None

            assert (
                completed.status


== STATUS_COMPLETED
            )

            assert (
                manager.get_active_session()
                is None
            )

            assert (
                manager.get_last_sync()
                is not None
            )

            assert (
                len(
                    manager.get_history()
                )
                == 1
            )

            # --------------------------------------------
            # 8. SAVE
            # --------------------------------------------

            saved = manager.save()

            assert saved.exists()

            # --------------------------------------------
            # 9. LOAD
            # --------------------------------------------

            manager2 = SyncState(
                state_path=state_path
            )

            assert (
                manager2.get_sync_version()
                == 1
            )

            assert (
                len(
                    manager2.list_devices()
                )
                == 2
            )

            assert (
                len(
                    manager2.get_history()
                )
                == 1
            )

            # --------------------------------------------
            # 10. VALIDATION
            # --------------------------------------------

            valid, errors = (
                manager2.validate()
            )

            assert valid
            assert errors == []

            # --------------------------------------------
            # 11. FAILED SESSION
            # --------------------------------------------

            manager2.start_session(
                session_id="TEST-SESSION-002",
                source_device="PC-001",
                target_device="USB-001",
            )

            failed = (
                manager2.cancel_session(
                    "Test failure."
                )
            )

            assert failed is not None

            assert (
                failed.status
                == STATUS_FAILED
            )

            assert (
                failed.errors == 1
            )

            assert (
                "Test failure."
                in failed.error_messages
            )

            assert (
                len(
                    manager2.get_history()
                )
                == 2
            )

            # --------------------------------------------
            # 12. EXPORT
            # --------------------------------------------

            exported = manager2.export()

            assert isinstance(
                exported,
                dict,
            )

            # --------------------------------------------
            # 13. STATUS
            # --------------------------------------------

            report = manager2.status()

            assert report[
                "valid"
            ]

            print(
                "[+] Self-test: OK"
            )

            return True

        except Exception as exc:

            print(
                f"[-] Self-test: FAIL: {exc}"
            )

            return False

        finally:

            try:

                for item in test_dir.iterdir():

                    if item.is_file():
                        item.unlink()

                test_dir.rmdir()

            except Exception:
                pass


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    SyncState.self_test()