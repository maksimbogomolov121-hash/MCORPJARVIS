"""
JARVIS V11
SYNC / CHANGE DETECTOR
Version: 1.0

Назначение:
    Определение изменений между двумя состояниями файлов.

Модуль отвечает за:
    - поиск добавленных файлов;
    - поиск изменённых файлов;
    - поиск удалённых файлов;
    - поиск неизменённых файлов;
    - сравнение hash;
    - сравнение размеров;
    - сравнение времени изменения;
    - создание структурированного отчёта.

Модуль НЕ выполняет:
    - копирование файлов;
    - удаление файлов;
    - синхронизацию;
    - создание backup;
    - разрешение конфликтов.

Он только отвечает на вопрос:

    "Что изменилось?"
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONSTANTS
# ============================================================

DETECTOR_VERSION = 1

CHANGE_ADDED = "added"
CHANGE_MODIFIED = "modified"
CHANGE_DELETED = "deleted"
CHANGE_UNCHANGED = "unchanged"

CHANGE_TYPES = {
    CHANGE_ADDED,
    CHANGE_MODIFIED,
    CHANGE_DELETED,
    CHANGE_UNCHANGED,
}


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class FileState:
    """
    Состояние одного файла.
    """

    path: str
    hash_value: str
    size: int
    modified_at: float
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "FileState":

        return cls(
            path=str(
                data["path"]
            ),
            hash_value=str(
                data.get(
                    "hash_value",
                    "",
                )
            ),
            size=int(
                data.get(
                    "size",
                    0,
                )
            ),
            modified_at=float(
                data.get(
                    "modified_at",
                    0,
                )
            ),
            version=int(
                data.get(
                    "version",
                    1,
                )
            ),
        )


@dataclass
class ChangeRecord:
    """
    Информация об изменении одного файла.
    """

    path: str
    change_type: str

    old_hash: Optional[str] = None
    new_hash: Optional[str] = None

    old_size: Optional[int] = None
    new_size: Optional[int] = None

    old_modified_at: Optional[float] = None
    new_modified_at: Optional[float] = None

    old_version: Optional[int] = None
    new_version: Optional[int] = None

    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChangeSummary:
    """
    Сводка изменений.
    """

    added: int = 0
    modified: int = 0
    deleted: int = 0
    unchanged: int = 0

    @property
    def total(self) -> int:
        return (
            self.added
            + self.modified
            + self.deleted
            + self.unchanged
        )

    @property
    def changed(self) -> int:
        return (
            self.added
            + self.modified
            + self.deleted
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "added": self.added,
            "modified": self.modified,
            "deleted": self.deleted,
            "unchanged": self.unchanged,
            "total": self.total,
            "changed": self.changed,
        }


# ============================================================
# CHANGE DETECTOR
# ============================================================

class ChangeDetector:
    """
    Определяет различия между двумя наборами файлов.

    old_state:
        Предыдущее известное состояние.

    new_state:
        Текущее состояние.

    Формат:

        {
            "CONFIG/test.json": {

Максим (09:16):
"path": "CONFIG/test.json",
                "hash_value": "...",
                "size": 100,
                "modified_at": 1234567890,
                "version": 1
            }
        }
    """

    def __init__(
        self,
        old_state: Optional[
            dict[str, Any]
        ] = None,
        new_state: Optional[
            dict[str, Any]
        ] = None,
    ):

        self.old_state: dict[
            str,
            FileState,
        ] = {}

        self.new_state: dict[
            str,
            FileState,
        ] = {}

        self.changes: list[
            ChangeRecord
        ] = []

        if old_state is not None:
            self.set_old_state(
                old_state
            )

        if new_state is not None:
            self.set_new_state(
                new_state
            )

    # ========================================================
    # LOGGING
    # ========================================================

    def _log(
        self,
        message: str,
    ) -> None:

        print(
            f"[ChangeDetector] {message}"
        )

    # ========================================================
    # STATE NORMALIZATION
    # ========================================================

    @staticmethod
    def _normalize_state(
        state: dict[str, Any],
    ) -> dict[str, FileState]:
        """
        Преобразует разные допустимые форматы
        состояния в единый формат.

        Поддерживается:

            {
                "file.txt": {
                    ...
                }
            }

        и manifest-подобный формат:

            {
                "files": {
                    "file.txt": {
                        ...
                    }
                }
            }
        """

        if not isinstance(
            state,
            dict,
        ):
            raise ValueError(
                "Состояние должно быть словарём."
            )

        if "files" in state:

            files = state[
                "files"
            ]

            if not isinstance(
                files,
                dict,
            ):
                raise ValueError(
                    "Поле files должно быть словарём."
                )

        else:
            files = state

        result: dict[
            str,
            FileState,
        ] = {}

        for path, data in files.items():

            if isinstance(
                data,
                FileState,
            ):

                file_state = data

            elif isinstance(
                data,
                dict,
            ):

                file_state = (
                    FileState.from_dict(
                        data
                    )
                )

            else:

                raise ValueError(
                    f"Некорректное состояние файла: {path}"
                )

            normalized_path = (
                Path(path).as_posix()
            )

            file_state.path = (
                normalized_path
            )

            result[
                normalized_path
            ] = file_state

        return result

    # ========================================================
    # SET STATES
    # ========================================================

    def set_old_state(
        self,
        state: dict[str, Any],
    ) -> None:

        self.old_state = (
            self._normalize_state(
                state
            )
        )

    def set_new_state(
        self,
        state: dict[str, Any],
    ) -> None:

        self.new_state = (
            self._normalize_state(
                state
            )
        )

    # ========================================================
    # GET STATES
    # ========================================================

    def get_old_state(
        self,
    ) -> dict[str, FileState]:

        return dict(
            self.old_state
        )


    def get_new_state(
        self,
    ) -> dict[str, FileState]:

        return dict(
            self.new_state
        )

    # ========================================================
    # COMPARE HASH
    # ========================================================

    @staticmethod
    def _hash_changed(
        old: FileState,
        new: FileState,
    ) -> bool:

        if not old.hash_value:
            return False

        if not new.hash_value:
            return False

        return (
            old.hash_value
            != new.hash_value
        )

    # ========================================================
    # COMPARE SIZE
    # ========================================================

    @staticmethod
    def _size_changed(
        old: FileState,
        new: FileState,
    ) -> bool:

        return (
            old.size
            != new.size
        )

    # ========================================================
    # COMPARE TIME
    # ========================================================

    @staticmethod
    def _time_changed(
        old: FileState,
        new: FileState,
    ) -> bool:

        return (
            old.modified_at
            != new.modified_at
        )

    # ========================================================
    # COMPARE VERSION
    # ========================================================

    @staticmethod
    def _version_changed(
        old: FileState,
        new: FileState,
    ) -> bool:

        return (
            old.version
            != new.version
        )

    # ========================================================
    # DETECT ONE FILE
    # ========================================================

    def detect_file(
        self,
        path: str,
        old: Optional[FileState],
        new: Optional[FileState],
    ) -> ChangeRecord:
        """
        Определяет состояние одного файла.
        """

        normalized_path = (
            Path(path).as_posix()
        )

        # ----------------------------------------------------
        # ADDED
        # ----------------------------------------------------

        if old is None and new is not None:

            return ChangeRecord(
                path=normalized_path,
                change_type=CHANGE_ADDED,

                old_hash=None,
                new_hash=new.hash_value,

                old_size=None,
                new_size=new.size,

                old_modified_at=None,
                new_modified_at=new.modified_at,

                old_version=None,
                new_version=new.version,

                reason="Файл отсутствовал в старом состоянии.",
            )

        # ----------------------------------------------------
        # DELETED
        # ----------------------------------------------------

        if old is not None and new is None:

            return ChangeRecord(
                path=normalized_path,
                change_type=CHANGE_DELETED,

                old_hash=old.hash_value,
                new_hash=None,

                old_size=old.size,
                new_size=None,

                old_modified_at=old.modified_at,
                new_modified_at=None,

                old_version=old.version,
                new_version=None,

                reason="Файл отсутствует в новом состоянии.",
            )

        # ----------------------------------------------------
        # BOTH MISSING
        # ----------------------------------------------------

        if old is None and new is None:

            raise ValueError(
                "old и new не могут одновременно быть None."
            )

        assert old is not None
        assert new is not None

        # ----------------------------------------------------
        # HASH COMPARISON
        # ----------------------------------------------------

        hash_changed = (
            self._hash_changed(
                old,
                new,
)
        )

        # ----------------------------------------------------
        # SIZE COMPARISON
        # ----------------------------------------------------

        size_changed = (
            self._size_changed(
                old,
                new,
            )
        )

        # ----------------------------------------------------
        # TIME COMPARISON
        # ----------------------------------------------------

        time_changed = (
            self._time_changed(
                old,
                new,
            )
        )

        # ----------------------------------------------------
        # VERSION COMPARISON
        # ----------------------------------------------------

        version_changed = (
            self._version_changed(
                old,
                new,
            )
        )

        # ----------------------------------------------------
        # MODIFIED
        # ----------------------------------------------------

        if hash_changed:

            return ChangeRecord(
                path=normalized_path,
                change_type=CHANGE_MODIFIED,

                old_hash=old.hash_value,
                new_hash=new.hash_value,

                old_size=old.size,
                new_size=new.size,

                old_modified_at=old.modified_at,
                new_modified_at=new.modified_at,

                old_version=old.version,
                new_version=new.version,

                reason="SHA-256 хеш файла изменился.",
            )

        # ----------------------------------------------------
        # MODIFIED WITHOUT HASH
        # ----------------------------------------------------

        if (
            size_changed
            or time_changed
            or version_changed
        ):

            reasons: list[str] = []

            if size_changed:
                reasons.append(
                    "размер"
                )

            if time_changed:
                reasons.append(
                    "время изменения"
                )

            if version_changed:
                reasons.append(
                    "версия"
                )

            return ChangeRecord(
                path=normalized_path,
                change_type=CHANGE_MODIFIED,

                old_hash=old.hash_value,
                new_hash=new.hash_value,

                old_size=old.size,
                new_size=new.size,

                old_modified_at=old.modified_at,
                new_modified_at=new.modified_at,

                old_version=old.version,
                new_version=new.version,

                reason=(
                    "Изменилось: "
                    + ", ".join(reasons)
                    + "."
                ),
            )

        # ----------------------------------------------------
        # UNCHANGED
        # ----------------------------------------------------

        return ChangeRecord(
            path=normalized_path,
            change_type=CHANGE_UNCHANGED,

            old_hash=old.hash_value,
            new_hash=new.hash_value,

            old_size=old.size,
            new_size=new.size,

            old_modified_at=old.modified_at,
            new_modified_at=new.modified_at,

            old_version=old.version,
            new_version=new.version,

            reason="Состояние файла не изменилось.",
        )

    # ========================================================
    # DETECT ALL
    # ========================================================

    def detect(
        self,
    ) -> list[ChangeRecord]:
        """
        Анализирует все файлы.
        """

        self.changes = []

        all_paths = (
            set(self.old_state.keys())
            | set(self.new_state.keys())
        )

        for path in sorted(
            all_paths
        ):

            old = self.old_state.get(
                path
            )

            new = self.new_state.get(

path
            )

            record = self.detect_file(
                path,
                old,
                new,
            )

            self.changes.append(
                record
            )

        return list(
            self.changes
        )

    # ========================================================
    # GET CHANGES
    # ========================================================

    def get_changes(
        self,
        change_type: Optional[str] = None,
    ) -> list[ChangeRecord]:
        """
        Возвращает найденные изменения.

        Если change_type указан:
            возвращаются только записи этого типа.
        """

        if not self.changes:
            self.detect()

        if change_type is None:
            return list(
                self.changes
            )

        if change_type not in CHANGE_TYPES:
            raise ValueError(
                f"Неизвестный тип изменения: {change_type}"
            )

        return [
            change
            for change in self.changes
            if change.change_type
            == change_type
        ]

    # ========================================================
    # SUMMARY
    # ========================================================

    def summary(
        self,
    ) -> ChangeSummary:

        if not self.changes:
            self.detect()

        summary = ChangeSummary()

        for change in self.changes:

            if (
                change.change_type
                == CHANGE_ADDED
            ):
                summary.added += 1

            elif (
                change.change_type
                == CHANGE_MODIFIED
            ):
                summary.modified += 1

            elif (
                change.change_type
                == CHANGE_DELETED
            ):
                summary.deleted += 1

            elif (
                change.change_type
                == CHANGE_UNCHANGED
            ):
                summary.unchanged += 1

        return summary

    # ========================================================
    # HAS CHANGES
    # ========================================================

    def has_changes(
        self,
    ) -> bool:

        return (
            self.summary().changed
            > 0
        )

    # ========================================================
    # GET CHANGED FILES
    # ========================================================

    def get_changed_files(
        self,
    ) -> list[str]:

        return [
            change.path
            for change in self.get_changes()
            if change.change_type
            != CHANGE_UNCHANGED
        ]

    # ========================================================
    # GET UNCHANGED FILES
    # ========================================================

    def get_unchanged_files(
        self,
    ) -> list[str]:

        return [
            change.path
            for change in self.get_changes(
                CHANGE_UNCHANGED
            )
        ]

    # ========================================================
    # EXPORT
    # ========================================================

    def export(
        self,
    ) -> dict[str, Any]:

        if not self.changes:
            self.detect()

        return {
            "detector_version": DETECTOR_VERSION,

            "summary": (
                self.summary().to_dict()
            ),

            "changes": [
                change.to_dict()
                for change in self.changes
            ],
        }

    # ========================================================
    # SAVE REPORT
    # ========================================================

    def save_report(
        self,
        path: Path | str,
    ) -> Path:
        """
        Сохраняет отчёт анализа.
        """

        output_path = Path(
            path
        ).resolve()

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output_path.open(
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.export(),
                file,
                ensure_ascii=False,
                indent=4,
            )

        return output_path

    # ========================================================
    # STATUS
    # ========================================================

    def status(
        self,
    ) -> dict[str, Any]:

        summary = (
            self.summary()
        )

        return {
            "detector_version": (
                DETECTOR_VERSION
            ),

            "old_files": len(
                self.old_state
            ),

            "new_files": len(
                self.new_state
            ),

            "changes_detected": (
                summary.changed
            ),

            "summary": (
                summary.to_dict()
            ),
        }

    # ========================================================
    # SELF TEST
    # ========================================================

    @staticmethod
    def self_test() -> bool:
        """
        Полный автономный тест.
        """

        test_dir = Path(
            tempfile.mkdtemp(
                prefix="jarvis_change_detector_test_"
            )
        )

        report_path = (
            test_dir
            / "change_report.json"
        )

        try:

            # ------------------------------------------------
            # OLD STATE
            # ------------------------------------------------

            old_state = {
                "CONFIG/settings.json": {
                    "path": "CONFIG/settings.json",
                    "hash_value": "a" * 64,
                    "size": 100,
                    "modified_at": 1000.0,
                    "version": 1,
                },

                "DATA/old.json": {
                    "path": "DATA/old.json",
                    "hash_value": "b" * 64,
                    "size": 200,
                    "modified_at": 2000.0,
                    "version": 1,
                },

                "DATA/same.json": {
                    "path": "DATA/same.json",
                    "hash_value": "c" * 64,
                    "size": 300,
                    "modified_at": 3000.0,
                    "version": 1,
                },

                "DATA/hash_change.json": {
                    "path": "DATA/hash_change.json",
                    "hash_value": "d" * 64,
                    "size": 400,
                    "modified_at": 4000.0,
                    "version": 1,
                },
            }

            # ------------------------------------------------
            # NEW STATE
            # ------------------------------------------------

            new_state = {
                # Same file
                "CONFIG/settings.json": {
                    "path": "CONFIG/settings.json",
                    "hash_value": "a" * 64,
                    "size": 100,
                    "modified_at": 1000.0,
                    "version": 1,
                },

                # Deleted file:
                # DATA/old.json
                # intentionally absent

                # Unchanged
                "DATA/same.json": {
                    "path": "DATA/same.json",
                    "hash_value": "c" * 64,
                    "size": 300,
                    "modified_at": 3000.0,
                    "version": 1,
                },

                # Hash changed
                "DATA/hash_change.json": {
                    "path": "DATA/hash_change.json",
                    "hash_value": "e" * 64,
                    "size": 400,
                    "modified_at": 4000.0,
                    "version": 2,
                },

                # Added file
                "DATA/new.json": {
                    "path": "DATA/new.json",
                    "hash_value": "f" * 64,
                    "size": 500,
                    "modified_at": 5000.0,
                    "version": 1,
                },
            }

            # ------------------------------------------------
            # CREATE DETECTOR
            # ------------------------------------------------

            detector = ChangeDetector(
                old_state=old_state,
                new_state=new_state,
            )

            # ------------------------------------------------
            # DETECT
            # ------------------------------------------------

            changes = detector.detect()

            assert len(
                changes
            ) == 5

            # ------------------------------------------------
            # SUMMARY
            # ------------------------------------------------

            summary = (
                detector.summary()
            )

            assert summary.added == 1
            assert summary.modified == 1
            assert summary.deleted == 1
            assert summary.unchanged == 2

            assert summary.total == 5
            assert summary.changed == 3

            # ------------------------------------------------
            # ADDED
            # ------------------------------------------------

            added = detector.get_changes(
                CHANGE_ADDED
            )

            assert len(
                added
            ) == 1

            assert (
                added[0].path
                == "DATA/new.json"
            )

            # ------------------------------------------------
            # MODIFIED
            # ------------------------------------------------

            modified = detector.get_changes(
                CHANGE_MODIFIED
            )

            assert len(
                modified
            ) == 1

            assert (
                modified[0].path
                == "DATA/hash_change.json"
            )

            # ------------------------------------------------
            # DELETED
            # ------------------------------------------------

            deleted = detector.get_changes(
                CHANGE_DELETED
            )

            assert len(
                deleted
            ) == 1

            assert (
                deleted[0].path
                == "DATA/old.json"
            )

            # ------------------------------------------------
            # UNCHANGED
            # ------------------------------------------------

            unchanged = detector.get_changes(
                CHANGE_UNCHANGED
            )

            assert len(
                unchanged
            ) == 2

            # ------------------------------------------------
            # HAS CHANGES
            # ------------------------------------------------

            assert (
                detector.has_changes()
            )

            # ------------------------------------------------
            # CHANGED FILES
            # ------------------------------------------------

            changed_files = (
                detector.get_changed_files()
            )

            assert (
                "DATA/new.json"
                in changed_files
            )

            assert (
                "DATA/hash_change.json"
                in changed_files
            )

            assert (
                "DATA/old.json"
                in changed_files
            )

            # ------------------------------------------------
            # UNCHANGED FILES
            # ------------------------------------------------

            unchanged_files = (
                detector.get_unchanged_files()
            )

            assert (
                "CONFIG/settings.json"
                in unchanged_files
            )

            assert (
                "DATA/same.json"
                in unchanged_files
            )


            # ------------------------------------------------
            # EXPORT
            # ------------------------------------------------

            exported = (
                detector.export()
            )

            assert (
                exported[
                    "detector_version"
                ]
                == DETECTOR_VERSION
            )

            assert (
                exported[
                    "summary"
                ]["changed"]
                == 3
            )

            assert (
                len(
                    exported["changes"]
                )
                == 5
            )

            # ------------------------------------------------
            # SAVE REPORT
            # ------------------------------------------------

            saved = (
                detector.save_report(
                    report_path
                )
            )

            assert saved.exists()

            # ------------------------------------------------
            # READ REPORT
            # ------------------------------------------------

            with report_path.open(
                "r",
                encoding="utf-8",
            ) as file:

                loaded = json.load(
                    file
                )

            assert (
                loaded[
                    "summary"
                ]["added"]
                == 1
            )

            assert (
                loaded[
                    "summary"
                ]["modified"]
                == 1
            )

            assert (
                loaded[
                    "summary"
                ]["deleted"]
                == 1
            )

            # ------------------------------------------------
            # STATUS
            # ------------------------------------------------

            status = detector.status()

            assert (
                status[
                    "old_files"
                ]
                == 4
            )

            assert (
                status[
                    "new_files"
                ]
                == 4
            )

            assert (
                status[
                    "changes_detected"
                ]
                == 3
            )

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

                if report_path.exists():
                    report_path.unlink()

                test_dir.rmdir()

            except Exception:
                pass

    def compare(
            self,
            old_state: dict[str, Any],
            new_state: dict[str, Any],
    ) -> list[ChangeRecord]:
        """
        Сравнивает два состояния файлов.

        Совместимый интерфейс для SyncEngine.
        """

        self.set_old_state(old_state)
        self.set_new_state(new_state)

        return self.detect()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ChangeDetector.self_test()