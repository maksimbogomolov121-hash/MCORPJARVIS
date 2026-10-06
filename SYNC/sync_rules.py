"""
JARVIS V11
SYNC / SYNC RULES
Version: 1.0

Назначение:
    Правила системы синхронизации JARVIS.

Модуль определяет:
    - какие директории синхронизируются;
    - какие директории игнорируются;
    - какие файлы запрещено изменять;
    - какие типы изменений разрешены;
    - направление синхронизации;
    - правила удаления;
    - правила конфликтов.

Модуль НЕ выполняет:
    - копирование;
    - удаление;
    - backup;
    - фактическую синхронизацию.

Он только отвечает на вопрос:

    "Что системе синхронизации разрешено делать?"
"""

from __future__ import annotations

import fnmatch
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONSTANTS
# ============================================================

RULES_VERSION = 1

# Направления
DIRECTION_PC_TO_USB = "pc_to_usb"
DIRECTION_USB_TO_PC = "usb_to_pc"
DIRECTION_BIDIRECTIONAL = "bidirectional"

ALLOWED_DIRECTIONS = {
    DIRECTION_PC_TO_USB,
    DIRECTION_USB_TO_PC,
    DIRECTION_BIDIRECTIONAL,
}

# Типы изменений
CHANGE_ADDED = "added"
CHANGE_MODIFIED = "modified"
CHANGE_DELETED = "deleted"
CHANGE_UNCHANGED = "unchanged"

ALLOWED_CHANGES = {
    CHANGE_ADDED,
    CHANGE_MODIFIED,
    CHANGE_DELETED,
    CHANGE_UNCHANGED,
}

# Действия
ACTION_COPY = "copy"
ACTION_UPDATE = "update"
ACTION_DELETE = "delete"
ACTION_SKIP = "skip"
ACTION_CONFLICT = "conflict"

ALLOWED_ACTIONS = {
    ACTION_COPY,
    ACTION_UPDATE,
    ACTION_DELETE,
    ACTION_SKIP,
    ACTION_CONFLICT,
}


# ============================================================
# DEFAULT PATH RULES
# ============================================================

DEFAULT_SYNC_DIRECTORIES = [
    "CONFIG",
    "DATA",
]

DEFAULT_IGNORED_DIRECTORIES = [
    "CACHE",
    "BACKUP",
    "LOGS",
    ".git",
    ".idea",
    ".venv",
    "__pycache__",
]

DEFAULT_PROTECTED_DIRECTORIES = [
    "SECURITY",
    "SECURITY_LOGS",
    "SECURITY_QUARANTINE",
    "SECURITY_REPORTS",
]

DEFAULT_IGNORED_PATTERNS = [
    "*.tmp",
    "*.temp",
    "*.bak",
    "*.part",
    "*.crdownload",
    "*.pyc",
    "*.pyo",
]

DEFAULT_PROTECTED_PATTERNS = [
    "manifest.json",
    "sync_state.json",
]


# ============================================================
# DATA CLASS
# ============================================================

@dataclass
class SyncRule:
    """
    Набор правил синхронизации.
    """

    direction: str = DIRECTION_BIDIRECTIONAL

    sync_directories: list[str] = field(
        default_factory=lambda: list(
            DEFAULT_SYNC_DIRECTORIES
        )
    )

    ignored_directories: list[str] = field(
        default_factory=lambda: list(
            DEFAULT_IGNORED_DIRECTORIES
        )
    )

    protected_directories: list[str] = field(
        default_factory=lambda: list(
            DEFAULT_PROTECTED_DIRECTORIES
        )
    )

    ignored_patterns: list[str] = field(
        default_factory=lambda: list(
            DEFAULT_IGNORED_PATTERNS
        )
    )

    protected_patterns: list[str] = field(
        default_factory=lambda: list(
            DEFAULT_PROTECTED_PATTERNS
        )
    )

    allow_add: bool = True
    allow_modify: bool = True
    allow_delete: bool = True

    delete_requires_backup: bool = True
    conflict_requires_manual_resolution: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "sync_directories": list(
                self.sync_directories
            ),
            "ignored_directories": list(
                self.ignored_directories
            ),
            "protected_directories": list(
                self.protected_directories
            ),
            "ignored_patterns": list(
                self.ignored_patterns
            ),
            "protected_patterns": list(
                self.protected_patterns
            ),


            "allow_add": self.allow_add,
            "allow_modify": self.allow_modify,
            "allow_delete": self.allow_delete,
            "delete_requires_backup": (
                self.delete_requires_backup
            ),
            "conflict_requires_manual_resolution": (
                self.conflict_requires_manual_resolution
            ),
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
    ) -> "SyncRule":

        return cls(
            direction=str(
                data.get(
                    "direction",
                    DIRECTION_BIDIRECTIONAL,
                )
            ),
            sync_directories=list(
                data.get(
                    "sync_directories",
                    DEFAULT_SYNC_DIRECTORIES,
                )
            ),
            ignored_directories=list(
                data.get(
                    "ignored_directories",
                    DEFAULT_IGNORED_DIRECTORIES,
                )
            ),
            protected_directories=list(
                data.get(
                    "protected_directories",
                    DEFAULT_PROTECTED_DIRECTORIES,
                )
            ),
            ignored_patterns=list(
                data.get(
                    "ignored_patterns",
                    DEFAULT_IGNORED_PATTERNS,
                )
            ),
            protected_patterns=list(
                data.get(
                    "protected_patterns",
                    DEFAULT_PROTECTED_PATTERNS,
                )
            ),
            allow_add=bool(
                data.get(
                    "allow_add",
                    True,
                )
            ),
            allow_modify=bool(
                data.get(
                    "allow_modify",
                    True,
                )
            ),
            allow_delete=bool(
                data.get(
                    "allow_delete",
                    True,
                )
            ),
            delete_requires_backup=bool(
                data.get(
                    "delete_requires_backup",
                    True,
                )
            ),
            conflict_requires_manual_resolution=bool(
                data.get(
                    "conflict_requires_manual_resolution",
                    True,
                )
            ),
        )


# ============================================================
# RULE DECISION
# ============================================================

@dataclass
class RuleDecision:
    """
    Результат проверки одного файла.
    """

    path: str
    allowed: bool
    action: str
    reason: str

    change_type: Optional[str] = None
    protected: bool = False
    ignored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "allowed": self.allowed,
            "action": self.action,
            "reason": self.reason,
            "change_type": self.change_type,
            "protected": self.protected,
            "ignored": self.ignored,
        }


# ============================================================
# SYNC RULES MANAGER
# ============================================================

class SyncRules:
    """
    Менеджер правил синхронизации.
    """

    def __init__(
        self,
        rules: Optional[SyncRule] = None,
    ):

        self.rules = rules or SyncRule()

    # ========================================================
    # LOG
    # ========================================================

    def _log(
        self,
        message: str,
    ) -> None:

        print(
            f"[SyncRules] {message}"
        )

    # ========================================================
    # NORMALIZE PATH
    # ========================================================

    @staticmethod
    def normalize_path(
        path: Path | str,
    ) -> str:

        return Path(
            path


).as_posix().strip("/")

    # ========================================================
    # DIRECTORY CHECK
    # ========================================================

    def _is_inside_directory(
        self,
        path: str,
        directory: str,
    ) -> bool:

        path = self.normalize_path(
            path
        ).lower()

        directory = self.normalize_path(
            directory
        ).lower()

        return (
            path == directory
            or path.startswith(
                directory + "/"
            )
        )

    # ========================================================
    # SYNC DIRECTORY
    # ========================================================

    def is_sync_directory(
        self,
        path: Path | str,
    ) -> bool:

        normalized = self.normalize_path(
            path
        )

        for directory in (
            self.rules.sync_directories
        ):

            if self._is_inside_directory(
                normalized,
                directory,
            ):
                return True

        return False

    # ========================================================
    # IGNORED DIRECTORY
    # ========================================================

    def is_ignored_directory(
        self,
        path: Path | str,
    ) -> bool:

        normalized = self.normalize_path(
            path
        )

        for directory in (
            self.rules.ignored_directories
        ):

            if self._is_inside_directory(
                normalized,
                directory,
            ):
                return True

        return False

    # ========================================================
    # PROTECTED DIRECTORY
    # ========================================================

    def is_protected_directory(
        self,
        path: Path | str,
    ) -> bool:

        normalized = self.normalize_path(
            path
        )

        for directory in (
            self.rules.protected_directories
        ):

            if self._is_inside_directory(
                normalized,
                directory,
            ):
                return True

        return False

    # ========================================================
    # IGNORED PATTERN
    # ========================================================

    def matches_ignored_pattern(
        self,
        path: Path | str,
    ) -> bool:

        normalized = self.normalize_path(
            path
        )

        filename = Path(
            normalized
        ).name

        for pattern in (
            self.rules.ignored_patterns
        ):

            if fnmatch.fnmatch(
                filename,
                pattern,
            ):
                return True

            if fnmatch.fnmatch(
                normalized,
                pattern,
            ):
                return True

        return False

    # ========================================================
    # PROTECTED PATTERN
    # ========================================================

    def matches_protected_pattern(
        self,
        path: Path | str,
    ) -> bool:

        normalized = self.normalize_path(
            path
        )

        filename = Path(
            normalized
        ).name

        for pattern in (
            self.rules.protected_patterns
        ):

            if fnmatch.fnmatch(
                filename,
                pattern,
            ):
                return True

            if fnmatch.fnmatch(
                normalized,
                pattern,
            ):
                return True

        return False

    # ========================================================
    # PROTECTED
    # ========================================================

    def is_protected(
        self,
        path: Path | str,
    ) -> bool:

        return (
            self.is_protected_directory(path)


or self.matches_protected_pattern(path)
        )

    # ========================================================
    # IGNORED
    # ========================================================

    def is_ignored(
        self,
        path: Path | str,
    ) -> bool:

        return (
            self.is_ignored_directory(path)
            or self.matches_ignored_pattern(path)
        )

    # ========================================================
    # DIRECTION
    # ========================================================

    def allows_direction(
        self,
        source_device: str,
        target_device: str,
    ) -> bool:
        """
        Проверяет разрешено ли направление.

        Для первой версии отдельно учитываем
        PC ↔ USB.

        Bidirectional разрешает оба направления.
        """

        direction = self.rules.direction

        source = source_device.lower()
        target = target_device.lower()

        if direction == DIRECTION_BIDIRECTIONAL:
            return True

        if direction == DIRECTION_PC_TO_USB:

            return (
                source == "pc"
                and target == "usb"
            )

        if direction == DIRECTION_USB_TO_PC:

            return (
                source == "usb"
                and target == "pc"
            )

        return False

    # ========================================================
    # CHANGE TYPE ALLOWED
    # ========================================================

    def allows_change_type(
        self,
        change_type: str,
    ) -> bool:

        if change_type not in ALLOWED_CHANGES:
            raise ValueError(
                f"Неизвестный тип изменения: {change_type}"
            )

        if change_type == CHANGE_ADDED:
            return self.rules.allow_add

        if change_type == CHANGE_MODIFIED:
            return self.rules.allow_modify

        if change_type == CHANGE_DELETED:
            return self.rules.allow_delete

        if change_type == CHANGE_UNCHANGED:
            return True

        return False

    # ========================================================
    # DECIDE
    # ========================================================

    def decide(
        self,
            path: Path | str,
            change_type: str,
            source_device: str = "PC",
            target_device: str = "USB",
    ) -> RuleDecision:
        """
        Принимает решение по конкретному файлу.
        """

        normalized = self.normalize_path(
            path
        )

        # ----------------------------------------------------
        # VALIDATE CHANGE TYPE
        # ----------------------------------------------------

        if change_type not in ALLOWED_CHANGES:

            raise ValueError(
                f"Неизвестный тип изменения: {change_type}"
            )

        # ----------------------------------------------------
        # IGNORED
        # ----------------------------------------------------

        if self.is_ignored(normalized):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Файл попадает под правило игнорирования.",
                change_type=change_type,
                ignored=True,
            )

        # ----------------------------------------------------
        # PROTECTED
        # ----------------------------------------------------

        if self.is_protected(normalized):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Файл защищён от синхронизации.",
                change_type=change_type,
                protected=True,
            )

        # ----------------------------------------------------
        # SYNC DIRECTORY
        # ----------------------------------------------------

        if not self.is_sync_directory(normalized):

         return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Файл находится вне разрешённых директорий.",
                change_type=change_type,
            )

        # ----------------------------------------------------
        # DIRECTION
        # ----------------------------------------------------

        if not self.allows_direction(
            source_device,
            target_device,
        ):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason=(
                    "Направление синхронизации "
                    "запрещено текущими правилами."
                ),
                change_type=change_type,
            )

        # ----------------------------------------------------
        # CHANGE TYPE
        # ----------------------------------------------------

        if not self.allows_change_type(
            change_type
        ):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason=(
                    "Данный тип изменения "
                    "запрещён текущими правилами."
                ),
                change_type=change_type,
            )

        # ----------------------------------------------------
        # UNCHANGED
        # ----------------------------------------------------

        if change_type == CHANGE_UNCHANGED:

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Файл не изменился.",
                change_type=change_type,
            )

        # ----------------------------------------------------
        # ADDED
        # ----------------------------------------------------

        if change_type == CHANGE_ADDED:

            return RuleDecision(
                path=normalized,
                allowed=True,
                action=ACTION_COPY,
                reason="Новый файл разрешено скопировать.",
                change_type=change_type,
            )

        # ----------------------------------------------------
        # MODIFIED
        # ----------------------------------------------------

        if change_type == CHANGE_MODIFIED:

            return RuleDecision(
                path=normalized,
                allowed=True,
                action=ACTION_UPDATE,
                reason="Изменённый файл разрешено обновить.",
                change_type=change_type,
            )

        # ----------------------------------------------------
        # DELETED
        # ----------------------------------------------------

        if change_type == CHANGE_DELETED:

            if self.rules.delete_requires_backup:

                return RuleDecision(
                    path=normalized,
                    allowed=True,
                    action=ACTION_DELETE,
                    reason=(
                        "Удаление разрешено после создания backup."
                    ),
                    change_type=change_type,
                )

            return RuleDecision(
                path=normalized,
                allowed=True,
                action=ACTION_DELETE,
                reason="Удаление разрешено.",
                change_type=change_type,
            )

        # ----------------------------------------------------
        # FALLBACK
        # ----------------------------------------------------

        return RuleDecision(
            path=normalized,
            allowed=False,
            action=ACTION_SKIP,
            reason="Нет подходящего правила.",
            change_type=change_type,
        )

    # ========================================================
    # CONFLICT
    # ========================================================


    def conflict_decision(
        self,
        path: Path | str,
    ) -> RuleDecision:

        normalized = self.normalize_path(
            path
        )

        if self.is_ignored(normalized):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Конфликтный файл игнорируется.",
                change_type="conflict",
                ignored=True,
            )

        if self.is_protected(normalized):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_SKIP,
                reason="Конфликтный файл защищён.",
                change_type="conflict",
                protected=True,
            )

        if (
            self.rules.conflict_requires_manual_resolution
        ):

            return RuleDecision(
                path=normalized,
                allowed=False,
                action=ACTION_CONFLICT,
                reason=(
                    "Конфликт требует ручного разрешения."
                ),
                change_type="conflict",
            )

        return RuleDecision(
            path=normalized,
            allowed=False,
            action=ACTION_CONFLICT,
            reason=(
                "Автоматическое разрешение "
                "конфликтов отключено."
            ),
            change_type="conflict",
        )

    # ========================================================
    # SET DIRECTION
    # ========================================================

    def set_direction(
        self,
        direction: str,
    ) -> None:

        if direction not in ALLOWED_DIRECTIONS:

            raise ValueError(
                f"Неизвестное направление: {direction}"
            )

        self.rules.direction = direction

    # ========================================================
    # DIRECTORY MANAGEMENT
    # ========================================================

    def add_sync_directory(
        self,
        directory: str,
    ) -> None:

        directory = self.normalize_path(
            directory
        )

        if directory not in (
            self.rules.sync_directories
        ):

            self.rules.sync_directories.append(
                directory
            )

    def remove_sync_directory(
        self,
        directory: str,
    ) -> bool:

        directory = self.normalize_path(
            directory
        )

        if directory not in (
            self.rules.sync_directories
        ):
            return False

        self.rules.sync_directories.remove(
            directory
        )

        return True

    def add_ignored_directory(
        self,
        directory: str,
    ) -> None:

        directory = self.normalize_path(
            directory
        )

        if directory not in (
            self.rules.ignored_directories
        ):

            self.rules.ignored_directories.append(
                directory
            )

    def add_protected_directory(
        self,
        directory: str,
    ) -> None:

        directory = self.normalize_path(
            directory
        )

        if directory not in (
            self.rules.protected_directories
        ):

            self.rules.protected_directories.append(
                directory
            )

    # ========================================================
    # PATTERN MANAGEMENT
    # ========================================================

    def add_ignored_pattern(
        self,
        pattern: str,
    ) -> None:

        if pattern not in (
            self.rules.ignored_patterns
        ):

            self.rules.ignored_patterns.append(
                pattern
            )

    def add_protected_pattern(
        self,
        pattern: str,
    ) -> None:

        if pattern not in (
            self.rules.protected_patterns
        ):


         self.rules.protected_patterns.append(
                pattern
            )

    # ========================================================
    # EXPORT
    # ========================================================

    def export(
        self,
    ) -> dict[str, Any]:

        return {
            "rules_version": RULES_VERSION,
            "rules": self.rules.to_dict(),
        }

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(
        self,
    ) -> tuple[bool, list[str]]:

        errors: list[str] = []

        if (
            self.rules.direction
            not in ALLOWED_DIRECTIONS
        ):

            errors.append(
                "Некорректное направление синхронизации."
            )

        if not self.rules.sync_directories:

            errors.append(
                "Не указаны директории синхронизации."
            )

        for directory in (
            self.rules.sync_directories
        ):

            if not directory:

                errors.append(
                    "Пустая директория синхронизации."
                )

        for pattern in (
            self.rules.ignored_patterns
        ):

            if not pattern:

                errors.append(
                    "Пустой ignored pattern."
                )

        for pattern in (
            self.rules.protected_patterns
        ):

            if not pattern:

                errors.append(
                    "Пустой protected pattern."
                )

        # Проверяем, чтобы защищённые директории
        # не находились одновременно в sync-директориях.
        for protected in (
            self.rules.protected_directories
        ):

            for sync_directory in (
                self.rules.sync_directories
            ):

                if self._is_inside_directory(
                    protected,
                    sync_directory,
                ):

                    errors.append(
                        f"Защищённая директория "
                        f"{protected} находится внутри "
                        f"sync-директории {sync_directory}."
                    )

        return (
            len(errors) == 0,
            errors,
        )

    # ========================================================
    # STATUS
    # ========================================================

    def status(
        self,
    ) -> dict[str, Any]:

        valid, errors = self.validate()

        return {
            "rules_version": RULES_VERSION,
            "direction": self.rules.direction,

            "sync_directories": list(
                self.rules.sync_directories
            ),

            "ignored_directories": list(
                self.rules.ignored_directories
            ),

            "protected_directories": list(
                self.rules.protected_directories
            ),

            "ignored_patterns": list(
                self.rules.ignored_patterns
            ),

            "protected_patterns": list(
                self.rules.protected_patterns
            ),

            "allow_add": self.rules.allow_add,
            "allow_modify": self.rules.allow_modify,
            "allow_delete": self.rules.allow_delete,

            "delete_requires_backup": (
                self.rules.delete_requires_backup
            ),

            "conflict_requires_manual_resolution": (
                self.rules.conflict_requires_manual_resolution
            ),

            "valid": valid,
            "errors": errors,
        }

    # ========================================================
    # SELF TEST
    # ========================================================


def self_test() -> bool:

    test_dir = Path(
        tempfile.mkdtemp(
            prefix="jarvis_sync_rules_test_"
        )
    )

    try:


        # ------------------------------------------------
        # CREATE
        # ------------------------------------------------

        rules = SyncRule()

        manager = SyncRules(
            rules
        )

        # ------------------------------------------------
        # DEFAULT VALIDATION
        # ------------------------------------------------

        valid, errors = (
            manager.validate()
        )

        assert valid
        assert errors == []

        # ------------------------------------------------
        # SYNC DIRECTORY
        # ------------------------------------------------

        assert manager.is_sync_directory(
            "CONFIG/settings.json"
        )

        assert manager.is_sync_directory(
            "DATA/user.json"
        )

        assert not manager.is_sync_directory(
            "VOICE/model.wav"
        )

        # ------------------------------------------------
        # IGNORED DIRECTORY
        # ------------------------------------------------

        assert manager.is_ignored(
            "CACHE/test.tmp"
        )

        assert manager.is_ignored(
            "BACKUP/old/file.json"
        )

        assert not manager.is_ignored(
            "CONFIG/settings.json"
        )

        # ------------------------------------------------
        # PROTECTED DIRECTORY
        # ------------------------------------------------

        assert manager.is_protected(
            "SECURITY/security.db"
        )

        assert manager.is_protected(
            "SECURITY_LOGS/test.log"
        )

        # ------------------------------------------------
        # PROTECTED PATTERN
        # ------------------------------------------------

        assert manager.is_protected(
            "CONFIG/manifest.json"
        )

        assert manager.is_protected(
            "DATA/sync_state.json"
        )

        # ------------------------------------------------
        # DIRECTION
        # ------------------------------------------------

        assert manager.allows_direction(
            "PC",
            "USB",
        )

        assert manager.allows_direction(
            "USB",
            "PC",
        )

        manager.set_direction(
            DIRECTION_PC_TO_USB
        )

        assert manager.allows_direction(
            "PC",
            "USB",
        )

        assert not manager.allows_direction(
            "USB",
            "PC",
        )

        manager.set_direction(
            DIRECTION_BIDIRECTIONAL
        )

        # ------------------------------------------------
        # ADDED
        # ------------------------------------------------

        decision = manager.decide(
            "CONFIG/new.json",
            CHANGE_ADDED,
            "PC",
            "USB",
        )

        assert decision.allowed
        assert (
            decision.action
            == ACTION_COPY
        )

        # ------------------------------------------------
        # MODIFIED
        # ------------------------------------------------

        decision = manager.decide(
            "CONFIG/settings.json",
            CHANGE_MODIFIED,
            "PC",
            "USB",
        )

        assert decision.allowed
        assert (
            decision.action
            == ACTION_UPDATE
        )

        # ------------------------------------------------
        # DELETED
        # ------------------------------------------------

        decision = manager.decide(


            "CONFIG/old.json",
            CHANGE_DELETED,
            "PC",
            "USB",
        )

        assert decision.allowed
        assert (
            decision.action
            == ACTION_DELETE
        )

        # ------------------------------------------------
        # UNCHANGED
        # ------------------------------------------------

        decision = manager.decide(
            "CONFIG/same.json",
            CHANGE_UNCHANGED,
            "PC",
            "USB",
        )

        assert not decision.allowed
        assert (
            decision.action
            == ACTION_SKIP
        )

        # ------------------------------------------------
        # IGNORED FILE
        # ------------------------------------------------

        decision = manager.decide(
            "CACHE/test.tmp",
            CHANGE_ADDED,
            "PC",
            "USB",
        )

        assert not decision.allowed
        assert decision.ignored

        # ------------------------------------------------
        # PROTECTED FILE
        # ------------------------------------------------

        decision = manager.decide(
            "SECURITY/test.db",
            CHANGE_MODIFIED,
            "PC",
            "USB",
        )

        assert not decision.allowed
        assert decision.protected

        # ------------------------------------------------
        # OUTSIDE SYNC DIRECTORY
        # ------------------------------------------------

        decision = manager.decide(
            "VOICE/test.wav",
            CHANGE_ADDED,
            "PC",
            "USB",
        )

        assert not decision.allowed

        # ------------------------------------------------
        # CONFLICT
        # ------------------------------------------------

        conflict = manager.conflict_decision(
            "CONFIG/settings.json"
        )

        assert (
            conflict.action
            == ACTION_CONFLICT
        )

        assert not conflict.allowed

        # ------------------------------------------------
        # EXPORT
        # ------------------------------------------------

        exported = manager.export()

        assert (
            exported["rules_version"]
            == RULES_VERSION
        )

        assert (
            exported["rules"]["direction"]
            == DIRECTION_BIDIRECTIONAL
        )

        # ------------------------------------------------
        # STATUS
        # ------------------------------------------------

        status = manager.status()

        assert status["valid"]

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
                elif item.is_dir():
                    import shutil
                    shutil.rmtree(item)
            test_dir.rmdir()
        except Exception:
            pass