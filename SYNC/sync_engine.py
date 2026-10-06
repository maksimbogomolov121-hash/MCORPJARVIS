from __future__ import annotations

import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from .device_manager import DeviceManager
    from .hash_manager import HashManager
    from .manifest_manager import ManifestManager
    from .change_detector import ChangeDetector
    from .sync_rules import (
        SyncRules,
        ACTION_COPY,
        ACTION_UPDATE,
        ACTION_DELETE,
        ACTION_SKIP,
        ACTION_CONFLICT,
        CHANGE_ADDED,
        CHANGE_MODIFIED,
        CHANGE_DELETED,
        CHANGE_UNCHANGED,
    )
    from .conflict_manager import (
        ConflictManager,
        CONFLICT_UNRESOLVED,
    )
    from .version_manager import VersionManager

except ImportError:
    from device_manager import DeviceManager
    from hash_manager import HashManager
    from manifest_manager import ManifestManager
    from change_detector import ChangeDetector
    from sync_rules import (
        SyncRules,
        ACTION_COPY,
        ACTION_UPDATE,
        ACTION_DELETE,
        ACTION_SKIP,
        ACTION_CONFLICT,
        CHANGE_ADDED,
        CHANGE_MODIFIED,
        CHANGE_DELETED,
        CHANGE_UNCHANGED,
    )
    from conflict_manager import (
        ConflictManager,
        CONFLICT_UNRESOLVED,
    )
    from version_manager import VersionManager


# ============================================================
# CONSTANTS
# ============================================================

ENGINE_VERSION = 1

ENGINE_IDLE = "idle"
ENGINE_ANALYZING = "analyzing"
ENGINE_BACKING_UP = "backing_up"
ENGINE_APPLYING = "applying"
ENGINE_VERIFYING = "verifying"
ENGINE_COMPLETED = "completed"
ENGINE_FAILED = "failed"
ENGINE_CONFLICT = "conflict"

OPERATION_COPY = "copy"
OPERATION_UPDATE = "update"
OPERATION_DELETE = "delete"
OPERATION_SKIP = "skip"
OPERATION_CONFLICT = "conflict"

DEFAULT_BACKUP_DIR = "BACKUP"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """Return current UTC time."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str | Path) -> str:
    """Normalize relative paths."""
    return str(path).replace("\\", "/").strip("/")


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class SyncOperation:
    """One planned synchronization operation."""

    operation_id: str
    path: str
    action: str

    source_path: Optional[str] = None
    target_path: Optional[str] = None

    change_type: Optional[str] = None

    status: str = "planned"

    error: Optional[str] = None

    verified: bool = False

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class SyncPlan:
    """Complete synchronization plan."""

    plan_id: str

    source_device: str
    target_device: str

    created_at: str

    operations: list[SyncOperation] = field(
        default_factory=list
    )

    conflicts: list[str] = field(
        default_factory=list
    )

    skipped: list[str] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )


@dataclass
class SyncResult:
    """Final result of synchronization."""

    session_id: str

    success: bool

    status: str

    started_at: str
    completed_at: Optional[str]

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


# ============================================================
# SYNC ENGINE
# ============================================================

class SyncEngine:
    """
    Core synchronization engine.

    Responsibilities:

        1. Analyze source and target.
        2. Detect changes.
        3. Apply SyncRules.
        4. Detect conflicts.
        5. Create backup before destructive actions.
        6. Copy/update/delete files.
        7. Verify resulting hashes.
        8. Update manifest.
        9. Track versions.

    SyncEngine does not handle:
        - voice commands
        - GUI
        - user interaction
        - scheduling
    """

    def __init__(
        self,
        source_root: str | Path,
        target_root: str | Path,
        source_device_id: str = "source",
        target_device_id: str = "target",
        backup_root: str | Path | None = None,
        sync_rules: SyncRules | None = None,
        hash_manager: HashManager | None = None,
        source_manifest: ManifestManager | None = None,
        target_manifest: ManifestManager | None = None,
        conflict_manager: ConflictManager | None = None,
        version_manager: VersionManager | None = None,
    ) -> None:

        self.source_root = Path(
            source_root
        ).resolve()

        self.target_root = Path(
            target_root
        ).resolve()

        self.source_device_id = source_device_id
        self.target_device_id = target_device_id

        if backup_root is None:
            backup_root = (
                self.target_root
                / DEFAULT_BACKUP_DIR
            )

        self.backup_root = Path(
            backup_root
        ).resolve()

        self.rules = (
            sync_rules
            if sync_rules is not None
            else SyncRules()
        )

        self.hash_manager = (
            hash_manager
            if hash_manager is not None
            else HashManager()
        )

        self.source_manifest = (
            source_manifest
            if source_manifest is not None
            else ManifestManager(
                self.source_root
                / "SYNC"
                / "manifest.json"
            )
        )

        self.target_manifest = (
            target_manifest
            if target_manifest is not None
            else ManifestManager(
                self.target_root
                / "SYNC"
                / "manifest.json"
            )
        )

        self.conflict_manager = (
            conflict_manager
            if conflict_manager is not None
            else ConflictManager(
                self.target_root
                / "SYNC"
                / "conflicts.json"
            )
        )

        self.version_manager = (
            version_manager
            if version_manager is not None
            else VersionManager(
                self.target_root
                / "SYNC"
                / "versions.json"
            )
        )

        self.change_detector = (
            ChangeDetector()
        )

        self.status = ENGINE_IDLE

        self.current_plan: Optional[
            SyncPlan
        ] = None

        self.last_result: Optional[
            SyncResult
        ] = None

    # ========================================================
    # INTERNAL
    # ========================================================

    def _log(
        self,
        message: str,
    ) -> None:
        """Temporary engine logger."""

        print(
            f"[SyncEngine] {message}"
        )

    def _resolve_source(
        self,
        relative_path: str,
    ) -> Path:

        return (
            self.source_root
            / normalize_path(relative_path)
        )

    def _resolve_target(
        self,
        relative_path: str,
    ) -> Path:

        return (
            self.target_root
            / normalize_path(relative_path)
        )

    # ========================================================
    # FILE DISCOVERY
    # ========================================================


    def _iter_sync_files(
        self,
        root: Path,
    ) -> dict[str, dict[str, Any]]:
        """
        Build a hash map of files eligible for synchronization.

        Uses the actual SyncRules interface:

            self.rules.sync_dirs

        A getter is also supported if it exists.
        """

        result: dict[str, dict[str, Any]] = {}

        if not root.exists():
            return result

        # ----------------------------------------------------
        # Get configured synchronization directories
        # ----------------------------------------------------

        sync_directories = getattr(
            self.rules,
            "sync_dirs",
            None,
        )

        if sync_directories is None:

            getter = getattr(
                self.rules,
                "get_sync_directories",
                None,
            )

            if callable(getter):
                sync_directories = getter()

        # ----------------------------------------------------
        # Safe default
        # ----------------------------------------------------

        if sync_directories is None:
            sync_directories = [
                "CONFIG",
                "DATA",
            ]

        # ----------------------------------------------------
        # Scan directories
        # ----------------------------------------------------

        for sync_dir in sync_directories:

            directory = (
                root
                / normalize_path(sync_dir)
            )

            if not directory.exists():
                continue

            if not directory.is_dir():
                continue

            for file_path in directory.rglob("*"):

                if not file_path.is_file():
                    continue

                try:

                    relative = normalize_path(
                        file_path.relative_to(root)
                    )

                except ValueError:

                    continue

                # ------------------------------------------------
                # Ignore protected / ignored files
                # ------------------------------------------------

                if self.rules.is_ignored(
                    relative
                ):
                    continue

                if self.rules.is_protected(
                    relative
                ):
                    continue

                # ------------------------------------------------
                # File information
                # ------------------------------------------------

                try:

                    info = (
                        self.hash_manager
                        .get_file_info(
                            file_path
                        )
                    )

                except Exception as exc:

                    self._log(
                        f"Cannot inspect "
                        f"{relative}: {exc}"
                    )

                    continue

                result[relative] = info

        return result

    # ========================================================
    # ANALYZE
    # ========================================================

    def analyze(self) -> SyncPlan:
        """
        Analyze source and target and create
        a synchronization plan.
        """

        self.status = ENGINE_ANALYZING

        source_files = (
            self._iter_sync_files(
                self.source_root
            )
        )

        target_files = (
            self._iter_sync_files(
                self.target_root
            )
        )

        # ----------------------------------------------------
        # Hash maps
        # ----------------------------------------------------

        source_map = {
            path: info.get("hash")
            for path, info
            in source_files.items()
        }

        target_map = {

path: info.get("hash")
            for path, info
            in target_files.items()
        }

        # ----------------------------------------------------
        # Detect changes
        # ----------------------------------------------------

        changes = self.change_detector.compare(
            old_state={
                "files": target_files
            },
            new_state={
                "files": source_files
            },
        )

        # ----------------------------------------------------
        # Compatibility handling
        # ----------------------------------------------------

        if changes is None:

            changes = []

        elif hasattr(changes, "changes"):

            changes = changes.changes

        elif isinstance(changes, dict):

            changes = (
                changes.get(
                    "changes",
                    []
                )
            )

        plan = SyncPlan(
            plan_id=str(
                uuid.uuid4()
            ),
            source_device=(
                self.source_device_id
            ),
            target_device=(
                self.target_device_id
            ),
            created_at=utc_now(),
        )

        # ----------------------------------------------------
        # Process changes
        # ----------------------------------------------------

        for change in changes:

            path = normalize_path(
                change.path
            )

            decision = self.rules.decide(
                change.path,
                change.change_type
            )

            action = decision.action

            # ------------------------------------------------
            # SKIP
            # ------------------------------------------------

            if action == ACTION_SKIP:

                plan.skipped.append(
                    path
                )

                plan.operations.append(
                    SyncOperation(
                        operation_id=str(
                            uuid.uuid4()
                        ),
                        path=path,
                        action=ACTION_SKIP,
                        source_path=str(
                            self._resolve_source(
                                path
                            )
                        ),
                        target_path=str(
                            self._resolve_target(
                                path
                            )
                        ),
                        change_type=(
                            change.change_type
                        ),
                        status="skipped",
                    )
                )

                continue

            # ------------------------------------------------
            # CONFLICT
            # ------------------------------------------------

            if action == ACTION_CONFLICT:

                conflict_id = (
                    self._register_conflict(
                        path,
                        source_files,
                        target_files,
                    )
                )

                plan.conflicts.append(
                    conflict_id
                )

                plan.operations.append(
                    SyncOperation(
                        operation_id=str(
                            uuid.uuid4()
                        ),
                        path=path,
                        action=ACTION_CONFLICT,
                        source_path=str(
                            self._resolve_source(
                                path
                            )
                        ),
                        target_path=str(
                            self._resolve_target(
                                path
                            )
                        ),
                        change_type=(
                            change.change_type
                        ),

                        status="conflict",
                        metadata={
                            "conflict_id":
                                conflict_id
                        },
                    )
                )

                continue

            # ------------------------------------------------
            # NORMAL OPERATION
            # ------------------------------------------------

            plan.operations.append(
                SyncOperation(
                    operation_id=str(
                        uuid.uuid4()
                    ),
                    path=path,
                    action=action,
                    source_path=str(
                        self._resolve_source(
                            path
                        )
                    ),
                    target_path=str(
                        self._resolve_target(
                            path
                        )
                    ),
                    change_type=(
                        change.change_type
                    ),
                )
            )

        self.current_plan = plan

        self._log(
            f"Analysis complete: "
            f"{len(plan.operations)} operations, "
            f"{len(plan.conflicts)} conflicts"
        )

        return plan

    # ========================================================
    # CONFLICT REGISTRATION
    # ========================================================

    def _register_conflict(
        self,
        path: str,
        source_files: dict[str, Any],
        target_files: dict[str, Any],
    ) -> str:

        source = source_files.get(
            path,
            {}
        )

        target = target_files.get(
            path,
            {}
        )

        source_hash = source.get(
            "hash"
        )

        target_hash = target.get(
            "hash"
        )

        base_file = (
            self.target_manifest
            .get_file(path)
        )

        base_hash = None

        if base_file is not None:

            base_hash = (
                base_file.hash_value
            )

        conflict = (
            self.conflict_manager
            .create_conflict(
                path=path,
                source_device=(
                    self.source_device_id
                ),
                target_device=(
                    self.target_device_id
                ),
                base_hash=base_hash,
                source_hash=source_hash,
                target_hash=target_hash,
                source_size=source.get(
                    "size"
                ),
                target_size=target.get(
                    "size"
                ),
                source_modified_at=source.get(
                    "modified_at"
                ),
                target_modified_at=target.get(
                    "modified_at"
                ),
            )
        )

        return conflict.conflict_id

    # ========================================================
    # BACKUP
    # ========================================================

    def _create_backup(
        self,
        relative_path: str,
    ) -> Optional[Path]:
        """
        Create a backup copy of an existing target file.
        """

        source = self._resolve_target(
            relative_path
        )

        if not source.exists():
            return None

        timestamp = (
            datetime.now()
            .strftime(
                "%Y-%m-%d_%H-%M-%S"
            )
        )

        snapshot_dir = (
            self.backup_root
            / "snapshots"
            / timestamp
        )

        destination = (
            snapshot_dir
            / normalize_path(
                relative_path
            )
        )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            destination,
        )


        return destination

    # ========================================================
    # APPLY
    # ========================================================

    def apply(
        self,
        plan: SyncPlan | None = None,
    ) -> SyncResult:
        """
        Apply synchronization plan.
        """

        if plan is None:
            plan = self.current_plan

        if plan is None:
            plan = self.analyze()

        session_id = str(
            uuid.uuid4()
        )

        started_at = utc_now()

        result = SyncResult(
            session_id=session_id,
            success=False,
            status=ENGINE_APPLYING,
            started_at=started_at,
            completed_at=None,
        )

        self.status = ENGINE_APPLYING

        for operation in plan.operations:

            # ------------------------------------------------
            # SKIP
            # ------------------------------------------------

            if operation.action == ACTION_SKIP:

                operation.status = "skipped"

                result.files_skipped += 1

                continue

            # ------------------------------------------------
            # CONFLICT
            # ------------------------------------------------

            if operation.action == ACTION_CONFLICT:

                operation.status = "conflict"

                result.conflicts += 1

                continue

            # ------------------------------------------------
            # APPLY
            # ------------------------------------------------

            try:

                self._apply_operation(
                    operation
                )

                operation.status = "completed"

                if (
                    operation.change_type
                    == CHANGE_ADDED
                ):

                    result.files_added += 1

                elif (
                    operation.change_type
                    == CHANGE_MODIFIED
                ):

                    result.files_modified += 1

                elif (
                    operation.change_type
                    == CHANGE_DELETED
                ):

                    result.files_deleted += 1

                elif (
                    operation.change_type
                    == CHANGE_UNCHANGED
                ):

                    result.files_unchanged += 1

            except Exception as exc:

                operation.status = "failed"

                operation.error = str(exc)

                result.errors += 1

                result.error_messages.append(
                    f"{operation.path}: {exc}"
                )

        # ----------------------------------------------------
        # Errors
        # ----------------------------------------------------

        if result.errors > 0:

            self.status = ENGINE_FAILED

            result.status = ENGINE_FAILED

            result.completed_at = utc_now()

            result.operations = [
                operation.__dict__.copy()
                for operation
                in plan.operations
            ]

            self.last_result = result

            return result

        # ----------------------------------------------------
        # Conflicts
        # ----------------------------------------------------

        if result.conflicts > 0:

            self.status = ENGINE_CONFLICT

            result.status = ENGINE_CONFLICT

            result.completed_at = utc_now()

            result.operations = [
                operation.__dict__.copy()
                for operation
                in plan.operations
            ]

            self.last_result = result

            return result

        # ----------------------------------------------------
        # Verification
        # ----------------------------------------------------

        self.status = ENGINE_VERIFYING

        verification_errors = (

        self.verify(plan)
        )

        if verification_errors:

            self.status = ENGINE_FAILED

            result.status = ENGINE_FAILED

            result.errors += len(
                verification_errors
            )

            result.error_messages.extend(
                verification_errors
            )

            result.completed_at = utc_now()

            result.operations = [
                operation.__dict__.copy()
                for operation
                in plan.operations
            ]

            self.last_result = result

            return result

        # ----------------------------------------------------
        # Update manifest
        # ----------------------------------------------------

        self._update_target_manifest()

        self.status = ENGINE_COMPLETED

        result.success = True

        result.status = ENGINE_COMPLETED

        result.completed_at = utc_now()

        result.operations = [
            operation.__dict__.copy()
            for operation
            in plan.operations
        ]

        self.last_result = result

        return result

    # ========================================================
    # APPLY SINGLE OPERATION
    # ========================================================

    def _apply_operation(
        self,
        operation: SyncOperation,
    ) -> None:

        source = self._resolve_source(
            operation.path
        )

        target = self._resolve_target(
            operation.path
        )

        action = operation.action

        # ----------------------------------------------------
        # COPY
        # ----------------------------------------------------

        if action == ACTION_COPY:

            if not source.exists():

                raise FileNotFoundError(
                    f"Source file not found: "
                    f"{source}"
                )

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copy2(
                source,
                target,
            )

            self._register_version(
                operation.path,
                source,
            )

            return

        # ----------------------------------------------------
        # UPDATE
        # ----------------------------------------------------

        if action == ACTION_UPDATE:

            if not source.exists():

                raise FileNotFoundError(
                    f"Source file not found: "
                    f"{source}"
                )

            if target.exists():

                self.status = (
                    ENGINE_BACKING_UP
                )

                self._create_backup(
                    operation.path
                )

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copy2(
                source,
                target,
            )

            self._register_version(
                operation.path,
                source,
            )

            return

        # ----------------------------------------------------
        # DELETE
        # ----------------------------------------------------

        if action == ACTION_DELETE:

            if target.exists():

                self.status = (
                    ENGINE_BACKING_UP
                )

                self._create_backup(
                    operation.path
                )

                target.unlink()

            self.version_manager.mark_deleted(
                path=operation.path,
                device_id=(
                    self.target_device_id
                ),
                device_type="target",
            )

            return

        raise ValueError(
            f"Unsupported action: {action}"
        )

    # ========================================================
    # VERSION REGISTRATION
    # ========================================================

    def _register_version(
        self,
        relative_path: str,
        source_file: Path,
    ) -> None:

        info = (
            self.hash_manager
            .get_file_info(
                source_file
            )
        )

        self.version_manager.create_version(
            path=relative_path,
            hash_value=info.get(
                "hash"
            ),
            device_id=(
                self.source_device_id
            ),
            device_type="source",
            size=info.get(
                "size"
            ),
            modified_at=info.get(
                "modified_at"
            ),
        )

    # ========================================================
    # VERIFY
    # ========================================================

    def verify(
        self,
        plan: SyncPlan | None = None,
    ) -> list[str]:
        """
        Verify target files against source files.
        """

        if plan is None:
            plan = self.current_plan

        if plan is None:

            return [
                "No synchronization plan"
            ]

        errors: list[str] = []

        for operation in plan.operations:

            if operation.action in {
                ACTION_SKIP,
                ACTION_CONFLICT,
            }:
                continue

            source = self._resolve_source(
                operation.path
            )

            target = self._resolve_target(
                operation.path
            )

            # ------------------------------------------------
            # DELETE
            # ------------------------------------------------

            if (
                operation.action
                == ACTION_DELETE
            ):

                if target.exists():

                    errors.append(
                        f"Delete verification failed: "
                        f"{operation.path}"
                    )

                else:

                    operation.verified = True

                continue

            # ------------------------------------------------
            # COPY / UPDATE
            # ------------------------------------------------

            if not source.exists():

                errors.append(
                    f"Source disappeared: "
                    f"{operation.path}"
                )

                continue

            if not target.exists():

                errors.append(
                    f"Target missing after sync: "
                    f"{operation.path}"
                )

                continue

            source_hash = (
                self.hash_manager
                .calculate_hash(
                    source
                )
            )

            target_hash = (
                self.hash_manager
                .calculate_hash(
                    target
                )
            )

            if source_hash != target_hash:

                errors.append(
                    f"Hash verification failed: "
                    f"{operation.path}"
                )

            else:

                operation.verified = True

        return errors

    # ========================================================
    # TARGET MANIFEST
    # ========================================================

    def _update_target_manifest(
        self,
    ) -> None:
        """
        Rebuild target manifest after successful sync.
        """

        target_files = (
            self._iter_sync_files(
                self.target_root
            )
        )

        self.target_manifest.clear_files()

        for relative_path, info in target_files.items():
            print(
                f"[DEBUG] Manifest info for {relative_path}: {info}"
            )

            self.target_manifest.add_file(
                path=relative_path,
                hash_value=info.get("hash", ""),
                size=info.get("size", 0),
                modified_at=info.get("modified_at"),
            )

        self.target_manifest.save()

    # ========================================================
    # FULL SYNC
    # ========================================================

    def sync(self) -> SyncResult:
        """
        Analyze and apply synchronization.
        """

        plan = self.analyze()

        return self.apply(
            plan
        )

    # ========================================================
    # PLAN EXPORT
    # ========================================================

    def export_plan(
        self,
        plan: SyncPlan | None = None,
    ) -> dict[str, Any]:
        """
        Export plan to JSON-compatible dictionary.
        """

        if plan is None:
            plan = self.current_plan

        if plan is None:
            return {}

        return {
            "plan_id": plan.plan_id,

            "source_device": (
                plan.source_device
            ),

            "target_device": (
                plan.target_device
            ),

            "created_at": plan.created_at,

            "operations": [
                operation.__dict__.copy()
                for operation
                in plan.operations
            ],

            "conflicts": list(
                plan.conflicts
            ),

            "skipped": list(
                plan.skipped
            ),

            "errors": list(
                plan.errors
            ),
        }

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(self) -> dict[str, Any]:
        """Return engine status."""

        return {
            "engine_version": (
                ENGINE_VERSION
            ),

            "status": self.status,

            "source_root": str(
                self.source_root
            ),

            "target_root": str(
                self.target_root
            ),

            "source_device_id": (
                self.source_device_id
            ),

            "target_device_id": (
                self.target_device_id
            ),

            "has_plan": (
                self.current_plan is not None
            ),

            "last_result": (
                self.last_result.__dict__.copy()
                if self.last_result
                else None
            ),
        }

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(self) -> bool:
        """
        Run complete isolated synchronization test.

        No real JARVIS files are modified.
        """

        with tempfile.TemporaryDirectory() as temp_dir:

            root = Path(temp_dir)

            source = root / "SOURCE"
            target = root / "TARGET"

            source.mkdir(parents=True)
            target.mkdir(parents=True)

            # ------------------------------------------------
            # Required directories
            # ------------------------------------------------

            (source / "CONFIG").mkdir()
            (target / "CONFIG").mkdir()

            # ------------------------------------------------
            # Create source file
            # ------------------------------------------------

            source_file = (
                    source
                    / "CONFIG"
                    / "settings.json"
            )

            source_file.write_text(
                '{"value": 123}',
                encoding="utf-8",
            )

            # ------------------------------------------------
            # Independent managers
            # ------------------------------------------------

            rules = SyncRules()

            rules.set_direction(
                "pc_to_usb"
            )

            source_hash_manager = HashManager()

            source_manifest = ManifestManager(
                source / "SYNC" / "manifest.json"
            )

            target_manifest = ManifestManager(
                target / "SYNC" / "manifest.json"
            )

            conflicts = ConflictManager(
                target / "SYNC" / "conflicts.json"
            )

            versions = VersionManager(
                target / "SYNC" / "versions.json"
            )

            engine = SyncEngine(
                source_root=source,
                target_root=target,
                source_device_id="PC_TEST",
                target_device_id="USB_TEST",
                backup_root=target / "BACKUP",
                sync_rules=rules,
                hash_manager=source_hash_manager,
                source_manifest=source_manifest,
                target_manifest=target_manifest,
                conflict_manager=conflicts,
                version_manager=versions,
            )

            # ------------------------------------------------
            # ANALYZE #1
            # ------------------------------------------------

            plan = engine.analyze()

            print(
                f"[SelfTest] Analyze #1 operations = "
                f"{len(plan.operations) if plan else 'NONE'}"
            )

            if plan is None:
                print("[SelfTest] FAIL: plan is None")
                return False

            if len(plan.operations) != 1:
                print(
                    "[SelfTest] FAIL: expected 1 operation, "
                    f"got {len(plan.operations)}"
                )
                return False

            operation = plan.operations[0]

            print(
                f"[SelfTest] Operation path = "
                f"{operation.path}"
            )

            print(
                f"[SelfTest] Operation action = "
                f"{operation.action}"
            )

            if operation.path != "CONFIG/settings.json":
                print(
                    "[SelfTest] FAIL: wrong operation path"
                )
                return False

            if operation.action not in {
                ACTION_COPY,
                ACTION_UPDATE,
            }:
                print(
                    "[SelfTest] FAIL: wrong operation action"
                )
                return False

            # ------------------------------------------------
            # APPLY #1
            # ------------------------------------------------

            result = engine.apply(plan)

            print(
                f"[SelfTest] Apply #1 success = "
                f"{result.success}"
            )

            print(
                f"[SelfTest] Apply #1 status = "
                f"{result.status}"
            )

            print(
                f"[SelfTest] Apply #1 errors = "
                f"{result.errors}"
            )

            print(
                f"[SelfTest] Apply #1 conflicts = "
                f"{result.conflicts}"
            )

            print(
                f"[SelfTest] Apply #1 messages = "

            f"{result.error_messages}"
            )

            if not result.success:
                print(
                    "[SelfTest] FAIL: Apply #1 failed"
                )
                return False

            # ------------------------------------------------
            # Target file
            # ------------------------------------------------

            target_file = (
                    target
                    / "CONFIG"
                    / "settings.json"
            )

            print(
                f"[SelfTest] Target exists = "
                f"{target_file.exists()}"
            )

            if not target_file.exists():
                print(
                    "[SelfTest] FAIL: target file missing"
                )
                return False

            target_content = (
                target_file.read_text(
                    encoding="utf-8"
                )
            )

            print(
                f"[SelfTest] Target content = "
                f"{target_content}"
            )

            if target_content != '{"value": 123}':
                print(
                    "[SelfTest] FAIL: target content mismatch"
                )
                return False

            # ------------------------------------------------
            # Hash
            # ------------------------------------------------

            source_hash = (
                source_hash_manager.calculate_hash(
                    source_file
                )
            )

            target_hash = (
                source_hash_manager.calculate_hash(
                    target_file
                )
            )

            print(
                f"[SelfTest] Source hash = "
                f"{source_hash}"
            )

            print(
                f"[SelfTest] Target hash = "
                f"{target_hash}"
            )

            if source_hash != target_hash:
                print(
                    "[SelfTest] FAIL: hash mismatch"
                )
                return False

            # ------------------------------------------------
            # Manifest
            # ------------------------------------------------

            manifest_path = (
                    target
                    / "SYNC"
                    / "manifest.json"
            )

            print(
                f"[SelfTest] Manifest exists = "
                f"{manifest_path.exists()}"
            )

            if not manifest_path.exists():
                print(
                    "[SelfTest] FAIL: manifest missing"
                )
                return False

            target_manifest.load()

            manifest_file = (
                target_manifest.get_file(
                    "CONFIG/settings.json"
                )
            )

            print(
                f"[SelfTest] Manifest file = "
                f"{manifest_file}"
            )

            if manifest_file is None:
                print(
                    "[SelfTest] FAIL: manifest file missing"
                )
                return False

            print(
                f"[SelfTest] Manifest hash = "
                f"{manifest_file.hash_value}"
            )

            if manifest_file.hash_value != source_hash:
                print(
                    "[SelfTest] FAIL: manifest hash mismatch"
                )
                return False

            # ------------------------------------------------
            # Version
            # ------------------------------------------------

            current_version = (
                versions.get_current_version(
                    "CONFIG/settings.json"
                )
            )

            print(
                f"[SelfTest] Current version = "
                f"{current_version}"
            )

            if current_version is None:
                print(
                    "[SelfTest] FAIL: version missing"
                )
                return False

            print(
                f"[SelfTest] Version hash = "
                f"{current_version.hash_value}"
            )

            if current_version.hash_value != source_hash:
                print(
                    "[SelfTest] FAIL: version hash mismatch"
                )
                return False

            # ------------------------------------------------
            # MODIFY SOURCE
            # ------------------------------------------------

            source_file.write_text(
                '{"value": 456}',

            encoding = "utf-8",
            )

            print(
                "[SelfTest] Source modified"
            )

            # ------------------------------------------------
            # ANALYZE #2
            # ------------------------------------------------

            plan2 = engine.analyze()

            print(
                f"[SelfTest] Analyze #2 operations = "
                f"{len(plan2.operations) if plan2 else 'NONE'}"
            )

            if plan2 is None:
                print(
                    "[SelfTest] FAIL: plan2 is None"
                )
                return False

            if len(plan2.operations) != 1:
                print(
                    "[SelfTest] FAIL: expected 1 operation "
                    f"in plan2, got {len(plan2.operations)}"
                )
                return False

            print(
                f"[SelfTest] Operation #2 action = "
                f"{plan2.operations[0].action}"
            )

            if plan2.operations[0].action not in {
                ACTION_COPY,
                ACTION_UPDATE,
            }:
                print(
                    "[SelfTest] FAIL: wrong action in plan2"
                )
                return False

            # ------------------------------------------------
            # APPLY #2
            # ------------------------------------------------

            result2 = engine.apply(plan2)

            print(
                f"[SelfTest] Apply #2 success = "
                f"{result2.success}"
            )

            print(
                f"[SelfTest] Apply #2 status = "
                f"{result2.status}"
            )

            print(
                f"[SelfTest] Apply #2 errors = "
                f"{result2.errors}"
            )

            if not result2.success:
                print(
                    f"[SelfTest] Apply #2 messages = "
                    f"{result2.error_messages}"
                )
                return False

            # ------------------------------------------------
            # Verify modification
            # ------------------------------------------------

            target_content2 = (
                target_file.read_text(
                    encoding="utf-8"
                )
            )

            print(
                f"[SelfTest] Target content #2 = "
                f"{target_content2}"
            )

            if target_content2 != '{"value": 456}':
                print(
                    "[SelfTest] FAIL: modification mismatch"
                )
                return False

            # ------------------------------------------------
            # Backup
            # ------------------------------------------------

            snapshots_root = (
                    target
                    / "BACKUP"
                    / "snapshots"
            )

            print(
                f"[SelfTest] Snapshots directory exists = "
                f"{snapshots_root.exists()}"
            )

            backup_files = []

            if snapshots_root.exists():
                backup_files = list(
                    snapshots_root.rglob(
                        "settings.json"
                    )
                )

            print(
                f"[SelfTest] Backup files = "
                f"{backup_files}"
            )

            if not backup_files:
                print(
                    "[SelfTest] FAIL: backup missing"
                )
                return False

            # ------------------------------------------------
            # Final status
            # ------------------------------------------------

            status = engine.get_status()

            print(
                f"[SelfTest] Final engine status = "
                f"{status['status']}"
            )

            if status["status"] != ENGINE_COMPLETED:
                print(
                    "[SelfTest] FAIL: engine not completed"
                )
                return False

            print(
                "[SelfTest] All checks passed"
            )

            return True


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    engine = SyncEngine(
        source_root=Path("."),
        target_root=Path("."),
    )

    if engine.self_test():

        print(
            "[+] Self-test: OK"
        )

    else:

        print(
            "[-] Self-test: FAILED"
        )