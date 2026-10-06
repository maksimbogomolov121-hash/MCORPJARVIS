from __future__ import annotations

import json
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ============================================================
# CONSTANTS
# ============================================================

CONFLICT_VERSION = 1

CONFLICT_UNRESOLVED = "unresolved"
CONFLICT_PC_WINS = "pc_wins"
CONFLICT_USB_WINS = "usb_wins"
CONFLICT_BOTH = "both"
CONFLICT_SKIP = "skip"
CONFLICT_MANUAL = "manual"

SOURCE_PC = "pc"
SOURCE_USB = "usb"
SOURCE_MOBILE = "mobile"

DEFAULT_CONFLICT_FILENAME = "conflicts.json"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str | Path) -> str:
    """Normalize a relative file path for cross-platform comparison."""
    return str(path).replace("\\", "/").strip("/")


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ConflictRecord:
    """
    Describes one synchronization conflict.
    """

    conflict_id: str
    path: str

    source_device: str
    target_device: str

    base_hash: Optional[str] = None
    source_hash: Optional[str] = None
    target_hash: Optional[str] = None

    source_size: Optional[int] = None
    target_size: Optional[int] = None

    source_modified_at: Optional[str] = None
    target_modified_at: Optional[str] = None

    status: str = CONFLICT_UNRESOLVED
    resolution: Optional[str] = None
    resolved_by: Optional[str] = None

    created_at: str = field(default_factory=utc_now)
    resolved_at: Optional[str] = None

    metadata: dict[str, Any] = field(default_factory=dict)


# ============================================================
# CONFLICT MANAGER
# ============================================================

class ConflictManager:
    """
    Manages synchronization conflicts.

    The manager does NOT automatically overwrite conflicting files.

    A conflict occurs when both source and target contain changes
    relative to the last common/base state.
    """

    def __init__(
        self,
        storage_path: str | Path | None = None,
    ) -> None:

        if storage_path is None:
            storage_path = (
                Path(__file__).resolve().parent / DEFAULT_CONFLICT_FILENAME
            )

        self.storage_path = Path(storage_path)

        self.data: dict[str, Any] = {
            "conflict_version": CONFLICT_VERSION,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "conflicts": {},
        }

        self.load()

    # ========================================================
    # INTERNAL
    # ========================================================

    def _log(self, message: str) -> None:
        """
        Lightweight internal logger.

        sync_logger.py will later provide centralized logging.
        """
        print(f"[ConflictManager] {message}")

    def _atomic_save(self) -> None:
        """Save JSON atomically."""
        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.data["updated_at"] = utc_now()

        temp_path = self.storage_path.with_suffix(
            self.storage_path.suffix + ".tmp"
        )

        with temp_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                self.data,
                file,
                ensure_ascii=False,
                indent=2,
            )

        temp_path.replace(self.storage_path)

    # ========================================================
    # LOAD / SAVE
    # ========================================================

    def load(self) -> bool:
        """Load conflict database from disk."""
        if not self.storage_path.exists():
            return False

        try:
            with self.storage_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                loaded = json.load(file)

            if not isinstance(loaded, dict):
                return False

            self.data = loaded

            if "conflicts" not in self.data:
                self.data["conflicts"] = {}

            return True

        except Exception as exc:
            self._log(f"Load error: {exc}")
            return False

    def save(self) -> bool:
        """Save conflict database."""
        try:
            self._atomic_save()
            return True

        except Exception as exc:
            self._log(f"Save error: {exc}")
            return False

    # ========================================================
    # CREATE CONFLICT
    # ========================================================

    def create_conflict(
        self,
        path: str | Path,
        source_device: str,
        target_device: str,
        base_hash: Optional[str] = None,
        source_hash: Optional[str] = None,
        target_hash: Optional[str] = None,
        source_size: Optional[int] = None,
        target_size: Optional[int] = None,
        source_modified_at: Optional[str] = None,
        target_modified_at: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> ConflictRecord:
        """
        Create and store a new unresolved conflict.
        """

        normalized = normalize_path(path)

        conflict = ConflictRecord(
            conflict_id=str(uuid.uuid4()),
            path=normalized,
            source_device=source_device,
            target_device=target_device,
            base_hash=base_hash,
            source_hash=source_hash,
            target_hash=target_hash,
            source_size=source_size,
            target_size=target_size,
            source_modified_at=source_modified_at,
            target_modified_at=target_modified_at,
            metadata=metadata or {},
        )

        self.data["conflicts"][conflict.conflict_id] = asdict(conflict)

        self.save()

        self._log(
            f"Conflict created: {normalized} "
            f"({source_device} -> {target_device})"
        )

        return conflict

    # ========================================================
    # GET
    # ========================================================

    def get_conflict(
        self,
        conflict_id: str,
    ) -> Optional[ConflictRecord]:
        """Return a conflict by ID."""
        raw = self.data["conflicts"].get(conflict_id)

        if raw is None:
            return None

        return ConflictRecord(**raw)

    def list_conflicts(
        self,
        status: Optional[str] = None,
    ) -> list[ConflictRecord]:
        """
        Return conflicts.

        If status is provided, only conflicts with that status
        are returned.
        """

        result: list[ConflictRecord] = []

        for raw in self.data["conflicts"].values():

            if status is not None and raw.get("status") != status:
                continue

            result.append(
                ConflictRecord(**raw)
            )

        return result

    def get_unresolved(self) -> list[ConflictRecord]:
        """Return all unresolved conflicts."""
        return self.list_conflicts(CONFLICT_UNRESOLVED)

    def has_unresolved(self) -> bool:
        """Return True if unresolved conflicts exist."""
        return len(self.get_unresolved()) > 0

    # ========================================================
    # RESOLUTION
    # ========================================================

    def resolve_conflict(
        self,
        conflict_id: str,
        resolution: str,


resolved_by: str = "manual",
    ) -> bool:
        """
        Resolve a conflict.

        Allowed resolutions:
            pc_wins
            usb_wins
            both
            skip
            manual
        """

        allowed = {
            CONFLICT_PC_WINS,
            CONFLICT_USB_WINS,
            CONFLICT_BOTH,
            CONFLICT_SKIP,
            CONFLICT_MANUAL,
        }

        if resolution not in allowed:
            self._log(
                f"Invalid resolution: {resolution}"
            )
            return False

        raw = self.data["conflicts"].get(conflict_id)

        if raw is None:
            return False

        raw["status"] = resolution
        raw["resolution"] = resolution
        raw["resolved_by"] = resolved_by
        raw["resolved_at"] = utc_now()

        self.save()

        self._log(
            f"Conflict resolved: {conflict_id} -> {resolution}"
        )

        return True

    # ========================================================
    # DELETE
    # ========================================================

    def remove_conflict(
        self,
        conflict_id: str,
    ) -> bool:
        """Remove a conflict record."""
        if conflict_id not in self.data["conflicts"]:
            return False

        del self.data["conflicts"][conflict_id]

        self.save()

        return True

    def clear_resolved(self) -> int:
        """
        Remove all already resolved conflicts.

        Returns number of removed records.
        """

        removable = {
            CONFLICT_PC_WINS,
            CONFLICT_USB_WINS,
            CONFLICT_BOTH,
            CONFLICT_SKIP,
            CONFLICT_MANUAL,
        }

        ids_to_remove = [
            conflict_id
            for conflict_id, raw in self.data["conflicts"].items()
            if raw.get("status") in removable
        ]

        for conflict_id in ids_to_remove:
            del self.data["conflicts"][conflict_id]

        if ids_to_remove:
            self.save()

        return len(ids_to_remove)

    # ========================================================
    # CONFLICT DETECTION
    # ========================================================

    def is_conflict(
        self,
        base_hash: Optional[str],
        source_hash: Optional[str],
        target_hash: Optional[str],
    ) -> bool:
        """
        Determine whether source and target were both changed
        relative to the same base version.

        Logic:

        Base == Source != Target
            -> target changed only

        Base == Target != Source
            -> source changed only

        Base != Source and Base != Target
            -> both changed -> conflict

        Source == Target
            -> same content -> no conflict
        """

        if source_hash is None or target_hash is None:
            return False

        # Both devices already contain identical content.
        if source_hash == target_hash:
            return False

        # Without a base state we cannot safely prove
        # that both sides changed.
        if base_hash is None:
            return False

        source_changed = source_hash != base_hash
        target_changed = target_hash != base_hash

        return source_changed and target_changed

    # ========================================================
    # AUTOMATIC DECISION
    # ========================================================

    def decide_resolution(
        self,
        conflict: ConflictRecord,
        prefer: Optional[str] = None,
    ) -> str:
        """
        Suggest a resolution.

        IMPORTANT:
        The default is MANUAL.

        The manager never silently chooses PC or USB.
        """

        if prefer in {
            CONFLICT_PC_WINS,
            CONFLICT_USB_WINS,
            CONFLICT_BOTH,
            CONFLICT_SKIP,
            CONFLICT_MANUAL,
        }:
            return prefer

        return CONFLICT_MANUAL


    # ========================================================
    # EXPORT
    # ========================================================

    def export_conflicts(self) -> dict[str, Any]:
        """Return a JSON-compatible export."""
        return {
            "conflict_version": self.data.get(
                "conflict_version",
                CONFLICT_VERSION,
            ),
            "created_at": self.data.get("created_at"),
            "updated_at": self.data.get("updated_at"),
            "conflicts": self.data.get("conflicts", {}),
        }

    def save_report(
        self,
        report_path: str | Path,
    ) -> bool:
        """Save a human-readable JSON conflict report."""

        report_path = Path(report_path)
        report_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        try:
            with report_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    self.export_conflicts(),
                    file,
                    ensure_ascii=False,
                    indent=2,
                )

            return True

        except Exception as exc:
            self._log(
                f"Report save error: {exc}"
            )
            return False

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:
        """Return manager status."""

        conflicts = self.list_conflicts()

        unresolved = [
            conflict
            for conflict in conflicts
            if conflict.status == CONFLICT_UNRESOLVED
        ]

        return {
            "conflict_version": CONFLICT_VERSION,
            "storage_path": str(self.storage_path),
            "total_conflicts": len(conflicts),
            "unresolved_conflicts": len(unresolved),
            "resolved_conflicts": (
                len(conflicts) - len(unresolved)
            ),
            "has_unresolved": bool(unresolved),
            "updated_at": self.data.get("updated_at"),
        }

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self) -> tuple[bool, list[str]]:
        """
        Validate conflict database structure.
        """

        errors: list[str] = []

        if not isinstance(self.data, dict):
            errors.append(
                "Root data must be a dictionary"
            )
            return False, errors

        if "conflicts" not in self.data:
            errors.append(
                "Missing conflicts field"
            )

        if not isinstance(
            self.data.get("conflicts"),
            dict,
        ):
            errors.append(
                "Conflicts must be a dictionary"
            )

        return len(errors) == 0, errors

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(self) -> bool:
        """
        Run isolated self-test.

        The test does NOT touch the real JARVIS conflict database.
        """

        with tempfile.TemporaryDirectory() as temp_dir:

            test_storage = (
                Path(temp_dir) / "conflicts.json"
            )

            manager = ConflictManager(
                storage_path=test_storage
            )

            # ------------------------------------------------
            # Test conflict detection
            # ------------------------------------------------

            base_hash = "BASE_HASH"
            pc_hash = "PC_HASH"
            usb_hash = "USB_HASH"

            if not manager.is_conflict(
                base_hash,
                pc_hash,
                usb_hash,
            ):
                return False

            # Same content = no conflict
            if manager.is_conflict(
                base_hash,
                pc_hash,
                pc_hash,
            ):
                return False

            # Only source changed
            if manager.is_conflict(
                base_hash,
                pc_hash,
                base_hash,
            ):
                return False

            # Only target changed
            if manager.is_conflict(
                base_hash,
                base_hash,
                usb_hash,
            ):
                return False

            # ------------------------------------------------
            # Test create
            # ------------------------------------------------

            conflict = manager.create_conflict(
                path="CONFIG/settings.json",
                source_device=SOURCE_PC,
                target_device=SOURCE_USB,
                base_hash=base_hash,
                source_hash=pc_hash,
                target_hash=usb_hash,
                source_size=100,
                target_size=120,
            )

            if not conflict.conflict_id:
                return False

            # ------------------------------------------------
            # Test get
            # ------------------------------------------------

            loaded_conflict = manager.get_conflict(
                conflict.conflict_id
            )

            if loaded_conflict is None:
                return False

            if loaded_conflict.path != "CONFIG/settings.json":
                return False

            # ------------------------------------------------
            # Test unresolved
            # ------------------------------------------------

            if not manager.has_unresolved():
                return False

            if len(manager.get_unresolved()) != 1:
                return False

            # ------------------------------------------------
            # Test decision
            # ------------------------------------------------

            decision = manager.decide_resolution(
                loaded_conflict
            )

            if decision != CONFLICT_MANUAL:
                return False

            # ------------------------------------------------
            # Test resolution
            # ------------------------------------------------

            if not manager.resolve_conflict(
                conflict.conflict_id,
                CONFLICT_PC_WINS,
                resolved_by="self_test",
            ):
                return False

            resolved = manager.get_conflict(
                conflict.conflict_id
            )

            if resolved is None:
                return False

            if resolved.status != CONFLICT_PC_WINS:
                return False

            if resolved.resolved_by != "self_test":
                return False

            # ------------------------------------------------
            # Test persistence
            # ------------------------------------------------

            manager2 = ConflictManager(
                storage_path=test_storage
            )

            persisted = manager2.get_conflict(
                conflict.conflict_id
            )

            if persisted is None:
                return False

            if persisted.status != CONFLICT_PC_WINS:
                return False

            # ------------------------------------------------
            # Test status
            # ------------------------------------------------

            status = manager2.status()

            if status["total_conflicts"] != 1:
                return False

            if status["unresolved_conflicts"] != 0:
                return False

            # ------------------------------------------------
            # Test validation
            # ------------------------------------------------

            valid, errors = manager2.validate()

            if not valid:
                self._log(


 f"Validation errors: {errors}"
                )
                return False

            # ------------------------------------------------
            # Test report
            # ------------------------------------------------

            report_path = (
                Path(temp_dir) / "report.json"
            )

            if not manager2.save_report(
                report_path
            ):
                return False

            if not report_path.exists():
                return False

        return True


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    manager = ConflictManager()

    if manager.self_test():
        print("[+] Self-test: OK")
    else:
        print("[-] Self-test: FAILED")