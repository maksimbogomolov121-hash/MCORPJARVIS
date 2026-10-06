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

VERSION_MANAGER_VERSION = 1
VERSION_FILENAME = "versions.json"

DEVICE_PC = "pc"
DEVICE_USB = "usb"
DEVICE_MOBILE = "mobile"

VERSION_STATUS_ACTIVE = "active"
VERSION_STATUS_REPLACED = "replaced"
VERSION_STATUS_DELETED = "deleted"

DEFAULT_VERSION = 1


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """Return current UTC time in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str | Path) -> str:
    """Normalize paths for cross-platform storage."""
    return str(path).replace("\\", "/").strip("/")


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class FileVersion:
    """
    Describes one concrete version of a file.
    """

    version_id: str
    path: str
    version: int

    hash_value: Optional[str]

    device_id: str
    device_type: str

    size: Optional[int] = None
    modified_at: Optional[str] = None

    created_at: str = field(
        default_factory=utc_now
    )

    status: str = VERSION_STATUS_ACTIVE

    parent_version_id: Optional[str] = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


# ============================================================
# VERSION MANAGER
# ============================================================

class VersionManager:
    """
    Manages file versions used by the synchronization system.

    Important:
        VersionManager does NOT copy files.

        It only records and tracks versions.

    Actual file operations belong to SyncEngine.
    """

    def __init__(
        self,
        storage_path: str | Path | None = None,
    ) -> None:

        if storage_path is None:
            storage_path = (
                Path(__file__).resolve().parent
                / VERSION_FILENAME
            )

        self.storage_path = Path(storage_path)

        self.data: dict[str, Any] = {
            "version_manager_version": (
                VERSION_MANAGER_VERSION
            ),
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "files": {},
        }

        self.load()

    # ========================================================
    # INTERNAL
    # ========================================================

    def _log(self, message: str) -> None:
        """Temporary internal logger."""
        print(f"[VersionManager] {message}")

    def _atomic_save(self) -> None:
        """Save database atomically."""

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

        temp_path.replace(
            self.storage_path
        )

    # ========================================================
    # LOAD / SAVE
    # ========================================================

    def load(self) -> bool:
        """Load version database."""

        if not self.storage_path.exists():
            return False

        try:

            with self.storage_path.open(
                "r",
                encoding="utf-8",
            ) as file:

                loaded = json.load(file)

            if not isinstance(
                loaded,
                dict,
            ):
                return False

            self.data = loaded

            if "files" not in self.data:
                self.data["files"] = {}

            return True

        except Exception as exc:

            self._log(
                f"Load error: {exc}"
            )

            return False

    def save(self) -> bool:
        """Save version database."""

        try:

            self._atomic_save()

            return True

        except Exception as exc:

            self._log(
                f"Save error: {exc}"
            )

            return False

    # ========================================================
    # VERSION CREATION
    # ========================================================

    def create_version(
        self,
        path: str | Path,
        hash_value: Optional[str],
        device_id: str,
        device_type: str,
        size: Optional[int] = None,
        modified_at: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> FileVersion:
        """
        Create a new version for a file.

        The version number is automatically incremented.
        """

        normalized_path = normalize_path(path)

        current = self.get_current_version(
            normalized_path
        )

        if current is None:

            next_version = DEFAULT_VERSION
            parent_id = None

        else:

            next_version = (
                current.version + 1
            )

            parent_id = current.version_id

            current.status = (
                VERSION_STATUS_REPLACED
            )

        version = FileVersion(
            version_id=str(uuid.uuid4()),
            path=normalized_path,
            version=next_version,
            hash_value=hash_value,
            device_id=device_id,
            device_type=device_type,
            size=size,
            modified_at=modified_at,
            parent_version_id=parent_id,
            metadata=metadata or {},
        )

        if normalized_path not in self.data["files"]:

            self.data["files"][normalized_path] = []

        self.data["files"][normalized_path].append(
            asdict(version)
        )

        self.save()

        self._log(
            f"Created version "
            f"{normalized_path} -> v{next_version}"
        )

        return version

    # ========================================================
    # GET CURRENT VERSION
    # ========================================================

    def get_current_version(
        self,
        path: str | Path,
    ) -> Optional[FileVersion]:
        """
        Return the active/latest version of a file.
        """

        normalized_path = normalize_path(path)

        versions = self.data["files"].get(
            normalized_path,
            [],
        )

        if not versions:
            return None

        active_versions = [
            raw
            for raw in versions
            if raw.get("status")
            == VERSION_STATUS_ACTIVE
        ]

        if active_versions:

            latest = max(
                active_versions,
                key=lambda item: item.get(
                    "version",
                    0,
                ),
            )

            return FileVersion(**latest)

        latest = max(
            versions,
            key=lambda item: item.get(
                "version",
                0,
            ),
        )

        return FileVersion(**latest)

    # ========================================================
    # GET VERSION BY NUMBER
    # ========================================================

    def get_version(
        self,
        path: str | Path,
        version_number: int,
    ) -> Optional[FileVersion]:
        """Return a specific numbered version."""

        normalized_path = normalize_path(path)

        versions = self.data["files"].get(
            normalized_path,
            [],
        )

        for raw in versions:

            if raw.get("version") == version_number:

                return FileVersion(**raw)

        return None

    # ========================================================
    # GET VERSION BY ID
    # ========================================================

    def get_version_by_id(
        self,
        version_id: str,
    ) -> Optional[FileVersion]:
        """Return a version using its UUID."""

        for versions in self.data["files"].values():

            for raw in versions:

                if raw.get("version_id") == version_id:

                    return FileVersion(**raw)

        return None

    # ========================================================
    # LIST VERSIONS
    # ========================================================

    def list_versions(
        self,
        path: str | Path,
    ) -> list[FileVersion]:
        """Return all versions of a file."""

        normalized_path = normalize_path(path)

        versions = self.data["files"].get(
            normalized_path,
            [],
        )

        return [
            FileVersion(**raw)
            for raw in versions
        ]

    def list_all_versions(self) -> list[FileVersion]:
        """Return every stored file version."""

        result: list[FileVersion] = []

        for versions in self.data["files"].values():

            for raw in versions:

                result.append(
                    FileVersion(**raw)
                )

        return result

    # ========================================================
    # VERSION COUNT
    # ========================================================

    def version_count(
        self,
        path: str | Path,
    ) -> int:
        """Return number of versions for a file."""

        return len(
            self.list_versions(path)
        )

    # ========================================================
    # FILE LIST
    # ========================================================

    def list_files(self) -> list[str]:
        """Return all files known to VersionManager."""

        return sorted(
            self.data["files"].keys()
        )

    # ========================================================
    # DELETE / MARK DELETED
    # ========================================================

    def mark_deleted(
        self,
        path: str | Path,
        device_id: str,
        device_type: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> FileVersion:
        """
        Create a deleted version marker.

        The physical file is NOT deleted here.
        """

        normalized_path = normalize_path(path)

        current = self.get_current_version(
            normalized_path
        )

        if current is None:

            next_version = DEFAULT_VERSION
            parent_id = None

        else:

            next_version = (
                current.version + 1
            )

            parent_id = current.version_id

            current.status = (
                VERSION_STATUS_REPLACED
            )

        deleted_version = FileVersion(
            version_id=str(uuid.uuid4()),
            path=normalized_path,
            version=next_version,
            hash_value=None,
            device_id=device_id,
            device_type=device_type,
            size=None,
            modified_at=None,
            status=VERSION_STATUS_DELETED,
            parent_version_id=parent_id,
            metadata=metadata or {},
        )

        if normalized_path not in self.data["files"]:

            self.data["files"][normalized_path] = []

        self.data["files"][normalized_path].append(
            asdict(deleted_version)
        )

        self.save()

        self._log(
            f"Marked deleted: "
            f"{normalized_path} -> v{next_version}"
        )

        return deleted_version


    # ========================================================
    # RESTORE / REACTIVATE
    # ========================================================

    def restore_version(
        self,
        path: str | Path,
        version_number: int,
    ) -> Optional[FileVersion]:
        """
        Mark a historical version as active.

        This only changes metadata.
        The actual file restoration belongs to SyncEngine/Backup.
        """

        normalized_path = normalize_path(path)

        versions = self.data["files"].get(
            normalized_path,
            [],
        )

        target: Optional[dict[str, Any]] = None

        for raw in versions:

            if raw.get("version") == version_number:

                target = raw
                break

        if target is None:
            return None

        for raw in versions:

            if raw is target:
                continue

            if raw.get("status") == VERSION_STATUS_ACTIVE:

                raw["status"] = (
                    VERSION_STATUS_REPLACED
                )

        target["status"] = VERSION_STATUS_ACTIVE

        target["metadata"] = {
            **target.get("metadata", {}),
            "restored_at": utc_now(),
        }

        self.save()

        self._log(
            f"Restored metadata version "
            f"{normalized_path} -> v{version_number}"
        )

        return FileVersion(**target)

    # ========================================================
    # HASH COMPARISON
    # ========================================================

    def is_same_content(
        self,
        path: str | Path,
        hash_value: Optional[str],
    ) -> bool:
        """
        Check whether the supplied hash matches
        the current stored version.
        """

        current = self.get_current_version(path)

        if current is None:
            return False

        if hash_value is None:
            return False

        return (
            current.hash_value
            == hash_value
        )

    # ========================================================
    # VERSION COMPARISON
    # ========================================================

    def compare_versions(
        self,
        path: str | Path,
        version_a: int,
        version_b: int,
    ) -> Optional[dict[str, Any]]:
        """
        Compare two versions of the same file.
        """

        first = self.get_version(
            path,
            version_a,
        )

        second = self.get_version(
            path,
            version_b,
        )

        if first is None or second is None:
            return None

        return {
            "path": normalize_path(path),
            "version_a": first.version,
            "version_b": second.version,
            "hash_a": first.hash_value,
            "hash_b": second.hash_value,
            "same_hash": (
                first.hash_value
                == second.hash_value
            ),
            "size_a": first.size,
            "size_b": second.size,
            "same_size": (
                first.size
                == second.size
            ),
            "device_a": first.device_id,
            "device_b": second.device_id,
        }

    # ========================================================
    # HISTORY
    # ========================================================

    def get_history(
        self,
        path: str | Path,
    ) -> list[dict[str, Any]]:
        """
        Return chronological version history.
        """

        versions = self.list_versions(path)

        versions.sort(
            key=lambda item: item.version
        )

        return [
            asdict(version)
            for version in versions
        ]

    # ========================================================
    # EXPORT
    # ========================================================

    def export(self) -> dict[str, Any]:


        """Return complete JSON-compatible export."""

        return {
            "version_manager_version": (
                VERSION_MANAGER_VERSION
            ),
            "created_at": self.data.get(
                "created_at"
            ),
            "updated_at": self.data.get(
                "updated_at"
            ),
            "files": self.data.get(
                "files",
                {},
            ),
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:
        """Return manager status."""

        all_versions = (
            self.list_all_versions()
        )

        active = [
            version
            for version in all_versions
            if version.status
            == VERSION_STATUS_ACTIVE
        ]

        deleted = [
            version
            for version in all_versions
            if version.status
            == VERSION_STATUS_DELETED
        ]

        return {
            "version_manager_version": (
                VERSION_MANAGER_VERSION
            ),
            "storage_path": str(
                self.storage_path
            ),
            "files": len(
                self.data.get(
                    "files",
                    {},
                )
            ),
            "total_versions": len(
                all_versions
            ),
            "active_versions": len(
                active
            ),
            "deleted_versions": len(
                deleted
            ),
            "updated_at": self.data.get(
                "updated_at"
            ),
        }

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self) -> tuple[bool, list[str]]:
        """Validate internal database."""

        errors: list[str] = []

        if not isinstance(
            self.data,
            dict,
        ):
            errors.append(
                "Root data must be a dictionary"
            )
            return False, errors

        if "files" not in self.data:

            errors.append(
                "Missing files field"
            )

        if not isinstance(
            self.data.get("files"),
            dict,
        ):

            errors.append(
                "Files field must be a dictionary"
            )

        for path, versions in (
            self.data.get(
                "files",
                {},
            ).items()
        ):

            if not isinstance(
                versions,
                list,
            ):

                errors.append(
                    f"Versions for {path} "
                    f"must be a list"
                )

                continue

            numbers: list[int] = []

            for raw in versions:

                if "version" not in raw:

                    errors.append(
                        f"Missing version "
                        f"for {path}"
                    )

                    continue

                numbers.append(
                    raw["version"]
                )

            if numbers:

                expected = list(
                    range(
                        1,
                        max(numbers) + 1,
                    )
                )

                if sorted(numbers) != expected:

                    errors.append(
                        f"Invalid version sequence "
                        f"for {path}"
                    )

        return len(errors) == 0, errors

    # ========================================================
    # SELF TEST
    # ========================================================

    def self_test(self) -> bool:
        """
        Run isolated self-test.

        The real VersionManager database
        is never touched.
        """

        with tempfile.TemporaryDirectory() as temp_dir:

            storage = (
                Path(temp_dir)
                / VERSION_FILENAME
            )

            manager = VersionManager(
                storage_path=storage
            )

            # ------------------------------------------------
            # Create first version
            # ------------------------------------------------

            version1 = manager.create_version(
                path="CONFIG/settings.json",
                hash_value="HASH_1",
                device_id="PC_TEST",
                device_type=DEVICE_PC,
                size=100,
                modified_at=utc_now(),
            )

            if version1.version != 1:
                return False

            if version1.status != VERSION_STATUS_ACTIVE:
                return False

            # ------------------------------------------------
            # Create second version
            # ------------------------------------------------

            version2 = manager.create_version(
                path="CONFIG/settings.json",
                hash_value="HASH_2",
                device_id="USB_TEST",
                device_type=DEVICE_USB,
                size=120,
                modified_at=utc_now(),
            )

            if version2.version != 2:
                return False

            if version2.status != VERSION_STATUS_ACTIVE:
                return False

            # ------------------------------------------------
            # Check previous version
            # ------------------------------------------------

            loaded_v1 = manager.get_version(
                "CONFIG/settings.json",
                1,
            )

            if loaded_v1 is None:
                return False

            if loaded_v1.status != VERSION_STATUS_REPLACED:
                return False

            # ------------------------------------------------
            # Current version
            # ------------------------------------------------

            current = manager.get_current_version(
                "CONFIG/settings.json"
            )

            if current is None:
                return False

            if current.version != 2:
                return False

            if current.hash_value != "HASH_2":
                return False

            # ------------------------------------------------
            # Count
            # ------------------------------------------------

            if manager.version_count(
                "CONFIG/settings.json"
            ) != 2:
                return False

            # ------------------------------------------------
            # Same content
            # ------------------------------------------------

            if not manager.is_same_content(
                "CONFIG/settings.json",
                "HASH_2",
            ):
                return False

            if manager.is_same_content(
                "CONFIG/settings.json",
                "WRONG_HASH",
            ):
                return False

            # ------------------------------------------------
            # Compare versions
            # ------------------------------------------------

            comparison = manager.compare_versions(
                "CONFIG/settings.json",
                1,
                2,
            )

            if comparison is None:
                return False

            if comparison["same_hash"]:
                return False

            if comparison["hash_a"] != "HASH_1":
                return False

            if comparison["hash_b"] != "HASH_2":
                return False

            # ------------------------------------------------
            # History
            # ------------------------------------------------

            history = manager.get_history(
                "CONFIG/settings.json"
            )

            if len(history) != 2:
                return False


            if history[0]["version"] != 1:
                return False

            if history[1]["version"] != 2:
                return False

            # ------------------------------------------------
            # Mark deleted
            # ------------------------------------------------

            deleted = manager.mark_deleted(
                path="CONFIG/settings.json",
                device_id="USB_TEST",
                device_type=DEVICE_USB,
            )

            if deleted.version != 3:
                return False

            if deleted.status != VERSION_STATUS_DELETED:
                return False

            # ------------------------------------------------
            # Current version should now be deleted
            # ------------------------------------------------

            current_deleted = (
                manager.get_current_version(
                    "CONFIG/settings.json"
                )
            )

            if current_deleted is None:
                return False

            if current_deleted.version != 3:
                return False

            if current_deleted.status != VERSION_STATUS_DELETED:
                return False

            # ------------------------------------------------
            # Restore version 2
            # ------------------------------------------------

            restored = manager.restore_version(
                "CONFIG/settings.json",
                2,
            )

            if restored is None:
                return False

            if restored.version != 2:
                return False

            if restored.status != VERSION_STATUS_ACTIVE:
                return False

            # ------------------------------------------------
            # Verify current version after restore
            # ------------------------------------------------

            current_restored = (
                manager.get_current_version(
                    "CONFIG/settings.json"
                )
            )

            if current_restored is None:
                return False

            if current_restored.version != 2:
                return False

            # ------------------------------------------------
            # Persistence
            # ------------------------------------------------

            manager2 = VersionManager(
                storage_path=storage
            )

            persisted = manager2.get_current_version(
                "CONFIG/settings.json"
            )

            if persisted is None:
                return False

            if persisted.version != 2:
                return False

            # ------------------------------------------------
            # Validation
            # ------------------------------------------------

            valid, errors = manager2.validate()

            if not valid:

                self._log(
                    f"Validation errors: {errors}"
                )

                return False

            # ------------------------------------------------
            # Status
            # ------------------------------------------------

            status = manager2.status()

            if status["files"] != 1:
                return False

            if status["total_versions"] != 3:
                return False

            # ------------------------------------------------
            # Export
            # ------------------------------------------------

            exported = manager2.export()

            if "files" not in exported:
                return False

            if (
                "CONFIG/settings.json"
                not in exported["files"]
            ):
                return False

        return True


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    manager = VersionManager()

    if manager.self_test():

        print("[+] Self-test: OK")

    else:

        print("[-] Self-test: FAILED")