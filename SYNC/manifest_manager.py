"""
JARVIS V11
SYNC / MANIFEST MANAGER
Version: 1.0

Назначение:
    Управление manifest.json для системы синхронизации JARVIS.

Manifest хранит:
    - информацию об устройстве;
    - версию синхронизации;
    - время создания/обновления;
    - список синхронизируемых файлов;
    - SHA-256 каждого файла;
    - размер файла;
    - время изменения;
    - версию файла.

Модуль НЕ выполняет синхронизацию.
Он только создаёт, читает, обновляет и проверяет manifest.
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

MANIFEST_VERSION = 1
MANIFEST_FILENAME = "manifest.json"

HASH_ALGORITHM = "sha256"


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """
    Возвращает текущее UTC-время в ISO 8601.
    """
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: Path) -> str:
    """
    Приводит путь к строке с единым разделителем '/'.
    """
    return path.as_posix()


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class ManifestFile:
    """
    Информация об одном файле в manifest.
    """

    path: str
    hash_value: str
    size: int
    modified_at: float
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ManifestFile":
        return cls(
            path=str(data["path"]),
            hash_value=str(data["hash_value"]),
            size=int(data["size"]),
            modified_at=float(data["modified_at"]),
            version=int(data.get("version", 1)),
        )


# ============================================================
# MANIFEST MANAGER
# ============================================================

class ManifestManager:
    """
    Менеджер manifest.json.

    Основные задачи:
        - создание manifest;
        - загрузка/сохранение;
        - добавление файлов;
        - удаление файлов;
        - обновление информации;
        - получение hash map;
        - проверка структуры;
        - экспорт состояния.
    """

    def __init__(
        self,
        manifest_path: Optional[Path | str] = None,
        device_info: Optional[dict[str, Any]] = None,
    ):
        """
        Args:
            manifest_path:
                Путь к manifest.json.

            device_info:
                Информация об устройстве.
                Может быть результатом DeviceManager.status()
                или обычным словарём.
        """

        if manifest_path is None:
            manifest_path = (
                Path(__file__).resolve().parent / MANIFEST_FILENAME
            )

        self.manifest_path = Path(manifest_path).resolve()

        self.device_info = device_info or {}

        self.manifest: dict[str, Any] = {}

        if self.manifest_path.exists():
            self.load()
        else:
            self.create_empty()

    # ========================================================
    # LOGGING
    # ========================================================

    def _log(self, message: str) -> None:
        """
        Внутренний простой лог.
        """
        print(f"[ManifestManager] {message}")

    # ========================================================
    # CREATE
    # ========================================================

    def create_empty(self) -> dict[str, Any]:
        """
        Создаёт пустой manifest.
        """

        now = utc_now()

        self.manifest = {
            "manifest_version": MANIFEST_VERSION,

            "created_at": now,

            "updated_at": now,

            "sync_version": 1,

            "device": self.device_info,

            "files": {},
        }

        return self.manifest

    # ========================================================
    # LOAD
    # ========================================================

    def load(self) -> dict[str, Any]:
        """
        Загружает manifest с диска.
        """

        if not self.manifest_path.exists():
            self._log("Manifest не найден. Создаю новый.")
            return self.create_empty()

        try:
            with self.manifest_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(file)

            if not isinstance(data, dict):
                raise ValueError("Manifest должен быть JSON-объектом.")

            self.manifest = data

            self._ensure_structure()

            return self.manifest

        except Exception as exc:
            raise RuntimeError(
                f"Не удалось загрузить manifest: {exc}"
            ) from exc

    # ========================================================
    # SAVE
    # ========================================================

    def save(self) -> Path:
        """
        Безопасно сохраняет manifest.

        Сначала создаётся временный файл,
        затем он атомарно заменяет основной.
        """

        self.manifest_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.manifest["updated_at"] = utc_now()

        fd, temp_name = tempfile.mkstemp(
            prefix=".manifest_",
            suffix=".tmp",
            dir=str(self.manifest_path.parent),
        )

        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    self.manifest,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temp_name,
                self.manifest_path,
            )

        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass

            raise

        return self.manifest_path

    # ========================================================
    # STRUCTURE
    # ========================================================

    def _ensure_structure(self) -> None:
        """
        Проверяет наличие обязательных разделов.
        """

        if "manifest_version" not in self.manifest:
            self.manifest["manifest_version"] = MANIFEST_VERSION

        if "created_at" not in self.manifest:
            self.manifest["created_at"] = utc_now()

        if "updated_at" not in self.manifest:
            self.manifest["updated_at"] = utc_now()

        if "sync_version" not in self.manifest:
            self.manifest["sync_version"] = 1

        if "device" not in self.manifest:
            self.manifest["device"] = self.device_info

        if "files" not in self.manifest:
            self.manifest["files"] = {}

        if not isinstance(
            self.manifest["files"],
            dict,
        ):
            raise ValueError(
                "Поле 'files' должно быть объектом."
            )

    # ========================================================
    # DEVICE
    # ========================================================

    def set_device_info(
        self,
        device_info: dict[str, Any],
    ) -> None:
        """
        Обновляет информацию об устройстве.
        """

        self.device_info = dict(device_info)

        self.manifest["device"] = self.device_info
        self.manifest["updated_at"] = utc_now()

    def get_device_info(self) -> dict[str, Any]:
        """

Максим (09:07):
Возвращает информацию об устройстве.
        """

        return dict(
            self.manifest.get(
                "device",
                {},
            )
        )

    # ========================================================
    # SYNC VERSION
    # ========================================================

    def get_sync_version(self) -> int:
        """
        Возвращает глобальную версию manifest.
        """

        return int(
            self.manifest.get(
                "sync_version",
                1,
            )
        )

    def increment_sync_version(self) -> int:
        """
        Увеличивает версию синхронизации.
        """

        current = self.get_sync_version()

        current += 1

        self.manifest["sync_version"] = current
        self.manifest["updated_at"] = utc_now()

        return current

    # ========================================================
    # FILE OPERATIONS
    # ========================================================

    def add_file(
        self,
        path: Path | str,
        hash_value: str,
        size: int,
        modified_at: float,
        version: int = 1,
    ) -> ManifestFile:
        """
        Добавляет файл в manifest.
        """

        file_path = normalize_path(
            Path(path)
        )

        file_info = ManifestFile(
            path=file_path,
            hash_value=str(hash_value),
            size=int(size),
            modified_at=float(modified_at),
            version=int(version),
        )

        self.manifest["files"][file_path] = (
            file_info.to_dict()
        )

        self.manifest["updated_at"] = utc_now()

        return file_info

    def update_file(
        self,
        path: Path | str,
        hash_value: str,
        size: int,
        modified_at: float,
        version: Optional[int] = None,
    ) -> ManifestFile:
        """
        Обновляет существующий файл.

        Если version не передана:
            существующая версия увеличивается на 1.

        Если файла ещё нет:
            создаётся версия 1.
        """

        file_path = normalize_path(
            Path(path)
        )

        existing = self.manifest["files"].get(
            file_path
        )

        if existing is None:
            new_version = 1
        elif version is None:
            new_version = (
                int(existing.get("version", 1))
                + 1
            )
        else:
            new_version = int(version)

        return self.add_file(
            path=file_path,
            hash_value=hash_value,
            size=size,
            modified_at=modified_at,
            version=new_version,
        )

    def remove_file(
        self,
        path: Path | str,
    ) -> bool:
        """
        Удаляет файл из manifest.

        Возвращает:
            True  — файл был найден и удалён.
            False — файла не было.
        """

        file_path = normalize_path(
            Path(path)
        )

        if file_path not in self.manifest["files"]:
            return False

        del self.manifest["files"][file_path]

        self.manifest["updated_at"] = utc_now()

        return True

    def has_file(
        self,
        path: Path | str,
    ) -> bool:
        """
        Проверяет наличие файла в manifest.
        """

        file_path = normalize_path(
            Path(path)
        )

        return (
            file_path
            in self.manifest["files"]
        )

    def get_file(
        self,
        path: Path | str,
    ) -> Optional[ManifestFile]:
        """
        Возвращает информацию о файле.
        """

        file_path = normalize_path(
            Path(path)
        )

        data = self.manifest["files"].get(
            file_path
        )

        if data is None:
            return None

        return ManifestFile.from_dict(data)

    # ========================================================
    # FILE LIST
    # ========================================================

    def list_files(self) -> list[str]:
        """
        Возвращает список всех файлов manifest.
        """

        return sorted(
            self.manifest["files"].keys()
        )

    def get_file_count(self) -> int:
        """
        Возвращает количество файлов.
        """

        return len(
            self.manifest["files"]
        )

    # ========================================================
    # HASH MAP
    # ========================================================

    def get_hash_map(self) -> dict[str, str]:
        """
        Возвращает:

            {
                "CONFIG/config.json": "...sha256...",
                "DATA/data.json": "...sha256..."
            }
        """

        result: dict[str, str] = {}

        for path, data in self.manifest[
            "files"
        ].items():

            result[path] = str(
                data.get(
                    "hash_value",
                    "",
                )
            )

        return result

    # ========================================================
    # FILE VERSIONS
    # ========================================================

    def get_file_version(
        self,
        path: Path | str,
    ) -> Optional[int]:
        """
        Возвращает версию конкретного файла.
        """

        file_info = self.get_file(path)

        if file_info is None:
            return None

        return file_info.version

    # ========================================================
    # REBUILD FROM HASH MAP
    # ========================================================

    def rebuild_from_hash_map(
        self,
        hash_map: dict[str, str],
        file_metadata: Optional[
            dict[str, dict[str, Any]]
        ] = None,
    ) -> None:
        """
        Полностью перестраивает список файлов
        на основании hash map.

        file_metadata может содержать:

            {
                "CONFIG/a.json": {
                    "size": 100,
                    "modified_at": 1234567890
                }
            }

        Если metadata нет:
            size = 0
            modified_at = 0
        """

        file_metadata = file_metadata or {}

        self.manifest["files"] = {}

        for path, hash_value in hash_map.items():

            metadata = file_metadata.get(
                path,
                {},
            )

            self.add_file(
                path=path,
                hash_value=hash_value,
                size=int(
                    metadata.get(
                        "size",
                        0,
                    )
                ),
                modified_at=float(
                    metadata.get(
                        "modified_at",
                        0,
                    )
                ),
                version=int(
                    metadata.get(
                        "version",
                        1,
                    )
                ),
            )

    # ========================================================
    # CLEAR
    # ========================================================

    def clear_files(self) -> None:
        """
        Полностью очищает список файлов.
        """

        self.manifest["files"] = {}
        self.manifest["updated_at"] = utc_now()

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate(self) -> tuple[bool, list[str]]:
        """
        Проверяет manifest.

        Возвращает:

            (True, [])

        или:

            (False, ["ошибка 1", "ошибка 2"])
        """

        errors: list[str] = []

        if not isinstance(
            self.manifest,
            dict,
        ):
            errors.append(
                "Manifest не является объектом."
            )
            return False, errors


        if "manifest_version" not in self.manifest:
            errors.append(
                "Отсутствует manifest_version."
            )

        if "created_at" not in self.manifest:
            errors.append(
                "Отсутствует created_at."
            )

        if "updated_at" not in self.manifest:
            errors.append(
                "Отсутствует updated_at."
            )

        if "sync_version" not in self.manifest:
            errors.append(
                "Отсутствует sync_version."
            )

        if "device" not in self.manifest:
            errors.append(
                "Отсутствует device."
            )

        if "files" not in self.manifest:
            errors.append(
                "Отсутствует files."
            )

        if not isinstance(
            self.manifest.get(
                "files",
                None,
            ),
            dict,
        ):
            errors.append(
                "files должен быть объектом."
            )
            return False, errors

        for path, data in self.manifest[
            "files"
        ].items():

            if not isinstance(
                path,
                str,
            ):
                errors.append(
                    "Обнаружен некорректный путь."
                )

            if not isinstance(
                data,
                dict,
            ):
                errors.append(
                    f"Некорректная запись файла: {path}"
                )
                continue

            required_fields = (
                "path",
                "hash_value",
                "size",
                "modified_at",
                "version",
            )

            for field in required_fields:
                if field not in data:
                    errors.append(
                        f"{path}: отсутствует {field}"
                    )

            if "hash_value" in data:
                hash_value = str(
                    data["hash_value"]
                )

                if len(hash_value) != 64:
                    errors.append(
                        f"{path}: некорректный SHA-256."
                    )

            if "size" in data:
                try:
                    if int(data["size"]) < 0:
                        errors.append(
                            f"{path}: отрицательный размер."
                        )
                except (
                    TypeError,
                    ValueError,
                ):
                    errors.append(
                        f"{path}: некорректный размер."
                    )

            if "version" in data:
                try:
                    if int(data["version"]) < 1:
                        errors.append(
                            f"{path}: некорректная версия."
                        )
                except (
                    TypeError,
                    ValueError,
                ):
                    errors.append(
                        f"{path}: некорректная версия."
                    )

        return (
            len(errors) == 0,
            errors,
        )

    # ========================================================
    # EXPORT
    # ========================================================

    def export(self) -> dict[str, Any]:
        """
        Возвращает независимую копию manifest.
        """

        return json.loads(
            json.dumps(
                self.manifest,
                ensure_ascii=False,
            )
        )

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> dict[str, Any]:
        """
        Возвращает краткий статус.
        """

        valid, errors = self.validate()

        return {
            "manifest_path": str(
                self.manifest_path
            ),
            "exists": self.manifest_path.exists(),


              "manifest_version": self.manifest.get(
                "manifest_version"
            ),
            "sync_version": self.get_sync_version(),
            "device": self.get_device_info(),
            "file_count": self.get_file_count(),
            "valid": valid,
            "errors": errors,
            "created_at": self.manifest.get(
                "created_at"
            ),
            "updated_at": self.manifest.get(
                "updated_at"
            ),
        }

    # ========================================================
    # SELF TEST
    # ========================================================

    @staticmethod
    def self_test() -> bool:
        """
        Полный автономный тест ManifestManager.
        """

        test_dir = Path(
            tempfile.mkdtemp(
                prefix="jarvis_manifest_test_"
            )
        )

        manifest_path = (
            test_dir / MANIFEST_FILENAME
        )

        try:
            # --------------------------------------------
            # 1. CREATE
            # --------------------------------------------

            device = {
                "device_id": "TEST-DEVICE-001",
                "device_type": "PC",
                "name": "Test PC",
            }

            manager = ManifestManager(
                manifest_path=manifest_path,
                device_info=device,
            )

            assert (
                manager.get_file_count() == 0
            )

            # --------------------------------------------
            # 2. ADD FILE
            # --------------------------------------------

            hash_a = "a" * 64

            manager.add_file(
                path="CONFIG/config.json",
                hash_value=hash_a,
                size=123,
                modified_at=1000.0,
            )

            assert manager.has_file(
                "CONFIG/config.json"
            )

            assert (
                manager.get_file_count() == 1
            )

            file_info = manager.get_file(
                "CONFIG/config.json"
            )

            assert file_info is not None
            assert file_info.hash_value == hash_a
            assert file_info.size == 123
            assert file_info.version == 1

            # --------------------------------------------
            # 3. UPDATE FILE
            # --------------------------------------------

            hash_b = "b" * 64

            manager.update_file(
                path="CONFIG/config.json",
                hash_value=hash_b,
                size=456,
                modified_at=2000.0,
            )

            updated = manager.get_file(
                "CONFIG/config.json"
            )

            assert updated is not None
            assert updated.hash_value == hash_b
            assert updated.size == 456
            assert updated.version == 2

            # --------------------------------------------
            # 4. ADD SECOND FILE
            # --------------------------------------------

            hash_c = "c" * 64

            manager.add_file(
                path="DATA/test.json",
                hash_value=hash_c,
                size=789,
                modified_at=3000.0,
            )

            assert (
                manager.get_file_count() == 2
            )

            # --------------------------------------------
            # 5. HASH MAP
            # --------------------------------------------

            hash_map = manager.get_hash_map()

            assert (
                hash_map["CONFIG/config.json"]
                == hash_b
            )

            assert (
                hash_map["DATA/test.json"]
                == hash_c
            )

            # --------------------------------------------
            # 6. FILE LIST
            # --------------------------------------------

            files = manager.list_files()

            assert (


                "CONFIG/config.json"
                in files
            )

            assert (
                "DATA/test.json"
                in files
            )

            # --------------------------------------------
            # 7. VALIDATION
            # --------------------------------------------

            valid, errors = manager.validate()

            assert valid
            assert errors == []

            # --------------------------------------------
            # 8. SYNC VERSION
            # --------------------------------------------

            old_version = (
                manager.get_sync_version()
            )

            new_version = (
                manager.increment_sync_version()
            )

            assert (
                new_version
                == old_version + 1
            )

            # --------------------------------------------
            # 9. SAVE
            # --------------------------------------------

            saved_path = manager.save()

            assert saved_path.exists()

            # --------------------------------------------
            # 10. LOAD
            # --------------------------------------------

            manager2 = ManifestManager(
                manifest_path=manifest_path,
            )

            assert (
                manager2.get_file_count() == 2
            )

            loaded = manager2.get_file(
                "CONFIG/config.json"
            )

            assert loaded is not None
            assert loaded.hash_value == hash_b
            assert loaded.version == 2

            # --------------------------------------------
            # 11. REMOVE
            # --------------------------------------------

            removed = manager2.remove_file(
                "DATA/test.json"
            )

            assert removed

            assert not manager2.has_file(
                "DATA/test.json"
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

            status = manager2.status()

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
            # --------------------------------------------
            # CLEANUP
            # --------------------------------------------

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
    ManifestManager.self_test()