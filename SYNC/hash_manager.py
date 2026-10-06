"""
JARVIS V11 — Hash Manager
=========================

Модуль вычисления и проверки хэшей файлов.

Назначение:
    - вычисление SHA-256;
    - проверка изменения файлов;
    - сравнение хэшей;
    - получение информации о файле;
    - пакетное вычисление хэшей;
    - безопасная работа с отсутствующими файлами.

Hash Manager НЕ выполняет синхронизацию.
Он только отвечает за идентификацию содержимого файлов.

Версия: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


# ============================================================
# CONSTANTS
# ============================================================

MODULE_VERSION = "1.0.0"

DEFAULT_ALGORITHM = "sha256"

# Размер блока чтения файла.
# 1 MB — хороший баланс между скоростью и использованием RAM.
DEFAULT_CHUNK_SIZE = 1024 * 1024


# ============================================================
# HELPERS
# ============================================================

def utc_now() -> str:
    """Возвращает текущее UTC-время в ISO-формате."""
    return datetime.now(timezone.utc).isoformat()


def normalize_path(path: str | Path) -> Path:
    """Возвращает нормализованный абсолютный путь."""
    return Path(path).expanduser().resolve()


# ============================================================
# HASH RESULT
# ============================================================

@dataclass
class HashResult:
    """
    Результат вычисления хэша файла.
    """

    path: str
    algorithm: str
    hash_value: str
    size: int
    modified_at: float
    calculated_at: str

    exists: bool = True
    readable: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует результат в словарь."""
        return {
            "path": self.path,
            "algorithm": self.algorithm,
            "hash": self.hash_value,
            "size": self.size,
            "modified_at": self.modified_at,
            "calculated_at": self.calculated_at,
            "exists": self.exists,
            "readable": self.readable,
            "error": self.error,
        }

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
    ) -> "HashResult":
        """Создаёт HashResult из словаря."""
        return cls(
            path=str(data.get("path", "")),
            algorithm=str(
                data.get(
                    "algorithm",
                    DEFAULT_ALGORITHM,
                )
            ),
            hash_value=str(
                data.get(
                    "hash",
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
                    0.0,
                )
            ),
            calculated_at=str(
                data.get(
                    "calculated_at",
                    utc_now(),
                )
            ),
            exists=bool(
                data.get(
                    "exists",
                    True,
                )
            ),
            readable=bool(
                data.get(
                    "readable",
                    True,
                )
            ),
            error=data.get("error"),
        )


# ============================================================
# HASH MANAGER
# ============================================================

class HashManager:
    """
    Менеджер хэшей JARVIS.

    Основной алгоритм:
        SHA-256

    Ответственность:
        - вычисление хэша;
        - проверка хэша;
        - сравнение файлов;
        - получение метаданных;
        - пакетное хэширование;
        - создание hash snapshot.
    """

    def __init__(
        self,
        algorithm: str = DEFAULT_ALGORITHM,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        logger: Any = None,
    ) -> None:

        self.logger = logger

        self.algorithm = algorithm.lower()

        self.chunk_size = int(chunk_size)

        if self.chunk_size <= 0:
            raise ValueError(
                "chunk_size должен быть больше 0"
            )

        # Проверяем наличие алгоритма.
        try:
            hashlib.new(self.algorithm)
        except ValueError as exc:
            raise ValueError(
                f"Неподдерживаемый алгоритм хэша: "
                f"{self.algorithm}"
            ) from exc

    # ========================================================
    # LOGGING
    # ========================================================

    def _log(
        self,
        level: str,
        message: str,
        *args: Any,
    ) -> None:
        """Безопасное логирование."""

        if self.logger is None:
            return

        method = getattr(
            self.logger,
            level,
            None,
        )

        if callable(method):
            try:
                method(
                    message,
                    *args,
                )
            except Exception:
                pass

    # ========================================================
    # HASH FILE
    # ========================================================

    def calculate_hash(
        self,
        file_path: str | Path,
    ) -> str:
        """
        Вычисляет хэш файла.

        По умолчанию используется SHA-256.

        Файл читается блоками, поэтому большие файлы
        не загружаются полностью в оперативную память.
        """

        path = normalize_path(file_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Файл не найден: {path}"
            )

        if not path.is_file():
            raise IsADirectoryError(
                f"Путь не является файлом: {path}"
            )

        hasher = hashlib.new(
            self.algorithm
        )

        try:

            with path.open(
                "rb"
            ) as file:

                while True:

                    chunk = file.read(
                        self.chunk_size
                    )

                    if not chunk:
                        break

                    hasher.update(
                        chunk
                    )

        except OSError as exc:

            self._log(
                "error",
                "Ошибка чтения файла %s: %s",
                path,
                exc,
            )

            raise

        return hasher.hexdigest()

    # ========================================================
    # HASH RESULT
    # ========================================================

    def calculate_hash_result(
        self,
        file_path: str | Path,
    ) -> HashResult:
        """
        Вычисляет хэш и возвращает полный результат
        вместе с метаданными файла.
        """

        path = normalize_path(file_path)

        try:

            stat = path.stat()

            hash_value = self.calculate_hash(
                path
            )

            return HashResult(
                path=str(path),
                algorithm=self.algorithm,
                hash_value=hash_value,
                size=stat.st_size,
                modified_at=stat.st_mtime,
                calculated_at=utc_now(),
                exists=True,
                readable=True,
                error=None,
            )

        except FileNotFoundError as exc:

            return HashResult(
                path=str(path),
                algorithm=self.algorithm,
                hash_value="",
                size=0,
                modified_at=0.0,
                calculated_at=utc_now(),
                exists=False,
                readable=False,
                error=str(exc),
            )

        except (
            PermissionError,
            OSError,
        ) as exc:

            return HashResult(
                path=str(path),
                algorithm=self.algorithm,
                hash_value="",
                size=0,
                modified_at=0.0,
                calculated_at=utc_now(),
                exists=True,
                readable=False,
                error=str(exc),
            )

    # ========================================================
    # VERIFY HASH
    # ========================================================

    def verify_hash(
        self,
        file_path: str | Path,
        expected_hash: str,
    ) -> bool:
        """
        Проверяет соответствие хэша файла ожидаемому хэшу.
        """

        if not expected_hash:
            return False

        try:

            actual_hash = self.calculate_hash(
                file_path
            )

        except (
            FileNotFoundError,
            IsADirectoryError,
            PermissionError,
            OSError,
        ):

            return False

        return (
            actual_hash.lower()
            == expected_hash.strip().lower()
        )

    # ========================================================
    # COMPARE FILES
    # ========================================================

    def compare_files(
        self,
        first_file: str | Path,
        second_file: str | Path,
    ) -> bool:
        """
        Сравнивает два файла по содержимому.

        Возвращает True, если содержимое идентично.
        """

        first = normalize_path(
            first_file
        )

        second = normalize_path(
            second_file
        )

        if not first.exists():
            return False

        if not second.exists():
            return False

        if not first.is_file():
            return False

        if not second.is_file():
            return False

        # ----------------------------------------------------
        # Быстрая проверка размера.
        # ----------------------------------------------------

        try:

            first_size = first.stat().st_size
            second_size = second.stat().st_size

        except OSError:

            return False

        if first_size != second_size:
            return False

        # ----------------------------------------------------
        # Если это один и тот же файл.
        # ----------------------------------------------------

        try:

            if first.samefile(second):
                return True

        except OSError:
            pass

        # ----------------------------------------------------
        # Сравнение содержимого.
        # ----------------------------------------------------

        try:

            first_hash = self.calculate_hash(
                first
            )

            second_hash = self.calculate_hash(
                second
            )

        except OSError:

            return False

        return first_hash == second_hash

    # ========================================================
    # GET FILE INFO
    # ========================================================

    def get_file_info(
            self,
            file_path: str | Path,
    ) -> Dict[str, Any]:
        """
        Возвращает базовую информацию о файле
        вместе с SHA-256 хэшем.

        Возвращаемые поля:
            path
            exists
            is_file
            size
            modified_at
            hash
            algorithm
        """

        path = normalize_path(
            file_path
        )

        try:

            stat = path.stat()

        except FileNotFoundError:

            return {
                "path": str(path),
                "exists": False,
                "is_file": False,
                "size": 0,
                "modified_at": None,
                "hash": "",
                "algorithm": self.algorithm,
            }

        except OSError as exc:

            return {
                "path": str(path),
                "exists": False,
                "is_file": False,
                "size": 0,
                "modified_at": None,
                "hash": "",
                "algorithm": self.algorithm,
                "error": str(exc),
            }

        if not path.is_file():
            return {
                "path": str(path),
                "exists": True,
                "is_file": False,
                "size": stat.st_size,
                "modified_at": stat.st_mtime,
                "hash": "",
                "algorithm": self.algorithm,
            }

        try:

            hash_value = self.calculate_hash(
                path
            )

        except (
                PermissionError,
                OSError,
        ) as exc:

            return {
                "path": str(path),
                "exists": True,
                "is_file": True,
                "size": stat.st_size,
                "modified_at": stat.st_mtime,
                "hash": "",
                "algorithm": self.algorithm,
                "error": str(exc),
            }

        return {
            "path": str(path),
            "exists": True,
            "is_file": True,
            "size": stat.st_size,
            "modified_at": stat.st_mtime,
            "hash": hash_value,
            "algorithm": self.algorithm,
        }

    # ========================================================
    # HASH DIRECTORY
    # ========================================================

    def hash_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
        extensions: Optional[Iterable[str]] = None,
    ) -> Dict[str, HashResult]:
        """
        Вычисляет хэши всех файлов в папке.

        extensions:
            Необязательный список расширений.

        Например:
            [".json", ".txt"]
        """

        root = normalize_path(
            directory
        )

        if not root.exists():
            raise FileNotFoundError(
                f"Папка не найдена: {root}"
            )

        if not root.is_dir():
            raise NotADirectoryError(
                f"Путь не является папкой: {root}"
            )

        normalized_extensions = None

        if extensions is not None:

            normalized_extensions = {
                extension.lower()
                if extension.startswith(".")
                else f".{extension.lower()}"
                for extension in extensions
            }

        if recursive:
            files = root.rglob("*")
        else:
            files = root.glob("*")

        results: Dict[
            str,
            HashResult
        ] = {}

        for path in files:

            if not path.is_file():
                continue

            if normalized_extensions is not None:

                if (
                    path.suffix.lower()
                    not in normalized_extensions
                ):
                    continue

            result = self.calculate_hash_result(
                path
            )

            results[str(path)] = result

        return results

    # ========================================================
    # HASH DIRECTORY AS DICT
    # ========================================================

    def create_snapshot(
        self,
        directory: str | Path,
        recursive: bool = True,
        extensions: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Создаёт hash snapshot папки.

        Snapshot — это состояние файлов на определённый
        момент времени.

        Он будет использоваться Manifest Manager
        и Change Detector.
        """

        results = self.hash_directory(
            directory=directory,
            recursive=recursive,
            extensions=extensions,
        )

        files: Dict[str, Any] = {}

        root = normalize_path(
            directory
        )

        for absolute_path, result in results.items():

            try:

                relative_path = str(
                    Path(absolute_path).relative_to(
                        root
                    )
                )

            except ValueError:

                relative_path = Path(
                    absolute_path
                ).name

            files[
                relative_path
            ] = result.to_dict()

        return {
            "module_version": MODULE_VERSION,
            "algorithm": self.algorithm,
            "created_at": utc_now(),
            "root": str(root),
            "file_count": len(files),
            "files": files,
        }

    # ========================================================
    # SAVE SNAPSHOT
    # ========================================================

    def save_snapshot(
        self,
        snapshot: Dict[str, Any],
        output_path: str | Path,
    ) -> None:
        """Сохраняет snapshot в JSON."""

        path = normalize_path(
            output_path
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temp_path = path.with_suffix(
            ".tmp"
        )

        try:

            with temp_path.open(
                "w",
                encoding="utf-8",
            ) as file:

                json.dump(
                    snapshot,
                    file,
                    ensure_ascii=False,
                    indent=4,
                )

            temp_path.replace(
                path
            )

        except OSError as exc:

            self._log(
                "error",
                "Ошибка сохранения hash snapshot: %s",
                exc,
            )

            try:

                if temp_path.exists():
                    temp_path.unlink()

            except OSError:
                pass

            raise

    # ========================================================
    # LOAD SNAPSHOT
    # ========================================================

    def load_snapshot(
        self,
        snapshot_path: str | Path,
    ) -> Dict[str, Any]:
        """Загружает hash snapshot."""

        path = normalize_path(
            snapshot_path
        )

        if not path.exists():
            raise FileNotFoundError(
                f"Snapshot не найден: {path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if not isinstance(
            data,
            dict,
        ):
            raise ValueError(
                "Некорректный формат hash snapshot"
            )

        return data

    # ========================================================
    # HASH MAP
    # ========================================================

    def get_hash_map(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> Dict[str, str]:
        """
        Возвращает простой словарь:

            относительный путь -> hash
        """

        root = normalize_path(
            directory
        )

        results = self.hash_directory(
            root,
            recursive=recursive,
        )

        hash_map: Dict[
            str,
            str
        ] = {}

        for absolute_path, result in results.items():

            try:

                relative = str(
                    Path(
                        absolute_path
                    ).relative_to(
                        root
                    )
                )

            except ValueError:

                relative = Path(
                    absolute_path
                ).name

            hash_map[
                relative
            ] = result.hash_value

        return hash_map

    # ========================================================
    # COMPARE HASH MAPS
    # ========================================================

    def compare_hash_maps(
        self,
        old_map: Dict[str, str],
        new_map: Dict[str, str],
    ) -> Dict[str, List[str]]:
        """
        Сравнивает два hash map.

        Результат:

            added
            modified
            deleted
            unchanged
        """

        old_files = set(
            old_map.keys()
        )

        new_files = set(
            new_map.keys()
        )

        added = sorted(
            new_files - old_files
        )

        deleted = sorted(
            old_files - new_files
        )

        common = (
            old_files
            & new_files
        )

        modified: List[str] = []
        unchanged: List[str] = []

        for path in sorted(common):

            old_hash = str(
                old_map[path]
            ).lower()

            new_hash = str(
                new_map[path]
            ).lower()

            if old_hash == new_hash:
                unchanged.append(path)
            else:
                modified.append(path)

        return {
            "added": added,
            "modified": modified,
            "deleted": deleted,
            "unchanged": unchanged,
        }

    # ========================================================
    # STATUS
    # ========================================================

    def status(self) -> Dict[str, Any]:
        """Возвращает статус Hash Manager."""

        return {
            "module": "HashManager",
            "version": MODULE_VERSION,
            "algorithm": self.algorithm,
            "chunk_size": self.chunk_size,
        }


# ============================================================
# SELF TEST
# ============================================================

def self_test() -> bool:
    """
    Полный автономный тест Hash Manager.

    Используется временная папка.
    Основные файлы JARVIS не изменяются.
    """

    import tempfile

    with tempfile.TemporaryDirectory() as temp_dir:

        root = Path(temp_dir)

        # ----------------------------------------------------
        # CREATE TEST FILES
        # ----------------------------------------------------

        file_a = (
            root
            / "test_a.txt"
        )

        file_b = (
            root
            / "test_b.txt"
        )

        sub_dir = (
            root
            / "sub"
        )

        sub_dir.mkdir()

        file_c = (
            sub_dir
            / "test_c.txt"
        )

        file_a.write_text(
            "JARVIS TEST DATA",
            encoding="utf-8",
        )

        file_b.write_text(
            "JARVIS TEST DATA",
            encoding="utf-8",
        )

        file_c.write_text(
            "SECOND FILE",
            encoding="utf-8",
        )

        # ----------------------------------------------------
        # MANAGER
        # ----------------------------------------------------

        manager = HashManager()

        # ----------------------------------------------------
        # HASH
        # ----------------------------------------------------

        hash_a = manager.calculate_hash(
            file_a
        )

        hash_b = manager.calculate_hash(
            file_b
        )

        if not hash_a:
            return False

        if hash_a != hash_b:
            return False

        # ----------------------------------------------------
        # DIFFERENT CONTENT
        # ----------------------------------------------------

        file_b.write_text(
            "DIFFERENT DATA",
            encoding="utf-8",
        )

        hash_b_new = manager.calculate_hash(
            file_b
        )

        if hash_a == hash_b_new:
            return False

        # ----------------------------------------------------
        # VERIFY
        # ----------------------------------------------------

        if not manager.verify_hash(
            file_a,
            hash_a,
        ):
            return False

        if manager.verify_hash(
            file_b,
            hash_a,
        ):
            return False

        # ----------------------------------------------------
        # COMPARE FILES
        # ----------------------------------------------------

        file_b.write_text(
            "JARVIS TEST DATA",
            encoding="utf-8",
        )

        if not manager.compare_files(
            file_a,
            file_b,
        ):
            return False

        file_b.write_text(
            "DIFFERENT AGAIN",
            encoding="utf-8",
        )

        if manager.compare_files(
            file_a,
            file_b,
        ):
            return False

        # ----------------------------------------------------
        # FILE INFO
        # ----------------------------------------------------

        info = manager.get_file_info(
            file_a
        )

        if not info["exists"]:
            return False

        if not info["is_file"]:
            return False

        if info["size"] <= 0:
            return False

        if not info["hash"]:
            return False

        # ----------------------------------------------------
        # DIRECTORY HASH
        # ----------------------------------------------------

        directory_hashes = manager.hash_directory(
            root
        )

        if len(directory_hashes) != 3:
            return False

        # ----------------------------------------------------
        # HASH MAP
        # ----------------------------------------------------

        hash_map = manager.get_hash_map(
            root
        )

        if len(hash_map) != 3:
            return False

        if "test_a.txt" not in hash_map:
            return False

        if "sub\\test_c.txt" not in hash_map:
            # На Linux-подобных окружениях может быть "/".
            if "sub/test_c.txt" not in hash_map:
                return False

        # ----------------------------------------------------
        # SNAPSHOT
        # ----------------------------------------------------

        snapshot = manager.create_snapshot(
            root
        )

        if snapshot["file_count"] != 3:
            return False

        if snapshot["algorithm"] != "sha256":
            return False

        # ----------------------------------------------------
        # SAVE / LOAD
        # ----------------------------------------------------

        snapshot_path = (
            root
            / "snapshot.json"
        )

        manager.save_snapshot(
            snapshot,
            snapshot_path,
        )

        if not snapshot_path.exists():
            return False

        loaded = manager.load_snapshot(
            snapshot_path
        )

        if loaded["file_count"] != 3:
            return False

        # ----------------------------------------------------
        # COMPARE HASH MAPS
        # ----------------------------------------------------

        old_map = {
            "a.txt": "111",
            "b.txt": "222",
            "deleted.txt": "333",
        }

        new_map = {
            "a.txt": "111",
            "b.txt": "999",
            "new.txt": "444",
        }

        comparison = (
            manager.compare_hash_maps(
                old_map,
                new_map,
            )
        )

        if comparison["added"] != [
            "new.txt"
        ]:
            return False

        if comparison["modified"] != [
            "b.txt"
        ]:
            return False

        if comparison["deleted"] != [
            "deleted.txt"
        ]:
            return False

        if comparison["unchanged"] != [
            "a.txt"
        ]:
            return False

        # ----------------------------------------------------
        # MISSING FILE
        # ----------------------------------------------------

        missing = manager.calculate_hash_result(
            root / "missing.txt"
        )

        if missing.exists:
            return False

        if missing.readable:
            return False

        # ----------------------------------------------------
        # STATUS
        # ----------------------------------------------------

        status = manager.status()

        if status["algorithm"] != "sha256":
            return False

        return True


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("JARVIS V11 — HASH MANAGER")
    print("=" * 70)

    print()
    print(
        f"[i] Версия модуля: {MODULE_VERSION}"
    )

    print(
        f"[i] Алгоритм: {DEFAULT_ALGORITHM.upper()}"
    )

    print(
        f"[i] Размер блока: "
        f"{DEFAULT_CHUNK_SIZE:,} bytes"
    )

    print()
    print("SELF-TEST")

    try:

        result = self_test()

        if result:

            print(
                "[+] Self-test: OK"
            )

        else:

            print(
                "[X] Self-test: FAILED"
            )

            raise SystemExit(1)

        print()
        print("STATUS")

        manager = HashManager()

        print(
            json.dumps(


        manager.status(),
                ensure_ascii=False,
                indent=4,
            )
        )

        print()
        print(
            "[+] Hash Manager готов."
        )

    except Exception as exc:

        print(
            f"[X] Ошибка: {exc}"
        )

        raise