"""
DESKTOP/active_target.py

Определение активного объекта Windows Explorer:
файла или папки, выделенного пользователем.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
import ctypes
import json
import subprocess


class ActiveTarget:
    """Получает текущий выделенный объект в Проводнике Windows."""

    def __init__(self, logger=None):
        self.logger = logger

    def _log(self, message: str) -> None:
        if self.logger:
            try:
                self.logger.info(message)
            except Exception:
                pass

    def get_selected(self) -> Optional[dict]:
        """
        Возвращает текущий выделенный объект.

        Результат:
        {
            "type": "file" | "folder",
            "path": "C:\\...",
            "name": "...",
            "exists": True
        }

        Если объект определить не удалось — None.
        """

        script = r'''
$explorer = New-Object -ComObject Shell.Application

foreach ($window in $explorer.Windows()) {

    try {
        if ($window.Name -ne "File Explorer") {
            continue
        }

        $selection = $window.Document.SelectedItems()

        if ($selection.Count -eq 0) {
            continue
        }

        # Берём первый выделенный объект.
        $item = $selection.Item(0)

        $path = $item.Path

        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if (Test-Path -LiteralPath $path -PathType Container) {
            $type = "folder"
        }
        elseif (Test-Path -LiteralPath $path -PathType Leaf) {
            $type = "file"
        }
        else {
            $type = "unknown"
        }

        [PSCustomObject]@{
            type   = $type
            path   = $path
            name   = $item.Name
            exists = Test-Path -LiteralPath $path
        } | ConvertTo-Json -Compress

        break
    }
    catch {
        continue
    }
}
'''

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=3,
            )

            output = result.stdout.strip()

            if not output:
                self._log("Выделенный объект не найден.")
                return None

            data = json.loads(output)

            path = data.get("path")

            if not path:
                return None

            path_obj = Path(path)

            if not path_obj.exists():
                return None

            target_type = data.get("type")

            if target_type not in ("file", "folder"):
                return None

            target = {
                "type": target_type,
                "path": str(path_obj.resolve()),
                "name": data.get("name") or path_obj.name,
                "exists": True,
            }

            self._log(
                f"Активный объект: {target['type']} → {target['path']}"
            )

            return target

        except subprocess.TimeoutExpired:
            self._log("Получение активного объекта превысило время ожидания.")
            return None

        except json.JSONDecodeError:
            self._log("Не удалось разобрать ответ PowerShell.")
            return None

        except Exception as exc:
            self._log(f"Ошибка определения активного объекта: {exc}")
            return None

    def get_selected_file(self) -> Optional[str]:
        """Возвращает путь выделенного файла."""

        target = self.get_selected()

        if target and target["type"] == "file":
            return target["path"]

        return None

    def get_selected_folder(self) -> Optional[str]:

        """Возвращает путь выделенной папки."""

        target = self.get_selected()

        if target and target["type"] == "folder":
            return target["path"]

        return None

    def is_file_selected(self) -> bool:
        """Проверяет, выделен ли файл."""

        return self.get_selected_file() is not None

    def is_folder_selected(self) -> bool:
        """Проверяет, выделена ли папка."""

        return self.get_selected_folder() is not None

    def get_target_path(self) -> Optional[str]:
        """Возвращает путь любого выделенного файла или папки."""

        target = self.get_selected()

        if target:
            return target["path"]

        return None

    def get_target_type(self) -> Optional[str]:
        """Возвращает тип выделенного объекта."""

        target = self.get_selected()

        if target:
            return target["type"]

        return None

    def get_target_info(self) -> Optional[dict]:
        """Возвращает полную информацию об активном объекте."""

        return self.get_selected()


if __name__ == "__main__":
    target = ActiveTarget()

    print("=" * 50)
    print("JARVIS Active Target Test")
    print("=" * 50)

    result = target.get_selected()

    if result:
        print(f"Тип:     {result['type']}")
        print(f"Имя:     {result['name']}")
        print(f"Путь:    {result['path']}")
        print(f"Существует: {result['exists']}")
    else:
        print("Выделенный файл или папка не найдены.")

    print("=" * 50)