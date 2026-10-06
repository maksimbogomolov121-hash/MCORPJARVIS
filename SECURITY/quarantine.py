"""
quarantine.py
Карантин подозрительных файлов JARVIS Security Core.

V1 — безопасное перемещение объектов в карантин.
Файлы не удаляются.
"""

import json
import os
import shutil
import uuid
from datetime import datetime


class QuarantineManager:

    def __init__(self, logger=None, quarantine_path=None):

        self.logger = logger

        # ------------------------------------------------------
        # Папка карантина
        # ------------------------------------------------------

        if quarantine_path:

            self.quarantine_path = os.path.abspath(
                quarantine_path
            )

        else:

            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )

            self.quarantine_path = os.path.join(
                project_root,
                "SECURITY_QUARANTINE"
            )

        os.makedirs(
            self.quarantine_path,
            exist_ok=True
        )

        # ------------------------------------------------------
        # Файл базы карантина
        # ------------------------------------------------------

        self.database_path = os.path.join(
            self.quarantine_path,
            "quarantine.json"
        )

        self.records = self._load_database()

        self.log(
            f"Карантин готов: {self.quarantine_path}"
        )

    # ==========================================================
    # Помещение файла в карантин
    # ==========================================================

    def quarantine(self, file_path, reason="", score=0):

        if not file_path:

            self.log(
                "Путь к файлу для карантина не указан."
            )

            return None

        file_path = os.path.abspath(
            os.path.expanduser(file_path)
        )

        if not os.path.isfile(file_path):

            self.log(
                f"Файл не найден: {file_path}"
            )

            return None

        try:

            quarantine_id = str(
                uuid.uuid4()
            )

            original_name = os.path.basename(
                file_path
            )

            safe_name = (
                f"{quarantine_id}_"
                f"{original_name}"
            )

            destination = os.path.join(
                self.quarantine_path,
                safe_name
            )

            # --------------------------------------------------
            # Перемещаем файл
            # --------------------------------------------------

            shutil.move(
                file_path,
                destination
            )

            record = {

                "id":
                    quarantine_id,

                "original_path":
                    file_path,

                "quarantine_path":
                    destination,

                "original_name":
                    original_name,

                "reason":
                    reason,

                "score":
                    score,

                "quarantined_at":
                    datetime.now().isoformat(),

            }

            self.records.append(
                record
            )

            self._save_database()

            self.log(
                f"Файл помещён в карантин: "
                f"{original_name}"
            )

            return record

        except Exception as e:

            self.log(
                f"Ошибка помещения файла "
                f"в карантин: {e}"
            )

            return None

    # ==========================================================
    # Получение списка карантина
    # ==========================================================

    def get_records(self):

        return list(
            self.records
        )

    # ==========================================================
    # Получение количества объектов
    # ==========================================================

    def count(self):

        return len(
            self.records
        )

    # ==========================================================
    # Восстановление файла
    # ==========================================================

    def restore(self, quarantine_id):

        if not quarantine_id:

            return False

        for record in self.records:

            if record.get("id") != quarantine_id:

                continue

            quarantine_path = record.get(
                "quarantine_path"
            )

            original_path = record.get(
                "original_path"
            )

            if not quarantine_path:
                return False

            if not os.path.exists(
                quarantine_path
            ):

                self.log(
                    "Объект карантина не найден."
                )

                return False

            try:

                original_directory = os.path.dirname(
                    original_path
                )

                os.makedirs(
                    original_directory,
                    exist_ok=True
                )

                # --------------------------------------------------
                # Не перезаписываем существующий файл
                # --------------------------------------------------

                destination = original_path

                if os.path.exists(destination):

                    base, extension = os.path.splitext(
                        original_path
                    )

                    destination = (
                        f"{base}_restored"
                        f"{extension}"
                    )

                shutil.move(
                    quarantine_path,
                    destination
                )

                record["restored_path"] = destination

                record["restored_at"] = (
                    datetime.now().isoformat()
                )

                self._save_database()

                self.log(
                    f"Файл восстановлен: {destination}"
                )

                return True

            except Exception as e:

                self.log(
                    f"Ошибка восстановления: {e}"
                )

                return False

        self.log(
            f"Объект карантина не найден: "
            f"{quarantine_id}"
        )

        return False

    # ==========================================================
    # Удаление объекта из карантина
    # ==========================================================

    def delete(self, quarantine_id):

        if not quarantine_id:

            return False

        for record in self.records:

            if record.get("id") != quarantine_id:

                continue

            quarantine_path = record.get(
                "quarantine_path"
            )

            if not quarantine_path:
                return False

            try:

                if os.path.exists(
                    quarantine_path
                ):

                    os.remove(
                        quarantine_path
                    )

                record["deleted"] = True

                record["deleted_at"] = (
                    datetime.now().isoformat()
                )

                self._save_database()

                self.log(
                    f"Объект удалён из карантина: "
                    f"{quarantine_id}"
                )

                return True

            except Exception as e:

                self.log(
                    f"Ошибка удаления объекта "
                    f"из карантина: {e}"
                )

                return False

        return False

    # ==========================================================
    # Очистка базы записей
    # ==========================================================

    def clear_records(self):


        self.records = []

        self._save_database()

        self.log(
            "База карантина очищена."
        )

    # ==========================================================
    # Загрузка базы
    # ==========================================================

    def _load_database(self):

        if not os.path.exists(
            self.database_path
        ):

            return []

        try:

            with open(
                self.database_path,
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(
                    file
                )

            if isinstance(data, list):

                return data

        except Exception as e:

            self.log(
                f"Ошибка загрузки базы карантина: {e}"
            )

        return []

    # ==========================================================
    # Сохранение базы
    # ==========================================================

    def _save_database(self):

        try:

            with open(
                self.database_path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.records,
                    file,
                    ensure_ascii=False,
                    indent=4
                )

        except Exception as e:

            self.log(
                f"Ошибка сохранения базы карантина: {e}"
            )

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )

        else:

            print(
                f"[SECURITY] {message}"
            )