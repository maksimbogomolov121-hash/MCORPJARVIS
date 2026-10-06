import os

# Автоматически находим путь к Рабочему столу текущего пользователя
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
output_file = os.path.join(desktop_path, "project_code.txt")

with open(output_file, "w", encoding="utf-8") as outfile:
    for root, dirs, files in os.walk("."):
        # Пропускаем виртуальное окружение, папки настроек PyCharm и git, чтобы не собирать мусор
        if "venv" in root or ".git" in root or ".idea" in root or "__pycache__" in root:
            continue

        for file in files:
            if file.endswith(".py") and file != "dump.py":
                file_path = os.path.join(root, file)
                outfile.write(f"\n\n{'=' * 40}\n")
                outfile.write(f"ФАЙЛ: {file_path}\n")
                outfile.write(f"{'=' * 40}\n\n")
                try:
                    with open(file_path, "r", encoding="utf-8") as infile:
                        outfile.write(infile.read())
                except Exception as e:
                    outfile.write(f"Ошибка чтения файла: {e}\n")

print(f"Готово! Весь код твоего проекта собран в файл на Рабочем столе: {output_file}")
