"""  
main.py
Главная точка входа JARVIS.
"""

import json
import socket
import ollama
import time
import os
import sqlite3
from duckduckgo_search import DDGS  # Библиотека для поиска в интернете

from CORE.startup import Startup

from VOICE.speech_recognition import SpeechRecognition
from VOICE.wake_word import WakeWordDetector
from VOICE.voice_commands import VoiceCommands

# =============================================================
# SECURITY IPC
# =============================================================

SECURITY_HOST = "127.0.0.1"
SECURITY_PORT = 8765
SECURITY_TIMEOUT = 2.0


def security_request(action: str, **kwargs):
    """
    Отправляет запрос работающему Security IPC Server.

    Security является отдельным процессом.
    Если Security недоступен, JARVIS продолжает работу.
    """

    request = {
        "action": action,
        **kwargs,
    }

    try:

        with socket.create_connection(
                (
                        SECURITY_HOST,
                        SECURITY_PORT,
                ),
                timeout=SECURITY_TIMEOUT,
        ) as connection:

            payload = (
                    json.dumps(
                        request,
                        ensure_ascii=False,
                    )
                    + "\n"
            )

            connection.sendall(
                payload.encode("utf-8")
            )

            buffer = b""

            while b"\n" not in buffer:

                data = connection.recv(
                    65536
                )

                if not data:
                    break

                buffer += data

            if not buffer:
                return None

            line = buffer.split(
                b"\n",
                1,
            )[0]

            return json.loads(
                line.decode("utf-8")
            )

    except (
            ConnectionRefusedError,
            TimeoutError,
            socket.timeout,
            OSError,
    ):

        return None

    except Exception as exc:

        print(
            f"[SECURITY IPC] Ошибка: {exc}"
        )

        return None


def connect_to_security():
    """
    Подключает JARVIS к уже работающему Security.

    Возвращает True, если Security успешно обнаружен
    и активирован для JARVIS.
    """

    print(
        "[SECURITY] Проверка подключения..."
    )

    # ---------------------------------------------------------
    # PING
    # ---------------------------------------------------------

    ping_response = security_request(
        "ping"
    )

    if not ping_response:
        print(
            "[SECURITY] Security не обнаружен. "
            "JARVIS продолжает работу автономно."
        )

        return False

    if not ping_response.get("ok"):
        print(
            "[SECURITY] Security ответил с ошибкой."
        )

        return False

    print(
        "[SECURITY] Security IPC: ONLINE"
    )

    # ---------------------------------------------------------
    # JARVIS ON
    # ---------------------------------------------------------

    jarvis_response = security_request(
        "jarvis_on"
    )

    if not jarvis_response:
        print(
            "[SECURITY] Не удалось активировать "
            "связь с JARVIS."
        )

        return False

    if not jarvis_response.get("ok"):
        print(
            "[SECURITY] Security не подтвердил "
            "активацию JARVIS."
        )

        return False

    print(
        "[SECURITY] JARVIS подключён к Security."
    )

    return True


def disconnect_from_security():
    """
    Уведомляет Security о завершении работы JARVIS.
    """

    response = security_request(
        "jarvis_off"
    )

    if response and response.get("ok"):

        print(
            "[SECURITY] JARVIS отключён от Security."
        )

    else:

        # Security мог быть выключен раньше JARVIS.
        # Это не считается ошибкой завершения JARVIS.
        print(
            "[SECURITY] Security недоступен "
            "при завершении JARVIS."
        )


# =============================================================
# ГЛОБАЛЬНЫЕ НАСТРОЙКИ
# =============================================================
DB_FILE = "jarvis_memory.db"
FACTS_FILE = "user_facts.txt"
MAX_HISTORY_LEN = 14


# =============================================================
# ИНСТРУМЕНТ: Поиск в интернете через DuckDuckGo
# =============================================================
def search_web(query: str) -> str:
    """
    Ищет информацию в интернете по запросу и возвращает краткую выжимку.
    Джарвис будет вызывать эту функцию автоматически при необходимости!
    """
    print(f"\n[JARVIS AGENT] Сэр, выполняю поиск в сети по запросу: '{query}'...")
    try:
        with DDGS() as ddgs:
            # Ищем первые 3 самые актуальные ссылки
            results = ddgs.text(query, max_results=3)
            if not results:
                return "В интернете ничего не найдено по этому запросу."

            # Собираем заголовки и текст с сайтов воедино
            compiled_results = []
            for r in results:
                compiled_results.append(f"Источник: {r['title']}\nИнформация: {r['body']}\n")

            return "\n".join(compiled_results)
    except Exception as e:
        return f"Не удалось получить данные из сети из-за ошибки: {e}"


# =============================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ БАЗЫ И ФАЙЛОВ (Оставляем как было)
# =============================================================
def get_all_facts() -> str:
    if not os.path.exists(FACTS_FILE):
        return "Пока нет личных данных."
    try:
        with open(FACTS_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith("#")]
        return "\n".join([f"- {line}" for line in lines]) if lines else "Нет личных данных."
    except:
        return ""


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("""
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, content TEXT NOT NULL
            )
        """)
        conn.commit()


def save_to_db(role: str, content: str):
    with sqlite3.connect(DB_FILE) as conn:
        conn.cursor().execute("INSERT INTO chat_history (role, content) VALUES (?, ?)", (role, content))
        conn.commit()


def load_recent_history() -> list:
    init_db()
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT role, content FROM chat_history ORDER BY id DESC LIMIT ?", (MAX_HISTORY_LEN,))
        return [{'role': str(row[0]), 'content': str(row[1])} for row in reversed(cursor.fetchall())]


# =============================================================
# ИИ ФУНКЦИЯ ДЛЯ ОБЩЕНИЯ С OLLAMA + WEB SEARCH AGENT
# =============================================================
def ask_local_ai(user_question: str) -> str:
    """
    Отправляет запрос в Qwen 2.5. Если вопрос сложный или требует свежих данных,
    нейросеть сама решает пойти в интернет через функцию search_web.
    """
    my_personal_data = get_all_facts()

    system_instruction = (
        "Тебя зовут Джарвис. Ты — высокотехнологичный искусственный интеллект и преданный личный помощник. "
        "Обращайся к пользователю строго 'сэр'. Твой тон — абсолютно спокойный, вежливый, уверенный, но с легкой британской иронией, юмором"
        "Отвечай кратко и по делу (1-2 предложения), но если я задаю какой нибудь ВОПРОС который нужно объяснить по шагам или обширно то говори до 6 предложений. Не используй списки и таблицы.\n"
        "Если пользователь спрашивает факты, погоду, новости или курсы валют на текущий момент, ты ОБЯЗАН использовать инструмент 'search_web' для получения свежей информации из интернета.\n\n"
        f"Важные данные о твоем пользователе:\n{my_personal_data}"
    )

    try:
        messages_to_send = [{'role': 'system', 'content': system_instruction}]
        messages_to_send.extend(load_recent_history())
        messages_to_send.append({'role': 'user', 'content': user_question})

        # Шаг 1: Отправляем запрос в Ollama вместе с описанием нашей функции поиска!
        response = ollama.chat(
            model='qwen2.5:7b',
            messages=messages_to_send,
            tools=[search_web]  # Передаем саму Python-функцию как инструмент!
        )

        # Шаг 2: Проверяем, захотела ли нейросеть вызвать интернет-поиск
        if response.get('message', {}).get('tool_calls'):
            for tool in response['message']['tool_calls']:
                if tool['function']['name'] == 'search_web':
                    # Получаем поисковый запрос, который придумала нейросеть
                    search_query = tool['function']['arguments']['query']

                    # Физически запускаем поиск через Python
                    web_info = search_web(search_query)

                    # Добавляем ответ интернета в историю для ИИ
                    messages_to_send.append(response['message'])
                    messages_to_send.append({
                        'role': 'tool',
                        'content': web_info
                    })

                    # Шаг 3: Делаем повторный запрос в Ollama, передав ей добытые из интернета данные
                    final_response = ollama.chat(model='qwen2.5:7b', messages=messages_to_send)
                    ai_reply = final_response['message']['content']

                    # Сохраняем итог
                    save_to_db('user', user_question)
                    save_to_db('assistant', ai_reply)
                    return ai_reply

        # Если интернет не потребовался — отдаем обычный ответ
        ai_reply = response['message']['content']
        save_to_db('user', user_question)
        save_to_db('assistant', ai_reply)
        return ai_reply

    except Exception as e:
        print(f"[JARVIS AGENT ERROR] Ошибка: {e}")
        return "Сэр, возникли временные неполадки в моих когнитивных цепях."



# =============================================================
# JARVIS MAIN
# =============================================================

def main():
    # ---------------------------------------------
    # Инициализация системы
    # ---------------------------------------------

    startup = Startup()
    startup.initialize()

    # ---------------------------------------------
    # Подключение Security
    # ---------------------------------------------

    security_connected = connect_to_security()

    if security_connected:
        print(
            "[SECURITY] Защита подключена."
        )

        # ---------------------------------------------------------
        # Проверка состояния Security
        # ---------------------------------------------------------

        security_status = security_request(
            "security_status"
        )

        if security_status and security_status.get("ok"):

            print(
                "[SECURITY] Статус Security получен."
            )

            print(
                f"[SECURITY] Состояние: {security_status}"
            )

        else:

            print(
                "[SECURITY] Не удалось получить "
                "статус Security."
            )

    else:
        print(
            "[SECURITY] Работа без подключения Security."
        )

    # ---------------------------------------------
    # Голосовая система
    # ---------------------------------------------

    recognizer = SpeechRecognition()
    wake_word = WakeWordDetector()
    voice_commands = VoiceCommands(startup.speech)

    recognizer.start()

    print("JARVIS готов к работе.")

    # ---------------------------------------------
    # ПЕРЕМЕННЫЕ ДЛЯ АКТИВНОЙ СЕССИИ (БЕЗ ИМЕНИ)
    # ---------------------------------------------
    last_interaction_time = 0.0  # Таймштамп последнего общения
    SESSION_TIMEOUT = 8.0       # Время удержания сессии в секундах

    # ---------------------------------------------
    # Основной цикл
    # ---------------------------------------------

    try:
        while True:
            text = recognizer.listen()

            if not text:
                continue

            print(f"Распознано: {text}")

            # ==================================================
            # РЕЖИМ ОЖИДАНИЯ ПОДТВЕРЖДЕНИЯ
            # ==================================================
            if voice_commands.is_waiting_confirmation():
                result = voice_commands.execute_confirmation(text)
                if result == "shutdown":
                    break
                # При любом подтверждении обновляем таймер сессии
                last_interaction_time = time.time()
                continue

            # ==================================================
            # ПРОВЕРКА АКТИВНОЙ СЕССИИ (Continuous Listening)
            # ==================================================
            current_time = time.time()
            # Проверяем, укладываемся ли мы в 15 секунд с прошлого раза
            is_session_active = (current_time - last_interaction_time) < SESSION_TIMEOUT

            # Проверяем активационное слово
            has_wake_word = wake_word.detect(text)

            # Если сессия уже НЕ активна, и ключевого слова в тексте НЕТ — игнорируем фразу
            if not is_session_active and not has_wake_word:
                continue

            # Выделяем саму команду (если было имя, удаляем его, если нет — оставляем как есть)
            if has_wake_word:
                command = wake_word.remove(text)
            else:
                command = text

            if not command:
                continue

            # Выполняем команду
            result = voice_commands.execute(command)

            # Завершение работы JARVIS
            if result == "shutdown":
                break

            # ==================================================
            # ИНТЕГРАЦИЯ ИИ: Если команда не обработана жестким кодом
            # ==================================================
            if not result:
                print(f"[JARVIS ИИ] Обработка свободного запроса: '{command}'")
                ai_reply = ask_local_ai(command)
                voice_commands.speak(ai_reply)

            # Обновляем время последнего взаимодействия, чтобы продлить сессию еще на 15 секунд
            last_interaction_time = time.time()

    except KeyboardInterrupt:
        print("\nЗавершение работы...")


    finally:

        # ---------------------------------------------
        # Остановка голосовой системы
        # ---------------------------------------------

        recognizer.stop()

        # ---------------------------------------------
        # Отключение от Security
        # ---------------------------------------------

        if security_connected:
            disconnect_from_security()

        # ---------------------------------------------
        # Завершение JARVIS
        # ---------------------------------------------

        startup.shutdown()


# =============================================================
# ENTRY POINT
# =============================================================

if __name__ == "__main__":
    main()
