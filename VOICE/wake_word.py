 # Voice/wake_word.py


class WakeWordDetector:
    """
    Модуль активационных слов JARVIS.
    """

    def __init__(self):

        self.wake_words = [
            "джарвис",
            "эйджарвис",
            "брат",
            "жарвис",
            "жарви",
            "джарви",
            "дружище",
            "чарльз",
            "жажду",
            "жаль",
            "шарлиз",
            "прат"
        ]

        self.active = True

# ===============================
    # Удалить активационное слово
    # ===============================

    def remove(self, text):

        text = text.lower()

        for word in self.wake_words:

            if word in text:
                text = text.replace(word, "", 1)

        return text.strip()

    # ===============================
    # Проверка активации
    # ===============================

    def detect(self, text):

        if not self.active:
            return False

        text = text.lower().strip()

        for word in self.wake_words:

            if word in text:
                return True

        return False


    # ===============================
    # Добавить новое слово
    # ===============================

    def add_word(self, word):

        word = word.lower()

        if word not in self.wake_words:
            self.wake_words.append(word)


    # ===============================
    # Удалить слово
    # ===============================

    def remove_word(self, word):

        word = word.lower()

        if word in self.wake_words:
            self.wake_words.remove(word)


    # ===============================
    # Включение / выключение
    # ===============================

    def enable(self):

        self.active = True


    def disable(self):

        self.active = False


    # ===============================
    # Получить список слов
    # ===============================

    def get_words(self):

        return self.wake_words