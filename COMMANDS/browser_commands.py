 
"""
browser_commands.py
Команды браузера и поиска для JARVIS.
"""

import webbrowser
import urllib.parse


class BrowserCommands:

    def __init__(self, logger=None):
        self.logger = logger

        self.sites = {
            "ютуб": "https://youtube.com",
            "youtube": "https://youtube.com",

            "гугл": "https://google.com",
            "google": "https://google.com",

            "яндекс": "https://yandex.ru",

            "вконтакте": "https://vk.com",
            "вк": "https://vk.com",

            "почта": "https://mail.google.com",

            "чат": "https://chat.openai.com",

            "погода": "https://yandex.ru/pogoda"
                      
                      }


    # ---------------------------------------------
    # Обработка команды браузера
    # ---------------------------------------------

    def execute(self, command):

        command = command.lower()


        # Открытие сайтов

        for name, url in self.sites.items():

            if name in command:

                return self.open_site(
                    url,
                    name
                )


        # Поиск в интернете

        if "найди" in command or "поиск" in command:

            query = self.get_search_query(
                command
            )

            if query:
                return self.search(query)


        self.log(
            f"Команда браузера не распознана: {command}"
        )

        return False



    # ---------------------------------------------
    # Открытие сайта
    # ---------------------------------------------

    def open_site(self, url, name):

        try:

            webbrowser.open(url)


            self.log(
                f"Открыт сайт: {name}"
            )


            return True


        except Exception as e:

            self.log(
                f"Ошибка открытия сайта: {e}"
            )

            return False



    # ---------------------------------------------
    # Поиск в интернете
    # ---------------------------------------------

    def search(self, query):

        try:

            encoded = urllib.parse.quote(
                query
            )

            url = (
                "https://www.google.com/search?q="
                + encoded
            )


            webbrowser.open(url)


            self.log(
                f"Поиск: {query}"
            )


            return True


        except Exception as e:

            self.log(
                f"Ошибка поиска: {e}"
            )

            return False



    # ---------------------------------------------
    # Получение текста поиска
    # ---------------------------------------------

    def get_search_query(self, command):

        words = [
            "найди",
            "поиск",
            "мне"
        ]


        query = command


        for word in words:

            query = query.replace(
                word,
                ""
            )


        return query.strip()



    # ---------------------------------------------
    # Логирование
    # ---------------------------------------------

    def log(self, message):

        if self.logger:
            self.logger.info(message)