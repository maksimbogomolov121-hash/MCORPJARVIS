 
"""
jarvis_manager.py
Управление самим JARVIS.
"""


class JarvisManager:

    def __init__(self, logger=None):
        self.logger = logger

    # ---------------------------------------------
    # Выключение JARVIS
    # ---------------------------------------------

    def shutdown(self):

        self.log("Получена команда выключения JARVIS")

        return "shutdown"

    # ---------------------------------------------
    # Логирование
    # ---------------------------------------------

    def log(self, message):

        if self.logger:
            self.logger.info(message)