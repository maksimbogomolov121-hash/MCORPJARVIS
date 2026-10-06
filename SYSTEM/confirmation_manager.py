 
"""
confirmation_manager.py
Подтверждение опасных команд JARVIS.
"""


class ConfirmationManager:
    """
    Менеджер подтверждения опасных действий.
    """

    def __init__(self):
        self.pending_action = None

    # -----------------------------------------
    # Запрос подтверждения
    # -----------------------------------------

    def request(self, action: str):

        self.pending_action = action

        return "confirm"

    # -----------------------------------------
    # Подтверждение
    # -----------------------------------------

    def confirm(self):

        action = self.pending_action

        self.pending_action = None

        return action

    # -----------------------------------------
    # Отмена
    # -----------------------------------------

    def cancel(self):

        self.pending_action = None

        return True

    # -----------------------------------------
    # Есть ли ожидающая команда
    # -----------------------------------------

    def has_pending(self):

        return self.pending_action is not None