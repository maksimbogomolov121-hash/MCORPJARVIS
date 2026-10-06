"""
command_handler.py
Главный маршрутизатор команд JARVIS.
"""

from COMMANDS.system_commands import SystemCommands
from COMMANDS.app_commands import AppCommands
from COMMANDS.browser_commands import BrowserCommands
from COMMANDS.media_commands import MediaCommands
from COMMANDS.utility_commands import UtilityCommands
from COMMANDS.universal_open import UniversalOpen

from SYSTEM.window_manager import WindowManager
from SYSTEM.jarvis_manager import JarvisManager
from SYSTEM.PC_monitor import PCMonitor
from SYSTEM.backup_manager import BackupManager


class CommandHandler:
    """
    Главный маршрутизатор команд JARVIS.

    Получает текстовую команду и передаёт её
    соответствующему модулю.
    """

    def __init__(self, logger=None, speech_output=None):

        self.logger = logger

        self.speech = speech_output

        # Управление окнами
        self.window = WindowManager(logger)

        # Загрузка всех подсистем
        self.load_modules()

        # Универсальное открытие
        self.universal_open = UniversalOpen(
            app_commands=self.apps,
            logger=self.logger,
            speech=self.speech
        )

    # ==========================================================
    # Загрузка модулей
    # ==========================================================

    def load_modules(self):

        self.system = SystemCommands(
            self.logger
        )

        self.apps = AppCommands(
            self.logger
        )

        self.browser = BrowserCommands(
            self.logger
        )

        self.media = MediaCommands(
            self.logger
        )

        self.utility = UtilityCommands(
            self.logger
        )

        self.jarvis = JarvisManager(
            self.logger
        )

        self.pc_monitor = PCMonitor(
            self.logger
        )

        self.backup = BackupManager(
            self.logger
        )

        self.log(
            "Модули команд загружены"
        )

    # ==========================================================
    # Главный обработчик
    # ==========================================================

    def execute(self, command):

        if not command:
            return False

        command = command.lower().strip()

        self.log(
            f"Команда получена: {command}"
        )

        # ======================================================
        # Управление самим JARVIS
        # ======================================================

        if "выключись" in command:

            return self.jarvis.shutdown()

        # ======================================================
        # Управление окнами
        # ======================================================

        if "закрой окно" in command:

            return self.window.close_window()

        if "сверни все окна" in command:

            return self.window.minimize_all()

        # ======================================================
        # Мониторинг компьютера
        # ======================================================

        if any(word in command for word in [
            "анализ системы",
            "состояние компьютера",
            "нагрузка процессора",
            "нагрузка cpu",
            "процессор",
            "оперативная память",
            "использование памяти",
            "свободное место"
        ]):

            result = self.pc_monitor.execute(
                command
            )

            if result:
                return result

        # ======================================================
        # Скриншот
        # ======================================================

        if "скриншот" in command:

            return self.system.screenshot()

        # ======================================================
        # Резервная копия
        # ======================================================

        if any(phrase in command for phrase in [
            "создай резервную копию",
            "сделай резервную копию",
            "создай бэкап",
            "сделай бэкап",
            "создай копию"
        ]):

            return self.backup.create_backup()

        # ======================================================
        # Системные команды
        # ======================================================

        if any(word in command for word in [
            "выключи компьютер",
            "перезагрузи компьютер",
            "заблокируй экран",
            "спящий режим",
            "включи ночной режим",
            "выключи ночной режим",
            "ночной режим",
            "обычный режим",
            "выключи интернет",
            "подтверждаю",
            "отмена"
        ]):

            return self.system.execute(
                command
            )

        # ======================================================
        # Медиа
        # ======================================================

        if (
                "включи музыку" in command
                or "запусти музыку" in command
                or "начни музыку" in command
                or "следующий трек" in command
                or "предыдущий трек" in command
                or "дальше" in command
                or "назад" in command
                or "громче" in command
                or "тише" in command
                or "громкость" in command
                or "выключи звук" in command
                or "включи звук" in command
                or "стоп" in command
                or "продолжи" in command
        ):

            result = self.media.execute(command)

            if result:
                return result

        # ======================================================
        # Запуск приложений
        # ======================================================

        if "открой" in command:

            result = self.universal_open.execute(
                command
            )

            if result:
                return result

        # ======================================================
        # Браузер и интернет
        #
        # ВАЖНО:
        # "вк" здесь НЕТ.
        # ======================================================

        if any(word in command for word in [
            "найди",
            "поиск",
            "сайт",
            "ютуб",
            "youtube",
            "гугл",
            "google",
            "яндекс",
            "погода",
            "вконтакте",
            "почта"
        ]):

            result = self.browser.execute(
                command
            )

            if result:
                return result

        # ======================================================
        # Утилиты
        # ======================================================

        if any(word in command for word in [
            "время",
            "сколько времени",
            "дата",
            "число",
            "какое сегодня число",
            "день недели",
            "калькулятор",
            "информация о компьютере",
            "другой язык",
            "блютуз",
            "bluetooth",
            "очисти корзину",
            "очисти темп",
            "сколько памяти",
            "че там по памяти"
        ]):

            result = self.utility.execute(
                command
            )

            if result:
                return result

        # ======================================================
        # Команда не распознана
        # ======================================================

        self.log(
            f"Команда не распознана: {command}"
        )

        return False

    # ==========================================================
    # Логирование
    # ==========================================================

    def log(self, message):

        if self.logger:

            self.logger.info(
                message
            )

        else:

            print(message)