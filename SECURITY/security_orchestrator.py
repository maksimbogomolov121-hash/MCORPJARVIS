"""
security_orchestrator.py

Диспетчер JARVIS Security.

V2.4

Отвечает за координацию:
- файлового сканирования;
- сканирования процессов;
- сканирования автозагрузки;
- сканирования USB;
- поведенческого анализа;
- формирования единого результата;
- статистики;
- журналирования.

ВАЖНО:
Orchestrator НЕ выполняет автоматический карантин.
Он только обнаруживает, анализирует и собирает результаты.
"""


class SecurityOrchestrator:

    # ==========================================================
    # ИНИЦИАЛИЗАЦИЯ
    # ==========================================================

    def __init__(
        self,
        security_core,
        logger=None
    ):

        self.security = security_core

        if logger is not None:

            self.logger = logger

        else:

            self.logger = getattr(
                security_core,
                "logger",
                None
            )

        self.last_result = None

        self.log(
            "Security Orchestrator V2.4 инициализирован."
        )

    # ==========================================================
    # ПОЛНЫЙ SECURITY SCAN
    # ==========================================================

    def full_scan(
        self,
        path=None,
        include_files=True,
        include_processes=True,
        include_startup=True,
        include_usb=True,
        include_behavior=True
    ):

        self.log(
            "Запуск полного Security Scan."
        )

        result = {

            "success": True,

            "files": [],

            "processes": [],

            "startup": [],

            "usb": [],

            "behavior": {},

            "statistics": {},

            "errors": []

        }

        # ======================================================
        # ФАЙЛЫ
        # ======================================================

        if include_files:

            if path:

                self.log(
                    f"Сканирование файлов: {path}"
                )

                try:

                    files = (
                        self.security.scan(
                            path
                        )
                    )

                    if files is None:

                        files = []

                    result["files"] = list(
                        files
                    )

                except Exception as e:

                    result["success"] = False

                    result["errors"].append(
                        {
                            "component": "files",
                            "error": str(e)
                        }
                    )

                    self.log(
                        f"Ошибка сканирования файлов: {e}"
                    )

            else:

                self.log(
                    "Сканирование файлов пропущено: "
                    "путь не указан."
                )

        # ======================================================
        # ПРОЦЕССЫ
        # ======================================================

        if include_processes:

            self.log(
                "Сканирование процессов."
            )

            try:

                processes = (
                    self.security.scan_processes()
                )

                if processes is None:

                    processes = []

                result["processes"] = list(
                    processes
                )

            except Exception as e:

                result["success"] = False

                result["errors"].append(
                    {
                        "component": "processes",
                        "error": str(e)
                    }
                )

                self.log(
                    f"Ошибка сканирования процессов: {e}"
                )

        # ======================================================
        # АВТОЗАГРУЗКА
        # ======================================================

        if include_startup:

            self.log(
                "Сканирование автозагрузки."
            )

            try:

                startup = (
                    self.security.scan_startup()
                )

                if startup is None:

                    startup = []

                result["startup"] = list(
                    startup
                )

            except Exception as e:

                result["success"] = False

                result["errors"].append(
                    {
                        "component": "startup",
                        "error": str(e)
                    }
                )

                self.log(
                    f"Ошибка сканирования автозагрузки: {e}"
                )

        # ======================================================
        # USB
        # ======================================================

        if include_usb:

            self.log(
                "Сканирование USB."
            )

            try:

                usb = (
                    self.security.scan_usb()
                )

                if usb is None:

                    usb = []

                result["usb"] = list(
                    usb
                )

            except Exception as e:

                result["success"] = False

                result["errors"].append(
                    {
                        "component": "usb",
                        "error": str(e)
                    }
                )

                self.log(
                    f"Ошибка сканирования USB: {e}"
                )

        # ======================================================
        # ПОВЕДЕНИЕ
        # ======================================================

        if include_behavior:

            self.log(
                "Проверка поведения."
            )

            try:

                behavior = (
                    self.security.check_behavior()
                )

                if behavior is None:

                    behavior = {}

                result["behavior"] = behavior

            except Exception as e:

                result["success"] = False

                result["errors"].append(
                    {
                        "component": "behavior",
                        "error": str(e)
                    }
                )

                self.log(
                    f"Ошибка поведенческого анализа: {e}"
                )

        # ======================================================
        # СТАТИСТИКА
        # ======================================================

        try:

            result["statistics"] = (
                self._build_statistics(
                    result
                )
            )

        except Exception as e:

            result["success"] = False

            result["errors"].append(
                {
                    "component": "statistics",
                    "error": str(e)
                }
            )

            self.log(
                f"Ошибка формирования статистики: {e}"
            )

        # ======================================================
        # Сохраняем результат
        # ======================================================

        self.last_result = result

        self.log(
            "Полный Security Scan завершён."
        )

        return result

    # ==========================================================
    # БЫСТРАЯ ПРОВЕРКА
    # ==========================================================

    def quick_scan(
        self,
        path=None
    ):

        self.log(
            "Запуск быстрого Security Scan."
        )

        return self.full_scan(

            path=path,

            include_files=(
                path is not None
            ),

            include_processes=True,

            include_startup=True,

            include_usb=False,


            include_behavior=False

        )

    # ==========================================================
    # ПРОВЕРКА ПОВЕДЕНИЯ
    # ==========================================================

    def behavior_scan(self):

        self.log(
            "Запуск отдельной проверки поведения."
        )

        try:

            behavior = (
                self.security.check_behavior()
            )

            result = {

                "success": True,

                "behavior":
                    behavior

            }

        except Exception as e:

            self.log(
                f"Ошибка behavior scan: {e}"
            )

            result = {

                "success": False,

                "behavior": {},

                "errors": [
                    {
                        "component": "behavior",
                        "error": str(e)
                    }
                ]

            }

        self.last_result = result

        return result

    # ==========================================================
    # СКАНИРОВАНИЕ ТОЛЬКО ПРОЦЕССОВ
    # ==========================================================

    def process_scan(self):

        self.log(
            "Запуск отдельного сканирования процессов."
        )

        try:

            processes = (
                self.security.scan_processes()
            )

            if processes is None:

                processes = []

            result = {

                "success": True,

                "processes":
                    list(processes)

            }

        except Exception as e:

            self.log(
                f"Ошибка process scan: {e}"
            )

            result = {

                "success": False,

                "processes": [],

                "errors": [
                    {
                        "component": "processes",
                        "error": str(e)
                    }
                ]

            }

        self.last_result = result

        return result

    # ==========================================================
    # СКАНИРОВАНИЕ ТОЛЬКО АВТОЗАГРУЗКИ
    # ==========================================================

    def startup_scan(self):

        self.log(
            "Запуск отдельного сканирования автозагрузки."
        )

        try:

            startup = (
                self.security.scan_startup()
            )

            if startup is None:

                startup = []

            result = {

                "success": True,

                "startup":
                    list(startup)

            }

        except Exception as e:

            self.log(
                f"Ошибка startup scan: {e}"
            )

            result = {

                "success": False,

                "startup": [],

                "errors": [
                    {
                        "component": "startup",
                        "error": str(e)
                    }
                ]

            }

        self.last_result = result

        return result

    # ==========================================================
    # СКАНИРОВАНИЕ USB
    # ==========================================================

    def usb_scan(self):

        self.log(
            "Запуск отдельного сканирования USB."
        )

        try:

            usb = (
                self.security.scan_usb()
            )

            if usb is None:

                usb = []

            result = {

                "success": True,

                "usb":
                    list(usb)

            }

        except Exception as e:

            self.log(
                f"Ошибка USB scan: {e}"
            )

            result = {

                "success": False,

                "usb": [],

                "errors": [
                    {
                        "component": "usb",
                        "error": str(e)
                    }
                ]

            }


            self.last_result = result

        return result

    # ==========================================================
    # ПОСТРОЕНИЕ СТАТИСТИКИ
    # ==========================================================

    def _build_statistics(
        self,
        result
    ):

        files = result.get(
            "files",
            []
        )

        processes = result.get(
            "processes",
            []
        )

        startup = result.get(
            "startup",
            []
        )

        usb = result.get(
            "usb",
            []
        )

        behavior = result.get(
            "behavior",
            {}
        )

        behavior_events = 0

        if isinstance(
            behavior,
            dict
        ):

            for value in behavior.values():

                if isinstance(
                    value,
                    dict
                ):

                    events = value.get(
                        "events",
                        []
                    )

                    if isinstance(
                        events,
                        list
                    ):

                        behavior_events += len(
                            events
                        )

        return {

            "files":
                len(files),

            "processes":
                len(processes),

            "startup":
                len(startup),

            "usb":
                len(usb),

            "behavior_events":
                behavior_events,

            "errors":
                len(
                    result.get(
                        "errors",
                        []
                    )
                )

        }

    # ==========================================================
    # ПОСЛЕДНИЙ РЕЗУЛЬТАТ
    # ==========================================================

    def get_last_result(self):

        if self.last_result is None:

            return None

        if isinstance(
            self.last_result,
            dict
        ):

            return dict(
                self.last_result
            )

        return self.last_result

    # ==========================================================
    # ЕСТЬ ЛИ РЕЗУЛЬТАТ
    # ==========================================================

    def has_result(self):

        return (
            self.last_result is not None
        )

    # ==========================================================
    # БЫЛИ ЛИ ОШИБКИ
    # ==========================================================

    def has_errors(self):

        if not self.last_result:

            return False

        return bool(
            self.last_result.get(
                "errors",
                []
            )
        )

    # ==========================================================
    # ПОЛУЧЕНИЕ ОШИБОК
    # ==========================================================

    def get_errors(self):

        if not self.last_result:

            return []

        return list(
            self.last_result.get(
                "errors",
                []
            )
        )

    # ==========================================================
    # ОЧИСТКА
    # ==========================================================

    def clear(self):

        self.last_result = None

        self.log(
            "Результат Security Orchestrator очищен."
        )

    # ==========================================================
    # ЛОГИРОВАНИЕ
    # ==========================================================

    def log(
        self,
        message
    ):

        if self.logger:

            if hasattr(
                self.logger,
                "info"
            ):

                self.logger.info(
                    message
                )

                return

        print(
            f"[SECURITY] {message}"
        )