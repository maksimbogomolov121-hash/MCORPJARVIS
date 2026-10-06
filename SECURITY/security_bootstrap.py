"""
JARVIS SECURITY
Security Bootstrap
Version: 2.1

Самостоятельный запуск Security независимо от JARVIS.

Архитектура запуска:

    Windows
       │
       ▼
    Security Bootstrap
       │
       ├── Security Core V2.3
       │
       ├── Security Orchestrator V2.4
       │
       ├── V3 Security Engines
       │      ├── Detection Engine
       │      ├── IOC Engine
       │      ├── Correlation Engine
       │      ├── Threat Chain
       │      ├── Risk Engine
       │      ├── Incident Manager
       │      └── Event Store
       │
       ├── V4 Security Pipeline
       │      ├── Decision Engine
       │      ├── Response Engine
       │      ├── Security Policy
       │      └── Security Controller
       │
       ├── V6
       │      ├── Security Automation
       │      ├── Auto Response
       │      ├── Remediation Engine
       │      └── Recovery Manager
       │
       ├── V7 Security API
       │
       ├── V8
       │      ├── Notifications
       │      ├── Alert Manager
       │      ├── JARVIS Security Bridge
       │      ├── Command Handler
       │      └── Voice Interface
       │
       ├── Security IPC Server
       │      └── 127.0.0.1:8765
       │
       └── Security Interface

Sandbox намеренно НЕ используется.
JARVIS main.py здесь НЕ используется.

JARVIS подключается к уже работающему Security
через локальный IPC Server.
"""

from __future__ import annotations

import logging
import signal
import sys
from pathlib import Path
from typing import Any, Optional


VERSION = "2.1"


# ============================================================
# PATHS
# ============================================================

SECURITY_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SECURITY_DIR.parent

# Позволяет запускать security_bootstrap.py
# напрямую из папки SECURITY.
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))


LOG_DIR = PROJECT_DIR / "LOGS"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "security_bootstrap.log"


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger("JARVIS.SecurityBootstrap")
logger.setLevel(logging.INFO)

if not logger.handlers:

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()

    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# ============================================================
# SECURITY BOOTSTRAP
# ============================================================

class SecurityBootstrap:
    """
    Главный загрузчик Security.

    Security полностью автономен от JARVIS.

    Bootstrap:
    1. Загружает Security Core.
    2. Загружает Security Orchestrator.
    3. Создаёт V3 аналитические компоненты.
    4. Создаёт Security Pipeline.
    5. Создаёт Decision Engine.
    6. Создаёт Security Policy.
    7. Создаёт Response Engine.
    8. Создаёт Security Controller.
    9. Создаёт V6 Remediation / Recovery.
    10. Создаёт Security API.
    11. Создаёт V8 Bridge / Handler / Alerts.
    12. Создаёт Security IPC Server.
    13. Создаёт Security Interface.

    Sandbox не используется.
    JARVIS main.py не используется.
    """

    STATUS_STOPPED = "stopped"
    STATUS_STARTING = "starting"
    STATUS_RUNNING = "running"
    STATUS_FAILED = "failed"
    STATUS_STOPPING = "stopping"

    def __init__(self) -> None:

        # ----------------------------------------------------
        # GENERAL
        # ----------------------------------------------------

        self.status = self.STATUS_STOPPED
        self._running = False

        # ----------------------------------------------------
        # SERVICES
        # ----------------------------------------------------

        self.interface: Optional[Any] = None
        self.logger: Optional[Any] = None
        self.policy: Optional[Any] = None
        self.notifications: Optional[Any] = None

        self.bridge: Optional[Any] = None

        # ----------------------------------------------------
        # CORE
        # ----------------------------------------------------

        self.security_core: Optional[Any] = None
        self.security_orchestrator: Optional[Any] = None

        # ----------------------------------------------------
        # V3
        # ----------------------------------------------------

        self.detection_engine: Optional[Any] = None
        self.ioc_engine: Optional[Any] = None
        self.correlation_engine: Optional[Any] = None
        self.threat_chain: Optional[Any] = None
        self.risk_engine: Optional[Any] = None
        self.incident_manager: Optional[Any] = None
        self.event_store: Optional[Any] = None

        # ----------------------------------------------------
        # V4
        # ----------------------------------------------------

        self.security_pipeline: Optional[Any] = None
        self.decision_engine: Optional[Any] = None
        self.response_engine: Optional[Any] = None
        self.security_policy: Optional[Any] = None
        self.security_controller: Optional[Any] = None

        # ----------------------------------------------------
        # V6
        # ----------------------------------------------------

        self.security_automation: Optional[Any] = None
        self.auto_response: Optional[Any] = None
        self.remediation_engine: Optional[Any] = None
        self.recovery_manager: Optional[Any] = None

        # ----------------------------------------------------
        # V7
        # ----------------------------------------------------

        self.security_api: Optional[Any] = None

        # ----------------------------------------------------
        # V8
        # ----------------------------------------------------

        self.security_notifications: Optional[Any] = None
        self.security_alert_manager: Optional[Any] = None
        self.jarvis_security_bridge: Optional[Any] = None
        self.security_command_handler: Optional[Any] = None
        self.security_voice_interface: Optional[Any] = None

        # ----------------------------------------------------
        # IPC
        # ----------------------------------------------------

        self.security_ipc_server: Optional[Any] = None

        # ----------------------------------------------------
        # INTERFACE
        # ----------------------------------------------------

        self.security_interface: Optional[Any] = None

    # ========================================================
    # START
    # ========================================================

    def start(self) -> bool:

        if self.status == self.STATUS_RUNNING:

            logger.info(
                "Security уже запущен."
            )

            return True

        self.status = self.STATUS_STARTING

        logger.info("=" * 70)
        logger.info("JARVIS SECURITY START")
        logger.info(
            "Security Bootstrap version: %s",
            VERSION,
        )
        logger.info(
            "Security directory: %s",
            SECURITY_DIR,
        )
        logger.info("=" * 70)

        try:

            # =================================================
            # 1. SECURITY CORE
            # =================================================

            self._load_security_core()

            # =================================================
            # 2. SECURITY ORCHESTRATOR
            # =================================================

            self._load_orchestrator()

            # =================================================
            # 3. V3 ENGINES
            # =================================================

            self._load_v3_components()

            # =================================================
            # 4. V4 PIPELINE
            # =================================================

            self._load_v4_components()

            # =================================================
            # 5. V6
            # =================================================

            self._load_v6_components()

            # =================================================
            # 6. V7 API
            # =================================================

            self._load_security_api()

            # =================================================
            # 7. V8
            # =================================================

            self._load_v8_components()

            # =================================================
            # 8. IPC SERVER
            # =================================================

            self._load_ipc_server()

            # =================================================
            # 9. INTERFACE
            # =================================================

            self._load_interface()

            # =================================================
            # FINAL CHECK
            # =================================================

            self._validate_system()

            self._running = True
            self.status = self.STATUS_RUNNING

            logger.info("=" * 70)
            logger.info(
                "SECURITY УСПЕШНО ЗАПУЩЕН."
            )
            logger.info(
                "Security работает независимо от JARVIS."
            )
            logger.info(
                "Security IPC Server: 127.0.0.1:8765"
            )
            logger.info(
                "Голосовое управление ожидает подключения JARVIS."
            )
            logger.info(
                "Все основные компоненты загружены."
            )
            logger.info("=" * 70)

            return True

        except Exception as exc:

            self.status = self.STATUS_FAILED
            self._running = False

            logger.exception(
                "КРИТИЧЕСКАЯ ОШИБКА ЗАПУСКА SECURITY: %s",
                exc,
            )

            # Если IPC успел запуститься,
            # обязательно остановим его.
            try:

                if self.security_ipc_server is not None:

                    self.security_ipc_server.stop()

            except Exception:

                logger.exception(
                    "Ошибка остановки IPC после ошибки запуска."
                )

            return False

    # ========================================================
    # CORE
    # ========================================================

    def _load_security_core(self) -> None:

        logger.info(
            "[1/9] Загрузка Security Core..."
        )

        from SECURITY.security_core import SecurityCore

        self.security_core = SecurityCore()

        logger.info(
            "Security Core V2.3 загружен."
        )

    # ========================================================
    # ORCHESTRATOR
    # ========================================================

    def _load_orchestrator(self) -> None:

        logger.info(
            "[2/9] Загрузка Security Orchestrator..."
        )

        from SECURITY.security_orchestrator import (
            SecurityOrchestrator
        )

        self.security_orchestrator = (
            SecurityOrchestrator(
                self.security_core,
                logger=getattr(
                    self.security_core,
                    "logger",
                    None,
                ),
            )
        )

        logger.info(
            "Security Orchestrator V2.4 загружен."
        )

    # ========================================================
    # V3
    # ========================================================

    def _load_v3_components(self) -> None:

        logger.info(
            "[3/9] Загрузка Security V3..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        # ----------------------------------------------------
        # Detection Engine
        # ----------------------------------------------------

        from SECURITY.detection_engine import (
            DetectionEngine
        )

        self.detection_engine = DetectionEngine(
            logger=shared_logger
        )

        logger.info(
            "Detection Engine V3.6 загружен."
        )

        # ----------------------------------------------------
        # IOC Engine
        # ----------------------------------------------------

        from SECURITY.ioc_engine import (
            IOCEngine
        )

        self.ioc_engine = IOCEngine(
            logger=shared_logger
        )

        logger.info(
            "IOC Engine V3.5 загружен."
        )

        # ----------------------------------------------------
        # Correlation Engine
        # ----------------------------------------------------

        from SECURITY.correlation_engine import (
            CorrelationEngine
        )

        self.correlation_engine = (
            CorrelationEngine(
                logger=shared_logger
            )
        )

        logger.info(
            "Correlation Engine V3.0 загружен."
        )

        # ----------------------------------------------------
        # Threat Chain
        # ----------------------------------------------------

        from SECURITY.threat_chain import (
            ThreatChain
        )

        self.threat_chain = ThreatChain(
            logger=shared_logger
        )

        logger.info(
            "Threat Chain V3.2 загружен."
        )

        # ----------------------------------------------------
        # Risk Engine
        # ----------------------------------------------------

        from SECURITY.risk_engine import (
            RiskEngine
        )

        self.risk_engine = RiskEngine(
            logger=shared_logger
        )

        logger.info(
            "Risk Engine V3.1 загружен."
        )

        # ----------------------------------------------------
        # Incident Manager
        # ----------------------------------------------------

        from SECURITY.incident_manager import (
            IncidentManager
        )

        self.incident_manager = IncidentManager(
            logger=shared_logger
        )

        logger.info(
            "Incident Manager V3.3 загружен."
        )

        # ----------------------------------------------------
        # Event Store
        # ----------------------------------------------------

        from SECURITY.security_event_store import (
            SecurityEventStore
        )

        self.event_store = SecurityEventStore(
            logger=shared_logger
        )

        logger.info(
            "Security Event Store V3.4 загружен."
        )

    # ========================================================
    # V4
    # ========================================================

    def _load_v4_components(self) -> None:

        logger.info(
            "[4/9] Сборка Security V4..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        # ----------------------------------------------------
        # Pipeline
        # ----------------------------------------------------

        from SECURITY.security_pipeline import (
            SecurityPipeline
        )

        self.security_pipeline = SecurityPipeline(
            detection_engine=self.detection_engine,
            ioc_engine=self.ioc_engine,
            correlation_engine=self.correlation_engine,
            threat_chain=self.threat_chain,
            risk_engine=self.risk_engine,
            logger=shared_logger,
        )

        logger.info(
            "Security Pipeline V4.0 загружен."
        )

        # ----------------------------------------------------
        # Decision Engine
        # ----------------------------------------------------

        from SECURITY.decision_engine import (
            DecisionEngine
        )

        self.decision_engine = DecisionEngine(
            logger=shared_logger
        )

        logger.info(
            "Decision Engine V4.1 загружен."
        )

        # ----------------------------------------------------
        # Response Engine
        # ----------------------------------------------------

        from SECURITY.response_engine import (
            ResponseEngine
        )

        self.response_engine = ResponseEngine(
            logger=shared_logger
        )

        logger.info(
            "Response Engine V4.2 загружен."
        )

        # ----------------------------------------------------
        # Security Policy
        # ----------------------------------------------------

        from SECURITY.security_policy import (
            SecurityPolicy
        )

        self.security_policy = SecurityPolicy(
            logger=shared_logger
        )

        logger.info(
            "Security Policy V4.3 загружен."
        )

        # ----------------------------------------------------
        # Security Controller
        # ----------------------------------------------------

        from SECURITY.security_controller import (
            SecurityController
        )

        self.security_controller = SecurityController(
            pipeline=self.security_pipeline,
            decision_engine=self.decision_engine,
            policy=self.security_policy,
            response_engine=self.response_engine,
            logger=shared_logger,
        )

        logger.info(
            "Security Controller V4.4 загружен."
        )

    # ========================================================
    # V6
    # ========================================================

    def _load_v6_components(self) -> None:

        logger.info(
            "[5/9] Загрузка Security V6..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        # ----------------------------------------------------
        # Security Automation
        # ----------------------------------------------------

        from SECURITY.security_automation import (
            SecurityAutomation
        )

        self.security_automation = SecurityAutomation(
            logger=shared_logger
        )

        logger.info(
            "Security Automation V6.0 загружен."
        )

        # ----------------------------------------------------
        # Auto Response
        # ----------------------------------------------------

        from SECURITY.auto_response import (
            AutoResponse
        )

        self.auto_response = AutoResponse(
            logger=shared_logger
        )

        logger.info(
            "Auto Response V6.1 загружен."
        )

        # ----------------------------------------------------
        # Remediation
        # ----------------------------------------------------

        from SECURITY.remediation_engine import (
            RemediationEngine
        )

        quarantine = getattr(
            self.security_core,
            "quarantine_manager",
            None,
        )

        self.remediation_engine = RemediationEngine(
            quarantine=quarantine,
            logger=shared_logger,
        )

        logger.info(
            "Remediation Engine V6.2 загружен."
        )

        # ----------------------------------------------------
        # Recovery
        # ----------------------------------------------------

        from SECURITY.recovery_manager import (
            RecoveryManager
        )


        self.recovery_manager = RecoveryManager(
            logger=shared_logger,
            quarantine=quarantine,
            remediation_engine=self.remediation_engine,
        )

        logger.info(
            "Recovery Manager V6.3 загружен."
        )

    # ========================================================
    # V7 API
    # ========================================================

    def _load_security_api(self) -> None:

        logger.info(
            "[6/9] Загрузка Security API..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        from SECURITY.security_api import (
            SecurityAPI
        )

        self.security_api = SecurityAPI(
            security_controller=self.security_controller,
            security_core=self.security_core,
            security_orchestrator=self.security_orchestrator,
            remediation_engine=self.remediation_engine,
            recovery_manager=self.recovery_manager,
            logger=shared_logger,
        )

        logger.info(
            "Security API V7.0 загружен."
        )

    # ========================================================
    # V8
    # ========================================================

    def _load_v8_components(self) -> None:

        logger.info(
            "[7/9] Загрузка Security V8..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        # ----------------------------------------------------
        # Notifications
        # ----------------------------------------------------

        from SECURITY.security_notifications import (
            SecurityNotifications
        )

        self.security_notifications = (
            SecurityNotifications(
                logger=shared_logger
            )
        )

        logger.info(
            "Security Notifications загружены."
        )

        # ----------------------------------------------------
        # Alert Manager
        # ----------------------------------------------------

        from SECURITY.security_alert_manager import (
            SecurityAlertManager
        )

        self.security_alert_manager = (
            SecurityAlertManager(
                notifications=self.security_notifications,
                logger=shared_logger,
            )
        )

        logger.info(
            "Security Alert Manager V8.3 загружен."
        )

        # ----------------------------------------------------
        # JARVIS Security Bridge
        # ----------------------------------------------------

        from SECURITY.jarvis_security_bridge import (
            JarvisSecurityBridge
        )

        self.jarvis_security_bridge = (
            JarvisSecurityBridge(
                security_api=self.security_api,
                notifications=self.security_notifications,
                logger=shared_logger,
            )
        )

        # Совместимость с коротким именем.
        self.bridge = self.jarvis_security_bridge

        logger.info(
            "JARVIS Security Bridge V8.0 загружен."
        )

        # ----------------------------------------------------
        # Security Command Handler
        # ----------------------------------------------------

        from SECURITY.security_command_handler import (
            SecurityCommandHandler
        )

        self.security_command_handler = (
            SecurityCommandHandler(
                security_bridge=self.jarvis_security_bridge,
                policy=self.security_policy,
                logger=shared_logger,
                notifications=self.security_notifications,
            )
        )

        logger.info(
            "Security Command Handler V8.1 загружен."
        )

        # ----------------------------------------------------
        # Security Voice Interface
        # ----------------------------------------------------

        from SECURITY.security_voice_interface import (
            SecurityVoiceInterface
        )

        self.security_voice_interface = (
            SecurityVoiceInterface(
                command_handler=self.security_command_handler,
                notifications=self.security_notifications,
                logger=shared_logger,
            )
        )

        # ----------------------------------------------------
        # ВАЖНО:
        # Голосовое управление Security отключено,
        # пока JARVIS не подключится через IPC.
        # ----------------------------------------------------

        set_jarvis_active = getattr(
            self.security_voice_interface,
            "set_jarvis_active",
            None,
        )

        if callable(set_jarvis_active):

            set_jarvis_active(False)

        logger.info(
            "Security Voice Interface V8.2 загружен."
        )

        logger.info(
            "Голосовое управление Security ожидает JARVIS."
        )

    # ========================================================
    # IPC SERVER
    # ========================================================

    def _load_ipc_server(self) -> None:

        logger.info(
            "[8/9] Запуск Security IPC Server..."
        )

        from SECURITY.security_ipc_server import (
            SecurityIPCServer
        )

        if self.security_voice_interface is None:

            raise RuntimeError(
                "Security Voice Interface не был создан."
            )

        if self.jarvis_security_bridge is None:

            raise RuntimeError(
                "JARVIS Security Bridge не был создан."
            )

        self.security_ipc_server = SecurityIPCServer(
            security_api=self.security_api,
            security_voice_interface=self.security_voice_interface,
            jarvis_security_bridge=self.jarvis_security_bridge,
            logger=getattr(
                self.security_core,
                "logger",
                None,
            ),
        )

        if not self.security_ipc_server.start():

            raise RuntimeError(
                "Не удалось запустить Security IPC Server."
            )

        logger.info(
            "Security IPC Server запущен."
        )

        logger.info(
            "Адрес: 127.0.0.1:8765"
        )

    # ========================================================
    # INTERFACE
    # ========================================================

    def _load_interface(self) -> None:

        logger.info(
            "[9/9] Загрузка Security Interface..."
        )

        shared_logger = getattr(
            self.security_core,
            "logger",
            None,
        )

        from SECURITY.security_interface import (
            SecurityInterface
        )

        self.security_interface = SecurityInterface(
            security_api=self.security_api,
            logger=shared_logger,
        )

        # Сохраняем короткую ссылку
        # для совместимости с внешним кодом.

        self.interface = self.security_interface

        logger.info(
            "Security Interface загружен."
        )

    # ========================================================
    # VALIDATION
    # ========================================================

    def _validate_system(self) -> None:

        logger.info(
            "Проверка собранной Security-системы..."
        )

        required_components = {

            "Security Core":
                self.security_core,

            "Security Orchestrator":
                self.security_orchestrator,

            "Detection Engine":
                self.detection_engine,

            "IOC Engine":
                self.ioc_engine,

            "Correlation Engine":
                self.correlation_engine,

            "Threat Chain":
                self.threat_chain,

            "Risk Engine":
                self.risk_engine,

            "Incident Manager":

                self.incident_manager,

            "Security Event Store":
                self.event_store,

            "Security Pipeline":
                self.security_pipeline,

            "Decision Engine":
                self.decision_engine,

            "Response Engine":
                self.response_engine,

            "Security Policy":
                self.security_policy,

            "Security Controller":
                self.security_controller,

            "Security Automation":
                self.security_automation,

            "Auto Response":
                self.auto_response,

            "Remediation Engine":
                self.remediation_engine,

            "Recovery Manager":
                self.recovery_manager,

            "Security API":
                self.security_api,

            "Security Notifications":
                self.security_notifications,

            "Security Alert Manager":
                self.security_alert_manager,

            "JARVIS Security Bridge":
                self.jarvis_security_bridge,

            "Security Command Handler":
                self.security_command_handler,

            "Security Voice Interface":
                self.security_voice_interface,

            "Security IPC Server":
                self.security_ipc_server,

            "Security Interface":
                self.security_interface,
        }

        missing = [
            name
            for name, component
            in required_components.items()
            if component is None
        ]

        if missing:

            raise RuntimeError(
                "Не загружены компоненты: "
                + ", ".join(missing)
            )

        logger.info(
            "Проверка компонентов завершена успешно."
        )

    # ========================================================
    # STOP
    # ========================================================

    def stop(self) -> None:

        if self.status == self.STATUS_STOPPED:

            # Даже если статус stopped,
            # попробуем аккуратно закрыть IPC,
            # если он был создан.
            try:

                if self.security_ipc_server is not None:
                    self.security_ipc_server.stop()

            except Exception:

                logger.exception(
                    "Ошибка остановки IPC Server."
                )

            return

        logger.info(
            "Остановка Security..."
        )

        self.status = self.STATUS_STOPPING
        self._running = False

        # ----------------------------------------------------
        # Отключаем голосовое управление Security
        # ----------------------------------------------------

        try:

            if self.security_voice_interface is not None:

                set_jarvis_active = getattr(
                    self.security_voice_interface,
                    "set_jarvis_active",
                    None,
                )

                if callable(set_jarvis_active):

                    set_jarvis_active(False)

        except Exception as exc:

            logger.warning(
                "Ошибка отключения Security Voice Interface: %s",
                exc,
            )

        # ----------------------------------------------------
        # Останавливаем IPC Server
        # ----------------------------------------------------

        try:

            if self.security_ipc_server is not None:

                self.security_ipc_server.stop()

                logger.info(
                    "Security IPC Server остановлен."
                )

        except Exception as exc:

            logger.warning(
                "Ошибка остановки IPC Server: %s",
                exc,
            )

        # ----------------------------------------------------
        # Останавливаем поведенческий мониторинг Core
        # ----------------------------------------------------

        try:


           if self.security_core is not None:

                stop_behavior = getattr(
                    self.security_core,
                    "stop_behavior_monitoring",
                    None,
                )

                if callable(stop_behavior):

                    stop_behavior()

        except Exception as exc:

            logger.warning(
                "Ошибка остановки Behavior Monitoring: %s",
                exc,
            )

        # ----------------------------------------------------
        # Останавливаем Scheduler, если он был создан
        # ----------------------------------------------------

        try:

            scheduler = getattr(
                self,
                "security_scheduler",
                None,
            )

            if scheduler is not None:

                stop_all = getattr(
                    scheduler,
                    "stop_all",
                    None,
                )

                if callable(stop_all):

                    stop_all()

        except Exception as exc:

            logger.warning(
                "Ошибка остановки Scheduler: %s",
                exc,
            )

        self.status = self.STATUS_STOPPED

        logger.info(
            "Security остановлен."
        )

    # ========================================================
    # RUN
    # ========================================================

    def run(self) -> None:

        if not self.start():

            return

        logger.info(
            "Security работает независимо от JARVIS."
        )

        logger.info(
            "Запуск Security Interface..."
        )

        try:

            # ------------------------------------------------
            # GUI является главным циклом
            # автономного Security.
            # IPC Server при этом работает
            # в отдельном потоке.
            # ------------------------------------------------

            if self.security_interface is not None:

                self.security_interface.run()

            else:

                raise RuntimeError(
                    "Security Interface не был создан."
                )

        except KeyboardInterrupt:

            logger.info(
                "Получен сигнал KeyboardInterrupt."
            )

        except Exception as exc:

            logger.exception(
                "Ошибка работы Security Interface: %s",
                exc,
            )

        finally:

            self.stop()

            logger.info(
                "JARVIS SECURITY STOP"
            )

    # ========================================================
    # STATUS
    # ========================================================

    def is_running(self) -> bool:

        return (
            self.status == self.STATUS_RUNNING
            and self._running
        )

    def get_status(self) -> str:

        return self.status

    # ========================================================
    # BEHAVIOR MONITORING
    # ========================================================

    def stop_behavior_monitoring(self) -> None:

        if self.security_core is None:

            return

        stop_behavior = getattr(
            self.security_core,
            "stop_behavior_monitoring",
            None,
        )

        if callable(stop_behavior):

            try:

                stop_behavior()

            except Exception as exc:

                logger.warning(
                    "Ошибка остановки Behavior Monitoring: %s",
                    exc,
                )


# ============================================================
# SIGNAL HANDLERS
# ============================================================

_bootstrap_instance: Optional[SecurityBootstrap] = None


def _signal_handler(
    signum: int,
    frame: Any,
) -> None:

    logger.info(
        "Получен системный сигнал: %s",
        signum,
    )

    global _bootstrap_instance


if _bootstrap_instance is not None:

        _bootstrap_instance.stop()


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    global _bootstrap_instance

    _bootstrap_instance = SecurityBootstrap()

    signal.signal(
        signal.SIGINT,
        _signal_handler,
    )

    if hasattr(signal, "SIGTERM"):

        signal.signal(
            signal.SIGTERM,
            _signal_handler,
        )

    _bootstrap_instance.run()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()