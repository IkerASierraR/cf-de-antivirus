"""
dependencies/container.py
===========================
Contenedor de inyección de dependencias del sistema antivirus.
Ensambla y conecta todos los componentes del sistema.
"""

import logging

from config.settings import Settings
from infrastructure.database_connection import DatabaseConnection
from infrastructure.signature_repository import SQLiteSignatureRepository
from infrastructure.file_scanner import FileScanner
from infrastructure.quarantine_manager import QuarantineManager
from infrastructure.file_monitor import FileMonitor
from infrastructure.cleanup_service import SystemCleanupService
from application.scan_use_case import SystemScanUseCase
from application.protection_use_case import RealTimeProtectionUseCase
from application.quarantine_use_case import QuarantineUseCase
from application.cleanup_use_case import PCCleanupUseCase

logger = logging.getLogger(__name__)


class DependencyContainer:
    """Ensamblador central de todas las dependencias del sistema."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

        # Infraestructura base
        self._db = DatabaseConnection.get_instance(settings.DB_PATH)
        self._repository = SQLiteSignatureRepository(self._db)

        # Servicios de infraestructura
        self._scanner = FileScanner(
            repository=self._repository,
            scan_extensions=settings.SCAN_EXTENSIONS,
            max_size_mb=settings.MAX_FILE_SIZE_MB,
        )
        self._quarantine_manager = QuarantineManager(
            quarantine_dir=settings.QUARANTINE_DIR
        )
        self._file_monitor = FileMonitor()
        self._cleanup_service = SystemCleanupService(
            temp_dirs=settings.TEMP_DIRS
        )

        # Casos de uso de aplicación
        self._quarantine_uc = QuarantineUseCase(self._quarantine_manager)

        self._scan_uc = SystemScanUseCase(
            scanner=self._scanner,
            repository=self._repository,
        )

        self._protection_uc = RealTimeProtectionUseCase(
            monitor=self._file_monitor,
            scanner=self._scanner,
            repository=self._repository,
            quarantine_use_case=self._quarantine_uc,
        )

        self._cleanup_uc = PCCleanupUseCase(
            cleanup_service=self._cleanup_service,
            quarantine_manager=self._quarantine_manager,
        )

        logger.info("DependencyContainer inicializado correctamente.")

    # ------------------------------------------------------------------
    # Accesores de casos de uso
    # ------------------------------------------------------------------

    def get_scan_use_case(self) -> SystemScanUseCase:
        """Retorna la instancia lista del caso de uso de escaneo."""
        return self._scan_uc

    def get_protection_use_case(self) -> RealTimeProtectionUseCase:
        """Retorna la instancia lista del caso de uso de protección en tiempo real."""
        return self._protection_uc

    def get_quarantine_use_case(self) -> QuarantineUseCase:
        """Retorna la instancia lista del caso de uso de cuarentena."""
        return self._quarantine_uc

    def get_cleanup_use_case(self) -> PCCleanupUseCase:
        """Retorna la instancia lista del caso de uso de limpieza."""
        return self._cleanup_uc

    def get_settings(self) -> Settings:
        """Retorna las configuraciones del sistema."""
        return self._settings

    def shutdown(self) -> None:
        """Cierra todos los recursos abiertos de forma ordenada."""
        logger.info("Iniciando cierre del sistema...")

        # Detener monitor si está activo
        if self._file_monitor.is_active():
            try:
                self._file_monitor.stop_monitoring()
            except Exception as exc:
                logger.warning("Error deteniendo monitor: %s", exc)

        # Cerrar base de datos
        try:
            self._db.close()
        except Exception as exc:
            logger.warning("Error cerrando base de datos: %s", exc)

        logger.info("Sistema cerrado correctamente.")
