import logging
import time
from typing import Callable, Optional

from domain.interfaces import IFileMonitor, IFileScanner, ISignatureRepository
from application.quarantine_use_case import QuarantineUseCase

logger = logging.getLogger(__name__)


class RealTimeProtectionUseCase:
    """Orquestador de la protección en tiempo real."""

    def __init__(
        self,
        monitor: IFileMonitor,
        scanner: IFileScanner,
        repository: ISignatureRepository,
        quarantine_use_case: QuarantineUseCase,
    ) -> None:
        self.monitor = monitor
        self.scanner = scanner
        self.repository = repository
        self.quarantine_use_case = quarantine_use_case
        self._alert_callback: Optional[Callable] = None

    def start(self, directory: str) -> None:
        """Inicia el monitoreo de un directorio."""
        self.monitor.set_on_file_created_callback(self._on_new_file)
        self.monitor.start_monitoring(directory)
        logger.info("Protección en tiempo real iniciada en: %s", directory)

    def stop(self) -> None:
        """Detiene el monitoreo de forma segura."""
        self.monitor.stop_monitoring()
        logger.info("Protección en tiempo real detenida.")

    def is_active(self) -> bool:
        """Retorna True si el monitoreo está activo en este momento."""
        return self.monitor.is_active()

    def _on_new_file(self, file_path: str) -> None:
        """Callback que se ejecuta cuando se detecta un nuevo archivo."""
        from domain.value_objects import FilePath

        try:
            # Esperar medio segundo para que el archivo termine de escribirse
            time.sleep(0.5)

            fp = FilePath(file_path)
            scan_result = self.scanner.scan_file(fp)

            if scan_result.has_threats():
                for threat in scan_result.threats_found:
                    from application.dtos import QuarantineRequestDTO

                    request = QuarantineRequestDTO(
                        file_path=threat.path,
                        reason=threat.signature_name,
                    )
                    response = self.quarantine_use_case.execute(request)

                    if self._alert_callback:
                        self._alert_callback(threat, response)

        except Exception as exc:
            logger.error("Error procesando nuevo archivo %s: %s", file_path, exc)

    def set_alert_callback(self, callback: Callable) -> None:
        """Registra una función que será llamada cuando se detecte una amenaza."""
        self._alert_callback = callback