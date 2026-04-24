"""
application/scan_use_case.py
==============================
Caso de uso de escaneo del sistema. Orquesta el motor de escaneo
y produce un ScanResponseDTO listo para la capa de presentación.
"""

import logging
import time
from pathlib import Path

from application.dtos import ScanRequestDTO, ScanResponseDTO
from domain.exceptions import InvalidFilePathException, ScannerException
from domain.interfaces import IFileScanner, ISignatureRepository
from domain.value_objects import FilePath

logger = logging.getLogger(__name__)


class SystemScanUseCase:
    """Caso de uso para escaneo de archivos y directorios."""

    def __init__(
        self,
        scanner: IFileScanner,
        repository: ISignatureRepository,
    ) -> None:
        self._scanner = scanner
        self._repository = repository

    def execute(self, request: ScanRequestDTO) -> ScanResponseDTO:
        """
        Ejecuta el escaneo según la solicitud.

        Args:
            request: DTO con la ruta objetivo y configuración del escaneo.

        Returns:
            ScanResponseDTO con estadísticas y lista de amenazas.

        Raises:
            InvalidFilePathException: Si la ruta no existe.
            ScannerException: Si ocurre un error durante el escaneo.
        """
        target = Path(request.target_path)
        if not target.exists():
            raise InvalidFilePathException(
                f"Ruta no encontrada: {request.target_path}"
            )

        start = time.time()

        try:
            if target.is_file():
                result = self._scanner.scan_file(FilePath(str(target)))
            else:
                result = self._scanner.scan_directory(str(target))
        except (InvalidFilePathException, ScannerException):
            raise
        except Exception as exc:
            logger.error("Error inesperado en escaneo: %s", exc)
            raise ScannerException(
                request.target_path, f"Error inesperado: {exc}"
            ) from exc

        threat_list = [
            {
                "file_path": threat.path,
                "threat_level": threat.threat_level.value,
                "threat_name": threat.signature_name,
                "signature_name": threat.signature_name,
                "category": threat.category,
                "threat_category": threat.category,
                "file_size": threat.file_size,
            }
            for threat in result.threats_found
        ]

        duration = time.time() - start
        status = "AMENAZAS DETECTADAS" if result.has_threats() else "LIMPIO"

        return ScanResponseDTO(
            total_files_scanned=result.scanned_files,
            threats_found=result.threat_count(),
            threat_list=threat_list,
            duration_seconds=duration,
            status=status,
        )