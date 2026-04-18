import logging
from datetime import datetime
from pathlib import Path
from typing import List

from domain.entities import ThreatFile
from domain.exceptions import InvalidFilePathException
from domain.interfaces import IQuarantineManager
from domain.value_objects import ThreatLevel
from application.dtos import QuarantineRequestDTO, QuarantineResponseDTO

logger = logging.getLogger(__name__)


class QuarantineUseCase:
    """Orquestador del proceso de cuarentena."""

    def __init__(self, manager: IQuarantineManager) -> None:
        self.manager = manager

    def execute(self, request: QuarantineRequestDTO) -> QuarantineResponseDTO:
        """Ejecuta el proceso de cuarentena de un archivo."""
        try:
            file_path = Path(request.file_path)
            if not file_path.exists():
                raise InvalidFilePathException(
                    f"El archivo no existe: {request.file_path}"
                )

            file_size = file_path.stat().st_size

            threat = ThreatFile(
                path=request.file_path,
                hash_sha256="0" * 64,
                threat_level=ThreatLevel.HIGH,
                detected_at=datetime.now(),
                file_size=file_size,
                signature_name=request.reason,
            )

            self.manager.quarantine(threat)

            return QuarantineResponseDTO(
                success=True,
                quarantine_path=threat.quarantine_path or "",
                error_message=None,
            )

        except Exception as exc:
            logger.error("Error en cuarentena: %s", exc)
            return QuarantineResponseDTO(
                success=False,
                quarantine_path="",
                error_message=str(exc),
            )

    def list_quarantined(self) -> List[dict]:
        """Retorna una lista de dicts con los archivos en cuarentena."""
        quarantined_files = self.manager.list_quarantined()
        return [
            {
                "original_path": f.path,
                "quarantine_path": f.quarantine_path or "",
                "reason": f.signature_name,
                "threat_level": f.threat_level.value,
                "quarantined_at": f.quarantined_at,
            }
            for f in quarantined_files
        ]

    def restore_file(self, file_path: str) -> bool:
        """Restaura un archivo de cuarentena a su ubicación original."""
        try:
            for threat in self.manager.list_quarantined():
                if threat.path == file_path or threat.quarantine_path == file_path:
                    return self.manager.restore(threat)
            logger.warning("Archivo no encontrado en cuarentena: %s", file_path)
            return False
        except Exception as exc:
            logger.error("Error restaurando archivo %s: %s", file_path, exc)
            return False