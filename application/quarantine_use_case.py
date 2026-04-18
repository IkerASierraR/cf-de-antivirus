import logging
from typing import List

from domain.interfaces import IQuarantineManager
from domain.exceptions import InvalidFilePathException
from application.dtos import QuarantineRequestDTO, QuarantineResponseDTO

logger = logging.getLogger(__name__)


class QuarantineUseCase:
    """Orquestador del proceso de cuarentena."""
    
    def __init__(self, manager: IQuarantineManager):
        self.manager = manager
    
    def execute(self, request: QuarantineRequestDTO) -> QuarantineResponseDTO:
        """Ejecuta el proceso de cuarentena de un archivo."""
        try:
            if not self._validate_file_exists(request.file_path):
                raise InvalidFilePathException(f"El archivo no existe: {request.file_path}")
            
            threat_file = self.manager.create_threat_file(request.file_path, request.reason)
            result = self.manager.move_to_quarantine(threat_file)
            
            return QuarantineResponseDTO(
                success=True,
                quarantine_path=str(result),
                error_message=None
            )
        except Exception as e:
            logger.error(f"Error en cuarentena: {e}")
            return QuarantineResponseDTO(
                success=False,
                quarantine_path="",
                error_message=str(e)
            )
    
    def list_quarantined(self) -> List[dict]:
        """Retorna una lista simplificada de todos los archivos en cuarentena."""
        quarantined_files = self.manager.list_quarantined_files()
        return [
            {
                "original_path": qf.original_path,
                "quarantine_path": qf.quarantine_path,
                "reason": qf.reason,
                "quarantined_at": qf.quarantined_at
            }
            for qf in quarantined_files
        ]
    
    def restore_file(self, file_path: str) -> bool:
        """Restaura un archivo de cuarentena a su ubicación original."""
        try:
            return self.manager.restore_from_quarantine(file_path)
        except Exception as e:
            logger.error(f"Error restaurando archivo {file_path}: {e}")
            return False
    
    def _validate_file_exists(self, path: str) -> bool:
        """Verifica que el archivo existe y es accesible."""
        from pathlib import Path
        return Path(path).exists()