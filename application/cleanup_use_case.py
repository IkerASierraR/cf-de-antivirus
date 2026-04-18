import logging
from typing import List

from domain.interfaces import ICleanupService, IQuarantineManager
from application.dtos import CleanupRequestDTO, CleanupReportDTO

logger = logging.getLogger(__name__)


class PCCleanupUseCase:
    """Orquestador de la limpieza del sistema."""
    
    def __init__(self, cleanup_service: ICleanupService, quarantine_manager: IQuarantineManager):
        self.cleanup_service = cleanup_service
        self.quarantine_manager = quarantine_manager
    
    def preview(self, request: CleanupRequestDTO) -> List[str]:
        """Muestra qué archivos serían eliminados sin eliminarlos aún."""
        files_to_delete = []
        
        if request.include_temp:
            files_to_delete.extend(self.cleanup_service.find_temp_files())
        
        if request.include_quarantine:
            quarantined_files = self.quarantine_manager.list_quarantined_files()
            files_to_delete.extend([qf.quarantine_path for qf in quarantined_files])
        
        if request.custom_paths:
            files_to_delete.extend(request.custom_paths)
        
        return files_to_delete
    
    def execute(self, request: CleanupRequestDTO) -> CleanupReportDTO:
        """Realiza la limpieza efectiva del sistema."""
        files_to_delete = self.preview(request)
        
        total_size = self._calculate_total_size(files_to_delete)
        files_deleted = 0
        errors = []
        
        for file_path in files_to_delete:
            try:
                if self.cleanup_service.delete_file(file_path):
                    files_deleted += 1
            except Exception as e:
                errors.append(f"{file_path}: {str(e)}")
                logger.error(f"Error eliminando {file_path}: {e}")
        
        space_freed_mb = total_size / (1024 * 1024)
        
        return CleanupReportDTO(
            files_deleted=files_deleted,
            space_freed_mb=space_freed_mb,
            errors=errors,
            success=len(errors) == 0
        )
    
    def _calculate_total_size(self, paths: List[str]) -> int:
        """Calcula el tamaño total en bytes de los archivos que serán eliminados."""
        from pathlib import Path
        
        total_size = 0
        for path in paths:
            try:
                file_path = Path(path)
                if file_path.exists():
                    total_size += file_path.stat().st_size
            except Exception as e:
                logger.warning(f"No se pudo obtener tamaño de {path}: {e}")
        
        return total_size