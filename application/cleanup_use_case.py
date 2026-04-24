import logging
from pathlib import Path
from typing import List

from domain.interfaces import ICleanupService, IQuarantineManager
from application.dtos import CleanupRequestDTO, CleanupReportDTO

logger = logging.getLogger(__name__)


class PCCleanupUseCase:
    """Orquestador de la limpieza del sistema."""

    def __init__(
        self,
        cleanup_service: ICleanupService,
        quarantine_manager: IQuarantineManager,
    ) -> None:
        self.cleanup_service = cleanup_service
        self.quarantine_manager = quarantine_manager

    def preview(self, request: CleanupRequestDTO) -> List[str]:
        """Muestra qué archivos serían eliminados sin eliminarlos aún."""
        files_to_delete: List[str] = []

        if request.include_temp:
            files_to_delete.extend(self.cleanup_service.find_temp_files())

        if request.include_quarantine:
            quarantined = self.quarantine_manager.list_quarantined()
            files_to_delete.extend(
                [qf.quarantine_path for qf in quarantined if qf.quarantine_path]
            )

        if request.custom_paths:
            files_to_delete.extend(request.custom_paths)

        return files_to_delete

    def execute(self, request: CleanupRequestDTO) -> CleanupReportDTO:
        """Realiza la limpieza efectiva del sistema."""
        files_to_delete = self.preview(request)

        total_size = self._calculate_total_size(files_to_delete)
        errors: List[str] = []

        # Eliminar archivos en lote
        try:
            files_deleted = self.cleanup_service.delete_files(files_to_delete)
        except Exception as exc:
            errors.append(str(exc))
            files_deleted = 0

        space_freed_mb = total_size / (1024 * 1024)

        return CleanupReportDTO(
            files_deleted=files_deleted,
            space_freed_mb=space_freed_mb,
            errors=errors,
            success=len(errors) == 0,
        )

    def _calculate_total_size(self, paths: List[str]) -> int:
        """Calcula el tamaño total en bytes de los archivos que serán eliminados."""
        total = 0
        for path in paths:
            try:
                p = Path(path)
                if p.exists():
                    total += p.stat().st_size
            except OSError as exc:
                logger.warning("No se pudo obtener tamaño de %s: %s", path, exc)
        return total