import logging
from pathlib import Path
from typing import List

from domain.interfaces import FileScanner
from domain.entities import ScanReport
from domain.exceptions import FileNotFoundError, ScanError
from .dtos import ScanRequestDTO, ScanResponseDTO, InfectedFileDTO

logger = logging.getLogger(__name__)


class ScanUseCase:
    """Caso de uso para escaneo de archivos"""
    
    def __init__(self, file_scanner: FileScanner):
        self.file_scanner = file_scanner
    
    async def execute(self, request: ScanRequestDTO) -> ScanResponseDTO:
        """
        Ejecuta el escaneo de archivos según la solicitud
        
        Args:
            request: DTO con la solicitud de escaneo
            
        Returns:
            DTO con los resultados del escaneo
            
        Raises:
            FileNotFoundError: Si el path no existe
            ScanError: Si ocurre un error durante el escaneo
        """
        try:
            # Validar que el path existe
            if not request.path.exists():
                raise FileNotFoundError(f"Path no encontrado: {request.path}")
            
            # Realizar el escaneo
            if request.path.is_file():
                # Escaneo de archivo individual
                result = await self.file_scanner.scan_file(request.path)
                report = ScanReport(
                    scan_id="single_file",
                    start_time=result.file_hash.sha256  # Esto no es correcto, pero para mantener la estructura
                )
                report.add_result(result)
                report.complete()
            else:
                # Escaneo de directorio
                report = await self.file_scanner.scan_directory(
                    request.path,
                    recursive=request.recursive
                )
            
            # Convertir a DTO de respuesta
            return self._to_response_dto(report)
            
        except (FileNotFoundError, ScanError) as e:
            logger.error(f"Error en caso de uso de escaneo: {e}")
            raise
        except Exception as e:
            logger.error(f"Error inesperado en escaneo: {e}")
            raise ScanError(f"Error inesperado durante el escaneo: {e}")
    
    def _to_response_dto(self, report: ScanReport) -> ScanResponseDTO:
        """Convierte un ScanReport a ScanResponseDTO"""
        infected_details = []
        
        for result in report.details:
            infected_details.append(InfectedFileDTO(
                file_path=str(result.file_path),
                file_size=result.file_size,
                threat_name=result.threat_name,
                threat_level=result.threat_level.value if result.threat_level else "UNKNOWN",
                threat_category=result.threat_category.value if result.threat_category else "UNKNOWN",
                pattern_matches=result.pattern_matches
            ))
        
        summary = report.get_summary()
        
        return ScanResponseDTO(
            scan_id=report.scan_id,
            start_time=report.start_time,
            end_time=report.end_time,
            total_files=report.total_files_scanned,
            infected_files=report.infected_files,
            threats_by_level=report.threats_by_level,
            threats_by_category=report.threats_by_category,
            summary=summary,
            details=infected_details
        )