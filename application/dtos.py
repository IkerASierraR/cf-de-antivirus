from dataclasses import dataclass
from typing import Optional, List


@dataclass
class ScanRequestDTO:
    """Datos de entrada para iniciar un escaneo."""
    target_path: str
    scan_type: str
    include_extensions: List[str]


@dataclass
class ScanResponseDTO:
    """Datos de salida después de completar un escaneo."""
    total_files_scanned: int
    threats_found: int
    threat_list: List[dict]
    duration_seconds: float
    status: str


@dataclass
class QuarantineRequestDTO:
    """Datos de entrada para solicitar cuarentena de un archivo."""
    file_path: str
    reason: str


@dataclass
class QuarantineResponseDTO:
    """Datos de salida tras intentar una cuarentena."""
    success: bool
    quarantine_path: str
    error_message: Optional[str]


@dataclass
class CleanupRequestDTO:
    """Datos de entrada para iniciar una limpieza del sistema."""
    include_temp: bool
    include_quarantine: bool
    custom_paths: List[str]


@dataclass
class CleanupReportDTO:
    """Datos de salida tras completar una limpieza."""
    files_deleted: int
    space_freed_mb: float
    errors: List[str]
    success: bool