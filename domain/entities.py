"""
domain/entities.py
==================
Entidades principales del dominio del antivirus.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from domain.value_objects import ThreatLevel


@dataclass
class ThreatFile:
    """Representa un archivo detectado como amenaza o sospechoso."""

    path: str
    hash_sha256: str
    threat_level: ThreatLevel
    detected_at: datetime
    is_quarantined: bool = False
    file_size: int = 0
    signature_name: str = ""
    category: str = ""
    quarantine_path: Optional[str] = None
    quarantined_at: Optional[datetime] = None

    def mark_as_quarantined(self, quarantine_path: str = "") -> None:
        """Cambia el estado interno a cuarentena."""
        self.is_quarantined = True
        self.quarantine_path = quarantine_path
        self.quarantined_at = datetime.now()

    def to_dict(self) -> dict:
        """Serializa la entidad a diccionario para transporte."""
        return {
            "path": self.path,
            "hash_sha256": self.hash_sha256,
            "threat_level": self.threat_level.value,
            "detected_at": self.detected_at.isoformat(),
            "is_quarantined": self.is_quarantined,
            "file_size": self.file_size,
            "signature_name": self.signature_name,
            "category": self.category,
            "quarantine_path": self.quarantine_path,
            "quarantined_at": (
                self.quarantined_at.isoformat() if self.quarantined_at else None
            ),
        }


@dataclass
class ScanResult:
    """Representa el resultado completo de un escaneo del sistema."""

    scanned_files: int
    threats_found: List[ThreatFile]
    scan_duration: float
    scan_path: str
    finished_at: datetime

    def has_threats(self) -> bool:
        """Retorna True si se encontraron amenazas."""
        return len(self.threats_found) > 0

    def threat_count(self) -> int:
        """Retorna el número de amenazas detectadas."""
        return len(self.threats_found)

    def summary(self) -> str:
        """Retorna un resumen legible del resultado."""
        status = "AMENAZAS DETECTADAS" if self.has_threats() else "LIMPIO"
        return (
            f"Ruta: {self.scan_path} | "
            f"Archivos: {self.scanned_files} | "
            f"Amenazas: {self.threat_count()} | "
            f"Duración: {self.scan_duration:.2f}s | "
            f"Estado: {status}"
        )


@dataclass
class SuspiciousPattern:
    """Representa un patrón de firma almacenado en la base de datos."""

    id: int
    pattern_name: str
    signature_hash: str   # hash_sha256 (de virus_signatures) o pattern_hex (de suspicious_patterns)
    threat_level: str
    category: str
    description: str

    def matches_hash(self, file_hash: str) -> bool:
        """Compara si el hash coincide con la firma."""
        return self.signature_hash.lower() == file_hash.lower()


@dataclass
class CleanupReport:
    """Representa el reporte generado tras una limpieza del sistema."""

    files_deleted: int
    bytes_freed: int
    errors: List[str]
    executed_at: datetime

    def bytes_freed_mb(self) -> float:
        """Convierte los bytes liberados a megabytes."""
        return self.bytes_freed / (1024 * 1024)

    def was_successful(self) -> bool:
        """Retorna True si no hubo errores durante la limpieza."""
        return len(self.errors) == 0
