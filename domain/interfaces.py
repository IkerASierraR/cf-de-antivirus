"""
domain/interfaces.py
=====================
Contratos abstractos (interfaces) que definen el comportamiento
esperado de los componentes de infraestructura.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from domain.entities import SuspiciousPattern, ThreatFile, ScanResult
from domain.value_objects import FilePath, FileHash


class ISignatureRepository(ABC):
    """Contrato para acceder a la base de datos de firmas."""

    @abstractmethod
    def find_by_hash(self, hash_value: str) -> Optional[SuspiciousPattern]:
        """Busca una firma por hash SHA-256. Retorna None si no existe."""

    @abstractmethod
    def find_by_pattern(self, pattern_hex: str) -> List[SuspiciousPattern]:
        """Busca patrones que coincidan con una secuencia hexadecimal."""

    @abstractmethod
    def get_all_signatures(self) -> List[SuspiciousPattern]:
        """Retorna todas las firmas de virus de la base de datos."""

    @abstractmethod
    def get_all_patterns(self) -> List[SuspiciousPattern]:
        """Retorna todos los patrones de comportamiento sospechoso."""


class IFileScanner(ABC):
    """Contrato para el motor de escaneo de archivos."""

    @abstractmethod
    def scan_file(self, path: FilePath) -> ScanResult:
        """Escanea un archivo individual y retorna el resultado del análisis."""

    @abstractmethod
    def scan_directory(self, path: str) -> ScanResult:
        """Escanea recursivamente todos los archivos de un directorio."""

    @abstractmethod
    def compute_hash(self, path: str) -> FileHash:
        """Calcula el hash SHA-256 de un archivo dado su ruta."""


class IQuarantineManager(ABC):
    """Contrato para el gestor de cuarentena."""

    @abstractmethod
    def quarantine(self, file: ThreatFile) -> bool:
        """Mueve el archivo a cuarentena. Retorna True si fue exitoso."""

    @abstractmethod
    def list_quarantined(self) -> List[ThreatFile]:
        """Lista todos los archivos actualmente en cuarentena."""

    @abstractmethod
    def restore(self, file: ThreatFile) -> bool:
        """Restaura un archivo de cuarentena a su ubicación original."""


class IFileMonitor(ABC):
    """Contrato para el monitor de archivos en tiempo real."""

    @abstractmethod
    def start_monitoring(self, directory: str) -> None:
        """Inicia la observación de un directorio en un hilo separado."""

    @abstractmethod
    def stop_monitoring(self) -> None:
        """Detiene el monitor de archivos de forma segura."""

    @abstractmethod
    def set_on_file_created_callback(self, callback) -> None:
        """Registra la función que se ejecutará cuando se detecte un nuevo archivo."""

    @abstractmethod
    def is_active(self) -> bool:
        """Retorna True si el monitoreo está activo."""


class ICleanupService(ABC):
    """Contrato para el servicio de limpieza del sistema."""

    @abstractmethod
    def find_temp_files(self) -> List[str]:
        """Localiza archivos temporales en el sistema operativo."""

    @abstractmethod
    def delete_files(self, paths: List[str]) -> int:
        """Elimina los archivos de las rutas indicadas. Retorna cantidad eliminada."""
