"""
domain/value_objects.py
========================
Objetos de valor inmutables del dominio.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from domain.exceptions import InvalidFilePathException, InvalidFileHashException


class ThreatLevel(Enum):
    """Niveles de amenaza del sistema antivirus."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def is_dangerous(self) -> bool:
        """Retorna True si el nivel es HIGH o CRITICAL."""
        return self in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def label(self) -> str:
        """Retorna una etiqueta legible para mostrar en pantalla."""
        labels = {
            ThreatLevel.LOW: "Bajo",
            ThreatLevel.MEDIUM: "Medio",
            ThreatLevel.HIGH: "Alto",
            ThreatLevel.CRITICAL: "Crítico",
        }
        return labels[self]

    def color_code(self) -> str:
        """Retorna un código de color ANSI para la CLI."""
        colors = {
            ThreatLevel.LOW: "\033[36m",       # cyan
            ThreatLevel.MEDIUM: "\033[33m",    # yellow
            ThreatLevel.HIGH: "\033[31m",      # red
            ThreatLevel.CRITICAL: "\033[91m",  # bright red
        }
        return colors[self]


@dataclass(frozen=True)
class FilePath:
    """Encapsula y valida una ruta de archivo del sistema."""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise InvalidFilePathException("La ruta del archivo no puede estar vacía.")

    def exists(self) -> bool:
        """Retorna True si el archivo existe físicamente."""
        return Path(self.value).exists()

    def extension(self) -> str:
        """Retorna la extensión del archivo (ej: '.exe', '.pdf')."""
        return Path(self.value).suffix.lower()

    def filename(self) -> str:
        """Retorna solo el nombre del archivo sin el directorio."""
        return Path(self.value).name


@dataclass(frozen=True)
class FileHash:
    """Encapsula un hash criptográfico SHA-256 de un archivo."""

    value: str
    algorithm: str = "sha256"

    def __post_init__(self) -> None:
        if not re.match(r"^[0-9a-fA-F]{64}$", self.value):
            raise InvalidFileHashException(
                f"Formato de hash SHA-256 inválido: {self.value}"
            )

    def equals(self, other: "FileHash") -> bool:
        """Compara dos hashes de forma segura (case-insensitive)."""
        return self.value.lower() == other.value.lower()

    def short(self) -> str:
        """Retorna los primeros 16 caracteres del hash para visualización."""
        return self.value[:16]
