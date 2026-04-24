"""
domain/exceptions.py
=====================
Excepciones propias del dominio del antivirus.
"""


class AntivirusException(Exception):
    """Clase base de todas las excepciones del sistema antivirus."""


class ThreatDetectedException(AntivirusException):
    """Se lanza cuando un archivo es identificado como amenaza."""

    def __init__(self, threat_file, message: str = ""):
        self.threat_file = threat_file
        super().__init__(message or f"Amenaza detectada: {getattr(threat_file, 'path', threat_file)}")


class QuarantineException(AntivirusException):
    """Se lanza cuando falla el proceso de mover un archivo a cuarentena."""

    def __init__(self, path: str, message: str = ""):
        self.path = path
        super().__init__(message or f"Error en cuarentena para: {path}")


class ScannerException(AntivirusException):
    """Se lanza cuando el motor de escaneo falla al analizar un archivo."""

    def __init__(self, path: str, message: str = ""):
        self.path = path
        super().__init__(message or f"Error de escaneo en: {path}")


class DatabaseConnectionException(AntivirusException):
    """Se lanza cuando no se puede establecer o mantener la conexión con SQLite."""


class InvalidFilePathException(AntivirusException):
    """Se lanza cuando se recibe una ruta de archivo inválida o inexistente."""


class InvalidFileHashException(AntivirusException):
    """Se lanza cuando el formato del hash SHA-256 no es válido."""


class MonitorException(AntivirusException):
    """Se lanza cuando el monitor de archivos en tiempo real falla."""
