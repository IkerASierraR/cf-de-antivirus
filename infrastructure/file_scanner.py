"""
infrastructure/file_scanner.py
================================
Implementación concreta de IFileScanner.
Motor de escaneo que detecta amenazas por hash SHA-256 y patrones hexadecimales.
"""

import hashlib
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import List

from domain.entities import ScanResult, ThreatFile
from domain.exceptions import ScannerException
from domain.interfaces import IFileScanner, ISignatureRepository
from domain.value_objects import FileHash, FilePath, ThreatLevel

logger = logging.getLogger(__name__)

# Extensiones escaneables por defecto
_DEFAULT_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js",
    ".pdf", ".docm", ".xlsm", ".zip", ".rar", ".jar", ".py",
}

# Tamaño máximo por defecto en MB
_DEFAULT_MAX_SIZE_MB = 100


class FileScanner(IFileScanner):
    """Motor principal de escaneo de archivos del antivirus."""

    def __init__(
        self,
        repository: ISignatureRepository,
        scan_extensions: List[str] | None = None,
        max_size_mb: int = _DEFAULT_MAX_SIZE_MB,
    ) -> None:
        self._repository = repository
        self._scan_extensions = (
            {ext.lower() for ext in scan_extensions}
            if scan_extensions
            else _DEFAULT_EXTENSIONS
        )
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._patterns_cache: list | None = None

    # ------------------------------------------------------------------
    # Métodos de la interfaz
    # ------------------------------------------------------------------

    def scan_file(self, path: FilePath) -> ScanResult:
        """Escanea un archivo individual y retorna el resultado."""
        start = time.time()

        if not path.exists():
            raise ScannerException(path.value, f"Archivo no encontrado: {path.value}")

        threats: List[ThreatFile] = []

        try:
            file_hash = self.compute_hash(path.value)
            stat = Path(path.value).stat()
            file_size = stat.st_size

            # 1 — Comprobar por hash SHA-256 en la base de firmas de virus
            signature = self._repository.find_by_hash(file_hash.value)
            if signature:
                threat = ThreatFile(
                    path=path.value,
                    hash_sha256=file_hash.value,
                    threat_level=self._parse_threat_level(signature.threat_level),
                    detected_at=datetime.now(),
                    file_size=file_size,
                    signature_name=signature.pattern_name,
                    category=signature.category,
                )
                threats.append(threat)
            else:
                # 2 — Comprobar patrones hexadecimales en el contenido del archivo
                content_threats = self._scan_content_patterns(path.value, file_size)
                threats.extend(content_threats)

        except ScannerException:
            raise
        except Exception as exc:
            logger.warning("Error escaneando %s: %s", path.value, exc)

        duration = time.time() - start
        return ScanResult(
            scanned_files=1,
            threats_found=threats,
            scan_duration=duration,
            scan_path=path.value,
            finished_at=datetime.now(),
        )

    def scan_directory(
        self,
        path: str,
        progress_callback=None,
    ) -> ScanResult:
        """Escanea recursivamente todos los archivos de un directorio."""
        start = time.time()
        all_threats: List[ThreatFile] = []
        total_scanned = 0
        scan_root = Path(path)

        if not scan_root.exists():
            raise ScannerException(path, f"Directorio no encontrado: {path}")

        # Recopilar archivos elegibles
        files_to_scan = [
            Path(root) / filename
            for root, _dirs, files in os.walk(scan_root)
            for filename in files
        ]

        total = len(files_to_scan)

        for idx, file_path in enumerate(files_to_scan, start=1):
            if not self._is_scannable(str(file_path)):
                continue
            try:
                fp = FilePath(str(file_path))
                result = self.scan_file(fp)
                total_scanned += result.scanned_files
                all_threats.extend(result.threats_found)
            except Exception as exc:
                logger.debug("Omitiendo %s: %s", file_path, exc)

            if progress_callback:
                progress_callback(idx, total)

        duration = time.time() - start
        return ScanResult(
            scanned_files=total_scanned,
            threats_found=all_threats,
            scan_duration=duration,
            scan_path=path,
            finished_at=datetime.now(),
        )

    def compute_hash(self, path: str) -> FileHash:
        """Calcula el hash SHA-256 de un archivo leyendo en chunks."""
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    sha256.update(chunk)
        except OSError as exc:
            raise ScannerException(path, f"No se puede leer el archivo: {exc}") from exc
        return FileHash(value=sha256.hexdigest())

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _scan_content_patterns(
        self, path: str, file_size: int
    ) -> List[ThreatFile]:
        """Busca patrones hexadecimales sospechosos en el contenido binario."""
        threats: List[ThreatFile] = []

        if file_size > self._max_size_bytes:
            return threats

        try:
            with open(path, "rb") as fh:
                content = fh.read()
        except OSError:
            return threats

        ext = Path(path).suffix.lower()
        patterns = self._get_patterns()

        matched = self._match_patterns(content, patterns, ext)
        for pattern in matched:
            threat = ThreatFile(
                path=path,
                hash_sha256="0" * 64,
                threat_level=self._parse_threat_level(pattern.threat_level),
                detected_at=datetime.now(),
                file_size=file_size,
                signature_name=pattern.pattern_name,
                category=pattern.category or "suspicious_pattern",
            )
            threats.append(threat)

        return threats

    def _match_patterns(self, content: bytes, patterns: list, ext: str) -> list:
        """Retorna los patrones cuya secuencia hex está presente en el contenido."""
        matched = []
        for pattern in patterns:
            # Filtrar por extensión si el patrón tiene una extensión definida
            if pattern.category and pattern.category != ext:
                continue
            try:
                pattern_bytes = bytes.fromhex(pattern.signature_hash)
                if pattern_bytes in content:
                    matched.append(pattern)
            except ValueError:
                continue
        return matched

    def _is_scannable(self, path: str) -> bool:
        """Verifica si un archivo debe ser escaneado según extensión y tamaño."""
        file_path = Path(path)

        # Solo archivos con extensiones en la lista configurada
        if file_path.suffix.lower() not in self._scan_extensions:
            return False

        # Verificar tamaño máximo
        try:
            if file_path.stat().st_size > self._max_size_bytes:
                return False
        except OSError:
            return False

        return True

    def _get_patterns(self) -> list:
        """Carga y cachea todos los patrones sospechosos de la base de datos."""
        if self._patterns_cache is None:
            try:
                self._patterns_cache = self._repository.get_all_patterns()
            except Exception as exc:
                logger.warning("No se pudieron cargar patrones: %s", exc)
                self._patterns_cache = []
        return self._patterns_cache

    @staticmethod
    def _parse_threat_level(level_str: str) -> ThreatLevel:
        """Convierte el string de nivel a ThreatLevel enum, con fallback."""
        try:
            return ThreatLevel(level_str.upper())
        except ValueError:
            return ThreatLevel.MEDIUM
