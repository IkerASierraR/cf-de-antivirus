"""
infrastructure/cleanup_service.py
===================================
Implementación concreta de ICleanupService.
Localiza y elimina archivos temporales del sistema operativo.
"""

import logging
import os
import platform
from pathlib import Path
from typing import List

from domain.interfaces import ICleanupService

logger = logging.getLogger(__name__)

# Extensiones consideradas temporales
_TEMP_EXTENSIONS = {".tmp", ".temp", ".log", ".old", ".bak", ".cache"}


class SystemCleanupService(ICleanupService):
    """Servicio de limpieza de archivos temporales del sistema."""

    def __init__(self, temp_dirs: List[str] | None = None) -> None:
        self._os = platform.system()
        self._temp_dirs: List[str] = temp_dirs or self._detect_temp_dirs()

    # ------------------------------------------------------------------
    # Métodos de la interfaz
    # ------------------------------------------------------------------

    def find_temp_files(self) -> List[str]:
        """Busca archivos temporales en los directorios configurados."""
        found: List[str] = []

        for directory in self._temp_dirs:
            dir_path = Path(directory)
            if not dir_path.exists():
                continue
            try:
                for root, _dirs, files in os.walk(dir_path):
                    for filename in files:
                        filepath = Path(root) / filename
                        if self._is_temp_file(filepath):
                            found.append(str(filepath))
            except PermissionError:
                logger.debug("Sin permisos para listar: %s", directory)

        return found

    def delete_files(self, paths: List[str]) -> int:
        """Elimina los archivos de las rutas indicadas. Retorna cantidad eliminada."""
        deleted = 0
        for path in paths:
            try:
                if not self._is_safe_to_delete(path):
                    logger.warning("Ruta no segura, omitiendo: %s", path)
                    continue
                os.remove(path)
                deleted += 1
            except OSError as exc:
                logger.debug("No se pudo eliminar %s: %s", path, exc)
        return deleted

    def get_system_temp_dirs(self) -> List[str]:
        """Retorna la lista de directorios temporales supervisados."""
        return list(self._temp_dirs)

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _detect_temp_dirs(self) -> List[str]:
        """Detecta los directorios temporales según el sistema operativo."""
        if self._os == "Windows":
            return [
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.environ.get("TMP", "C:\\Windows\\Temp"),
                "C:\\Windows\\Prefetch",
            ]
        # Linux / macOS
        home = str(Path.home())
        candidates = ["/tmp", "/var/tmp", f"{home}/.cache"]
        return [d for d in candidates if Path(d).exists()]

    def _is_temp_file(self, path: Path) -> bool:
        """Retorna True si el archivo tiene una extensión temporal o nombre temporal."""
        ext = path.suffix.lower()
        name = path.name.lower()
        return ext in _TEMP_EXTENSIONS or name.startswith("~")

    def _is_safe_to_delete(self, path: str) -> bool:
        """Verifica que el archivo está dentro de un directorio temporal permitido."""
        target = Path(path).resolve()
        for safe_dir in self._temp_dirs:
            try:
                target.relative_to(Path(safe_dir).resolve())
                return True
            except ValueError:
                continue
        return False

    def _get_file_size(self, path: str) -> int:
        """Retorna el tamaño en bytes de un archivo. Retorna 0 si no es accesible."""
        try:
            return Path(path).stat().st_size
        except OSError:
            return 0
