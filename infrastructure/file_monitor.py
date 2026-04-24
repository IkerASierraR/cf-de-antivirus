"""
infrastructure/file_monitor.py
================================
Implementación concreta de IFileMonitor usando la librería watchdog.
"""

import logging
import threading
from typing import Callable, Optional

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from domain.exceptions import MonitorException
from domain.interfaces import IFileMonitor

logger = logging.getLogger(__name__)


class _AntivirusEventHandler(FileSystemEventHandler):
    """Manejador de eventos del sistema de archivos para el antivirus."""

    def __init__(self, callback: Callable[[str], None]) -> None:
        super().__init__()
        self._callback = callback

    def on_created(self, event) -> None:
        """Invocado automáticamente cuando se crea un archivo nuevo."""
        if event.is_directory:
            return
        logger.debug("Nuevo archivo detectado: %s", event.src_path)
        try:
            self._callback(event.src_path)
        except Exception as exc:
            logger.error("Error en callback de nuevo archivo: %s", exc)

    def on_modified(self, event) -> None:
        """Invocado cuando un archivo existente es modificado."""
        if event.is_directory:
            return
        logger.debug("Archivo modificado: %s", event.src_path)


class FileMonitor(IFileMonitor):
    """Observador del sistema de archivos en tiempo real usando watchdog."""

    def __init__(self) -> None:
        self._observer: Optional[Observer] = None
        self._callback: Optional[Callable[[str], None]] = None
        self._active = False
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Métodos de la interfaz
    # ------------------------------------------------------------------

    def start_monitoring(self, directory: str) -> None:
        """Configura y lanza el Observer de watchdog en el directorio dado."""
        with self._lock:
            if self._active:
                logger.warning("El monitor ya está activo.")
                return

            if self._callback is None:
                raise MonitorException(
                    "Debes registrar un callback antes de iniciar el monitoreo."
                )

            from pathlib import Path
            if not Path(directory).exists():
                raise MonitorException(
                    f"Directorio no encontrado para monitorear: {directory}"
                )

            try:
                self._observer = Observer()
                handler = _AntivirusEventHandler(self._callback)
                self._observer.schedule(handler, directory, recursive=True)
                self._observer.start()
                self._active = True
                logger.info("Monitor iniciado en: %s", directory)
            except Exception as exc:
                self._active = False
                raise MonitorException(
                    f"Error iniciando el monitor: {exc}"
                ) from exc

    def stop_monitoring(self) -> None:
        """Detiene el Observer de watchdog de forma ordenada."""
        with self._lock:
            if not self._active or self._observer is None:
                return
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception as exc:
                logger.warning("Error al detener el monitor: %s", exc)
            finally:
                self._observer = None
                self._active = False
                logger.info("Monitor de archivos detenido.")

    def set_on_file_created_callback(self, callback: Callable[[str], None]) -> None:
        """Registra la función invocada cuando se detecte un nuevo archivo."""
        self._callback = callback

    def is_active(self) -> bool:
        """Retorna True si el monitoreo está activo."""
        return self._active
