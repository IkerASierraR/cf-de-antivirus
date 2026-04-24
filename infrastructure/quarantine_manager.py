"""
infrastructure/quarantine_manager.py
======================================
Implementación concreta de IQuarantineManager.
Gestiona el movimiento físico de archivos amenazantes hacia cuarentena.
"""

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import List

from domain.entities import ThreatFile
from domain.exceptions import QuarantineException
from domain.interfaces import IQuarantineManager
from domain.value_objects import ThreatLevel
from config.paths import QUARANTINE_PATH, QUARANTINE_INDEX_PATH

logger = logging.getLogger(__name__)


class QuarantineManager(IQuarantineManager):
    """Gestor físico de la cuarentena de archivos."""

    def __init__(self, quarantine_dir: str | None = None) -> None:
        self._quarantine_dir = Path(quarantine_dir) if quarantine_dir else QUARANTINE_PATH
        self._index_path = self._quarantine_dir / "quarantine_index.json"
        self._quarantine_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Métodos de la interfaz
    # ------------------------------------------------------------------

    def quarantine(self, file: ThreatFile) -> bool:
        """Mueve el archivo amenazante a la carpeta de cuarentena."""
        source = Path(file.path)
        if not source.exists():
            raise QuarantineException(file.path, f"El archivo no existe: {file.path}")

        quarantine_name = self._generate_quarantine_filename(source.name)
        dest = self._quarantine_dir / quarantine_name

        try:
            shutil.move(str(source), str(dest))

            # Quitar permisos de ejecución en sistemas Unix
            if os.name != "nt":
                dest.chmod(0o600)

            # Actualizar índice y marcar la entidad
            self._update_index(quarantine_name, str(dest), file)
            file.mark_as_quarantined(str(dest))

            logger.info("Archivo en cuarentena: %s → %s", file.path, dest)
            return True

        except (OSError, shutil.Error) as exc:
            raise QuarantineException(
                file.path, f"Error moviendo a cuarentena: {exc}"
            ) from exc

    def list_quarantined(self) -> List[ThreatFile]:
        """Lista todos los archivos actualmente en cuarentena."""
        index = self._load_index()
        result: List[ThreatFile] = []

        for _qname, entry in index.items():
            qpath = entry.get("quarantine_path", "")
            if not qpath or not Path(qpath).exists():
                continue  # Archivo ya no presente físicamente

            detected_at = self._parse_dt(entry.get("quarantined_at"))
            quarantined_at = detected_at

            tf = ThreatFile(
                path=entry.get("original_path", ""),
                hash_sha256=entry.get("hash_sha256", "0" * 64),
                threat_level=self._parse_threat_level(entry.get("threat_level", "MEDIUM")),
                detected_at=detected_at,
                is_quarantined=True,
                file_size=entry.get("file_size", 0),
                signature_name=entry.get("reason", ""),
                category=entry.get("category", ""),
                quarantine_path=qpath,
                quarantined_at=quarantined_at,
            )
            result.append(tf)

        return result

    def restore(self, file: ThreatFile) -> bool:
        """Restaura un archivo de cuarentena a su ubicación original."""
        if not file.quarantine_path or not Path(file.quarantine_path).exists():
            raise QuarantineException(
                file.quarantine_path or "",
                "Archivo de cuarentena no encontrado.",
            )

        dest = Path(file.path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.move(str(file.quarantine_path), str(dest))
            self._remove_from_index(Path(file.quarantine_path).name)
            logger.info("Archivo restaurado: %s → %s", file.quarantine_path, dest)
            return True
        except (OSError, shutil.Error) as exc:
            raise QuarantineException(
                file.quarantine_path,
                f"Error restaurando archivo: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _update_index(
        self, quarantine_name: str, quarantine_path: str, file: ThreatFile
    ) -> None:
        """Añade o actualiza una entrada en el índice JSON de cuarentena."""
        index = self._load_index()
        index[quarantine_name] = {
            "original_path": file.path,
            "quarantine_path": quarantine_path,
            "reason": file.signature_name,
            "threat_level": file.threat_level.value,
            "category": file.category,
            "hash_sha256": file.hash_sha256,
            "file_size": file.file_size,
            "quarantined_at": datetime.now().isoformat(),
        }
        self._save_index(index)

    def _remove_from_index(self, quarantine_name: str) -> None:
        """Elimina una entrada del índice JSON."""
        index = self._load_index()
        index.pop(quarantine_name, None)
        self._save_index(index)

    def _load_index(self) -> dict:
        """Carga el índice JSON de cuarentena desde disco."""
        if not self._index_path.exists():
            return {}
        try:
            with open(self._index_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("No se pudo leer el índice de cuarentena: %s", exc)
            return {}

    def _save_index(self, index: dict) -> None:
        """Guarda el índice JSON de cuarentena en disco."""
        try:
            with open(self._index_path, "w", encoding="utf-8") as fh:
                json.dump(index, fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            logger.error("No se pudo guardar el índice de cuarentena: %s", exc)

    @staticmethod
    def _generate_quarantine_filename(original_name: str) -> str:
        """Genera un nombre único para el archivo en cuarentena."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return f"{timestamp}_{original_name}.quar"

    @staticmethod
    def _parse_threat_level(level_str: str) -> ThreatLevel:
        try:
            return ThreatLevel(level_str.upper())
        except ValueError:
            return ThreatLevel.MEDIUM

    @staticmethod
    def _parse_dt(value) -> datetime:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        return datetime.now()
