"""
infrastructure/signature_repository.py
========================================
Implementación concreta de ISignatureRepository usando SQLite.
"""

import logging
from typing import List, Optional

from domain.entities import SuspiciousPattern
from domain.exceptions import DatabaseConnectionException
from domain.interfaces import ISignatureRepository
from infrastructure.database_connection import DatabaseConnection

logger = logging.getLogger(__name__)


class SQLiteSignatureRepository(ISignatureRepository):
    """Repositorio de firmas almacenadas en SQLite."""

    def __init__(self, db_connection: DatabaseConnection) -> None:
        self._db = db_connection

    # ------------------------------------------------------------------
    # Métodos públicos
    # ------------------------------------------------------------------

    def find_by_hash(self, hash_value: str) -> Optional[SuspiciousPattern]:
        """Busca una firma en virus_signatures por hash SHA-256."""
        try:
            cursor = self._db.get_cursor()
            cursor.execute(
                "SELECT id, name, hash_sha256, threat_level, category, description "
                "FROM virus_signatures WHERE hash_sha256 = ?",
                (hash_value.lower(),),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._map_virus_row(row)
        except Exception as exc:
            logger.error("Error buscando firma por hash: %s", exc)
            raise DatabaseConnectionException(f"Error en find_by_hash: {exc}") from exc

    def find_by_pattern(self, pattern_hex: str) -> List[SuspiciousPattern]:
        """Busca patrones en suspicious_patterns por secuencia hexadecimal."""
        try:
            cursor = self._db.get_cursor()
            cursor.execute(
                "SELECT id, pattern_name, pattern_hex, threat_level, file_extension, description "
                "FROM suspicious_patterns WHERE pattern_hex LIKE ?",
                (f"%{pattern_hex}%",),
            )
            return [self._map_pattern_row(row) for row in cursor.fetchall()]
        except Exception as exc:
            logger.error("Error buscando patrón: %s", exc)
            raise DatabaseConnectionException(f"Error en find_by_pattern: {exc}") from exc

    def get_all_signatures(self) -> List[SuspiciousPattern]:
        """Retorna todas las firmas de la tabla virus_signatures."""
        try:
            cursor = self._db.get_cursor()
            cursor.execute(
                "SELECT id, name, hash_sha256, threat_level, category, description "
                "FROM virus_signatures"
            )
            return [self._map_virus_row(row) for row in cursor.fetchall()]
        except Exception as exc:
            logger.error("Error obteniendo firmas: %s", exc)
            raise DatabaseConnectionException(f"Error en get_all_signatures: {exc}") from exc

    def get_all_patterns(self) -> List[SuspiciousPattern]:
        """Retorna todos los patrones de la tabla suspicious_patterns."""
        try:
            cursor = self._db.get_cursor()
            cursor.execute(
                "SELECT id, pattern_name, pattern_hex, threat_level, file_extension, description "
                "FROM suspicious_patterns"
            )
            return [self._map_pattern_row(row) for row in cursor.fetchall()]
        except Exception as exc:
            logger.error("Error obteniendo patrones: %s", exc)
            raise DatabaseConnectionException(f"Error en get_all_patterns: {exc}") from exc

    # ------------------------------------------------------------------
    # Métodos privados de mapeo
    # ------------------------------------------------------------------

    def _map_virus_row(self, row) -> SuspiciousPattern:
        """Convierte una fila de virus_signatures a SuspiciousPattern."""
        return SuspiciousPattern(
            id=row["id"],
            pattern_name=row["name"],
            signature_hash=row["hash_sha256"],
            threat_level=row["threat_level"],
            category=row["category"],
            description=row["description"] or "",
        )

    def _map_pattern_row(self, row) -> SuspiciousPattern:
        """Convierte una fila de suspicious_patterns a SuspiciousPattern."""
        return SuspiciousPattern(
            id=row["id"],
            pattern_name=row["pattern_name"],
            signature_hash=row["pattern_hex"],
            threat_level=row["threat_level"],
            category=row["file_extension"] or "",
            description=row["description"] or "",
        )
