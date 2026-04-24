"""
infrastructure/database_connection.py
=======================================
Conexión centralizada y única a la base de datos SQLite.
Patrón Singleton. Solo realiza operaciones SELECT en tiempo de ejecución.
"""

import sqlite3
import logging
from pathlib import Path
from typing import Optional

from domain.exceptions import DatabaseConnectionException
from config.paths import DB_FILE_PATH

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Esquema SQLite y datos semilla (adaptado desde schema.sql)
# -------------------------------------------------------------------

_CREATE_VIRUS_SIGNATURES = """
CREATE TABLE IF NOT EXISTS virus_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    hash_md5    TEXT,
    hash_sha256 TEXT    NOT NULL UNIQUE,
    threat_level TEXT   NOT NULL DEFAULT 'MEDIUM',
    category    TEXT    NOT NULL,
    description TEXT,
    added_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

_CREATE_SUSPICIOUS_PATTERNS = """
CREATE TABLE IF NOT EXISTS suspicious_patterns (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name   TEXT NOT NULL,
    pattern_hex    TEXT NOT NULL,
    file_extension TEXT,
    threat_level   TEXT NOT NULL DEFAULT 'MEDIUM',
    description    TEXT
);
"""

_SEED_SIGNATURES = [
    (
        "EICAR-Test-File",
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "LOW", "test",
        "Archivo de prueba estándar EICAR. No es malware real.",
    ),
    (
        "Ransomware.WannaCry.v1",
        "84c82835a5d21bbcf75a61706d8ab549",
        "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        "CRITICAL", "ransomware",
        "Variante original de WannaCry. Cifra archivos y exige rescate en Bitcoin.",
    ),
    (
        "Ransomware.Locky",
        "aa4db4b5e7a8c9d1e2f3a4b5c6d7e8f9",
        "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        "CRITICAL", "ransomware",
        "Locky se propaga por macros maliciosas en documentos Office.",
    ),
    (
        "Trojan.AgentTesla",
        "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
        "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        "HIGH", "trojan",
        "Troyano de acceso remoto (RAT). Roba credenciales y capturas de pantalla.",
    ),
    (
        "Trojan.Emotet",
        "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
        "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "CRITICAL", "trojan",
        "Emotet es un malware modular bancario/dropper muy peligroso.",
    ),
    (
        "Worm.Conficker.A",
        "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
        "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "HIGH", "worm",
        "Conficker explota la vulnerabilidad MS08-067 de Windows.",
    ),
    (
        "Adware.OpenCandy",
        "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        "LOW", "adware",
        "Adware que muestra publicidad no deseada en el navegador.",
    ),
    (
        "Spyware.KeyloggerGeneric",
        "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1",
        "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "HIGH", "spyware",
        "Keylogger genérico que registra pulsaciones y las envía a un servidor remoto.",
    ),
    (
        "Rootkit.ZeroAccess",
        "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
        "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
        "CRITICAL", "rootkit",
        "Rootkit que deshabilita el firewall y convierte el equipo en bot.",
    ),
]

_SEED_PATTERNS = [
    (
        "PowerShell-EncodedCommand",
        "706F7765727368656C6C202D656E636F646564436F6D6D616E64",
        ".ps1", "HIGH",
        "Comando PowerShell con -encodedCommand. Técnica para ejecutar código ofuscado.",
    ),
    (
        "VBA-AutoOpen-Macro",
        "537562204175746F4F70656E28",
        ".docm", "HIGH",
        "Macro VBA que se ejecuta automáticamente al abrir el documento.",
    ),
    (
        "PE-Header-Inside-PDF",
        "4D5A90000300000004000000FFFF",
        ".pdf", "HIGH",
        "Cabecera de ejecutable Windows (MZ) dentro de un PDF.",
    ),
    (
        "AutoRun-USB-Dropper",
        "5B4175746F52756E5D0D0A4F70656E3D",
        ".inf", "MEDIUM",
        "Patrón de autorun.inf que lanza un ejecutable al insertar USB.",
    ),
    (
        "Batch-WebDownload",
        "706F7765727368656C6C202D63202849",
        ".bat", "MEDIUM",
        "Script batch que usa PowerShell para descargar contenido de Internet.",
    ),
    (
        "NOP-Sled-Shellcode",
        "9090909090909090909090909090",
        None, "CRITICAL",
        "Secuencia NOP (0x90). Indicador de shellcode para buffer overflow.",
    ),
    (
        "Password-Protected-ZIP",
        "504B030414000900",
        ".zip", "LOW",
        "Archivo ZIP protegido con contraseña. Técnica de evasión de antivirus.",
    ),
    (
        "JS-Obfuscated-Eval",
        "6576616C28756E657363617065",
        ".js", "HIGH",
        "JavaScript con eval() y unescape(). Patrón de ofuscación para ocultar código.",
    ),
]


class DatabaseConnection:
    """Singleton que gestiona la única conexión SQLite del sistema."""

    _instance: Optional["DatabaseConnection"] = None

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._connection: Optional[sqlite3.Connection] = None
        self._connect(db_path)

    @classmethod
    def get_instance(cls, db_path: str = str(DB_FILE_PATH)) -> "DatabaseConnection":
        """Punto de acceso global al Singleton."""
        if cls._instance is None:
            cls._instance = cls(db_path)
        return cls._instance

    def get_cursor(self) -> sqlite3.Cursor:
        """Retorna un cursor listo para ejecutar consultas SELECT."""
        if self._connection is None:
            raise DatabaseConnectionException("La conexión a la base de datos no está activa.")
        try:
            self._connection.execute("SELECT 1")
        except sqlite3.Error:
            self._connect(self._db_path)
        return self._connection.cursor()  # type: ignore[union-attr]

    def close(self) -> None:
        """Cierra la conexión de forma segura y destruye el Singleton."""
        if self._connection:
            try:
                self._connection.close()
            except sqlite3.Error as exc:
                logger.warning("Error al cerrar la conexión: %s", exc)
            finally:
                self._connection = None
        DatabaseConnection._instance = None
        logger.info("Conexión a la base de datos cerrada.")

    # ------------------------------------------------------------------
    # Métodos privados
    # ------------------------------------------------------------------

    def _connect(self, db_path: str) -> None:
        """Establece la conexión con el archivo SQLite."""
        try:
            needs_init = not Path(db_path).exists()
            self._connection = sqlite3.connect(db_path, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            if needs_init:
                logger.info("Base de datos nueva. Inicializando esquema y datos semilla.")
                self._initialize_schema()
            else:
                # Ensure tables exist even if DB file was empty
                self._ensure_tables()
        except sqlite3.Error as exc:
            raise DatabaseConnectionException(
                f"No se puede conectar a la base de datos '{db_path}': {exc}"
            ) from exc

    def _initialize_schema(self) -> None:
        """Crea las tablas e inserta los datos semilla."""
        self._ensure_tables()
        self._seed_data()

    def _ensure_tables(self) -> None:
        """Crea las tablas si no existen."""
        assert self._connection is not None
        cursor = self._connection.cursor()
        cursor.execute(_CREATE_VIRUS_SIGNATURES)
        cursor.execute(_CREATE_SUSPICIOUS_PATTERNS)
        self._connection.commit()

    def _seed_data(self) -> None:
        """Inserta los datos iniciales en las tablas."""
        assert self._connection is not None
        cursor = self._connection.cursor()
        cursor.executemany(
            """INSERT OR IGNORE INTO virus_signatures
               (name, hash_md5, hash_sha256, threat_level, category, description)
               VALUES (?, ?, ?, ?, ?, ?)""",
            _SEED_SIGNATURES,
        )
        cursor.executemany(
            """INSERT OR IGNORE INTO suspicious_patterns
               (pattern_name, pattern_hex, file_extension, threat_level, description)
               VALUES (?, ?, ?, ?, ?)""",
            _SEED_PATTERNS,
        )
        self._connection.commit()
        logger.info(
            "Datos semilla insertados: %d firmas, %d patrones.",
            len(_SEED_SIGNATURES),
            len(_SEED_PATTERNS),
        )
