# config/__init__.py
# Marca este directorio como paquete Python.

from config.paths import (
    BASE_DIR,
    DB_FILE_PATH,
    QUARANTINE_PATH,
    QUARANTINE_INDEX_PATH,
    SCHEMA_SQL_PATH,
    ENV_FILE_PATH
)

from config.settings import Settings

__all__ = [
    "BASE_DIR",
    "DB_FILE_PATH",
    "QUARANTINE_PATH",
    "QUARANTINE_INDEX_PATH",
    "SCHEMA_SQL_PATH",
    "ENV_FILE_PATH",
    "Settings"
]