from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DB_FILE_PATH = BASE_DIR / 'antivirus.db'

QUARANTINE_PATH = BASE_DIR / 'quarantine'
QUARANTINE_PATH.mkdir(parents=True, exist_ok=True)

QUARANTINE_INDEX_PATH = QUARANTINE_PATH / 'quarantine_index.json'

SCHEMA_SQL_PATH = BASE_DIR / 'schema.sql'

ENV_FILE_PATH = BASE_DIR / '.env'