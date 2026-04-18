import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Settings:
    """Configuración global de la aplicación"""
    
    def __init__(self):
        """Carga las variables de entorno desde el archivo .env (si existe).
        Asigna valores por defecto a cada configuración si no están en .env."""
        self.DB_PATH = os.getenv("DB_PATH", "antivirus.db")
        self.QUARANTINE_DIR = os.getenv("QUARANTINE_DIR", "./quarantine")
        
        # Auto-detectar directorios temporales según el sistema operativo
        if os.name == "nt":
            self.TEMP_DIRS = [
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.environ.get("TMP", "C:\\Windows\\Temp"),
                "C:\\Windows\\Prefetch"
            ]
        else:
            self.TEMP_DIRS = [
                "/tmp",
                "/var/tmp",
                "/dev/shm"
            ]
        
        self.SCAN_EXTENSIONS = os.getenv("SCAN_EXTENSIONS", ".exe,.dll,.bat,.ps1,.vbs,.js,.pdf,.docm,.xlsm,.zip,.rar,.jar,.py").split(",")
        self.MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))
        
        # Directorio de Descargas del usuario actual
        self.MONITOR_DIRECTORY = os.getenv("MONITOR_DIRECTORY", str(Path.home() / "Downloads"))
        
        self.AUTO_QUARANTINE_LEVELS = os.getenv("AUTO_QUARANTINE_LEVELS", "CRITICAL,HIGH").split(",")
        self.APP_VERSION = os.getenv("APP_VERSION", "1.0.0")