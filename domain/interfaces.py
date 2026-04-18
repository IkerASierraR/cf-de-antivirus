"""
domain/interfaces.py
=====================
Contratos abstractos (interfaces) que definen el comportamiento
esperado de los componentes de infraestructura.

Este archivo usa el módulo ABC (Abstract Base Classes) de Python.
La capa de infrastructure DEBE implementar estas interfaces.
La capa de application solo conoce estas interfaces, nunca las implementaciones.

Este patrón es la aplicación directa del Principio de Inversión de Dependencias (SOLID - D).

Interfaces que debe contener:
-------------------------------

ISignatureRepository (ABC):
    Contrato para acceder a la base de datos de firmas sospechosas.
    Métodos abstractos:
        - find_by_hash(hash_value: str) -> Optional[SuspiciousPattern]:
            Busca una firma en la base de datos comparando el hash SHA-256.
            Retorna la entidad si existe coincidencia, None en caso contrario.
        - find_by_pattern(pattern_hex: str) -> list[SuspiciousPattern]:
            Busca patrones que coincidan con una secuencia hexadecimal dada.
            Retorna una lista (puede estar vacía) de patrones coincidentes.
        - get_all_signatures() -> list[SuspiciousPattern]:
            Retorna todas las firmas almacenadas en la base de datos.

IFileScanner (ABC):
    Contrato para el motor de escaneo de archivos.
    Métodos abstractos:
        - scan_file(path: FilePath) -> ScanResult:
            Escanea un archivo individual y retorna el resultado del análisis.
        - scan_directory(path: str) -> ScanResult:
            Escanea recursivamente todos los archivos de un directorio.
        - compute_hash(path: str) -> FileHash:
            Calcula el hash SHA-256 de un archivo dado su ruta.

IQuarantineManager (ABC):
    Contrato para el gestor de cuarentena.
    Métodos abstractos:
        - quarantine(file: ThreatFile) -> bool:
            Mueve el archivo amenazante a la carpeta de cuarentena segura.
            Retorna True si la operación fue exitosa.
        - list_quarantined() -> list[ThreatFile]:
            Lista todos los archivos actualmente en cuarentena.
        - restore(file: ThreatFile) -> bool:
            Restaura un archivo de cuarentena a su ubicación original.

IFileMonitor (ABC):
    Contrato para el monitor de archivos en tiempo real.
    Métodos abstractos:
        - start_monitoring(directory: str) -> None:
            Inicia la observación de un directorio en un hilo separado.
        - stop_monitoring() -> None:
            Detiene el monitor de archivos de forma segura.
        - set_on_file_created_callback(callback: callable) -> None:
            Registra la función que se ejecutará cuando se detecte un nuevo archivo.

ICleanupService (ABC):
    Contrato para el servicio de limpieza del sistema.
    Métodos abstractos:
        - find_temp_files() -> list[str]:
            Localiza archivos temporales en el sistema operativo.
        - delete_files(paths: list[str]) -> int:
            Elimina los archivos de las rutas indicadas. Retorna cantidad eliminada.
"""
