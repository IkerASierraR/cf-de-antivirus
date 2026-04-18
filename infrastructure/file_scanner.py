"""
infrastructure/file_scanner.py
================================
Implementación concreta de IFileScanner.

Este archivo contiene el motor de escaneo de archivos del antivirus.
Es responsable de calcular hashes y detectar patrones sospechosos
en el contenido de los archivos del sistema.

Depende de:
    - domain/interfaces.py      → implementa IFileScanner
    - domain/entities.py        → construye ThreatFile y ScanResult
    - domain/value_objects.py   → usa FileHash y FilePath
    - domain/exceptions.py      → lanza ScannerException si hay errores
    - infrastructure/signature_repository.py → consulta firmas detectadas

Clases que debe contener:
--------------------------

FileScanner (implementa IFileScanner):
    Motor principal de escaneo de archivos.

    Constructor:
        Recibe el ISignatureRepository para consultar hashes detectados.
        Recibe configuración de settings (extensiones permitidas, tamaño máximo).

    Método: scan_file(path: FilePath) -> ScanResult
        Escanea un archivo individual.
        Flujo interno:
            1. Verifica que el archivo existe y tiene permisos de lectura.
            2. Calcula el hash SHA-256 del archivo.
            3. Consulta el repositorio para ver si el hash coincide.
            4. Lee el contenido del archivo en fragmentos (chunks) para
               no cargar archivos grandes completos en memoria.
            5. Busca patrones hexadecimales sospechosos en el contenido.
            6. Construye y retorna un ScanResult.

    Método: scan_directory(path: str) -> ScanResult
        Escanea recursivamente todos los archivos de un directorio.
        Usa os.walk() para navegar subdirectorios.
        Agrega todos los ThreatFile encontrados en un único ScanResult.
        Muestra progreso si se proporcionó un callback de progreso.

    Método: compute_hash(path: str) -> FileHash
        Calcula el hash SHA-256 de un archivo.
        Lee el archivo en chunks de 8192 bytes para eficiencia en memoria.
        Retorna un objeto FileHash con el valor hexadecimal del hash.
        Lanza ScannerException si no puede leer el archivo.

    Método privado: _match_patterns(content: bytes, patterns: list) -> list
        Busca una lista de patrones hexadecimales en el contenido binario.
        Convierte cada patrón hex a bytes y verifica si está presente.
        Retorna los patrones que coincidieron.

    Método privado: _is_scannable(path: str) -> bool
        Verifica si un archivo debe ser escaneado según su extensión
        y tamaño máximo configurado. Excluye archivos del sistema
        críticos (ej: archivos del directorio de Windows del SO).
"""
