"""
domain/value_objects.py
========================
Objetos de valor inmutables del dominio.

Los Value Objects son objetos sin identidad propia. Dos instancias
con los mismos datos son consideradas iguales. Son inmutables.

Clases que debe contener:
--------------------------

FilePath:
    Encapsula y valida una ruta de archivo del sistema.
    Atributos: value (str).
    Validaciones internas:
        - La ruta no debe estar vacía.
        - Puede verificar si el archivo existe en el sistema.
    Métodos:
        - exists(): Retorna True si el archivo existe físicamente.
        - extension(): Retorna la extensión del archivo (ej: '.exe', '.pdf').
        - filename(): Retorna solo el nombre del archivo sin el directorio.

FileHash:
    Encapsula un hash criptográfico de un archivo (SHA-256).
    Atributos: value (str), algorithm (str = 'sha256').
    Validaciones internas:
        - El hash debe tener exactamente 64 caracteres hexadecimales.
        - Solo debe contener caracteres válidos hexadecimales.
    Métodos:
        - equals(other: FileHash): Compara dos hashes de forma segura.
        - short(): Retorna los primeros 16 caracteres del hash para visualización.

ThreatLevel:
    Enum que define los niveles de amenaza del sistema.
    Valores: LOW, MEDIUM, HIGH, CRITICAL.
    Métodos:
        - is_dangerous(): Retorna True si el nivel es HIGH o CRITICAL.
        - label(): Retorna una etiqueta legible para mostrar en pantalla.
        - color_code(): Retorna un código de color ANSI para la CLI (ej: rojo para CRITICAL).
"""
