"""
domain/entities.py
==================
Entidades principales del dominio del antivirus.

Este archivo define los objetos de negocio centrales del sistema.
NO debe importar nada de capas externas (infrastructure, application, presentation).

Clases que debe contener:
--------------------------

ThreatFile:
    Representa un archivo detectado como amenaza o sospechoso.
    Atributos: path (str), hash_sha256 (str), threat_level (ThreatLevel),
               detected_at (datetime), is_quarantined (bool), file_size (int).
    Métodos:
        - mark_as_quarantined(): Cambia el estado interno a cuarentena.
        - to_dict(): Serializa la entidad a diccionario para transporte.

ScanResult:
    Representa el resultado completo de un escaneo del sistema.
    Atributos: scanned_files (int), threats_found (list[ThreatFile]),
               scan_duration (float), scan_path (str), finished_at (datetime).
    Métodos:
        - has_threats(): Retorna True si se encontraron amenazas.
        - threat_count(): Retorna el número de amenazas detectadas.
        - summary(): Retorna un resumen legible del resultado.

SuspiciousPattern:
    Representa un patrón de firma almacenado en la base de datos.
    Atributos: id (int), pattern_name (str), signature_hash (str),
               threat_level (str), category (str), description (str).
    Métodos:
        - matches_hash(file_hash: str): Compara si el hash coincide con la firma.

CleanupReport:
    Representa el reporte generado tras una limpieza del sistema.
    Atributos: files_deleted (int), bytes_freed (int), errors (list[str]),
               executed_at (datetime).
    Métodos:
        - bytes_freed_mb(): Convierte los bytes liberados a megabytes.
        - was_successful(): Retorna True si no hubo errores durante la limpieza.
"""
