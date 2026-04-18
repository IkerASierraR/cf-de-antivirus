"""
infrastructure/signature_repository.py
========================================
Implementación concreta de ISignatureRepository usando SQLite.

Este archivo implementa el contrato definido en domain/interfaces.py.
Es la única clase que ejecuta consultas SQL contra la base de datos.
Todas las consultas son SELECT (solo lectura, sin modificaciones).

Depende de:
    - domain/interfaces.py → implementa ISignatureRepository
    - domain/entities.py   → retorna objetos SuspiciousPattern
    - infrastructure/database_connection.py → obtiene el cursor SQL

Clases que debe contener:
--------------------------

SQLiteSignatureRepository (implementa ISignatureRepository):
    Repositorio de firmas almacenadas en la base de datos SQLite.

    Constructor:
        Recibe la instancia de DatabaseConnection (por inyección de dependencias).
        Guarda la referencia al cursor para ejecutar las consultas.

    Método: find_by_hash(hash_value: str) -> Optional[SuspiciousPattern]
        Ejecuta:
            SELECT * FROM virus_signatures WHERE hash_sha256 = ?
        Recibe el hash SHA-256 de un archivo escaneado.
        Retorna un objeto SuspiciousPattern si hay coincidencia.
        Retorna None si no se encontró el hash en la base de datos.
        Maneja excepciones de base de datos y las convierte en
        DatabaseConnectionException del dominio.

    Método: find_by_pattern(pattern_hex: str) -> list[SuspiciousPattern]
        Ejecuta:
            SELECT * FROM suspicious_patterns WHERE pattern_hex LIKE ?
        Busca patrones de comportamiento sospechoso por secuencia hexadecimal.
        Retorna una lista de coincidencias (puede estar vacía).

    Método: get_all_signatures() -> list[SuspiciousPattern]
        Ejecuta:
            SELECT * FROM virus_signatures
        Retorna todas las firmas disponibles en la base de datos.
        Usado para mostrar estadísticas o para cargar firmas en memoria
        al iniciar el sistema (precarga opcional para mejor rendimiento).

    Método privado: _map_row_to_entity(row: tuple) -> SuspiciousPattern
        Convierte una fila de la base de datos (tupla) al objeto
        SuspiciousPattern del dominio. Centraliza el mapeo para
        evitar duplicación en cada método de consulta.
"""
