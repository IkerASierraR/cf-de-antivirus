"""
infrastructure/database_connection.py
=======================================
Conexión centralizada y única a la base de datos SQLite.

REGLA CRÍTICA: Este archivo es el ÚNICO punto de acceso a la base de datos
en todo el proyecto. Ningún otro archivo debe crear conexiones SQLite
directamente. Todos los repositorios deben usar esta clase.

Patrón de diseño aplicado: Singleton.
El Singleton garantiza que solo exista UNA instancia de la conexión
durante toda la ejecución del programa, evitando conflictos y
optimizando los recursos del sistema.

Comportamiento de la conexión:
    - Solo realiza operaciones SELECT (lectura).
    - Nunca realiza INSERT, UPDATE ni DELETE.
    - La base de datos es de solo referencia (watchlist de firmas).
    - Se abre al iniciar el sistema y se cierra al terminar.

Clases que debe contener:
--------------------------

DatabaseConnection:
    Singleton que gestiona la conexión SQLite.

    Atributo de clase: _instance (DatabaseConnection | None)
        Almacena la única instancia del Singleton. Inicialmente None.

    Método de clase: get_instance() -> DatabaseConnection
        Punto de acceso global al Singleton.
        Si _instance es None, crea la conexión y la almacena.
        Si ya existe, la retorna directamente.
        Es el ÚNICO método que debe llamarse desde otros módulos.

    Método: get_cursor() -> sqlite3.Cursor
        Retorna un cursor listo para ejecutar consultas SELECT.
        Debe verificar que la conexión sigue activa antes de retornar.

    Método: close() -> None
        Cierra la conexión de forma segura.
        Llama a connection.close() y pone _instance en None.
        Debe llamarse al final de la ejecución del programa (en main.py).

    Método privado: _connect(db_path: str) -> sqlite3.Connection
        Establece la conexión con el archivo SQLite.
        Lanza DatabaseConnectionException si el archivo no existe
        o si hay un error al conectar.
        Configura la conexión en modo de solo lectura si el SO lo permite.
"""
