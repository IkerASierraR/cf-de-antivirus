"""
dependencies/container.py
===========================
Contenedor de inyección de dependencias del sistema antivirus.

Este archivo es el "ensamblador" del proyecto. Su única responsabilidad
es construir y conectar todas las piezas del sistema: crea las instancias
concretas de infraestructura, las inyecta en los casos de uso, y expone
los casos de uso listos para ser usados por la presentación.

Patrón de diseño aplicado: Service Locator / Dependency Injection Container.

Al centralizar la creación de objetos aquí, el resto del código no necesita
saber CÓMO se construyen las dependencias, solo las solicita al contenedor.

Esto hace que cambiar una implementación (ej: cambiar SQLite por PostgreSQL)
solo requiera modificar este archivo, sin tocar application/ ni domain/.

Depende de:
    - config/settings.py                         → configuraciones del sistema
    - infrastructure/database_connection.py      → única conexión a BD
    - infrastructure/signature_repository.py     → implementación del repositorio
    - infrastructure/file_scanner.py             → motor de escaneo
    - infrastructure/quarantine_manager.py       → gestor de cuarentena
    - infrastructure/file_monitor.py             → monitor en tiempo real
    - infrastructure/cleanup_service.py          → servicio de limpieza
    - application/scan_use_case.py               → caso de uso de escaneo
    - application/protection_use_case.py         → caso de uso de protección
    - application/quarantine_use_case.py         → caso de uso de cuarentena
    - application/cleanup_use_case.py            → caso de uso de limpieza

Clases que debe contener:
--------------------------

DependencyContainer:
    Ensamblador central de todas las dependencias del sistema.

    Constructor:
        Recibe el objeto Settings con las configuraciones.
        Inicializa la conexión única a la base de datos (DatabaseConnection).
        Crea las instancias de infraestructura inyectando sus dependencias.
        Crea los casos de uso inyectando las instancias de infraestructura.
        Todos los objetos se crean UNA SOLA VEZ en el constructor (singleton informal).

    Método: get_scan_use_case() -> SystemScanUseCase
        Retorna la instancia lista del caso de uso de escaneo.

    Método: get_protection_use_case() -> RealTimeProtectionUseCase
        Retorna la instancia lista del caso de uso de protección en tiempo real.

    Método: get_quarantine_use_case() -> QuarantineUseCase
        Retorna la instancia lista del caso de uso de cuarentena.

    Método: get_cleanup_use_case() -> PCCleanupUseCase
        Retorna la instancia lista del caso de uso de limpieza.

    Método: shutdown() -> None
        Cierra todos los recursos abiertos de forma ordenada.
        Detiene el monitor de archivos si estaba activo.
        Cierra la conexión a la base de datos.
        Debe llamarse desde main.py al terminar la ejecución del programa.
"""
