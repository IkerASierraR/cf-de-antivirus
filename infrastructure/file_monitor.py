"""
infrastructure/file_monitor.py
================================
Implementación concreta de IFileMonitor usando la librería watchdog.

Este archivo observa un directorio del sistema de archivos en tiempo real
y notifica al sistema cuando se crea un nuevo archivo.

La librería watchdog lanza eventos en un hilo separado del hilo principal,
por lo que este módulo debe manejar correctamente la concurrencia.

Depende de:
    - domain/interfaces.py  → implementa IFileMonitor
    - domain/exceptions.py  → lanza MonitorException si falla
    - Librería externa: watchdog (Observer, FileSystemEventHandler)

Clases que debe contener:
--------------------------

AntivirusEventHandler (hereda de watchdog.FileSystemEventHandler):
    Manejador de eventos del sistema de archivos.
    Filtra y procesa los eventos relevantes de watchdog.

    Método: on_created(event)
        Llamado automáticamente por watchdog cuando se crea un archivo.
        Filtra directorios (solo procesa archivos).
        Llama al callback registrado con la ruta del nuevo archivo.

    Método: on_modified(event)
        Llamado cuando un archivo existente es modificado.
        Opcional: puede verificar archivos que cambien sospechosamente.

FileMonitor (implementa IFileMonitor):
    Observador del sistema de archivos en tiempo real.

    Constructor:
        Inicializa el Observer de watchdog (sin iniciarlo).
        Inicializa el callback a None (debe registrarse antes de start).
        Guarda el estado is_active = False.

    Método: start_monitoring(directory: str) -> None
        Configura y lanza el Observer de watchdog en el directorio dado.
        Crea una instancia de AntivirusEventHandler con el callback registrado.
        Inicia el Observer (corre en hilo separado del hilo principal).
        Cambia is_active a True.
        Lanza MonitorException si el directorio no existe o hay error.

    Método: stop_monitoring() -> None
        Detiene el Observer de watchdog de forma ordenada.
        Llama a observer.stop() y observer.join() para esperar el cierre.
        Cambia is_active a False.

    Método: set_on_file_created_callback(callback: callable) -> None
        Registra la función que será invocada cuando se detecte un nuevo archivo.
        Debe llamarse ANTES de start_monitoring().
        El callback recibe la ruta del archivo nuevo como único argumento.

    Método: is_active() -> bool
        Retorna True si el monitoreo está activo en este momento.
"""
