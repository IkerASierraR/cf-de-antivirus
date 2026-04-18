"""
infrastructure/cleanup_service.py
===================================
Implementación concreta de ICleanupService.

Este archivo localiza y elimina archivos temporales del sistema operativo.
Detecta automáticamente el sistema operativo (Windows, Linux, macOS)
y accede a las rutas de temporales correspondientes.

PRECAUCIÓN: Este módulo opera directamente sobre el sistema de archivos.
Debe ser muy cuidadoso de no eliminar archivos importantes del sistema.
Solo debe actuar sobre directorios claramente identificados como temporales.

Depende de:
    - domain/interfaces.py  → implementa ICleanupService
    - config/settings.py    → obtiene las rutas de directorios temporales
    - config/paths.py       → rutas base del sistema

Clases que debe contener:
--------------------------

SystemCleanupService (implementa ICleanupService):
    Servicio de limpieza de archivos temporales del sistema.

    Constructor:
        Recibe las configuraciones de Settings.
        Detecta el sistema operativo usando el módulo platform.
        Prepara la lista de directorios temporales según el SO:
            - Windows: %TEMP%, %TMP%, C:\Windows\Temp
            - Linux/macOS: /tmp, /var/tmp, ~/.cache/thumbnails

    Método: find_temp_files() -> list[str]
        Busca todos los archivos temporales en los directorios configurados.
        Usa os.walk() para recorrer recursivamente cada directorio.
        Aplica filtros de extensiones temporales: .tmp, .temp, .log, .old, ~*
        Retorna solo las rutas de archivos (no carpetas).
        Omite archivos que no tienen permisos de lectura sin lanzar excepción.

    Método: delete_files(paths: list[str]) -> int
        Elimina físicamente los archivos de la lista recibida.
        Itera la lista e intenta eliminar cada archivo con os.remove().
        Registra los errores individualmente sin interrumpir la eliminación.
        Retorna el número total de archivos eliminados exitosamente.

    Método: get_system_temp_dirs() -> list[str]
        Retorna la lista de directorios temporales que el servicio supervisará.
        Útil para mostrar al usuario qué directorios serán limpiados.

    Método privado: _get_file_size(path: str) -> int
        Retorna el tamaño en bytes de un archivo dado su ruta.
        Retorna 0 si el archivo no es accesible (manejo silencioso del error).

    Método privado: _is_safe_to_delete(path: str) -> bool
        Verifica que el archivo está dentro de un directorio temporal permitido.
        Rechaza cualquier ruta fuera de los directorios configurados.
        Actúa como salvaguarda final antes de eliminar.
"""
