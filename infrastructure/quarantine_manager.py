"""
infrastructure/quarantine_manager.py
======================================
Implementación concreta de IQuarantineManager.

Este archivo gestiona el movimiento físico de archivos amenazantes
hacia una carpeta segura de cuarentena en el sistema de archivos.

La carpeta de cuarentena debe ser una ubicación donde los archivos
no puedan ejecutarse por el sistema operativo (sin permisos de ejecución).

Depende de:
    - domain/interfaces.py    → implementa IQuarantineManager
    - domain/entities.py      → recibe ThreatFile, retorna listas de ThreatFile
    - domain/exceptions.py    → lanza QuarantineException si falla
    - config/settings.py      → obtiene la ruta de la carpeta de cuarentena
    - config/paths.py         → constante QUARANTINE_PATH

Clases que debe contener:
--------------------------

QuarantineManager (implementa IQuarantineManager):
    Gestor físico de la cuarentena de archivos.

    Constructor:
        Recibe la ruta de cuarentena desde Settings.
        Crea la carpeta de cuarentena si no existe (solo en el constructor).
        Genera el archivo de índice de cuarentena (quarantine_index.json)
        que rastrea qué archivos están en cuarentena y su ruta original.

    Método: quarantine(file: ThreatFile) -> bool
        Mueve el archivo amenazante a la carpeta de cuarentena.
        Flujo interno:
            1. Genera un nombre único para el archivo (evita colisiones de nombres).
               Sugerencia: usar timestamp + nombre original.
            2. Mueve el archivo usando shutil.move().
            3. Registra la ruta original y la nueva ruta en el índice JSON.
            4. Opcionalmente cambia los permisos del archivo para evitar ejecución.
            5. Retorna True si el movimiento fue exitoso.
            6. Lanza QuarantineException si falla.

    Método: list_quarantined() -> list[ThreatFile]
        Lee el índice JSON de cuarentena y retorna la lista de archivos aislados.
        Filtra archivos que ya no existen físicamente en la carpeta de cuarentena.

    Método: restore(file: ThreatFile) -> bool
        Restaura un archivo de cuarentena a su ubicación original.
        Lee el índice para obtener la ruta original del archivo.
        Usa shutil.move() para moverlo de vuelta.
        Elimina el registro del índice JSON.
        Retorna True si la restauración fue exitosa.

    Método privado: _update_index(file_path: str, quarantine_path: str, original_path: str) -> None
        Actualiza el archivo quarantine_index.json con el nuevo registro.
        El índice tiene formato: {quarantine_filename: {original_path, detected_at, hash}}.

    Método privado: _generate_quarantine_filename(original_name: str) -> str
        Genera un nombre único para el archivo en cuarentena.
        Formato sugerido: YYYYMMDD_HHMMSS_originalname.quar
"""
