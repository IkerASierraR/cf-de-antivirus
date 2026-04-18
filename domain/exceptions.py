"""
domain/exceptions.py
=====================
Excepciones propias del dominio del antivirus.

Definir excepciones personalizadas permite manejar errores específicos
del negocio de forma clara y separada de los errores genéricos de Python.

Todas las excepciones heredan de una base común (AntivirusException)
para poder capturarlas de forma unificada cuando sea necesario.

Clases que debe contener:
--------------------------

AntivirusException (Exception):
    Clase base de todas las excepciones del sistema.
    Todos los errores propios del dominio deben heredar de esta clase.

ThreatDetectedException (AntivirusException):
    Se lanza cuando un archivo es identificado como amenaza.
    Debe incluir el objeto ThreatFile detectado como atributo.
    Uso típico: en file_scanner.py cuando encuentra una coincidencia.

QuarantineException (AntivirusException):
    Se lanza cuando falla el proceso de mover un archivo a cuarentena.
    Puede ocurrir por permisos, archivo en uso, o disco lleno.
    Debe incluir el path del archivo que no pudo ser movido.

ScannerException (AntivirusException):
    Se lanza cuando el motor de escaneo falla al analizar un archivo.
    Puede ocurrir por permisos de lectura o archivo corrupto.
    Debe incluir el path del archivo que generó el error.

DatabaseConnectionException (AntivirusException):
    Se lanza cuando no se puede establecer o mantener la conexión con SQLite.
    Crítica: si esta excepción ocurre, el sistema no puede verificar firmas.

InvalidFilePathException (AntivirusException):
    Se lanza cuando se recibe una ruta de archivo inválida o inexistente.
    Uso típico: en el Value Object FilePath durante su validación.

InvalidFileHashException (AntivirusException):
    Se lanza cuando el formato del hash SHA-256 no es válido.
    Uso típico: en el Value Object FileHash durante su validación.

MonitorException (AntivirusException):
    Se lanza cuando el monitor de archivos en tiempo real falla al iniciarse
    o detener su observación del sistema de archivos.
"""
