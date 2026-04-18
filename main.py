"""
main.py
========
Punto de entrada principal del sistema antivirus académico.

Este archivo es el único que debe ejecutarse directamente:
    python main.py

Su responsabilidad es mínima:
    1. Cargar las configuraciones del sistema.
    2. Construir el contenedor de dependencias.
    3. Lanzar la interfaz de usuario.
    4. Garantizar el cierre limpio de recursos al terminar.

No debe contener lógica de negocio ni detalles de implementación.

Flujo de ejecución:
    1. Se instancia Settings() → carga configuraciones y variables de entorno.
    2. Se instancia DependencyContainer(settings) → ensambla todo el sistema.
    3. Se instancia CLIInterface(container) → prepara la interfaz de usuario.
    4. Se llama a interface.run() → inicia el bucle principal de la aplicación.
    5. Al salir (por el usuario o por excepción), se llama a container.shutdown()
       para cerrar la base de datos y detener el monitor de forma ordenada.

Manejo de errores en este nivel:
    - DatabaseConnectionException: muestra mensaje claro y termina el programa.
    - KeyboardInterrupt (Ctrl+C): termina limpiamente sin stack trace.
    - Cualquier otra excepción no capturada: muestra el error y cierra recursos.
"""

# Las importaciones irían aquí:
# from config.settings import Settings
# from dependencies.container import DependencyContainer
# from presentation.cli_interface import CLIInterface

# El bloque if __name__ == "__main__": iría aquí con el flujo descrito arriba.
