"""
main.py
========
Punto de entrada principal del sistema antivirus SecureGuard.

Ejecutar:
    python main.py

Flujo:
    1. Carga configuraciones (Settings).
    2. Construye el contenedor de dependencias (DependencyContainer).
    3. Lanza la interfaz gráfica customtkinter (GUI).
       Si el entorno es sin pantalla o customtkinter no está disponible,
       usa automáticamente la interfaz CLI (rich).
    4. Al salir, cierra recursos ordenadamente.
"""

import logging
import sys

# Configuración básica de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("secureguard")


def main() -> None:
    """Función principal del sistema antivirus."""
    from config.settings import Settings
    from dependencies.container import DependencyContainer
    from domain.exceptions import DatabaseConnectionException

    try:
        # 1. Cargar configuraciones
        settings = Settings()
        logger.info("Configuración cargada. Versión: %s", settings.APP_VERSION)

        # 2. Construir contenedor de dependencias (inicializa BD, repositorios, etc.)
        container = DependencyContainer(settings)
        logger.info("Contenedor de dependencias inicializado.")

    except DatabaseConnectionException as exc:
        logger.critical("Error crítico de base de datos: %s", exc)
        print(f"\n[ERROR] No se puede iniciar el sistema: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        logger.critical("Error inesperado al iniciar el sistema: %s", exc)
        print(f"\n[ERROR] Error inesperado: {exc}", file=sys.stderr)
        sys.exit(1)

    # 3. Lanzar interfaz — primero GUI, luego CLI como fallback
    try:
        import customtkinter  # noqa: F401

        # Verificar que hay un display disponible (sistemas Unix sin X)
        _has_display = True
        if sys.platform.startswith("linux"):
            import os
            if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
                _has_display = False

        if _has_display:
            from presentation.gui_interface import AntivirusGUI
            logger.info("Lanzando interfaz gráfica (customtkinter).")
            app = AntivirusGUI(container)
            app.run()
            return

    except ImportError:
        logger.info("customtkinter no disponible. Usando interfaz CLI.")
    except Exception as exc:
        logger.warning("No se pudo iniciar la GUI (%s). Cambiando a CLI.", exc)

    # Fallback: interfaz CLI
    try:
        from presentation.cli_interface import CLIInterface
        logger.info("Lanzando interfaz CLI.")
        interface = CLIInterface(container)
        interface.run()
    except KeyboardInterrupt:
        print("\n\nCerrado por el usuario (Ctrl+C).")
    except Exception as exc:
        logger.error("Error en la interfaz CLI: %s", exc)
        print(f"\n[ERROR] {exc}", file=sys.stderr)
    finally:
        try:
            container.shutdown()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCerrado por el usuario.")
    except Exception as exc:
        print(f"\n[ERROR] Error inesperado: {exc}", file=sys.stderr)
        sys.exit(1)

