"""
presentation/menu_handler.py
==============================
Manejador del menú principal de la interfaz CLI.
Gestiona la navegación entre opciones y delega a los casos de uso.
"""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

from application.dtos import (
    ScanRequestDTO,
    CleanupRequestDTO,
    QuarantineRequestDTO,
)


class MenuHandler:
    """Gestor de la navegación y selección del menú de usuario."""

    def __init__(self, scan_use_case, protection_use_case,
                 quarantine_use_case, cleanup_use_case, cli_interface):
        self.scan_uc        = scan_use_case
        self.protection_uc  = protection_use_case
        self.quarantine_uc  = quarantine_use_case
        self.cleanup_uc     = cleanup_use_case
        self.cli            = cli_interface
        self.console        = Console()

        # Mapa de opciones → métodos (evita if/elif en cascada)
        self._menu_map = {
            1: self.handle_scan,
            2: self.handle_protection,
            3: self.handle_quarantine,
            4: self.handle_cleanup,
        }

    # ------------------------------------------------------------------
    # Menú principal
    # ------------------------------------------------------------------

    def show_main_menu(self) -> None:
        """Muestra el menú principal con las opciones disponibles."""

        table = Table(
            title="[bold cyan]MENÚ PRINCIPAL[/bold cyan]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold white"
        )
        table.add_column("Opción", justify="center", style="bold cyan", width=8)
        table.add_column("Función",                  style="bold white")
        table.add_column("Descripción",              style="dim white")

        table.add_row("[1]", "System Scan",              "Escanear archivos o directorios del sistema")
        table.add_row("[2]", "Real-Time Protection",     "Activar o desactivar la protección en tiempo real")
        table.add_row("[3]", "Quarantine Manager",       "Ver y gestionar archivos en cuarentena")
        table.add_row("[4]", "PC Cleanup",               "Eliminar archivos temporales y liberar espacio")
        table.add_row("[0]", "Exit",                     "Salir del programa")

        self.console.print()
        self.console.print(table)
        self.console.print()

    # ------------------------------------------------------------------
    # Enrutador de selección
    # ------------------------------------------------------------------

    def handle_selection(self, option: int) -> None:
        """Enruta la selección del usuario al método correspondiente."""
        action = self._menu_map.get(option)
        if action:
            action()
        else:
            self.console.print("[red]Opción no válida. Ingresa un número entre 0 y 4.[/red]")

    # ------------------------------------------------------------------
    # [1] Escaneo
    # ------------------------------------------------------------------

    def handle_scan(self) -> None:
        """Solicita la ruta, construye el DTO y ejecuta el escaneo."""
        self.console.print("\n[bold cyan]─── System Scan ───[/bold cyan]")

        target_path = Prompt.ask(
            "[white]Ingresa la ruta a escanear[/white]",
            default="."
        )

        self.console.print(
            "\n[dim]Extensiones escaneadas: .exe .dll .bat .ps1 .vbs .js .pdf .docm .xlsm .zip .rar .jar .py[/dim]"
        )

        request = ScanRequestDTO(
            target_path=target_path,
            scan_type="full",
            include_extensions=[
                ".exe", ".dll", ".bat", ".ps1", ".vbs",
                ".js",  ".pdf", ".docm", ".xlsm", ".zip",
                ".rar", ".jar", ".py"
            ]
        )

        self.console.print("\n[yellow]Iniciando escaneo...[/yellow]")
        try:
            result = self.scan_uc.execute(request)
            self.cli.display_scan_result(result)
        except Exception as e:
            self.console.print(f"[red]Error durante el escaneo: {e}[/red]")

    # ------------------------------------------------------------------
    # [2] Protección en tiempo real
    # ------------------------------------------------------------------

    def handle_protection(self) -> None:
        """Activa o desactiva la protección en tiempo real."""
        self.console.print("\n[bold cyan]─── Real-Time Protection ───[/bold cyan]")

        is_active = self.protection_uc.is_active()
        self.cli.show_protection_status(is_active)

        if is_active:
            confirm = Confirm.ask("[yellow]¿Deseas detener la protección en tiempo real?[/yellow]")
            if confirm:
                self.protection_uc.stop()
                self.console.print("[red]● Protección en tiempo real detenida.[/red]")
        else:
            confirm = Confirm.ask("[green]¿Deseas activar la protección en tiempo real?[/green]")
            if confirm:
                from config.settings import Settings
                settings = Settings()
                directory = Prompt.ask(
                    "[white]Directorio a monitorear[/white]",
                    default=settings.MONITOR_DIRECTORY
                )
                # Registrar callback de alerta antes de iniciar
                self.protection_uc.set_alert_callback(
                    lambda scan_result, response: self.cli.display_threat_alert(scan_result)
                )
                self.protection_uc.start(directory)
                self.console.print(f"[green]● Protección activa monitoreando:[/green] {directory}")

        self.cli.show_protection_status(self.protection_uc.is_active())

    # ------------------------------------------------------------------
    # [3] Cuarentena
    # ------------------------------------------------------------------

    def handle_quarantine(self) -> None:
        """Muestra el submenú de cuarentena."""
        self.console.print("\n[bold cyan]─── Quarantine Manager ───[/bold cyan]")

        sub_table = Table(box=box.SIMPLE, show_header=False)
        sub_table.add_column("Op",   style="bold cyan", width=5)
        sub_table.add_column("Acción", style="white")
        sub_table.add_row("[1]", "Ver archivos en cuarentena")
        sub_table.add_row("[2]", "Restaurar un archivo")
        sub_table.add_row("[3]", "Volver al menú principal")
        self.console.print(sub_table)

        option = Prompt.ask("[white]Selecciona una opción[/white]", choices=["1", "2", "3"], default="3")

        if option == "1":
            files = self.quarantine_uc.list_quarantined()
            self.cli.formatter.format_quarantine_list(files)

        elif option == "2":
            files = self.quarantine_uc.list_quarantined()
            if not files:
                self.console.print("[yellow]No hay archivos en cuarentena para restaurar.[/yellow]")
                return

            self.cli.formatter.format_quarantine_list(files)
            file_path = Prompt.ask("[white]Ingresa la ruta del archivo a restaurar[/white]")
            success = self.quarantine_uc.restore_file(file_path)
            if success:
                self.console.print(f"[green]✔ Archivo restaurado exitosamente:[/green] {file_path}")
            else:
                self.console.print(f"[red]✘ No se pudo restaurar el archivo:[/red] {file_path}")

        # opción 3 → regresa sin hacer nada

    # ------------------------------------------------------------------
    # [4] Limpieza
    # ------------------------------------------------------------------

    def handle_cleanup(self) -> None:
        """Muestra vista previa, pide confirmación y ejecuta la limpieza."""
        self.console.print("\n[bold cyan]─── PC Cleanup ───[/bold cyan]")

        include_temp       = Confirm.ask("[white]¿Incluir archivos temporales del sistema?[/white]", default=True)
        include_quarantine = Confirm.ask("[white]¿Incluir archivos en cuarentena?[/white]",          default=False)

        request = CleanupRequestDTO(
            include_temp=include_temp,
            include_quarantine=include_quarantine,
            custom_paths=[]
        )

        # Vista previa
        self.console.print("\n[yellow]Calculando archivos a eliminar...[/yellow]")
        try:
            preview_files = self.cleanup_uc.preview(request)

            if not preview_files:
                self.console.print("[green]No se encontraron archivos para eliminar.[/green]")
                return

            preview_table = Table(
                title=f"[bold]Vista previa — {len(preview_files)} archivo(s) a eliminar[/bold]",
                box=box.SIMPLE, show_header=True, header_style="bold white"
            )
            preview_table.add_column("Ruta del archivo", style="dim white")
            for f in preview_files[:20]:      # Mostrar máximo 20 en preview
                preview_table.add_row(str(f))
            if len(preview_files) > 20:
                preview_table.add_row(f"[dim]... y {len(preview_files) - 20} archivo(s) más[/dim]")
            self.console.print(preview_table)

            confirm = Confirm.ask(
                f"[bold red]¿Confirmas la eliminación de {len(preview_files)} archivo(s)?[/bold red]",
                default=False
            )
            if confirm:
                self.console.print("\n[yellow]Ejecutando limpieza...[/yellow]")
                report = self.cleanup_uc.execute(request)
                self.cli.formatter.format_cleanup_report(report)
            else:
                self.console.print("[dim]Limpieza cancelada.[/dim]")

        except Exception as e:
            self.console.print(f"[red]Error durante la limpieza: {e}[/red]")