"""
presentation/cli_interface.py
==============================
Interfaz principal de línea de comandos (CLI) del antivirus.
Punto de entrada de la interfaz de usuario. Solo presentación, sin lógica de negocio.
"""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich import box

from application.dtos import ScanResponseDTO, QuarantineRequestDTO
from presentation.menu_handler import MenuHandler
from presentation.report_formatter import ReportFormatter


class CLIInterface:
    """Controlador principal de la interfaz de usuario en terminal."""

    def __init__(self, container):
        self.container = container
        self.console   = Console()

        # Obtener casos de uso desde el contenedor
        self.scan_uc       = container.get_scan_use_case()
        self.protection_uc = container.get_protection_use_case()
        self.quarantine_uc = container.get_quarantine_use_case()
        self.cleanup_uc    = container.get_cleanup_use_case()

        # Componentes de presentación
        self.formatter = ReportFormatter()
        self.menu      = MenuHandler(
            scan_use_case       = self.scan_uc,
            protection_use_case = self.protection_uc,
            quarantine_use_case = self.quarantine_uc,
            cleanup_use_case    = self.cleanup_uc,
            cli_interface       = self,
        )

    # ------------------------------------------------------------------
    # Punto de entrada principal
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Punto de entrada principal de la interfaz. Inicia el bucle del menú."""
        self.show_banner()

        try:
            while True:
                self.menu.show_main_menu()
                option_str = Prompt.ask(
                    "[bold cyan]Selecciona una opción[/bold cyan]",
                    choices=["0", "1", "2", "3", "4"],
                    default="0"
                )
                option = int(option_str)

                if option == 0:
                    self.console.print(
                        "\n[bold cyan]Gracias por usar SecureGuard. ¡Hasta pronto![/bold cyan]\n"
                    )
                    break

                self.menu.handle_selection(option)

        finally:
            # Cierre limpio de recursos
            self.console.print("[dim]Cerrando recursos del sistema...[/dim]")
            self.container.shutdown()

    # ------------------------------------------------------------------
    # Resultado de escaneo
    # ------------------------------------------------------------------

    def display_scan_result(self, result: ScanResponseDTO) -> None:
        """Muestra el resultado del escaneo y ofrece cuarentena si hay amenazas."""
        self.formatter.format_scan_report(result)

        if result.threats_found > 0 and result.threat_list:
            self.console.print()
            for threat in result.threat_list:
                file_path = threat.get("file_path", "")
                if file_path and self.prompt_quarantine_confirmation(file_path):
                    request = QuarantineRequestDTO(
                        file_path=file_path,
                        reason=threat.get("signature_name",
                               threat.get("threat_name", "Amenaza detectada"))
                    )
                    try:
                        response = self.quarantine_uc.execute(request)
                        if response.success:
                            self.console.print(
                                f"[green]✔ Archivo enviado a cuarentena:[/green] {response.quarantine_path}"
                            )
                        else:
                            self.console.print(
                                f"[red]✘ Error al cuarentenar:[/red] {response.error_message}"
                            )
                    except Exception as e:
                        self.console.print(f"[red]Error en cuarentena: {e}[/red]")

    # ------------------------------------------------------------------
    # Alerta de protección en tiempo real
    # ------------------------------------------------------------------

    def display_threat_alert(self, threat_file) -> None:
        """Muestra una alerta urgente cuando la protección detecta un archivo sospechoso."""
        file_path    = getattr(threat_file, "file_path",    str(threat_file))
        threat_level = getattr(threat_file, "threat_level", "HIGH")
        sig_name     = getattr(threat_file, "signature_name", "Firma desconocida")

        alert_text = (
            f"[bold bright_red]¡AMENAZA DETECTADA EN TIEMPO REAL![/bold bright_red]\n\n"
            f"[white]Archivo:[/white]  [red]{file_path}[/red]\n"
            f"[white]Nivel:  [/white]  [bold bright_red]{threat_level}[/bold bright_red]\n"
            f"[white]Firma:  [/white]  [yellow]{sig_name}[/yellow]"
        )
        self.console.print(
            Panel(
                alert_text,
                title="[bold bright_red]⚠ PROTECCIÓN EN TIEMPO REAL[/bold bright_red]",
                border_style="bright_red",
                box=box.HEAVY,
            )
        )

    # ------------------------------------------------------------------
    # Confirmación de cuarentena
    # ------------------------------------------------------------------

    def prompt_quarantine_confirmation(self, file_path: str) -> bool:
        """Pregunta al usuario si desea enviar el archivo a cuarentena."""
        self.console.print(f"\n[bold red]Amenaza:[/bold red] [white]{file_path}[/white]")
        return Confirm.ask(
            "[yellow]¿Deseas enviar este archivo a cuarentena?[/yellow]",
            default=True
        )

    # ------------------------------------------------------------------
    # Banner de bienvenida
    # ------------------------------------------------------------------

    def show_banner(self) -> None:
        """Muestra el banner ASCII de bienvenida del antivirus."""
        banner = Text()
        banner.append(
            r"""
   _____                      _    _____                     
  / ____|                    | |  / ____|                    
 | (___   ___  ___ _   _ _ __| | | |  __ _ __ __ _  __ _  ___ 
  \___ \ / _ \/ __| | | | '__| | | | |_ | '__/ _` |/ _` |/ _ \
  ____) |  __/ (__| |_| | |  | | | |__| | | | (_| | (_| |  __/
 |_____/ \___|\___|\__,_|_|  |_|  \_____|_|  \__,_|\__, |\___|
                                                     __/ |     
                                                    |___/      
""",
            style="bold cyan"
        )
        banner.append("\n         SecureGuard — Sistema Antivirus Profesional  v1.0.0\n", style="bold white")
        banner.append("         Protección Avanzada · Detección en Tiempo Real · Cuarentena Segura\n", style="dim white")

        self.console.print(Panel(banner, box=box.DOUBLE, border_style="cyan"))
        self.console.print()

    # ------------------------------------------------------------------
    # Estado de la protección
    # ------------------------------------------------------------------

    def show_protection_status(self, is_active: bool) -> None:
        """Muestra si la protección en tiempo real está activa o inactiva."""
        if is_active:
            self.console.print(
                Panel("[bold green]● Protección en tiempo real: ACTIVA[/bold green]",
                      border_style="green", box=box.ROUNDED)
            )
        else:
            self.console.print(
                Panel("[bold red]○ Protección en tiempo real: INACTIVA[/bold red]",
                      border_style="red", box=box.ROUNDED)
            )