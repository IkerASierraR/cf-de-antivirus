"""
presentation/report_formatter.py
==================================
Formateador de reportes y resultados para la interfaz CLI.
Usa la librería 'rich' para tablas, colores, paneles y barras de progreso.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

from application.dtos import ScanResponseDTO, CleanupReportDTO


class ReportFormatter:
    """Generador de reportes visuales en terminal usando rich."""

    def __init__(self):
        self.console = Console()
        self.color_map = {
            "CRITICAL": "bright_red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
        }

    # ------------------------------------------------------------------
    # Reporte de escaneo
    # ------------------------------------------------------------------

    def format_scan_report(self, result: ScanResponseDTO) -> None:
        """Muestra el reporte completo de un escaneo."""

        duration = f"{result.duration_seconds:.2f}s"
        stats = (
            f"[bold]Archivos escaneados:[/bold] {result.total_files_scanned}\n"
            f"[bold]Amenazas encontradas:[/bold] {result.threats_found}\n"
            f"[bold]Duración:[/bold] {duration}\n"
            f"[bold]Estado:[/bold] {result.status}"
        )
        self.console.print(Panel(stats, title="[bold blue]Resultado del Escaneo[/bold blue]", box=box.ROUNDED))

        if result.threats_found > 0 and result.threat_list:
            self.format_threat_table(result.threat_list)
        else:
            self.console.print(
                Panel("[bold green]✔ Sistema limpio — No se encontraron amenazas.[/bold green]",
                      box=box.ROUNDED)
            )

    # ------------------------------------------------------------------
    # Tabla de amenazas
    # ------------------------------------------------------------------

    def format_threat_table(self, threats: list) -> None:
        """Muestra una tabla formateada de amenazas detectadas."""

        table = Table(
            title="[bold red]⚠ Amenazas Detectadas[/bold red]",
            box=box.ROUNDED,
            show_lines=True
        )
        table.add_column("Archivo",        style="white", no_wrap=False, max_width=50)
        table.add_column("Nivel",          style="bold",  no_wrap=True,  width=10)
        table.add_column("Firma / Nombre", style="white", no_wrap=True)
        table.add_column("Categoría",      style="white", no_wrap=True)

        for threat in threats:
            level    = threat.get("threat_level", "UNKNOWN").upper()
            color    = self.color_map.get(level, "white")
            nivel_txt = Text(level, style=color)

            table.add_row(
                threat.get("file_path", "N/A"),
                nivel_txt,
                threat.get("signature_name", threat.get("threat_name", "N/A")),
                threat.get("category", threat.get("threat_category", "N/A")),
            )

        self.console.print(table)

    # ------------------------------------------------------------------
    # Lista de cuarentena
    # ------------------------------------------------------------------

    def format_quarantine_list(self, files: list) -> None:
        """Muestra la lista de archivos actualmente en cuarentena."""

        if not files:
            self.console.print(
                Panel("[yellow]La cuarentena está vacía.[/yellow]",
                      title="[bold]Cuarentena[/bold]", box=box.ROUNDED)
            )
            return

        table = Table(
            title="[bold yellow]📦 Archivos en Cuarentena[/bold yellow]",
            box=box.ROUNDED,
            show_lines=True
        )
        table.add_column("Nombre original",     style="white", no_wrap=False, max_width=45)
        table.add_column("Fecha de cuarentena", style="cyan",  no_wrap=True)
        table.add_column("Nivel de amenaza",    style="bold",  no_wrap=True)
        table.add_column("Motivo",              style="white", no_wrap=False, max_width=30)

        for f in files:
            threat_level   = str(f.get("threat_level", "N/A"))
            color          = self.color_map.get(threat_level.upper(), "white")
            quarantined_at = f.get("quarantined_at", "N/A")
            if hasattr(quarantined_at, "strftime"):
                quarantined_at = quarantined_at.strftime("%Y-%m-%d %H:%M:%S")

            table.add_row(
                str(f.get("original_path", "N/A")),
                str(quarantined_at),
                Text(threat_level, style=color),
                str(f.get("reason", "N/A")),
            )

        self.console.print(table)

    # ------------------------------------------------------------------
    # Reporte de limpieza
    # ------------------------------------------------------------------

    def format_cleanup_report(self, report: CleanupReportDTO) -> None:
        """Muestra el resultado de la limpieza del sistema."""

        status_color = "green" if report.success else "red"
        status_text  = "✔ Exitosa" if report.success else "✘ Con errores"

        content = (
            f"[bold]Archivos eliminados:[/bold] {report.files_deleted}\n"
            f"[bold]Espacio liberado:[/bold]    {report.space_freed_mb:.2f} MB\n"
            f"[bold]Estado:[/bold]              [{status_color}]{status_text}[/{status_color}]"
        )
        self.console.print(Panel(content, title="[bold blue]Reporte de Limpieza[/bold blue]", box=box.ROUNDED))

        if report.errors:
            error_table = Table(title="[red]Errores durante la limpieza[/red]", box=box.SIMPLE)
            error_table.add_column("Detalle del error", style="red")
            for err in report.errors:
                error_table.add_row(err)
            self.console.print(error_table)

    # ------------------------------------------------------------------
    # Barra de progreso
    # ------------------------------------------------------------------

    def show_progress_bar(self, total: int, description: str = "Escaneando...") -> Progress:
        """Crea y retorna una barra de progreso rich para operaciones largas."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )
        progress.add_task(description, total=total)
        return progress

    # ------------------------------------------------------------------
    # Alerta visual
    # ------------------------------------------------------------------

    def show_alert(self, message: str, level: str = "HIGH") -> None:
        """Muestra un panel de alerta visual con bordes de color según el nivel."""
        color = self.color_map.get(level.upper(), "white")
        self.console.print(
            Panel(
                f"[bold {color}]{message}[/bold {color}]",
                title=f"[bold {color}]⚠ ALERTA — {level.upper()}[/bold {color}]",
                border_style=color,
                box=box.HEAVY,
            )
        )