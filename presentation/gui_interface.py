"""
presentation/gui_interface.py
==============================
Interfaz gráfica principal del antivirus SecureGuard usando customtkinter.
Proporciona una UI moderna tipo antivirus real con navegación lateral.
"""

import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import customtkinter as ctk

from application.dtos import CleanupRequestDTO, QuarantineRequestDTO, ScanRequestDTO

logger = logging.getLogger(__name__)

# Configuración global del tema
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Paleta de colores
COLORS = {
    "bg_primary": "#1a1a2e",
    "bg_secondary": "#16213e",
    "bg_card": "#0f3460",
    "accent": "#e94560",
    "accent_blue": "#3a86ff",
    "accent_green": "#06d6a0",
    "accent_yellow": "#ffd166",
    "text_primary": "#ffffff",
    "text_secondary": "#b0b3c1",
    "threat_low": "#06d6a0",
    "threat_medium": "#ffd166",
    "threat_high": "#ef8c45",
    "threat_critical": "#e94560",
}

THREAT_COLORS = {
    "LOW": COLORS["threat_low"],
    "MEDIUM": COLORS["threat_medium"],
    "HIGH": COLORS["threat_high"],
    "CRITICAL": COLORS["threat_critical"],
}


class AntivirusGUI(ctk.CTk):
    """Ventana principal del antivirus SecureGuard."""

    def __init__(self, container) -> None:
        super().__init__()

        self._container = container
        self._scan_uc = container.get_scan_use_case()
        self._protection_uc = container.get_protection_use_case()
        self._quarantine_uc = container.get_quarantine_use_case()
        self._cleanup_uc = container.get_cleanup_use_case()
        self._settings = container.get_settings()

        self._scan_running = False
        self._last_scan_result: Optional[object] = None
        self._active_frame: Optional[ctk.CTkFrame] = None

        self._setup_window()
        self._build_layout()
        self._show_dashboard()

    # ------------------------------------------------------------------
    # Configuración de ventana y layout
    # ------------------------------------------------------------------

    def _setup_window(self) -> None:
        self.title("SecureGuard — Sistema Antivirus Profesional v1.0.0")
        self.geometry("1200x750")
        self.minsize(960, 620)
        self.configure(fg_color=COLORS["bg_primary"])

    def _build_layout(self) -> None:
        """Construye el layout principal: sidebar + área de contenido."""
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content_area()

    def _build_sidebar(self) -> None:
        """Construye la barra lateral de navegación."""
        sidebar = ctk.CTkFrame(
            self, width=220, fg_color=COLORS["bg_secondary"], corner_radius=0
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(9, weight=1)

        # Logo y título
        logo_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=(25, 5), sticky="ew")

        ctk.CTkLabel(
            logo_frame,
            text="🛡 SecureGuard",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLORS["accent_blue"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            logo_frame,
            text="Antivirus Profesional",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w")

        ctk.CTkFrame(sidebar, height=1, fg_color=COLORS["bg_card"]).grid(
            row=1, column=0, padx=15, pady=10, sticky="ew"
        )

        # Botones de navegación
        nav_items = [
            ("🏠  Dashboard", self._show_dashboard),
            ("🔍  Escaneo",    self._show_scan),
            ("🛡  Protección", self._show_protection),
            ("📦  Cuarentena", self._show_quarantine),
            ("🧹  Limpieza",   self._show_cleanup),
            ("⚙  Ajustes",    self._show_settings),
        ]

        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        for i, (label, command) in enumerate(nav_items):
            btn = ctk.CTkButton(
                sidebar,
                text=label,
                font=ctk.CTkFont(size=13),
                anchor="w",
                fg_color="transparent",
                text_color=COLORS["text_secondary"],
                hover_color=COLORS["bg_card"],
                corner_radius=8,
                height=40,
                command=command,
            )
            btn.grid(row=i + 2, column=0, padx=10, pady=2, sticky="ew")
            self._nav_buttons[label] = btn

        # Separador
        ctk.CTkFrame(sidebar, height=1, fg_color=COLORS["bg_card"]).grid(
            row=9, column=0, padx=15, pady=10, sticky="ews"
        )

        # Botón salir
        ctk.CTkButton(
            sidebar,
            text="⏻  Salir",
            font=ctk.CTkFont(size=13),
            anchor="w",
            fg_color="transparent",
            text_color=COLORS["accent"],
            hover_color=COLORS["bg_card"],
            corner_radius=8,
            height=40,
            command=self._on_close,
        ).grid(row=10, column=0, padx=10, pady=(0, 20), sticky="ew")

    def _build_content_area(self) -> None:
        """Construye el área de contenido principal."""
        self._content = ctk.CTkFrame(
            self, fg_color=COLORS["bg_primary"], corner_radius=0
        )
        self._content.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    def _set_active_nav(self, label: str) -> None:
        """Marca el botón de navegación activo."""
        for btn_label, btn in self._nav_buttons.items():
            if btn_label == label:
                btn.configure(
                    fg_color=COLORS["bg_card"],
                    text_color=COLORS["text_primary"],
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=COLORS["text_secondary"],
                )

    def _clear_content(self) -> None:
        """Limpia el área de contenido."""
        for widget in self._content.winfo_children():
            widget.destroy()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def _show_dashboard(self) -> None:
        self._clear_content()
        self._set_active_nav("🏠  Dashboard")

        frame = ctk.CTkScrollableFrame(
            self._content, fg_color="transparent"
        )
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Título
        ctk.CTkLabel(
            frame,
            text="Dashboard",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 20))

        # Tarjetas de estado
        protection_status = self._protection_uc.is_active()
        quarantined = self._quarantine_uc.list_quarantined()
        signatures_count = self._get_signatures_count()

        cards = [
            (
                "🛡 Protección",
                "ACTIVA" if protection_status else "INACTIVA",
                COLORS["accent_green"] if protection_status else COLORS["accent"],
            ),
            (
                "📦 Cuarentena",
                f"{len(quarantined)} archivo(s)",
                COLORS["accent_yellow"],
            ),
            (
                "🗃 Firmas cargadas",
                str(signatures_count),
                COLORS["accent_blue"],
            ),
        ]

        for col, (title, value, color) in enumerate(cards):
            self._stat_card(frame, row=1, col=col, title=title, value=value, color=color)

        # Último escaneo
        ctk.CTkLabel(
            frame,
            text="Último escaneo",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(25, 8))

        result_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        result_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 15))

        if self._last_scan_result:
            r = self._last_scan_result
            summary_text = (
                f"Ruta: {r.get('path', 'N/A')}    |    "
                f"Archivos: {r.get('total', 0)}    |    "
                f"Amenazas: {r.get('threats', 0)}    |    "
                f"Estado: {r.get('status', 'N/A')}"
            )
            color = COLORS["accent"] if r.get("threats", 0) > 0 else COLORS["accent_green"]
            ctk.CTkLabel(
                result_frame,
                text=summary_text,
                font=ctk.CTkFont(size=13),
                text_color=color,
            ).pack(padx=20, pady=15)
        else:
            ctk.CTkLabel(
                result_frame,
                text="No se ha realizado ningún escaneo aún.",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text_secondary"],
            ).pack(padx=20, pady=15)

        # Botón de escaneo rápido
        ctk.CTkButton(
            frame,
            text="🔍  Iniciar Escaneo Rápido",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent_blue"],
            hover_color="#2563eb",
            height=45,
            corner_radius=10,
            command=self._show_scan,
        ).grid(row=4, column=0, columnspan=3, pady=10, sticky="ew")

    def _stat_card(
        self,
        parent,
        row: int,
        col: int,
        title: str,
        value: str,
        color: str,
    ) -> None:
        card = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=12)
        card.grid(row=row, column=col, padx=8, pady=5, sticky="ew")
        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        ).pack(padx=15, pady=(12, 2), anchor="w")
        ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=color,
        ).pack(padx=15, pady=(0, 12), anchor="w")

    def _get_signatures_count(self) -> int:
        try:
            repo = self._container._repository
            return len(repo.get_all_signatures())
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Escaneo
    # ------------------------------------------------------------------

    def _show_scan(self) -> None:
        self._clear_content()
        self._set_active_nav("🔍  Escaneo")

        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(
            frame,
            text="Escaneo del Sistema",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Selección de ruta
        path_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        path_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        path_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            path_frame,
            text="Ruta a escanear",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=(12, 5))

        self._scan_path_var = ctk.StringVar(value=str(Path.home()))
        path_entry = ctk.CTkEntry(
            path_frame,
            textvariable=self._scan_path_var,
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_primary"],
            border_color=COLORS["bg_card"],
            height=38,
        )
        path_entry.grid(row=1, column=0, padx=(15, 8), pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            path_frame,
            text="Explorar",
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["accent_blue"],
            width=100,
            height=38,
            command=self._browse_path,
        ).grid(row=1, column=1, padx=(0, 15), pady=(0, 12))

        # Barra de progreso + estado
        self._scan_progress = ctk.CTkProgressBar(
            frame, fg_color=COLORS["bg_secondary"], progress_color=COLORS["accent_blue"]
        )
        self._scan_progress.grid(row=2, column=0, sticky="ew", pady=(0, 5))
        self._scan_progress.set(0)

        self._scan_status_label = ctk.CTkLabel(
            frame,
            text="Listo para escanear.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        )
        self._scan_status_label.grid(row=3, column=0, sticky="w")

        # Botón escanear
        self._scan_btn = ctk.CTkButton(
            frame,
            text="▶  Iniciar Escaneo",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent_blue"],
            hover_color="#2563eb",
            height=45,
            corner_radius=10,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=4, column=0, sticky="ew", pady=15)

        # Resultados
        self._scan_results_frame = ctk.CTkScrollableFrame(
            frame, fg_color=COLORS["bg_secondary"], corner_radius=12, label_text="Resultados"
        )
        self._scan_results_frame.grid(row=5, column=0, sticky="nsew", pady=(0, 10))
        self._scan_results_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._scan_results_frame,
            text="Los resultados del escaneo aparecerán aquí.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        ).grid(row=0, column=0, padx=15, pady=15)

    def _browse_path(self) -> None:
        path = filedialog.askdirectory(title="Seleccionar directorio a escanear")
        if path:
            self._scan_path_var.set(path)

    def _start_scan(self) -> None:
        if self._scan_running:
            return

        target = self._scan_path_var.get().strip()
        if not target or not Path(target).exists():
            messagebox.showerror("Error", f"La ruta no existe: {target}")
            return

        self._scan_running = True
        self._scan_btn.configure(state="disabled", text="⏳  Escaneando...")
        self._scan_status_label.configure(text="Escaneando...", text_color=COLORS["accent_yellow"])
        self._scan_progress.set(0)
        self._scan_progress.start()

        # Limpiar resultados previos
        for widget in self._scan_results_frame.winfo_children():
            widget.destroy()

        thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()

    def _run_scan(self, target: str) -> None:
        """Ejecuta el escaneo en un hilo secundario."""
        try:
            request = ScanRequestDTO(
                target_path=target,
                scan_type="full",
                include_extensions=self._settings.SCAN_EXTENSIONS,
            )
            result = self._scan_uc.execute(request)
            self.after(0, lambda: self._scan_complete(result, target))
        except Exception as exc:
            self.after(0, lambda: self._scan_error(str(exc)))

    def _scan_complete(self, result, target: str) -> None:
        """Actualiza la UI con el resultado del escaneo."""
        self._scan_running = False
        self._scan_progress.stop()
        self._scan_progress.set(1)
        self._scan_btn.configure(state="normal", text="▶  Iniciar Escaneo")

        color = COLORS["accent"] if result.threats_found > 0 else COLORS["accent_green"]
        status_text = (
            f"✔ Escaneo completado — {result.total_files_scanned} archivos, "
            f"{result.threats_found} amenaza(s) — {result.duration_seconds:.2f}s"
        )
        self._scan_status_label.configure(text=status_text, text_color=color)

        # Guardar para dashboard
        self._last_scan_result = {
            "path": target,
            "total": result.total_files_scanned,
            "threats": result.threats_found,
            "status": result.status,
        }

        # Limpiar resultados previos
        for widget in self._scan_results_frame.winfo_children():
            widget.destroy()

        if result.threats_found == 0:
            ctk.CTkLabel(
                self._scan_results_frame,
                text="✅  No se encontraron amenazas. El sistema está limpio.",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["accent_green"],
            ).grid(row=0, column=0, padx=15, pady=15)
            return

        # Encabezados de la tabla
        headers = ["Archivo", "Nivel", "Nombre de amenaza", "Categoría", "Acción"]
        col_widths = [350, 80, 200, 120, 100]
        for col_i, (header, width) in enumerate(zip(headers, col_widths)):
            ctk.CTkLabel(
                self._scan_results_frame,
                text=header,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_secondary"],
                width=width,
                anchor="w",
            ).grid(row=0, column=col_i, padx=8, pady=(10, 5), sticky="w")

        for row_i, threat in enumerate(result.threat_list, start=1):
            level = threat.get("threat_level", "MEDIUM").upper()
            tc = THREAT_COLORS.get(level, COLORS["text_primary"])

            row_data = [
                (str(Path(threat.get("file_path", "N/A")).name), COLORS["text_primary"]),
                (level, tc),
                (threat.get("threat_name", "N/A"), COLORS["text_primary"]),
                (threat.get("category", "N/A"), COLORS["text_secondary"]),
            ]
            for col_i, (val, color) in enumerate(row_data):
                ctk.CTkLabel(
                    self._scan_results_frame,
                    text=val,
                    font=ctk.CTkFont(size=11),
                    text_color=color,
                    anchor="w",
                ).grid(row=row_i, column=col_i, padx=8, pady=3, sticky="w")

            # Botón cuarentena
            file_path = threat.get("file_path", "")
            reason = threat.get("threat_name", "Amenaza detectada")
            ctk.CTkButton(
                self._scan_results_frame,
                text="Cuarentenar",
                font=ctk.CTkFont(size=11),
                fg_color=COLORS["accent"],
                hover_color="#b91c1c",
                width=100,
                height=28,
                command=lambda fp=file_path, r=reason: self._quarantine_file(fp, r),
            ).grid(row=row_i, column=4, padx=8, pady=3)

    def _scan_error(self, error_msg: str) -> None:
        self._scan_running = False
        self._scan_progress.stop()
        self._scan_progress.set(0)
        self._scan_btn.configure(state="normal", text="▶  Iniciar Escaneo")
        self._scan_status_label.configure(
            text=f"✘ Error: {error_msg}", text_color=COLORS["accent"]
        )

    def _quarantine_file(self, file_path: str, reason: str) -> None:
        if not file_path or not Path(file_path).exists():
            messagebox.showwarning("Aviso", f"El archivo ya no existe:\n{file_path}")
            return
        request = QuarantineRequestDTO(file_path=file_path, reason=reason)
        response = self._quarantine_uc.execute(request)
        if response.success:
            messagebox.showinfo("Cuarentena", f"Archivo enviado a cuarentena:\n{response.quarantine_path}")
        else:
            messagebox.showerror("Error", f"Error en cuarentena:\n{response.error_message}")

    # ------------------------------------------------------------------
    # Protección en tiempo real
    # ------------------------------------------------------------------

    def _show_protection(self) -> None:
        self._clear_content()
        self._set_active_nav("🛡  Protección")

        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Protección en Tiempo Real",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Estado
        status_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        status_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        status_frame.grid_columnconfigure(0, weight=1)

        is_active = self._protection_uc.is_active()
        status_color = COLORS["accent_green"] if is_active else COLORS["accent"]
        status_text = "● ACTIVA" if is_active else "○ INACTIVA"

        self._protection_status_label = ctk.CTkLabel(
            status_frame,
            text=f"Estado de protección: {status_text}",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=status_color,
        )
        self._protection_status_label.grid(row=0, column=0, sticky="w", padx=20, pady=(15, 5))

        ctk.CTkLabel(
            status_frame,
            text="Monitorea automáticamente los archivos nuevos en el directorio configurado.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        ).grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

        # Directorio a monitorear
        ctk.CTkLabel(
            status_frame,
            text="Directorio a monitorear:",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text_primary"],
        ).grid(row=2, column=0, sticky="w", padx=20, pady=(5, 2))

        dir_row = ctk.CTkFrame(status_frame, fg_color="transparent")
        dir_row.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))
        dir_row.grid_columnconfigure(0, weight=1)

        self._monitor_dir_var = ctk.StringVar(value=self._settings.MONITOR_DIRECTORY)
        ctk.CTkEntry(
            dir_row,
            textvariable=self._monitor_dir_var,
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_primary"],
            border_color=COLORS["bg_card"],
            height=36,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            dir_row,
            text="Explorar",
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["accent_blue"],
            width=90,
            height=36,
            command=lambda: self._monitor_dir_var.set(
                filedialog.askdirectory() or self._monitor_dir_var.get()
            ),
        ).grid(row=0, column=1)

        # Toggle
        toggle_text = "⏹  Detener Protección" if is_active else "▶  Activar Protección"
        toggle_color = COLORS["accent"] if is_active else COLORS["accent_green"]

        ctk.CTkButton(
            frame,
            text=toggle_text,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=toggle_color,
            hover_color="#059669" if not is_active else "#b91c1c",
            height=45,
            corner_radius=10,
            command=self._toggle_protection,
        ).grid(row=2, column=0, sticky="ew", pady=15)

        # Log de alertas
        ctk.CTkLabel(
            frame,
            text="Registro de alertas",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=3, column=0, sticky="w", pady=(10, 5))

        self._alert_log = ctk.CTkTextbox(
            frame,
            height=200,
            font=ctk.CTkFont(size=11, family="Courier"),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_primary"],
            state="disabled",
        )
        self._alert_log.grid(row=4, column=0, sticky="ew")

        # Configurar callback de alerta
        self._protection_uc.set_alert_callback(self._on_threat_alert)

    def _toggle_protection(self) -> None:
        if self._protection_uc.is_active():
            self._protection_uc.stop()
            messagebox.showinfo("Protección", "Protección en tiempo real detenida.")
        else:
            directory = self._monitor_dir_var.get()
            if not Path(directory).exists():
                messagebox.showerror("Error", f"El directorio no existe:\n{directory}")
                return
            try:
                self._protection_uc.start(directory)
                messagebox.showinfo(
                    "Protección", f"Protección activa monitoreando:\n{directory}"
                )
            except Exception as exc:
                messagebox.showerror("Error", f"No se pudo iniciar la protección:\n{exc}")
        self._show_protection()

    def _on_threat_alert(self, threat, response) -> None:
        """Callback invocado desde el hilo del monitor cuando hay amenaza."""
        msg = (
            f"[{datetime.now().strftime('%H:%M:%S')}] ⚠ AMENAZA: "
            f"{getattr(threat, 'path', str(threat))} | "
            f"Nivel: {getattr(threat, 'threat_level', 'N/A')} | "
            f"Firma: {getattr(threat, 'signature_name', 'N/A')}\n"
        )
        self.after(0, lambda: self._append_alert_log(msg))

    def _append_alert_log(self, msg: str) -> None:
        if hasattr(self, "_alert_log"):
            self._alert_log.configure(state="normal")
            self._alert_log.insert("end", msg)
            self._alert_log.see("end")
            self._alert_log.configure(state="disabled")

    # ------------------------------------------------------------------
    # Cuarentena
    # ------------------------------------------------------------------

    def _show_quarantine(self) -> None:
        self._clear_content()
        self._set_active_nav("📦  Cuarentena")

        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            frame,
            text="Gestor de Cuarentena",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Botón refrescar
        ctk.CTkButton(
            frame,
            text="🔄  Actualizar lista",
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["accent_blue"],
            width=160,
            height=36,
            command=self._show_quarantine,
        ).grid(row=1, column=0, sticky="w", pady=(0, 10))

        # Lista
        q_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color=COLORS["bg_secondary"],
            corner_radius=12,
            label_text="Archivos en cuarentena",
        )
        q_frame.grid(row=2, column=0, sticky="nsew")
        q_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        files = self._quarantine_uc.list_quarantined()

        if not files:
            ctk.CTkLabel(
                q_frame,
                text="La cuarentena está vacía.",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text_secondary"],
            ).grid(row=0, column=0, columnspan=5, padx=15, pady=20)
            return

        headers = ["Archivo original", "Nivel", "Motivo", "Fecha", "Acciones"]
        for col_i, header in enumerate(headers):
            ctk.CTkLabel(
                q_frame,
                text=header,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_secondary"],
                anchor="w",
            ).grid(row=0, column=col_i, padx=10, pady=(10, 5), sticky="w")

        for row_i, f in enumerate(files, start=1):
            level = str(f.get("threat_level", "N/A")).upper()
            color = THREAT_COLORS.get(level, COLORS["text_primary"])

            quarantined_at = f.get("quarantined_at", "N/A")
            if hasattr(quarantined_at, "strftime"):
                quarantined_at = quarantined_at.strftime("%Y-%m-%d %H:%M")

            row_vals = [
                (str(Path(f.get("original_path", "N/A")).name), COLORS["text_primary"]),
                (level, color),
                (f.get("reason", "N/A"), COLORS["text_secondary"]),
                (str(quarantined_at), COLORS["text_secondary"]),
            ]
            for col_i, (val, c) in enumerate(row_vals):
                ctk.CTkLabel(
                    q_frame,
                    text=val,
                    font=ctk.CTkFont(size=11),
                    text_color=c,
                    anchor="w",
                ).grid(row=row_i, column=col_i, padx=10, pady=3, sticky="w")

            # Botón restaurar
            original = f.get("original_path", "")
            ctk.CTkButton(
                q_frame,
                text="Restaurar",
                font=ctk.CTkFont(size=11),
                fg_color=COLORS["accent_yellow"],
                text_color="#000",
                hover_color="#d97706",
                width=90,
                height=28,
                command=lambda p=original: self._restore_file(p),
            ).grid(row=row_i, column=4, padx=10, pady=3)

    def _restore_file(self, file_path: str) -> None:
        if messagebox.askyesno(
            "Restaurar archivo",
            f"¿Restaurar este archivo a su ubicación original?\n{file_path}",
        ):
            success = self._quarantine_uc.restore_file(file_path)
            if success:
                messagebox.showinfo("Restaurado", "Archivo restaurado exitosamente.")
                self._show_quarantine()
            else:
                messagebox.showerror("Error", "No se pudo restaurar el archivo.")

    # ------------------------------------------------------------------
    # Limpieza
    # ------------------------------------------------------------------

    def _show_cleanup(self) -> None:
        self._clear_content()
        self._set_active_nav("🧹  Limpieza")

        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Limpieza del Sistema",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Opciones
        opts_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        opts_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        ctk.CTkLabel(
            opts_frame,
            text="Opciones de limpieza",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=15, pady=(12, 8))

        self._cleanup_temp_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opts_frame,
            text="Archivos temporales del sistema (.tmp, .log, .old, .bak)",
            variable=self._cleanup_temp_var,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_primary"],
            fg_color=COLORS["accent_blue"],
        ).grid(row=1, column=0, sticky="w", padx=15, pady=4)

        self._cleanup_quarantine_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_frame,
            text="Archivos en cuarentena",
            variable=self._cleanup_quarantine_var,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_primary"],
            fg_color=COLORS["accent_blue"],
        ).grid(row=2, column=0, sticky="w", padx=15, pady=(4, 12))

        # Botones
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="ew", pady=10)
        btn_row.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            btn_row,
            text="🔍  Vista previa",
            font=ctk.CTkFont(size=13),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["accent_blue"],
            height=40,
            corner_radius=10,
            command=self._cleanup_preview,
        ).grid(row=0, column=0, padx=(0, 8), sticky="ew")

        ctk.CTkButton(
            btn_row,
            text="🗑  Ejecutar Limpieza",
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=COLORS["accent"],
            hover_color="#b91c1c",
            height=40,
            corner_radius=10,
            command=self._cleanup_execute,
        ).grid(row=0, column=1, padx=(8, 0), sticky="ew")

        # Resultado
        self._cleanup_result_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color=COLORS["bg_secondary"],
            corner_radius=12,
            label_text="Resultado",
            height=300,
        )
        self._cleanup_result_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self._cleanup_result_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._cleanup_result_frame,
            text="Selecciona opciones y ejecuta la vista previa.",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_secondary"],
        ).grid(row=0, column=0, padx=15, pady=15)

    def _cleanup_preview(self) -> None:
        request = CleanupRequestDTO(
            include_temp=self._cleanup_temp_var.get(),
            include_quarantine=self._cleanup_quarantine_var.get(),
            custom_paths=[],
        )
        try:
            files = self._cleanup_uc.preview(request)
            self._show_cleanup_files(files, is_preview=True)
        except Exception as exc:
            messagebox.showerror("Error", f"Error en vista previa:\n{exc}")

    def _cleanup_execute(self) -> None:
        request = CleanupRequestDTO(
            include_temp=self._cleanup_temp_var.get(),
            include_quarantine=self._cleanup_quarantine_var.get(),
            custom_paths=[],
        )
        try:
            files = self._cleanup_uc.preview(request)
            if not files:
                messagebox.showinfo("Limpieza", "No se encontraron archivos para eliminar.")
                return
            if not messagebox.askyesno(
                "Confirmar limpieza",
                f"¿Eliminar {len(files)} archivo(s)?\nEsta acción no se puede deshacer.",
            ):
                return
            report = self._cleanup_uc.execute(request)
            status = "✔ Exitosa" if report.success else "✘ Con errores"
            messagebox.showinfo(
                "Limpieza completa",
                f"Archivos eliminados: {report.files_deleted}\n"
                f"Espacio liberado: {report.space_freed_mb:.2f} MB\n"
                f"Estado: {status}",
            )
            self._show_cleanup_files([], is_preview=False, report=report)
        except Exception as exc:
            messagebox.showerror("Error", f"Error durante la limpieza:\n{exc}")

    def _show_cleanup_files(self, files: list, is_preview: bool, report=None) -> None:
        for widget in self._cleanup_result_frame.winfo_children():
            widget.destroy()

        if report:
            status_color = COLORS["accent_green"] if report.success else COLORS["accent"]
            ctk.CTkLabel(
                self._cleanup_result_frame,
                text=(
                    f"✔ Eliminados: {report.files_deleted}  |  "
                    f"Liberado: {report.space_freed_mb:.2f} MB  |  "
                    f"{'Sin errores' if report.success else str(len(report.errors)) + ' error(es)'}"
                ),
                font=ctk.CTkFont(size=13),
                text_color=status_color,
            ).grid(row=0, column=0, padx=15, pady=15, sticky="w")
            return

        if not files:
            ctk.CTkLabel(
                self._cleanup_result_frame,
                text="No se encontraron archivos temporales.",
                font=ctk.CTkFont(size=12),
                text_color=COLORS["text_secondary"],
            ).grid(row=0, column=0, padx=15, pady=15)
            return

        title = f"Vista previa — {len(files)} archivo(s) a eliminar" if is_preview else "Archivos encontrados"
        ctk.CTkLabel(
            self._cleanup_result_frame,
            text=title,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, padx=15, pady=(12, 5), sticky="w")

        for i, filepath in enumerate(files[:50], start=1):
            ctk.CTkLabel(
                self._cleanup_result_frame,
                text=f"  {filepath}",
                font=ctk.CTkFont(size=11),
                text_color=COLORS["text_secondary"],
                anchor="w",
            ).grid(row=i, column=0, padx=15, pady=1, sticky="w")

        if len(files) > 50:
            ctk.CTkLabel(
                self._cleanup_result_frame,
                text=f"  ... y {len(files) - 50} archivo(s) más",
                font=ctk.CTkFont(size=11),
                text_color=COLORS["text_secondary"],
                anchor="w",
            ).grid(row=51, column=0, padx=15, pady=(1, 10), sticky="w")

    # ------------------------------------------------------------------
    # Ajustes
    # ------------------------------------------------------------------

    def _show_settings(self) -> None:
        self._clear_content()
        self._set_active_nav("⚙  Ajustes")

        frame = ctk.CTkScrollableFrame(self._content, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Configuración",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=0, column=0, sticky="w", pady=(0, 20))

        # Sección de configuración
        cfg_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        cfg_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        cfg_frame.grid_columnconfigure(1, weight=1)

        settings_items = [
            ("Base de datos (SQLite):",   self._settings.DB_PATH),
            ("Directorio de cuarentena:", self._settings.QUARANTINE_DIR),
            ("Directorio monitorizado:",  self._settings.MONITOR_DIRECTORY),
            ("Tamaño máximo de archivo:", f"{self._settings.MAX_FILE_SIZE_MB} MB"),
            ("Niveles de cuarentena auto:", ", ".join(self._settings.AUTO_QUARANTINE_LEVELS)),
            ("Versión:",                  self._settings.APP_VERSION),
        ]

        for i, (label, value) in enumerate(settings_items):
            ctk.CTkLabel(
                cfg_frame,
                text=label,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=COLORS["text_secondary"],
                anchor="w",
            ).grid(row=i, column=0, padx=15, pady=6, sticky="w")
            ctk.CTkLabel(
                cfg_frame,
                text=str(value),
                font=ctk.CTkFont(size=12),
                text_color=COLORS["text_primary"],
                anchor="w",
            ).grid(row=i, column=1, padx=15, pady=6, sticky="w")

        # Extensiones
        ctk.CTkLabel(
            frame,
            text="Extensiones escaneadas",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text_primary"],
        ).grid(row=2, column=0, sticky="w", pady=(15, 8))

        ext_frame = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"], corner_radius=12)
        ext_frame.grid(row=3, column=0, sticky="ew")

        ext_text = "  ".join(self._settings.SCAN_EXTENSIONS)
        ctk.CTkLabel(
            ext_frame,
            text=ext_text,
            font=ctk.CTkFont(size=12, family="Courier"),
            text_color=COLORS["accent_blue"],
            wraplength=700,
            justify="left",
        ).pack(padx=15, pady=12, anchor="w")

        # Botón acerca de
        ctk.CTkButton(
            frame,
            text="ℹ  Acerca de SecureGuard",
            font=ctk.CTkFont(size=12),
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["accent_blue"],
            height=38,
            corner_radius=10,
            command=self._show_about,
        ).grid(row=4, column=0, sticky="w", pady=20)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "Acerca de SecureGuard",
            "SecureGuard — Sistema Antivirus Profesional\n"
            "Versión 1.0.0\n\n"
            "Tecnologías: Python 3.10+ · customtkinter · SQLite · watchdog\n"
            "Arquitectura: Clean Architecture · DI · SOLID\n\n"
            "Motor de detección:\n"
            "  • Comparación de hashes SHA-256\n"
            "  • Detección de patrones hexadecimales\n"
            "  • Monitoreo en tiempo real con watchdog",
        )

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Inicia el bucle principal de la aplicación."""
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.mainloop()

    def _on_close(self) -> None:
        """Cierra la aplicación de forma limpia."""
        try:
            self._container.shutdown()
        except Exception as exc:
            logger.warning("Error cerrando contenedor: %s", exc)
        self.destroy()
