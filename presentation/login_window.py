"""
presentation/login_window.py
=============================
Pantalla de inicio de sesión de SecureGuard.
Muestra el logo de base de datos (cilindro), campos de usuario y contraseña,
barra de progreso animada y mensajes amigables antes de abrir la aplicación principal.
"""

import tkinter as tk
import threading
import logging

import customtkinter as ctk

logger = logging.getLogger(__name__)

# Credenciales por defecto (demo). Pueden cambiarse en .env o en configuración.
_DEFAULT_USER = "admin"
_DEFAULT_PASS = "admin"

# Paleta de colores (coincide con la interfaz principal)
_COLORS = {
    "bg_primary":   "#1a1a2e",
    "bg_secondary": "#16213e",
    "bg_card":      "#0f3460",
    "accent":       "#e94560",
    "accent_blue":  "#3a86ff",
    "accent_green": "#06d6a0",
    "text_primary": "#ffffff",
    "text_secondary": "#b0b3c1",
}


def _draw_cylinder(parent: tk.Widget, width: int = 64, height: int = 72) -> tk.Canvas:
    """Dibuja un ícono de cilindro (base de datos clásico) en un Canvas de tkinter."""
    canvas = tk.Canvas(
        parent,
        width=width,
        height=height,
        bg=_COLORS["bg_primary"],
        highlightthickness=0,
    )

    body_color   = _COLORS["accent_blue"]   # #3a86ff
    top_color    = "#6aaeff"                 # más claro
    shadow_color = "#1a56cc"                 # más oscuro

    lx, rx = 6, width - 6         # límites horizontales
    top_ey  = int(height * 0.18)  # centro de la elipse superior
    eh      = int(height * 0.18)  # altura de las elipses
    bot_cy  = int(height * 0.82)  # centro de la elipse inferior

    # Cuerpo (rectángulo entre las dos elipses)
    canvas.create_rectangle(
        lx, top_ey, rx, bot_cy,
        fill=body_color, outline="",
    )

    # Elipse inferior (sombra)
    canvas.create_oval(
        lx, bot_cy - eh // 2, rx, bot_cy + eh // 2,
        fill=shadow_color, outline="",
    )

    # Elipse superior (tapa)
    canvas.create_oval(
        lx, top_ey - eh // 2, rx, top_ey + eh // 2,
        fill=top_color, outline="",
    )

    # Línea horizontal en el cuerpo (ranura decorativa)
    mid_y = (top_ey + bot_cy) // 2
    canvas.create_oval(
        lx, mid_y - eh // 2, rx, mid_y + eh // 2,
        fill=body_color, outline="#1a56cc", width=1,
    )
    # Restaurar la mitad superior de esa línea decorativa
    canvas.create_rectangle(
        lx + 1, mid_y - eh // 2 + 1, rx - 1, mid_y,
        fill=body_color, outline="",
    )

    return canvas


class LoginWindow(ctk.CTk):
    """
    Ventana de inicio de sesión.
    Una vez autenticado, llama a `on_success(container)` y se cierra.
    """

    def __init__(self, container) -> None:
        super().__init__()

        self._container  = container
        self._on_success_cb = None   # se asigna desde main.py

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("SecureGuard — Iniciar Sesión")
        self.geometry("420x560")
        self.resizable(False, False)
        self.configure(fg_color=_COLORS["bg_primary"])

        self._build_ui()

    # ------------------------------------------------------------------
    # Construcción de la UI
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        # ── Logo cilindro ──────────────────────────────────────────────
        logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        logo_frame.grid(row=0, column=0, pady=(40, 8))

        cyl = _draw_cylinder(logo_frame, width=64, height=72)
        cyl.pack()

        # ── Título ─────────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="SecureGuard",
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color=_COLORS["accent_blue"],
        ).grid(row=1, column=0)

        ctk.CTkLabel(
            self,
            text="Protección de Base de Datos",
            font=ctk.CTkFont(size=13),
            text_color=_COLORS["text_secondary"],
        ).grid(row=2, column=0, pady=(2, 28))

        # ── Campos de entrada ─────────────────────────────────────────
        form_frame = ctk.CTkFrame(
            self, fg_color=_COLORS["bg_secondary"], corner_radius=14
        )
        form_frame.grid(row=3, column=0, padx=40, sticky="ew")
        form_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            form_frame,
            text="Usuario",
            font=ctk.CTkFont(size=12),
            text_color=_COLORS["text_secondary"],
            anchor="w",
        ).grid(row=0, column=0, padx=20, pady=(20, 2), sticky="w")

        self._user_entry = ctk.CTkEntry(
            form_frame,
            font=ctk.CTkFont(size=13),
            fg_color=_COLORS["bg_primary"],
            border_color=_COLORS["bg_card"],
            height=38,
            placeholder_text="Usuario",
        )
        self._user_entry.grid(row=1, column=0, padx=20, sticky="ew")
        self._user_entry.insert(0, _DEFAULT_USER)

        ctk.CTkLabel(
            form_frame,
            text="Contraseña",
            font=ctk.CTkFont(size=12),
            text_color=_COLORS["text_secondary"],
            anchor="w",
        ).grid(row=2, column=0, padx=20, pady=(14, 2), sticky="w")

        self._pass_entry = ctk.CTkEntry(
            form_frame,
            font=ctk.CTkFont(size=13),
            fg_color=_COLORS["bg_primary"],
            border_color=_COLORS["bg_card"],
            height=38,
            show="●",
            placeholder_text="Contraseña",
        )
        self._pass_entry.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        self._pass_entry.insert(0, _DEFAULT_PASS)

        # ── Barra de progreso ──────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(
            self,
            fg_color=_COLORS["bg_secondary"],
            progress_color=_COLORS["accent_blue"],
        )
        self._progress.grid(row=4, column=0, padx=40, pady=(20, 4), sticky="ew")
        self._progress.set(0)

        # ── Mensaje de estado ──────────────────────────────────────────
        self._status_label = ctk.CTkLabel(
            self,
            text="Ingresa tus datos para continuar.",
            font=ctk.CTkFont(size=12),
            text_color=_COLORS["text_secondary"],
        )
        self._status_label.grid(row=5, column=0, pady=(0, 16))

        # ── Botón ingresar ─────────────────────────────────────────────
        self._login_btn = ctk.CTkButton(
            self,
            text="Ingresar",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=_COLORS["accent_blue"],
            hover_color="#2563eb",
            height=44,
            corner_radius=10,
            command=self._attempt_login,
        )
        self._login_btn.grid(row=6, column=0, padx=40, sticky="ew")

        # Atajo de teclado: Enter en cualquier campo
        self._user_entry.bind("<Return>", lambda _: self._attempt_login())
        self._pass_entry.bind("<Return>", lambda _: self._attempt_login())

    # ------------------------------------------------------------------
    # Lógica de autenticación
    # ------------------------------------------------------------------

    def _attempt_login(self) -> None:
        username = self._user_entry.get().strip()
        password = self._pass_entry.get()

        self._login_btn.configure(state="disabled")
        self._status_label.configure(
            text="Verificando...", text_color=_COLORS["accent_blue"]
        )
        self._progress.set(0)
        self._progress.start()

        threading.Thread(
            target=self._validate_credentials,
            args=(username, password),
            daemon=True,
        ).start()

    def _validate_credentials(self, username: str, password: str) -> None:
        """Simula la validación (se podría extender con BD real)."""
        import time
        time.sleep(1.2)   # animación de verificación

        if username == _DEFAULT_USER and password == _DEFAULT_PASS:
            self.after(0, self._login_success)
        else:
            self.after(0, self._login_failed)

    def _login_success(self) -> None:
        self._progress.stop()
        self._progress.set(1)
        self._status_label.configure(
            text="✔ Prueba exitosa", text_color=_COLORS["accent_green"]
        )
        # Esperar 0.7 s para que el usuario vea el mensaje de éxito
        self.after(700, self._open_main_app)

    def _login_failed(self) -> None:
        self._progress.stop()
        self._progress.set(0)
        self._login_btn.configure(state="normal")
        self._status_label.configure(
            text="Datos incorrectos. Intenta de nuevo.",
            text_color=_COLORS["accent"],
        )
        self._pass_entry.delete(0, "end")
        self._pass_entry.focus_set()

    def _open_main_app(self) -> None:
        """Cierra la pantalla de login y abre la aplicación principal."""
        self.destroy()
        if callable(self._on_success_cb):
            self._on_success_cb(self._container)

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def set_on_success(self, callback) -> None:
        """Registra el callback que se llama cuando el login es exitoso."""
        self._on_success_cb = callback

    def run(self) -> None:
        """Inicia el bucle de la ventana de login."""
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.mainloop()
