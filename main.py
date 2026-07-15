from __future__ import annotations

import json
import os
import queue
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
import ctypes
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk
from urllib.parse import urlsplit

from PIL import Image, ImageDraw, ImageTk
import pystray

from remnawave import ApiError, NodeSnapshot, OnlineUser, RemnawaveClient, tcp_latency
from openwrt import LanDevice, OpenWrtClient, OpenWrtSshClient, RouterSnapshot
from nettest import measure_parallel
from history import HistoryStore
from routecheck import RouteSnapshot, check_routes
from leaktest import LeakTestResult, run_leak_test
from security import protect, unprotect
from webpanel import CaddyManager, DashboardWebServer

APP_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR.parent if getattr(sys, "frozen", False) and APP_DIR.name.lower() == "dist" else APP_DIR
CONFIG_PATH = APP_DIR / "config.local.json"
DEFAULT_ROUTER_KEY = PROJECT_DIR / "keys" / "router_monitor_ed25519"
BG = "#10090f"
HEADER = "#180c13"
CARD = "#211019"
CARD_ALT = "#2b1420"
TEXT = "#fff5f1"
MUTED = "#b08c92"
GREEN = "#62e6a7"
RED = "#ff493d"
CYAN = "#ffc078"
PURPLE = "#e060ff"
ORANGE = "#ff983d"
_INSTANCE_MUTEX = None


def acquire_single_instance() -> bool:
    global _INSTANCE_MUTEX
    _INSTANCE_MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\StarStackCascadeMonitor")
    return ctypes.windll.kernel32.GetLastError() != 183


def default_config() -> dict:
    return {
        "panel_url": "",
        "token_dpapi": "",
        "access_query_dpapi": "",
        "refresh_seconds": 10,
        "always_on_top": True,
        "opacity": 0.91,
        "router_url": "http://192.168.1.1",
        "router_username": "root",
        "router_password_dpapi": "",
        "router_ssh_key": str(DEFAULT_ROUTER_KEY),
        "router_ssh_port": 22,
        "compact_mode": False,
        "notifications": True,
        "latency_warn_ms": 150,
        "ram_warn_percent": 85,
        "watchdog_enabled": True,
        "auto_backup_enabled": True,
        "web_enabled": True,
        "web_domain": "monitor.example.com",
        "web_port": 8765,
        "web_username": "starstack",
        "web_password_dpapi": "",
        "window_x": 30,
        "window_y": 80,
    }


def load_config() -> dict:
    cfg = default_config()
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def human_bytes(value: float) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(value) < 1024 or unit == "ТБ":
            return f"{value:.1f} {unit}"
        value /= 1024
    return "0 Б"


def human_rate(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value * 8 / 1_000_000:.2f} Мбит/с"


def node_country_and_name(name: str) -> tuple[str | None, str]:
    lowered = name.lower()
    if "germany" in lowered or "german" in lowered or lowered.startswith("de"):
        return "de", "Germany"
    if "moscow" in lowered or lowered.startswith("ru"):
        return "ru", "Moscow"
    return None, name


class SettingsDialog(tk.Toplevel):
    def __init__(self, parent: "MonitorApp"):
        super().__init__(parent)
        self.parent = parent
        self.title("Настройки")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.attributes("-alpha", 0.98)
        self.transient(parent)
        self.grab_set()
        ttk.Label(self, text="Адрес Remnawave Panel").grid(row=0, column=0, padx=14, pady=(14, 4), sticky="w")
        self.url = ttk.Entry(self, width=48)
        self.url.grid(row=1, column=0, padx=14, sticky="ew")
        self.url.insert(0, parent.config.get("panel_url", ""))
        ttk.Label(self, text="API-токен (хранится зашифрованным DPAPI)").grid(row=2, column=0, padx=14, pady=(12, 4), sticky="w")
        self.token = ttk.Entry(self, width=48, show="•")
        self.token.grid(row=3, column=0, padx=14, sticky="ew")
        try:
            self.token.insert(0, unprotect(parent.config.get("token_dpapi", "")))
        except Exception:
            pass
        ttk.Label(self, text="NX31: адрес LuCI").grid(row=4, column=0, padx=14, pady=(14, 4), sticky="w")
        self.router_url = ttk.Entry(self, width=48)
        self.router_url.grid(row=5, column=0, padx=14, sticky="ew")
        self.router_url.insert(0, parent.config.get("router_url", "http://192.168.1.1"))
        router_auth = ttk.Frame(self)
        router_auth.grid(row=6, column=0, padx=14, pady=(5, 0), sticky="ew")
        self.router_user = ttk.Entry(router_auth, width=14)
        self.router_user.pack(side="left")
        self.router_user.insert(0, parent.config.get("router_username", "root"))
        self.router_password = ttk.Entry(router_auth, width=28, show="•")
        self.router_password.pack(side="left", padx=(7, 0), fill="x", expand=True)
        try:
            self.router_password.insert(0, unprotect(parent.config.get("router_password_dpapi", "")))
        except Exception:
            pass
        ttk.Label(self, text="Логин и пароль роутера (fallback, DPAPI)", foreground=MUTED).grid(row=7, column=0, padx=14, sticky="w")
        ttk.Label(self, text="SSH private key / порт").grid(row=8, column=0, padx=14, pady=(10, 4), sticky="w")
        ssh_row = ttk.Frame(self)
        ssh_row.grid(row=9, column=0, padx=14, sticky="ew")
        self.router_key = ttk.Entry(ssh_row, width=39)
        self.router_key.pack(side="left", fill="x", expand=True)
        self.router_key.insert(0, parent.config.get("router_ssh_key", str(DEFAULT_ROUTER_KEY)))
        self.router_port = ttk.Spinbox(ssh_row, from_=1, to=65535, width=6)
        self.router_port.pack(side="left", padx=(7, 0))
        self.router_port.set(parent.config.get("router_ssh_port", 22))
        ttk.Label(self, text="Обновление, секунд").grid(row=10, column=0, padx=14, pady=(12, 4), sticky="w")
        self.refresh = ttk.Spinbox(self, from_=5, to=300, width=8)
        self.refresh.grid(row=11, column=0, padx=14, sticky="w")
        self.refresh.set(parent.config.get("refresh_seconds", 10))
        ttk.Label(self, text="Пороги предупреждений: задержка / RAM").grid(row=12, column=0, padx=14, pady=(12, 4), sticky="w")
        thresholds = ttk.Frame(self)
        thresholds.grid(row=13, column=0, padx=14, sticky="w")
        self.latency_warn = ttk.Spinbox(thresholds, from_=50, to=2000, width=8)
        self.latency_warn.pack(side="left")
        self.latency_warn.set(parent.config.get("latency_warn_ms", 150))
        ttk.Label(thresholds, text="мс     ").pack(side="left")
        self.ram_warn = ttk.Spinbox(thresholds, from_=50, to=100, width=8)
        self.ram_warn.pack(side="left")
        self.ram_warn.set(parent.config.get("ram_warn_percent", 85))
        ttk.Label(thresholds, text="%").pack(side="left")
        ttk.Label(self, text="Прозрачность").grid(row=14, column=0, padx=14, pady=(12, 4), sticky="w")
        self.opacity = ttk.Scale(self, from_=0.78, to=1.0, orient="horizontal", length=260)
        self.opacity.grid(row=15, column=0, padx=14, sticky="w")
        self.opacity.set(float(parent.config.get("opacity", 0.94)))
        self.watchdog_enabled = tk.BooleanVar(value=bool(parent.config.get("watchdog_enabled", True)))
        ttk.Checkbutton(self, text="Безопасный watchdog sing-box", variable=self.watchdog_enabled).grid(
            row=16, column=0, padx=14, pady=(12, 0), sticky="w"
        )
        ttk.Label(self, text="3 сбоя подряд · пауза 10 мин · максимум 2 запуска/час", foreground=MUTED).grid(
            row=17, column=0, padx=14, sticky="w"
        )
        self.auto_backup_enabled = tk.BooleanVar(value=bool(parent.config.get("auto_backup_enabled", True)))
        ttk.Checkbutton(self, text="Автокопия NX31 раз в неделю", variable=self.auto_backup_enabled).grid(
            row=18, column=0, padx=14, pady=(9, 0), sticky="w"
        )
        ttk.Label(self, text="Хранятся последние 5 архивов", foreground=MUTED).grid(
            row=19, column=0, padx=14, sticky="w"
        )
        self.web_enabled = tk.BooleanVar(value=bool(parent.config.get("web_enabled", True)))
        ttk.Checkbutton(self, text="Мобильная web-панель HTTPS", variable=self.web_enabled).grid(
            row=20, column=0, padx=14, pady=(9, 0), sticky="w"
        )
        ttk.Label(self, text="Домен web-панели").grid(row=21, column=0, padx=14, pady=(8, 4), sticky="w")
        self.web_domain = ttk.Entry(self, width=48)
        self.web_domain.grid(row=22, column=0, padx=14, sticky="ew")
        self.web_domain.insert(0, parent.config.get("web_domain", "monitor.example.com"))
        web_auth = ttk.Frame(self)
        web_auth.grid(row=23, column=0, padx=14, pady=(7, 0), sticky="ew")
        self.web_username = ttk.Entry(web_auth, width=15)
        self.web_username.pack(side="left")
        self.web_username.insert(0, parent.config.get("web_username", "starstack"))
        self.web_password = ttk.Entry(web_auth, width=28, show="•")
        self.web_password.pack(side="left", padx=(7, 0), fill="x", expand=True)
        try:
            self.web_password.insert(0, unprotect(parent.config.get("web_password_dpapi", "")))
        except Exception:
            pass
        ttk.Label(self, text="Логин и отдельный пароль web-панели (DPAPI)", foreground=MUTED).grid(
            row=24, column=0, padx=14, sticky="w"
        )
        buttons = ttk.Frame(self)
        buttons.grid(row=25, column=0, padx=14, pady=14, sticky="e")
        ttk.Button(buttons, text="Отмена", command=self.destroy).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Сохранить", command=self.save).pack(side="left")

    def save(self) -> None:
        token = self.token.get().strip()
        self.parent.config["panel_url"] = self.url.get().strip().rstrip("/")
        self.parent.config["token_dpapi"] = protect(token)
        self.parent.config["router_url"] = self.router_url.get().strip().rstrip("/")
        self.parent.config["router_username"] = self.router_user.get().strip() or "root"
        self.parent.config["router_password_dpapi"] = protect(self.router_password.get())
        self.parent.config["router_ssh_key"] = self.router_key.get().strip()
        self.parent.config["router_ssh_port"] = int(self.router_port.get() or 22)
        self.parent.config["refresh_seconds"] = max(5, int(self.refresh.get() or 10))
        self.parent.config["latency_warn_ms"] = max(50, int(self.latency_warn.get() or 150))
        self.parent.config["ram_warn_percent"] = max(50, min(100, int(self.ram_warn.get() or 85)))
        self.parent.config["opacity"] = round(float(self.opacity.get()), 2)
        self.parent.config["watchdog_enabled"] = bool(self.watchdog_enabled.get())
        self.parent.config["auto_backup_enabled"] = bool(self.auto_backup_enabled.get())
        self.parent.config["web_enabled"] = bool(self.web_enabled.get())
        self.parent.config["web_domain"] = self.web_domain.get().strip().lower()
        self.parent.config["web_username"] = self.web_username.get().strip() or "starstack"
        self.parent.config["web_password_dpapi"] = protect(self.web_password.get())
        save_config(self.parent.config)
        self.parent.attributes("-alpha", self.parent.config["opacity"])
        self.destroy()
        self.parent.restart_web_panel()
        self.parent.refresh_now()


class MonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self._new_web_password = ""
        if self.config.get("web_enabled", True) and not self.config.get("web_password_dpapi"):
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
            self._new_web_password = "".join(secrets.choice(alphabet) for _ in range(20))
            self.config["web_password_dpapi"] = protect(self._new_web_password)
            save_config(self.config)
        self.title("StarStack Cascade Monitor")
        self.geometry(f"420x180+{self.config['window_x']}+{self.config['window_y']}")
        self.configure(bg=BG)
        self.attributes("-topmost", bool(self.config.get("always_on_top", True)))
        self.attributes("-alpha", float(self.config.get("opacity", 0.94)))
        self.overrideredirect(True)
        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self._drag_x = self._drag_y = 0
        self._busy = False
        self._queue: queue.Queue = queue.Queue()
        self._last_traffic: dict[str, tuple[int, float]] = {}
        self._last_nodes: list[NodeSnapshot] = []
        self._last_users: list[OnlineUser] = []
        self._last_api_ms = 0.0
        self._last_router = RouterSnapshot()
        self._last_remna_error = ""
        self._last_route = RouteSnapshot()
        self._last_route_check = 0.0
        self._force_route_check = False
        self.users_expanded = True
        self.compact_mode = bool(self.config.get("compact_mode", False))
        self._previous_health: dict[str, bool] | None = None
        self._previous_users: set[str] | None = None
        self._previous_routes: tuple[str, str, str] | None = None
        self._threshold_active: set[str] = set()
        self._flag_images: dict[str, ImageTk.PhotoImage] = {}
        self._speed_testing: set[str] = set()
        self._speed_results: dict[str, str] = {}
        self._last_leak: LeakTestResult | None = None
        self._leak_running = False
        self._log_window: tk.Toplevel | None = None
        self._lan_window: tk.Toplevel | None = None
        self._last_lan_devices: list[LanDevice] = []
        self._blocked_macs: set[str] = set()
        self._device_metadata: dict[str, tuple[str, bool]] = {}
        self._lan_tree: ttk.Treeview | None = None
        self._device_traffic: dict[str, tuple[int, int, float, float]] = {}
        self._last_device_totals: dict[str, tuple[int, int, float]] = {}
        self._singbox_failures = 0
        self._watchdog_recovering = False
        self._watchdog_restarts: list[float] = []
        self._auto_backup_running = False
        self._last_auto_backup_check = 0.0
        self.web_server: DashboardWebServer | None = None
        self.caddy: CaddyManager | None = None
        self.history = HistoryStore(APP_DIR / "history.db")
        self.history.add_event("info", "StarStack Cascade Monitor запущен")
        self._really_closing = False
        self.tray_icon: pystray.Icon | None = None
        self._configure_styles()
        self._build_ui()
        self._start_tray()
        self._start_web_panel()
        if self._new_web_password:
            self.after(1200, self._show_new_web_credentials)
        self.after(100, self._poll_result)
        self.after(250, self.refresh_now)
        has_router_auth = bool(self.config.get("router_password_dpapi")) or Path(
            self.config.get("router_ssh_key", str(DEFAULT_ROUTER_KEY))
        ).exists()
        if not self.config.get("token_dpapi") or not has_router_auth:
            self.after(500, self.open_settings)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=("Segoe UI", 9))
        style.configure("TEntry", fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT, bordercolor="#304056")
        style.configure("TSpinbox", fieldbackground=CARD, foreground=TEXT, arrowcolor=TEXT)
        style.configure("TButton", background=CARD_ALT, foreground=TEXT, borderwidth=0, padding=(11, 7))
        style.map("TButton", background=[("active", "#24344a")])
        style.configure("Horizontal.TScale", background=BG, troughcolor=CARD, sliderrelief="flat")

    def _show_new_web_credentials(self) -> None:
        login = self.config.get("web_username", "starstack")
        text = f"Web-панель: https://{self.config.get('web_domain')}\n\nЛогин: {login}\nПароль: {self._new_web_password}"
        self.clipboard_clear()
        self.clipboard_append(self._new_web_password)
        messagebox.showinfo("Доступ с телефона", text + "\n\nПароль скопирован в буфер обмена.")

    def _build_ui(self) -> None:
        shell = tk.Frame(self, bg=RED, padx=1, pady=1)
        shell.pack(fill="both", expand=True)
        inner = tk.Frame(shell, bg=BG)
        inner.pack(fill="both", expand=True)
        header = tk.Frame(inner, bg=HEADER, height=43)
        header.pack(fill="x")
        header.bind("<ButtonPress-1>", self._drag_start)
        header.bind("<B1-Motion>", self._drag_move)
        tk.Label(header, text="◈", bg=HEADER, fg=ORANGE,
                 font=("Segoe UI Semibold", 15)).pack(side="left", padx=(13, 5), pady=7)
        title_box = tk.Frame(header, bg=HEADER)
        title_box.pack(side="left", pady=5)
        tk.Label(title_box, text="StarStack", bg=HEADER, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).pack(anchor="w")
        tk.Label(title_box, text="NEON CASCADE MONITOR", bg=HEADER, fg=RED,
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        self.overall = tk.Label(header, text="● ПРОВЕРКА", bg=HEADER, fg=MUTED,
                                font=("Segoe UI Semibold", 9))
        self.overall.pack(side="right", padx=(0, 8))
        tk.Button(header, text="×", command=self.hide_to_tray, bg=HEADER, fg=MUTED, bd=0,
                  activebackground=HEADER, activeforeground=TEXT, font=("Segoe UI", 14),
                  cursor="hand2").pack(side="right", padx=5)

        self.body = tk.Frame(inner, bg=BG)
        self.body.pack(fill="both", expand=True, padx=8)
        self.message = tk.Label(self.body, text="Подключение к Remnawave…", bg=CARD, fg=MUTED,
                                font=("Segoe UI", 9), justify="left", wraplength=345, padx=12, pady=14)
        self.message.pack(fill="x", pady=4)
        footer = tk.Frame(inner, bg=BG)
        footer.pack(fill="x", padx=10, pady=(2, 7))
        self.updated = tk.Label(footer, text="", bg=BG, fg=MUTED, font=("Segoe UI", 8))
        self.updated.pack(side="left")
        tk.Button(footer, text="⚙", command=self.open_settings, bg=BG, fg=MUTED, bd=0,
                  activebackground=BG, activeforeground=CYAN, font=("Segoe UI", 11)).pack(side="right")
        tk.Button(footer, text="↻", command=self.refresh_now, bg=BG, fg=MUTED, bd=0,
                  activebackground=BG, activeforeground=CYAN, font=("Segoe UI", 11)).pack(side="right", padx=5)
        self.user_toggle = tk.Button(footer, text="ПОЛЬЗОВАТЕЛИ", command=self.toggle_users_or_expand,
                                     bg=BG, fg=ORANGE, bd=0, activebackground=BG,
                                     activeforeground=TEXT, font=("Segoe UI Semibold", 8), cursor="hand2")
        self.user_toggle.pack(side="right", padx=8)

    def _tray_image(self) -> Image.Image:
        image = Image.new("RGBA", (64, 64), (16, 9, 15, 255))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((4, 4, 60, 60), radius=15, fill=(33, 16, 25, 255), outline=(255, 73, 61, 255), width=3)
        draw.line((18, 42, 32, 18, 46, 42), fill=(255, 152, 61, 255), width=6, joint="curve")
        draw.ellipse((27, 26, 37, 36), fill=(85, 230, 165, 255))
        return image

    def _start_tray(self) -> None:
        menu = pystray.Menu(
            pystray.MenuItem("Открыть", lambda: self.after(0, self.show_from_tray), default=True),
            pystray.MenuItem("Открыть мобильную web-панель", lambda: self.after(0, self.open_web_panel)),
            pystray.MenuItem("Обновить", lambda: self.after(0, self.refresh_now)),
            pystray.MenuItem("Проверить выходные IP", lambda: self.after(0, self.force_route_check)),
            pystray.MenuItem("Проверить DNS / IPv6", lambda: self.after(0, self.start_leak_test)),
            pystray.MenuItem("Журнал событий", lambda: self.after(0, self.show_event_log)),
            pystray.MenuItem("Устройства домашней сети", lambda: self.after(0, self.show_lan_devices)),
            pystray.MenuItem("Все известные устройства", lambda: self.after(0, self.show_known_devices)),
            pystray.MenuItem("Компактный режим", lambda: self.after(0, self.toggle_compact),
                             checked=lambda item: self.compact_mode),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Журнал sing-box", lambda: self.after(0, self.show_singbox_log)),
            pystray.MenuItem("Папка диагностики watchdog", lambda: self.after(0, self.open_diagnostics_folder)),
            pystray.MenuItem("Создать резервную копию", lambda: self.after(0, self.create_backup)),
            pystray.MenuItem("Открыть папку резервных копий", lambda: self.after(0, self.open_backup_folder)),
            pystray.MenuItem("Перезапустить sing-box…", lambda: self.after(0, self.request_singbox_restart)),
            pystray.MenuItem("Перезагрузить NX31…", lambda: self.after(0, self.request_router_reboot)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", lambda: self.after(0, self.exit_app)),
        )
        self.tray_icon = pystray.Icon("StarStackCascade", self._tray_image(), "StarStack Cascade Monitor", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _start_web_panel(self) -> None:
        if not self.config.get("web_enabled", True):
            return
        try:
            password = unprotect(self.config.get("web_password_dpapi", ""))
        except Exception:
            password = ""
        if not password:
            self.history.add_event("warning", "Web-панель не запущена: не задан отдельный пароль")
            return
        try:
            self.web_server = DashboardWebServer(
                int(self.config.get("web_port", 8765)),
                self.config.get("web_username", "starstack"),
                password,
                self._web_state,
            )
            self.web_server.start()
            domain = self.config.get("web_domain", "monitor.example.com")
            caddyfile = PROJECT_DIR / "Caddyfile"
            caddyfile.write_text(
                "{\n    admin off\n}\n\n"
                f"{domain} {{\n    encode gzip\n    reverse_proxy 127.0.0.1:{int(self.config.get('web_port', 8765))}\n"
                "    header {\n        -Server\n    }\n}\n", encoding="utf-8"
            )
            self.caddy = CaddyManager(
                PROJECT_DIR / "tools" / "caddy.exe", caddyfile, PROJECT_DIR / "logs" / "caddy.log"
            )
            if self.caddy.start():
                self.history.add_event("ok", f"Web-панель запущена: https://{domain}")
            else:
                self.history.add_event("warning", "Web backend запущен, но caddy.exe не найден")
        except Exception as exc:
            self.history.add_event("error", f"Web-панель не запущена: {exc}")
            if self.web_server:
                self.web_server.stop()
                self.web_server = None

    def restart_web_panel(self) -> None:
        if self.caddy:
            self.caddy.stop()
            self.caddy = None
        if self.web_server:
            self.web_server.stop()
            self.web_server = None
        self._start_web_panel()

    def open_web_panel(self) -> None:
        webbrowser.open("https://" + self.config.get("web_domain", "monitor.example.com"))

    def _web_state(self) -> dict:
        nodes = []
        for node in self._last_nodes:
            country, name = node_country_and_name(node.name)
            nodes.append({
                "name": name, "flag": "🇷🇺" if country == "ru" else "🇩🇪" if country == "de" else "◇",
                "online": bool(node.connected and not node.disabled),
                "latency": f"{node.latency_ms:.0f} мс" if node.latency_ms is not None else "—",
                "load": f"{node.load_1m:.2f}" if node.load_1m is not None else "—",
                "ram": f"{node.ram_percent:.0f}%" if node.ram_percent is not None else "—",
                "users": node.users_online, "traffic": node.traffic_bytes,
            })
        users = [{"name": user.username, "node": node_country_and_name(user.node_name)[1],
                  "device": user.device_label, "ip": user.request_ip or "—"} for user in self._last_users]
        devices = []
        for device in self._last_lan_devices:
            alias, trusted = self._device_metadata.get(device.mac, ("", False))
            rx_total, tx_total, rx_rate, tx_rate = self._device_traffic.get(device.mac, (0, 0, 0.0, 0.0))
            devices.append({
                "name": alias or device.hostname, "ip": device.ip or "—", "connection": device.connection,
                "signal": f"{device.signal_dbm} dBm" if device.signal_dbm is not None else "—",
                "state": device.state, "trusted": trusted, "blocked": device.mac in self._blocked_macs,
                "rx_total": rx_total, "tx_total": tx_total, "rx_rate": rx_rate, "tx_rate": tx_rate,
            })
        router_ok = self._last_router.online and self._last_router.singbox_running
        return {
            "updated": int(time.time()),
            "healthy": bool(router_ok and nodes and all(item["online"] for item in nodes)),
            "router": {"hostname": self._last_router.hostname or "NX31", "online": self._last_router.online,
                       "singbox": self._last_router.singbox_running,
                       "load": f"{self._last_router.load_1m:.2f}" if self._last_router.load_1m is not None else "—",
                       "ram": f"{self._last_router.ram_percent:.0f}%" if self._last_router.ram_percent is not None else "—",
                       "wan": self._last_router.wan_ip or "—"},
            "nodes": nodes, "users": users, "devices": devices,
            "routes": {"direct": self._last_route.direct_ip or "—", "moscow": self._last_route.moscow_ip or "—",
                       "germany": self._last_route.germany_ip or "—", "healthy": self._last_route.healthy},
        }

    def hide_to_tray(self) -> None:
        self.config["window_x"] = self.winfo_x()
        self.config["window_y"] = self.winfo_y()
        save_config(self.config)
        self.withdraw()

    def show_from_tray(self) -> None:
        self.deiconify()
        self.lift()
        self.attributes("-topmost", bool(self.config.get("always_on_top", True)))

    def toggle_users(self) -> None:
        self.users_expanded = not self.users_expanded
        self._render_nodes(self._last_nodes, self._last_api_ms, self._last_users, self._last_router,
                           self._last_route, self._last_remna_error)

    def toggle_users_or_expand(self) -> None:
        if self.compact_mode:
            self.toggle_compact()
        else:
            self.toggle_users()

    def toggle_compact(self) -> None:
        self.compact_mode = not self.compact_mode
        self.config["compact_mode"] = self.compact_mode
        save_config(self.config)
        self._render_nodes(self._last_nodes, self._last_api_ms, self._last_users, self._last_router,
                           self._last_route, self._last_remna_error)
        if self.tray_icon:
            self.tray_icon.update_menu()

    def _drag_start(self, event):
        self._drag_x, self._drag_y = event.x_root - self.winfo_x(), event.y_root - self.winfo_y()

    def _drag_move(self, event):
        self.geometry(f"+{event.x_root - self._drag_x}+{event.y_root - self._drag_y}")

    def open_settings(self):
        SettingsDialog(self)

    def refresh_now(self):
        if self._busy:
            return
        self._busy = True
        threading.Thread(target=self._fetch, daemon=True).start()

    def force_route_check(self) -> None:
        self._force_route_check = True
        self.history.add_event("info", "Запущена ручная проверка выходных IP")
        self.refresh_now()

    def _router_ssh_client(self) -> OpenWrtSshClient:
        router_url = self.config.get("router_url", "http://192.168.1.1")
        host = urlsplit(router_url if "://" in router_url else "http://" + router_url).hostname or "192.168.1.1"
        return OpenWrtSshClient(
            host,
            self.config.get("router_username", "root"),
            self.config.get("router_ssh_key", str(DEFAULT_ROUTER_KEY)),
            int(self.config.get("router_ssh_port", 22)),
        )

    def request_router_reboot(self) -> None:
        key = Path(self.config.get("router_ssh_key", str(DEFAULT_ROUTER_KEY)))
        if not key.exists():
            messagebox.showerror("SSH-ключ не найден", f"Не найден private key:\n{key}")
            return
        if not messagebox.askyesno(
            "Перезагрузить NX31?",
            "Интернет пропадёт примерно на 1–3 минуты.\n\nПерезагрузить роутер сейчас?",
            icon="warning",
        ):
            return
        threading.Thread(target=self._reboot_router_worker, daemon=True).start()

    def _reboot_router_worker(self) -> None:
        try:
            self._router_ssh_client().reboot()
            self.history.add_event("warning", "Отправлена команда перезагрузки NX31")
            self.after(0, lambda: self.tray_icon and self.tray_icon.notify(
                "Команда перезагрузки отправлена. Ожидается восстановление сети.", "NX31"
            ))
        except Exception as exc:
            self.after(0, lambda message=str(exc): messagebox.showerror("Не удалось перезагрузить NX31", message))

    def request_singbox_restart(self) -> None:
        if not messagebox.askyesno(
            "Перезапустить sing-box?",
            "VPN-соединения прервутся на несколько секунд.\n\nПерезапустить sing-box на NX31?",
            icon="warning",
        ):
            return
        threading.Thread(target=self._restart_singbox_worker, daemon=True).start()

    def _restart_singbox_worker(self) -> None:
        try:
            self._router_ssh_client().restart_singbox()
            self.history.add_event("warning", "sing-box на NX31 перезапущен пользователем")
            self.after(0, lambda: self.tray_icon and self.tray_icon.notify(
                "Сервис перезапущен", "sing-box"
            ))
            self.after(2500, self.refresh_now)
        except Exception as exc:
            self.history.add_event("error", f"Ошибка перезапуска sing-box: {exc}")
            self.after(0, lambda message=str(exc): messagebox.showerror("Не удалось перезапустить sing-box", message))

    def _watchdog_check(self, router: RouterSnapshot) -> None:
        if not self.config.get("watchdog_enabled", True):
            self._singbox_failures = 0
            return
        if not router.online:
            self._singbox_failures = 0
            return
        if router.singbox_running:
            self._singbox_failures = 0
            return
        self._singbox_failures += 1
        if self._singbox_failures < 3 or self._watchdog_recovering:
            return
        now = time.monotonic()
        self._watchdog_restarts = [stamp for stamp in self._watchdog_restarts if now - stamp < 3600]
        if self._watchdog_restarts and now - self._watchdog_restarts[-1] < 600:
            return
        if len(self._watchdog_restarts) >= 2:
            self.history.add_event("error", "Watchdog остановлен: достигнут лимит 2 перезапуска sing-box за час")
            return
        self._watchdog_recovering = True
        self._watchdog_restarts.append(now)
        self._singbox_failures = 0
        self.history.add_event("warning", "Watchdog: sing-box не работает 3 проверки, выполняется безопасный перезапуск")
        if self.tray_icon and self.config.get("notifications", True):
            self.tray_icon.notify("3 проверки подряд: сервис остановлен. Выполняю перезапуск.", "Watchdog sing-box")
        threading.Thread(target=self._watchdog_restart_worker, daemon=True).start()

    def _watchdog_restart_worker(self) -> None:
        error = ""
        try:
            client = self._router_ssh_client()
            diagnostics_folder = PROJECT_DIR / "diagnostics"
            diagnostics_folder.mkdir(parents=True, exist_ok=True)
            diagnostics_path = diagnostics_folder / f"watchdog-{time.strftime('%Y%m%d-%H%M%S')}.log"
            try:
                diagnostics_path.write_text(client.collect_singbox_diagnostics(), encoding="utf-8")
                self._protect_private_file(diagnostics_path)
                self.history.add_event("info", f"Watchdog: диагностика сохранена в {diagnostics_path.name}")
            except Exception as diagnostic_error:
                self.history.add_event("warning", f"Watchdog: не удалось сохранить диагностику: {diagnostic_error}")
            client.restart_singbox()
            self.history.add_event("ok", "Watchdog: команда перезапуска sing-box выполнена")
        except Exception as exc:
            error = str(exc)
            self.history.add_event("error", f"Watchdog: ошибка перезапуска sing-box: {error}")
        self.after(0, self._watchdog_restart_finished, error)

    def _watchdog_restart_finished(self, error: str) -> None:
        self._watchdog_recovering = False
        if self.tray_icon:
            self.tray_icon.notify(error or "Сервис перезапущен, состояние будет проверено автоматически.", "Watchdog sing-box")
        self.after(2500, self.refresh_now)

    def open_backup_folder(self) -> None:
        folder = PROJECT_DIR / "backups"
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(folder)

    def open_diagnostics_folder(self) -> None:
        folder = PROJECT_DIR / "diagnostics"
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(folder)

    @staticmethod
    def _protect_private_file(path: Path) -> None:
        current_user = os.environ.get("USERNAME") or os.getlogin()
        subprocess.run(
            ["icacls.exe", str(path), "/inheritance:r", "/grant:r", f"{current_user}:(F)", "SYSTEM:(F)"],
            capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=15,
        )

    def create_backup(self, manual: bool = True) -> None:
        if self._auto_backup_running:
            if manual and self.tray_icon:
                self.tray_icon.notify("Резервная копия уже создаётся", "StarStack")
            return
        self._auto_backup_running = True
        threading.Thread(target=self._backup_worker, args=(manual,), daemon=True).start()

    def _backup_worker(self, manual: bool = True) -> None:
        folder = PROJECT_DIR / "backups"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        destination = folder / f"StarStack-backup-{stamp}.zip"
        try:
            router_backup = self._router_ssh_client().create_system_backup()
            singbox_config = self._router_ssh_client().read_singbox_config()
            with tempfile.TemporaryDirectory(prefix="starstack-backup-") as temp_name:
                history_copy = Path(temp_name) / "history.db"
                self.history.backup_to(history_copy)
                manifest = {
                    "created": time.strftime("%Y-%m-%d %H:%M:%S %z"),
                    "router": self._last_router.hostname or "NX31",
                    "wan_ip": self._last_router.wan_ip,
                    "contents": ["openwrt-backup.tar.gz", "sing-box-config.json", "history.db", "config.local.json"],
                }
                with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("openwrt-backup.tar.gz", router_backup)
                    archive.writestr("sing-box-config.json", singbox_config)
                    archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
                    archive.write(history_copy, "history.db")
                    if CONFIG_PATH.exists():
                        archive.write(CONFIG_PATH, "config.local.json")
            self._protect_private_file(destination)
            archives = sorted(folder.glob("StarStack-backup-*.zip"), key=lambda item: item.stat().st_mtime, reverse=True)
            for old_archive in archives[5:]:
                old_archive.unlink(missing_ok=True)
            kind = "Автоматическая" if not manual else "Ручная"
            self.history.add_event("ok", f"{kind} резервная копия создана: {destination.name}")
            self.after(0, lambda: self.tray_icon and self.tray_icon.notify(destination.name, "Резервная копия готова"))
        except Exception as exc:
            self.history.add_event("error", f"Ошибка резервного копирования: {exc}")
            if manual:
                self.after(0, lambda message=str(exc): messagebox.showerror("Не удалось создать резервную копию", message))
        finally:
            self._auto_backup_running = False

    def _auto_backup_check(self, router: RouterSnapshot) -> None:
        if not self.config.get("auto_backup_enabled", True) or not router.online or not router.singbox_running:
            return
        now = time.monotonic()
        if self._auto_backup_running or now - self._last_auto_backup_check < 3600:
            return
        self._last_auto_backup_check = now
        folder = PROJECT_DIR / "backups"
        archives = list(folder.glob("StarStack-backup-*.zip")) if folder.exists() else []
        newest = max((item.stat().st_mtime for item in archives), default=0)
        if time.time() - newest >= 7 * 86400:
            self.create_backup(manual=False)

    def show_lan_devices(self) -> None:
        threading.Thread(target=self._load_lan_devices, daemon=True).start()

    def _load_lan_devices(self) -> None:
        try:
            client = self._router_ssh_client()
            devices = client.get_lan_devices()
            self._blocked_macs = client.blocked_macs()
            error = ""
        except Exception as exc:
            devices, error = [], str(exc)
        self.after(0, self._show_lan_window, devices, error)

    def _show_lan_window(self, devices: list[LanDevice], error: str = "") -> None:
        self._last_lan_devices = devices
        if self._lan_window and self._lan_window.winfo_exists():
            self._lan_window.destroy()
        window = tk.Toplevel(self)
        self._lan_window = window
        window.title("Устройства домашней сети — NX31")
        window.geometry("1230x410")
        window.configure(bg=BG)
        header = ttk.Frame(window)
        header.pack(fill="x", padx=12, pady=(12, 7))
        ttk.Label(header, text=f"Устройства NX31: {len(devices)}" if not error else error).pack(side="left")
        ttk.Button(header, text="Обновить", command=self.show_lan_devices).pack(side="right")
        ttk.Button(header, text="Все известные", command=self.show_known_devices).pack(side="right", padx=6)
        columns = ("name", "ip", "mac", "connection", "signal", "speed", "now", "today", "month", "state")
        tree = ttk.Treeview(window, columns=columns, show="headings", height=13)
        self._lan_tree = tree
        labels = {"name": "Устройство", "ip": "IP", "mac": "MAC", "connection": "Подключение",
                  "signal": "Сигнал", "speed": "Линк RX / TX", "now": "Сейчас ↓ / ↑",
                  "today": "Сегодня ↓ / ↑", "month": "Месяц ↓ / ↑", "state": "Состояние"}
        widths = {"name": 150, "ip": 105, "mac": 125, "connection": 100, "signal": 65,
                  "speed": 125, "now": 140, "today": 135, "month": 145, "state": 80}
        for column in columns:
            tree.heading(column, text=labels[column])
            tree.column(column, width=widths[column], anchor="w")
        for device in devices:
            tree.insert("", "end", iid=device.mac, values=self._lan_device_values(device))
        tree.bind("<Button-3>", self._show_lan_device_menu)
        tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _lan_device_values(self, device: LanDevice) -> tuple:
        alias, trusted = self._device_metadata.get(device.mac, ("", False))
        display_name = alias or device.hostname
        if trusted:
            display_name = "✓ " + display_name
        signal = f"{device.signal_dbm} dBm" if device.signal_dbm is not None else "—"
        speed = "—" if device.rx_mbps is None else f"{device.rx_mbps:.1f} / {device.tx_mbps:.1f} Мбит/с"
        rx_total, tx_total, rx_rate, tx_rate = self._device_traffic.get(device.mac, (0, 0, 0.0, 0.0))
        current = f"{human_rate(rx_rate)} / {human_rate(tx_rate)}" if rx_total or tx_total else "ожидание данных"
        local_now = time.localtime()
        day_start = int(time.mktime((local_now.tm_year, local_now.tm_mon, local_now.tm_mday, 0, 0, 0, 0, 0, -1)))
        day_rx, day_tx = self.history.device_usage_since(device.mac, day_start)
        today = f"{human_bytes(day_rx)} / {human_bytes(day_tx)}" if day_rx or day_tx else "—"
        month = f"{human_bytes(rx_total)} / {human_bytes(tx_total)}" if rx_total or tx_total else "—"
        state = "BLOCKED" if device.mac in self._blocked_macs else device.state
        return (display_name, device.ip or "—", device.mac, device.connection, signal, speed,
                current, today, month, state)

    def _refresh_lan_tree_values(self) -> None:
        if not self._lan_tree or not self._lan_window or not self._lan_window.winfo_exists():
            return
        for device in self._last_lan_devices:
            if self._lan_tree.exists(device.mac):
                self._lan_tree.item(device.mac, values=self._lan_device_values(device))

    def _show_lan_device_menu(self, event) -> None:
        if not self._lan_tree:
            return
        item_id = self._lan_tree.identify_row(event.y)
        if not item_id:
            return
        self._lan_tree.selection_set(item_id)
        device = next((item for item in self._last_lan_devices if item.mac == item_id), None)
        if not device:
            return
        alias, trusted = self._device_metadata.get(device.mac, ("", False))
        blocked = device.mac in self._blocked_macs
        menu = tk.Menu(self, tearoff=False, bg=CARD_ALT, fg=TEXT, activebackground=RED,
                       activeforeground=TEXT, bd=0, font=("Segoe UI", 9))
        menu.add_command(label="Переименовать…", command=lambda: self.rename_lan_device(device))
        menu.add_command(label="Убрать из доверенных" if trusted else "Отметить доверенным",
                         command=lambda: self.toggle_lan_device_trusted(device, not trusted))
        menu.add_separator()
        menu.add_command(label="График трафика — 24 часа", command=lambda: self.show_device_graph(device, 86400))
        menu.add_command(label="График трафика — 7 дней", command=lambda: self.show_device_graph(device, 7 * 86400))
        menu.add_command(label="История подключений", command=lambda: self.show_device_history(device))
        menu.add_separator()
        menu.add_command(label="Разблокировать на NX31" if blocked else "Заблокировать на NX31…",
                         command=lambda: self.request_device_block(device, not blocked))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def rename_lan_device(self, device: LanDevice) -> None:
        alias, _ = self._device_metadata.get(device.mac, ("", False))
        value = simpledialog.askstring("Имя устройства", f"Имя для {device.mac}:", initialvalue=alias or device.hostname,
                                       parent=self)
        if value is None:
            return
        self.history.set_device_alias(device.mac, value)
        self._device_metadata = self.history.device_metadata()
        self._refresh_lan_tree_values()

    def toggle_lan_device_trusted(self, device: LanDevice, trusted: bool) -> None:
        self.history.set_device_trusted(device.mac, trusted)
        self._device_metadata = self.history.device_metadata()
        self.history.add_event("info", f"{device.mac}: {'доверенное устройство' if trusted else 'метка доверия снята'}")
        self._refresh_lan_tree_values()

    def request_device_block(self, device: LanDevice, block: bool) -> None:
        try:
            local_ips = {info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
        except OSError:
            local_ips = set()
        if block and device.ip in local_ips:
            messagebox.showerror("Блокировка запрещена", "Нельзя заблокировать компьютер, на котором запущен монитор.")
            return
        action = "заблокировать" if block else "разблокировать"
        warning = ("Устройство потеряет доступ к интернету и интерфейсу роутера.\n\n" if block else "")
        if not messagebox.askyesno(f"{action.capitalize()} устройство?",
                                   f"{device.hostname}\n{device.ip} · {device.mac}\n\n{warning}{action.capitalize()} сейчас?",
                                   icon="warning" if block else "question"):
            return
        threading.Thread(target=self._device_block_worker, args=(device, block), daemon=True).start()

    def _device_block_worker(self, device: LanDevice, block: bool) -> None:
        try:
            client = self._router_ssh_client()
            client.block_device(device.mac) if block else client.unblock_device(device.mac)
            error = ""
        except Exception as exc:
            error = str(exc)
        self.after(0, self._finish_device_block, device, block, error)

    def _finish_device_block(self, device: LanDevice, block: bool, error: str) -> None:
        if error:
            self.history.add_event("error", f"Ошибка изменения блокировки {device.mac}: {error}")
            messagebox.showerror("NX31", error)
            return
        if block:
            self._blocked_macs.add(device.mac)
        else:
            self._blocked_macs.discard(device.mac)
        action = "заблокировано" if block else "разблокировано"
        self.history.add_event("warning" if block else "ok", f"Устройство {device.hostname} ({device.mac}) {action}")
        self._refresh_lan_tree_values()

    def show_device_history(self, device: LanDevice) -> None:
        event_names = {"first_seen": "обнаружено впервые", "connected": "подключилось", "disconnected": "отключилось"}
        lines = [f"{device.hostname} · {device.mac}", ""]
        for timestamp, event, hostname, ip in self.history.device_events(device.mac):
            stamp = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime(timestamp))
            lines.append(f"{stamp}  {event_names.get(event, event)}  {ip or ''}")
        self._show_text_window("История устройства", "\n".join(lines) if len(lines) > 2 else "История пока пуста")

    def show_known_devices(self) -> None:
        rows = self.history.known_devices()
        lines = ["Все устройства, которые видел NX31", ""]
        for mac, alias, hostname, first_seen, last_seen, present, trusted in rows:
            name = alias or hostname or "Неизвестное устройство"
            marks = ("✓ доверенное" if trusted else "не доверенное") + (" · сейчас в сети" if present else " · не в сети")
            lines.append(f"{name}\n  {mac} · {marks}")
            lines.append(f"  впервые: {time.strftime('%d.%m.%Y %H:%M', time.localtime(first_seen))}"
                         f" · последний раз: {time.strftime('%d.%m.%Y %H:%M', time.localtime(last_seen))}\n")
        self._show_text_window("Известные устройства NX31", "\n".join(lines) if rows else "Устройства ещё не обнаружены")

    def show_device_graph(self, device: LanDevice, seconds: int) -> None:
        series = self.history.device_rate_series(device.mac, seconds)
        window = tk.Toplevel(self)
        window.title(f"Трафик — {device.hostname}")
        window.geometry("820x390")
        window.configure(bg=BG)
        tk.Label(window, text=f"{device.hostname} · {device.mac} · {'7 дней' if seconds > 86400 else '24 часа'}",
                 bg=BG, fg=TEXT, font=("Segoe UI Semibold", 11)).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(window, text="↓ загрузка     ↑ отдача", bg=BG, fg=CYAN,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=16)
        canvas = tk.Canvas(window, bg="#0b070a", highlightthickness=0, width=780, height=290)
        canvas.pack(fill="both", expand=True, padx=16, pady=12)
        if len(series) < 2:
            canvas.create_text(390, 140, text="Недостаточно данных — график заполнится со временем",
                               fill=MUTED, font=("Segoe UI", 10))
            return
        width, height, pad = 780, 290, 35
        maximum = max(0.1, max(max(rx, tx) for _, rx, tx in series))
        canvas.create_line(pad, height - pad, width - 10, height - pad, fill="#563342")
        canvas.create_line(pad, 10, pad, height - pad, fill="#563342")
        canvas.create_text(5, 12, text=f"{maximum:.1f}\nМбит/с", fill=MUTED, anchor="nw", font=("Segoe UI", 7))
        for value_index, color in ((1, CYAN), (2, PURPLE)):
            points: list[float] = []
            for index, item in enumerate(series):
                x = pad + index * (width - pad - 12) / max(1, len(series) - 1)
                y = height - pad - item[value_index] / maximum * (height - pad - 15)
                points.extend((x, y))
            canvas.create_line(*points, fill=color, width=2, smooth=True)

    def show_singbox_log(self) -> None:
        threading.Thread(target=self._load_singbox_log, daemon=True).start()

    def _load_singbox_log(self) -> None:
        try:
            content = self._router_ssh_client().read_singbox_log(160)
        except Exception as exc:
            content = "Не удалось прочитать журнал:\n" + str(exc)
        self.after(0, self._show_text_window, "Журнал sing-box — NX31", content)

    def _show_text_window(self, title: str, content: str) -> None:
        if self._log_window and self._log_window.winfo_exists():
            self._log_window.destroy()
        window = tk.Toplevel(self)
        self._log_window = window
        window.title(title)
        window.geometry("820x480")
        window.configure(bg=BG)
        text_widget = tk.Text(window, bg="#0b070a", fg=TEXT, insertbackground=TEXT,
                              font=("Consolas", 9), wrap="none", bd=0, padx=10, pady=10)
        scroll_y = ttk.Scrollbar(window, orient="vertical", command=text_widget.yview)
        scroll_x = ttk.Scrollbar(window, orient="horizontal", command=text_widget.xview)
        text_widget.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        text_widget.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        text_widget.insert("1.0", content or "Журнал пуст")
        text_widget.configure(state="disabled")
        buttons = ttk.Frame(window)
        buttons.grid(row=2, column=0, columnspan=2, sticky="e", padx=9, pady=8)
        ttk.Button(buttons, text="Копировать", command=lambda: (
            window.clipboard_clear(), window.clipboard_append(content)
        )).pack(side="left", padx=4)
        ttk.Button(buttons, text="Закрыть", command=window.destroy).pack(side="left", padx=4)
        window.rowconfigure(0, weight=1)
        window.columnconfigure(0, weight=1)

    def show_event_log(self) -> None:
        level_icons = {"info": "·", "warning": "!", "error": "✕", "ok": "✓"}
        lines = []
        for timestamp, level, message in self.history.recent_events():
            stamp = time.strftime("%d.%m %H:%M:%S", time.localtime(timestamp))
            lines.append(f"{stamp}  {level_icons.get(level, '·')}  {message}")
        self._show_text_window("Журнал событий — StarStack Cascade", "\n".join(lines) or "Событий пока нет")

    def start_leak_test(self) -> None:
        if self._leak_running:
            return
        self._leak_running = True
        self.history.add_event("info", "Запущена проверка DNS / IPv6")
        threading.Thread(target=self._leak_test_worker, daemon=True).start()

    def _leak_test_worker(self) -> None:
        result = run_leak_test(self._last_router.wan_ip)
        self.after(0, self._finish_leak_test, result)

    def _finish_leak_test(self, result: LeakTestResult) -> None:
        self._leak_running = False
        self._last_leak = result
        if result.error:
            level, summary = "error", "Ошибка DNS/IPv6 теста: " + result.error
        elif result.safe:
            level, summary = "ok", "DNS resolver безопасен, публичный IPv6 не обнаружен"
        else:
            level, summary = "warning", "Возможна DNS или IPv6 утечка"
        self.history.add_event(level, summary)
        lines = [f"Внешний IP: {result.public_ip or 'не определён'}", "", "DNS resolvers:"]
        if result.resolvers:
            lines.extend(f"  {resolver.ip}  •  {resolver.country or '—'}  •  {resolver.asn or '—'}" for resolver in result.resolvers)
        else:
            lines.append("  не обнаружены")
        lines.extend(["", f"IPv6: {result.ipv6_ip or 'не обнаружен'}", "", summary])
        self._show_text_window("Проверка DNS / IPv6", "\n".join(lines))
        self._render_nodes(self._last_nodes, self._last_api_ms, self._last_users, self._last_router,
                           self._last_route, self._last_remna_error)
        if self.tray_icon:
            self.tray_icon.notify(summary, "DNS / IPv6")

    def _fetch(self):
        nodes: list[NodeSnapshot] = []
        users: list[OnlineUser] = []
        api_ms = 0.0
        remna_error = ""
        try:
            token = unprotect(self.config.get("token_dpapi", ""))
            access_query = {}
            encrypted_query = self.config.get("access_query_dpapi", "")
            if encrypted_query:
                access_query = json.loads(unprotect(encrypted_query))
            elif self.config.get("access_query"):
                access_query = self.config["access_query"]
            client = RemnawaveClient(self.config.get("panel_url", ""), token, access_query)
            nodes, api_ms = client.get_nodes()
            with ThreadPoolExecutor(max_workers=4) as pool:
                latencies = list(pool.map(lambda n: tcp_latency(n.address, n.port), nodes))
            for node, latency in zip(nodes, latencies):
                node.latency_ms = latency
            users = client.get_online_users(nodes)
        except Exception as exc:
            remna_error = str(exc)

        router_password = ""
        try:
            router_password = unprotect(self.config.get("router_password_dpapi", ""))
        except Exception:
            pass
        key_path = Path(self.config.get("router_ssh_key", str(DEFAULT_ROUTER_KEY)))
        router = self._router_ssh_client().snapshot() if key_path.exists() else RouterSnapshot(
            configured=False, error="SSH-ключ NX31 не найден"
        )
        if not router.online and router_password:
            router = OpenWrtClient(
                self.config.get("router_url", "http://192.168.1.1"),
                self.config.get("router_username", "root"),
                router_password,
            ).snapshot()
        device_totals: dict[str, tuple[int, int]] = {}
        lan_devices: list[LanDevice] = []
        blocked_macs: set[str] = set()
        if router.online and key_path.exists():
            try:
                ssh_client = self._router_ssh_client()
                device_totals = ssh_client.get_device_traffic()
                lan_devices = ssh_client.get_lan_devices()
                blocked_macs = ssh_client.blocked_macs()
            except Exception:
                pass
        route = self._last_route
        if self._force_route_check or not self._last_route_check or time.monotonic() - self._last_route_check >= 300:
            route = check_routes(router.wan_ip)
            self._last_route_check = time.monotonic()
            self._force_route_check = False
        self._queue.put((nodes, users, api_ms, router, route, remna_error,
                         device_totals, lan_devices, blocked_macs))

    def _poll_result(self):
        try:
            nodes, users, api_ms, router, route, error, device_totals, lan_devices, blocked_macs = self._queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_result)
            return
        self._busy = False
        if lan_devices:
            self._last_lan_devices = lan_devices
            self._blocked_macs = blocked_macs
            self._observe_lan_devices(lan_devices)
        self._update_device_traffic(device_totals)
        self.history.record_device_traffic(device_totals)
        self.history.record(router, nodes)
        self._render_nodes(nodes, api_ms, users, router, route, error)
        self._watchdog_check(router)
        self._auto_backup_check(router)
        self._refresh_lan_tree_values()
        self.after(int(self.config.get("refresh_seconds", 10)) * 1000, self.refresh_now)
        self.after(100, self._poll_result)

    def _update_device_traffic(self, totals: dict[str, tuple[int, int]]) -> None:
        now = time.monotonic()
        updated: dict[str, tuple[int, int, float, float]] = {}
        for mac, (rx_total, tx_total) in totals.items():
            previous = self._last_device_totals.get(mac)
            rx_rate = tx_rate = 0.0
            if previous:
                old_rx, old_tx, old_time = previous
                elapsed = max(0.1, now - old_time)
                if rx_total >= old_rx:
                    rx_rate = (rx_total - old_rx) / elapsed
                if tx_total >= old_tx:
                    tx_rate = (tx_total - old_tx) / elapsed
            updated[mac] = (rx_total, tx_total, rx_rate, tx_rate)
            self._last_device_totals[mac] = (rx_total, tx_total, now)
        self._device_traffic = updated

    def _observe_lan_devices(self, devices: list[LanDevice]) -> None:
        changes = self.history.observe_devices(devices)
        self._device_metadata = self.history.device_metadata()
        for mac, name in changes["new"]:
            message = f"Новое устройство в сети: {name} ({mac})"
            self.history.add_event("warning", message)
            if self.tray_icon and self.config.get("notifications", True):
                self.tray_icon.notify(message, "NX31 — новое устройство")
        for mac, name in changes["connected"]:
            self.history.add_event("info", f"Устройство подключилось: {name} ({mac})")
        for mac, name in changes["disconnected"]:
            self.history.add_event("info", f"Устройство отключилось: {name} ({mac})")

    def _render_error(self, error: str):
        for child in self.body.winfo_children():
            child.destroy()
        self.overall.configure(text="● ОШИБКА", fg=RED)
        self.message = tk.Label(self.body, text=error, bg=CARD, fg=RED, font=("Segoe UI", 9),
                                justify="left", wraplength=345, padx=12, pady=14)
        self.message.pack(fill="x", pady=4)
        self.updated.configure(text=time.strftime("Ошибка: %H:%M:%S"))
        self.geometry(f"420x150+{self.winfo_x()}+{self.winfo_y()}")

    def _render_nodes(self, nodes: list[NodeSnapshot], api_ms: float, users: list[OnlineUser],
                      router: RouterSnapshot, route: RouteSnapshot, remna_error: str = ""):
        self._last_nodes, self._last_users, self._last_api_ms = nodes, users, api_ms
        self._last_router, self._last_remna_error = router, remna_error
        self._last_route = route
        for child in self.body.winfo_children():
            child.destroy()
        now = time.monotonic()
        connected = sum(1 for n in nodes if n.connected and not n.disabled)
        all_ok = router.online and router.singbox_running and bool(nodes) and connected == len(nodes)
        self.overall.configure(text="● КАСКАД OK" if all_ok else "● НУЖНА ПРОВЕРКА", fg=GREEN if all_ok else RED)
        self._cascade_strip(router, nodes)
        self._route_card(route)
        self._router_card(router)
        if self.compact_mode:
            self.user_toggle.configure(text="РАЗВЕРНУТЬ")
            self.updated.configure(text=f"обновлено {time.strftime('%H:%M:%S')}")
            self.geometry(f"420x265+{self.winfo_x()}+{self.winfo_y()}")
            self._notify_changes(router, nodes, users, route)
            return
        if remna_error:
            tk.Label(self.body, text=f"Remnawave: {remna_error}", bg=CARD, fg=RED,
                     font=("Segoe UI", 8), wraplength=370, padx=10, pady=8).pack(fill="x", pady=3)
        elif not nodes:
            tk.Label(self.body, text="Ноды не найдены", bg=CARD, fg=MUTED, padx=12, pady=10).pack(fill="x", pady=3)
        for node in nodes:
            previous = self._last_traffic.get(node.uuid)
            rate = None
            if previous and node.traffic_bytes >= previous[0]:
                elapsed = max(0.1, now - previous[1])
                rate = (node.traffic_bytes - previous[0]) / elapsed
            self._last_traffic[node.uuid] = (node.traffic_bytes, now)
            self._node_card(node, rate)
        self._users_section(users)
        self.user_toggle.configure(text=f"ПОЛЬЗОВАТЕЛИ {len(users)}  {'▴' if self.users_expanded else '▾'}")
        self.updated.configure(text=f"API {api_ms:.0f} мс  •  обновлено {time.strftime('%H:%M:%S')}")
        users_height = (37 + min(len(users), 6) * 52) if self.users_expanded else 0
        error_height = 45 if remna_error or not nodes else 0
        speed_height = sum(21 for node in nodes if node.uuid in self._speed_testing or node.uuid in self._speed_results)
        height = 285 + len(nodes) * 101 + users_height + error_height + speed_height
        self.geometry(f"420x{height}+{self.winfo_x()}+{self.winfo_y()}")
        self._notify_changes(router, nodes, users, route)

    def _cascade_strip(self, router: RouterSnapshot, nodes: list[NodeSnapshot]) -> None:
        row = tk.Frame(self.body, bg=HEADER, padx=8, pady=9)
        row.pack(fill="x", pady=(5, 3))
        moscow = next((n for n in nodes if "mos" in n.name.lower() or n.name.lower().startswith("ru")), None)
        germany = next((n for n in nodes if "ger" in n.name.lower() or n.name.lower().startswith("de")), None)
        points = [
            ("NX31", router.online and router.singbox_running, None),
            ("MOSCOW", bool(moscow and moscow.connected and not moscow.disabled), "ru"),
            ("GERMANY", bool(germany and germany.connected and not germany.disabled), "de"),
        ]
        for index, (name, ok, country) in enumerate(points):
            if index:
                tk.Label(row, text="━━▶", bg=HEADER, fg=ORANGE if ok else MUTED,
                         font=("Consolas", 8)).pack(side="left", expand=True)
            box = tk.Frame(row, bg=CARD_ALT, padx=8, pady=5)
            box.pack(side="left")
            tk.Label(box, text="●", bg=CARD_ALT, fg=GREEN if ok else RED,
                     font=("Segoe UI", 8)).pack(side="left")
            flag = self._flag_image(country) if country else None
            tk.Label(box, text=name, image=flag, compound="left", bg=CARD_ALT, fg=TEXT,
                     font=("Segoe UI Semibold", 7)).pack(side="left", padx=(3, 0))

    def _flag_image(self, country: str | None) -> ImageTk.PhotoImage | None:
        if not country:
            return None
        if country in self._flag_images:
            return self._flag_images[country]
        image = Image.new("RGB", (24, 15), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        if country == "de":
            draw.rectangle((0, 0, 23, 4), fill=(25, 25, 25))
            draw.rectangle((0, 5, 23, 9), fill=(210, 20, 42))
            draw.rectangle((0, 10, 23, 14), fill=(255, 206, 0))
        else:
            draw.rectangle((0, 0, 23, 4), fill=(255, 255, 255))
            draw.rectangle((0, 5, 23, 9), fill=(0, 87, 184))
            draw.rectangle((0, 10, 23, 14), fill=(213, 43, 30))
        draw.rectangle((0, 0, 23, 14), outline=(95, 72, 79))
        result = ImageTk.PhotoImage(image)
        self._flag_images[country] = result
        return result

    def _route_card(self, route: RouteSnapshot) -> None:
        card = tk.Frame(self.body, bg=HEADER, padx=9, pady=7)
        card.pack(fill="x", pady=3)
        status = "МАРШРУТЫ OK" if route.healthy else "ПРОВЕРКА МАРШРУТОВ"
        if self._last_leak:
            status += "   •   DNS/IPv6 " + ("OK" if self._last_leak.safe else "CHECK")
        tk.Label(card, text=status, bg=HEADER, fg=GREEN if route.healthy else RED,
                 font=("Segoe UI Semibold", 7)).pack(anchor="w")
        if route.error:
            value = "Ошибка проверки: " + route.error
        else:
            value = f"DIRECT {route.direct_ip or '—'}   •   MOSCOW {route.moscow_ip or '—'}   •   GERMANY {route.germany_ip or '—'}"
        tk.Label(card, text=value, bg=HEADER, fg=CYAN if route.healthy else MUTED,
                 font=("Consolas", 7), wraplength=380, justify="left").pack(anchor="w", pady=(3, 0))
        self._bind_route_context(card)

    def _bind_route_context(self, widget: tk.Widget) -> None:
        widget.bind("<Button-3>", self._show_route_menu)
        for child in widget.winfo_children():
            self._bind_route_context(child)

    def _show_route_menu(self, event) -> None:
        menu = tk.Menu(self, tearoff=False, bg=CARD_ALT, fg=TEXT, activebackground=RED,
                       activeforeground=TEXT, bd=0, font=("Segoe UI", 9))
        menu.add_command(label="Проверить выходные IP", command=self.force_route_check)
        menu.add_command(label="Проверить DNS / IPv6", command=self.start_leak_test,
                         state="disabled" if self._leak_running else "normal")
        menu.add_command(label="Журнал событий", command=self.show_event_log)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _sparkline(self, parent: tk.Widget, values: list[float], row: int, column: int) -> None:
        canvas = tk.Canvas(parent, width=78, height=24, bg=CARD, highlightthickness=0)
        canvas.grid(row=row, column=column, sticky="e", padx=(6, 0))
        if len(values) < 2:
            canvas.create_text(39, 12, text="история 1ч", fill=MUTED, font=("Segoe UI", 6))
            return
        width, height = 76, 22
        points = []
        for index, value in enumerate(values):
            x = 1 + index * (width - 2) / max(1, len(values) - 1)
            y = height - 1 - max(0, min(100, value)) / 100 * (height - 3)
            points.extend((x, y))
        canvas.create_line(*points, fill=ORANGE, width=2, smooth=True)
        canvas.create_text(4, 3, text="RAM 1ч", fill=MUTED, font=("Segoe UI", 5), anchor="nw")

    def _router_card(self, router: RouterSnapshot) -> None:
        card = tk.Frame(self.body, bg=CARD, padx=11, pady=8)
        card.pack(fill="x", pady=3)
        status = "ONLINE" if router.online else "НЕ НАСТРОЕН" if not router.configured else "OFFLINE"
        tk.Label(card, text=f"▰  {router.hostname or 'NX31'}", bg=CARD, fg=TEXT,
                 font=("Segoe UI Semibold", 9)).grid(row=0, column=0, sticky="w")
        tk.Label(card, text=status, bg=CARD, fg=GREEN if router.online else RED,
                 font=("Segoe UI Semibold", 8)).grid(row=0, column=1, sticky="e")
        if router.online:
            load = f"Load {router.load_1m:.2f}" if router.load_1m is not None else "Load —"
            ram = f"RAM {router.ram_percent:.0f}%" if router.ram_percent is not None else "RAM —"
            service = "sing-box ●" if router.singbox_running else "sing-box ✕"
            watchdog = "WD ●" if self.config.get("watchdog_enabled", True) else "WD OFF"
            detail = f"{router.access_method or 'LuCI'}   •   {service}   •   {watchdog}   •   {load}   •   {ram}"
            wan_detail = f"WAN {router.wan_device or '—'}   •   {router.wan_ip or '—'}"
        else:
            detail = router.error or "NX31 недоступен"
            wan_detail = "ПКМ → управление роутером"
        tk.Label(card, text=detail, bg=CARD, fg=CYAN if router.online else MUTED,
                 font=("Segoe UI", 8)).grid(row=1, column=0, sticky="w", pady=(4, 0))
        tk.Label(card, text=wan_detail, bg=CARD, fg=MUTED,
                 font=("Segoe UI", 8)).grid(row=2, column=0, sticky="w", pady=(3, 0))
        self._sparkline(card, self.history.values("router", "NX31"), 1, 1)
        card.columnconfigure(0, weight=1)
        self._bind_router_context(card)

    def _bind_router_context(self, widget: tk.Widget) -> None:
        widget.bind("<Button-3>", self._show_router_menu)
        for child in widget.winfo_children():
            self._bind_router_context(child)

    def _show_router_menu(self, event) -> None:
        menu = tk.Menu(self, tearoff=False, bg=CARD_ALT, fg=TEXT, activebackground=RED,
                       activeforeground=TEXT, bd=0, font=("Segoe UI", 9))
        menu.add_command(label="Перезапустить sing-box…", command=self.request_singbox_restart)
        menu.add_command(label="Журнал sing-box", command=self.show_singbox_log)
        menu.add_command(label="Папка диагностики watchdog", command=self.open_diagnostics_folder)
        menu.add_command(label="Устройства домашней сети", command=self.show_lan_devices)
        menu.add_command(label="Создать резервную копию", command=self.create_backup)
        menu.add_command(label="Открыть папку резервных копий", command=self.open_backup_folder)
        menu.add_separator()
        menu.add_command(label="Перезагрузить NX31…", command=self.request_router_reboot)
        menu.add_command(label="Проверить выходные IP", command=self.force_route_check)
        menu.add_separator()
        menu.add_command(label="Открыть LuCI", command=lambda: webbrowser.open(
            self.config.get("router_url", "http://192.168.1.1")
        ))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _notify_changes(self, router: RouterSnapshot, nodes: list[NodeSnapshot], users: list[OnlineUser],
                        route: RouteSnapshot) -> None:
        health = {"NX31": router.online and router.singbox_running}
        health.update({node_country_and_name(node.name)[1]: node.connected and not node.disabled for node in nodes})
        current_users = {user.username for user in users}
        if self._previous_health is not None:
            for name, ok in health.items():
                before = self._previous_health.get(name)
                if before is not None and before != ok:
                    message = f"{name}: {'восстановлено' if ok else 'соединение потеряно'}"
                    self.history.add_event("ok" if ok else "error", message)
                    if self.tray_icon and self.config.get("notifications", True):
                        self.tray_icon.notify(message, "StarStack Cascade")
        if self._previous_users is not None:
            newcomers = current_users - self._previous_users
            if newcomers:
                message = "Подключились: " + ", ".join(sorted(newcomers))
                self.history.add_event("info", message)
                if self.tray_icon and self.config.get("notifications", True):
                    self.tray_icon.notify(message, "Новые подключения")
        current_routes = (route.direct_ip, route.moscow_ip, route.germany_ip)
        if self._previous_routes is not None and current_routes != self._previous_routes and route.healthy:
            self.history.add_event("warning", "Изменились выходные IP каскада")
            if self.tray_icon and self.config.get("notifications", True):
                self.tray_icon.notify("Изменились выходные IP каскада", "Проверка маршрутов")
        active_thresholds: dict[str, str] = {}
        ram_limit = float(self.config.get("ram_warn_percent", 85))
        latency_limit = float(self.config.get("latency_warn_ms", 150))
        if router.ram_percent is not None and router.ram_percent >= ram_limit:
            active_thresholds["ram:NX31"] = f"NX31: RAM {router.ram_percent:.0f}%"
        for node in nodes:
            name = node_country_and_name(node.name)[1]
            if node.ram_percent is not None and node.ram_percent >= ram_limit:
                active_thresholds[f"ram:{node.uuid}"] = f"{name}: RAM {node.ram_percent:.0f}%"
            if node.latency_ms is not None and node.latency_ms >= latency_limit:
                active_thresholds[f"latency:{node.uuid}"] = f"{name}: задержка {node.latency_ms:.0f} мс"
        if self._previous_routes is not None and not route.healthy:
            active_thresholds["routes"] = "Выходные IP каскада не подтверждены"
        for key in set(active_thresholds) - self._threshold_active:
            self.history.add_event("warning", active_thresholds[key])
            if self.config.get("notifications", True) and self.tray_icon:
                self.tray_icon.notify(active_thresholds[key], "Предупреждение каскада")
        for key in self._threshold_active - set(active_thresholds):
            message = key.split(":")[-1] + ": показатель нормализовался"
            self.history.add_event("ok", message)
            if self.config.get("notifications", True) and self.tray_icon:
                self.tray_icon.notify(message, "Каскад восстановлен")
        self._threshold_active = set(active_thresholds)
        self._previous_routes = current_routes
        self._previous_health, self._previous_users = health, current_users

    def _users_section(self, users: list[OnlineUser]) -> None:
        if not self.users_expanded:
            return
        title = tk.Frame(self.body, bg=BG)
        title.pack(fill="x", pady=(8, 2))
        tk.Label(title, text="ПОДКЛЮЧЕНЫ СЕЙЧАС", bg=BG, fg=ORANGE,
                 font=("Segoe UI Semibold", 8)).pack(side="left", padx=3)
        tk.Label(title, text=str(len(users)), bg=RED, fg=TEXT, padx=6,
                 font=("Segoe UI Semibold", 8)).pack(side="left", padx=5)
        if not users:
            tk.Label(self.body, text="Активных подключений не обнаружено", bg=CARD, fg=MUTED,
                     font=("Segoe UI", 8), padx=11, pady=10).pack(fill="x", pady=2)
            return
        for user in users[:6]:
            row = tk.Frame(self.body, bg=CARD_ALT, padx=10, pady=7)
            row.pack(fill="x", pady=2)
            platform = (user.platform or "").lower()
            icon = "▣" if "windows" in platform else "◆" if "android" in platform else "●" if "ios" in platform else "◇"
            tk.Label(row, text=icon, bg=CARD_ALT, fg=RED, font=("Segoe UI Semibold", 11)).grid(row=0, column=0, rowspan=2, padx=(0, 8))
            tk.Label(row, text=user.username, bg=CARD_ALT, fg=TEXT,
                     font=("Segoe UI Semibold", 9)).grid(row=0, column=1, sticky="w")
            _, clean_node_name = node_country_and_name(user.node_name)
            tk.Label(row, text=f"{clean_node_name}  •  {user.seconds_ago} сек назад", bg=CARD_ALT,
                     fg=GREEN, font=("Segoe UI", 8)).grid(row=0, column=2, sticky="e")
            detail = user.device_label + (f"  •  {user.request_ip}" if user.request_ip else "")
            tk.Label(row, text=detail, bg=CARD_ALT, fg=MUTED, font=("Segoe UI", 8),
                     anchor="w").grid(row=1, column=1, columnspan=2, sticky="w", pady=(3, 0))
            row.columnconfigure(1, weight=1)
        if len(users) > 6:
            tk.Label(self.body, text=f"Ещё подключений: {len(users) - 6}", bg=BG, fg=MUTED,
                     font=("Segoe UI", 8)).pack(pady=3)

    def _node_card(self, node: NodeSnapshot, rate: float | None):
        card_shell = tk.Frame(self.body, bg=ORANGE if node.connected and not node.disabled else RED, padx=2)
        card_shell.pack(fill="x", pady=4)
        card = tk.Frame(card_shell, bg=CARD, padx=12, pady=9)
        card.pack(fill="x")
        is_up = node.connected and not node.disabled
        country, clean_name = node_country_and_name(node.name)
        flag = self._flag_image(country)
        tk.Label(card, text=f"  {clean_name}", image=flag, compound="left", bg=CARD, fg=TEXT,
                 font=("Segoe UI Semibold", 10)).grid(row=0, column=0, sticky="w")
        tk.Label(card, text="ONLINE" if is_up else "OFFLINE", bg=CARD, fg=GREEN if is_up else RED,
                 font=("Segoe UI Semibold", 9)).grid(row=0, column=1, sticky="e")
        latency = f"{node.latency_ms:.0f} мс" if node.latency_ms is not None else "API online" if is_up else "нет ответа"
        load = f"CPU {node.cpu_percent:.0f}%" if node.cpu_percent is not None else f"Load {node.load_1m:.2f}" if node.load_1m is not None else "CPU —"
        ram = f"RAM {node.ram_percent:.0f}%" if node.ram_percent is not None else "RAM —"
        details = f"{latency}   •   {load}   •   {ram}   •   👤 {node.users_online}"
        tk.Label(card, text=details, bg=CARD, fg=MUTED, font=("Segoe UI", 8)).grid(row=1, column=0, sticky="w", pady=(4, 0))
        traffic = f"Сейчас {human_rate(rate)}   •   Всего {human_bytes(node.traffic_bytes)}"
        tk.Label(card, text=traffic, bg=CARD, fg=CYAN, font=("Segoe UI", 8)).grid(row=2, column=0, sticky="w", pady=(3, 0))
        self._sparkline(card, self.history.values("node", node.uuid), 1, 1)
        if node.uuid in self._speed_testing or node.uuid in self._speed_results:
            value = "Тест скорости выполняется…" if node.uuid in self._speed_testing else self._speed_results[node.uuid]
            tk.Label(card, text=value, bg=CARD, fg=ORANGE, font=("Segoe UI Semibold", 8)).grid(
                row=3, column=0, columnspan=2, sticky="w", pady=(5, 0)
            )
        card.columnconfigure(0, weight=1)
        self._bind_node_context(card_shell, node)

    def _bind_node_context(self, widget: tk.Widget, node: NodeSnapshot) -> None:
        widget.bind("<Button-3>", lambda event, selected=node: self._show_node_menu(event, selected))
        for child in widget.winfo_children():
            self._bind_node_context(child, node)

    def _show_node_menu(self, event, node: NodeSnapshot) -> None:
        _, clean_name = node_country_and_name(node.name)
        menu = tk.Menu(self, tearoff=False, bg=CARD_ALT, fg=TEXT, activebackground=RED,
                       activeforeground=TEXT, bd=0, font=("Segoe UI", 9))
        menu.add_command(label=f"Тест скорости — {clean_name}",
                         command=lambda: self.start_speed_test(node),
                         state="disabled" if self._speed_testing else "normal")
        menu.add_separator()
        menu.add_command(label="Обновить данные", command=self.refresh_now)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def start_speed_test(self, node: NodeSnapshot) -> None:
        if self._speed_testing:
            return
        country, clean_name = node_country_and_name(node.name)
        self._speed_testing.add(node.uuid)
        self._speed_results.pop(node.uuid, None)
        self._render_nodes(self._last_nodes, self._last_api_ms, self._last_users,
                           self._last_router, self._last_route, self._last_remna_error)
        threading.Thread(target=self._run_speed_test, args=(node.uuid, country, clean_name), daemon=True).start()

    def _run_speed_test(self, node_uuid: str, country: str | None, clean_name: str) -> None:
        cache_buster = int(time.time() * 1000)
        if country == "ru":
            urls = [f"https://speedtest.selectel.ru/10MB?t={cache_buster}&stream={index}" for index in range(4)]
        else:
            urls = [f"https://speed.cloudflare.com/__down?bytes=10000000&t={cache_buster}&stream={index}" for index in range(4)]
        try:
            result = measure_parallel(urls)
            text = f"Тест: ↓ {result.megabits_per_second:.1f} Мбит/с   •   отклик {result.ttfb_ms:.0f} мс"
            error = None
        except Exception as exc:
            text = ""
            error = str(exc)
        self.after(0, self._finish_speed_test, node_uuid, clean_name, text, error)

    def _finish_speed_test(self, node_uuid: str, clean_name: str, text: str, error: str | None) -> None:
        self._speed_testing.discard(node_uuid)
        self._speed_results[node_uuid] = text if not error else f"Ошибка теста: {error}"
        self.history.add_event("error" if error else "info", f"Тест скорости {clean_name}: {self._speed_results[node_uuid]}")
        self._render_nodes(self._last_nodes, self._last_api_ms, self._last_users,
                           self._last_router, self._last_route, self._last_remna_error)
        if self.tray_icon:
            self.tray_icon.notify(self._speed_results[node_uuid], f"Тест скорости — {clean_name}")

    def exit_app(self):
        if self._really_closing:
            return
        self._really_closing = True
        self.config["window_x"] = self.winfo_x()
        self.config["window_y"] = self.winfo_y()
        save_config(self.config)
        self.history.add_event("info", "StarStack Cascade Monitor завершён")
        if self.caddy:
            self.caddy.stop()
        if self.web_server:
            self.web_server.stop()
        if self.tray_icon:
            self.tray_icon.stop()
        self.history.close()
        self.destroy()


if __name__ == "__main__":
    if acquire_single_instance():
        MonitorApp().mainloop()
    else:
        ctypes.windll.user32.MessageBoxW(0, "StarStack Cascade Monitor уже запущен.", "StarStack Cascade", 0x40)
