"""
gui.py — Tkinter GUI for EQ Bridge.
"""

import re
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from typing import Callable

from PIL import Image
import pystray

import icon_manager
from config import (
    APP_NAME, APP_VERSION,
    SRV_KEY_CLIENTS, SRV_KEY_ACTIVE_SOURCE, SRV_KEY_VERSION,
)
from ws_client import WSClient
from pipe_reader import ZealPipeReader



class App:
    """Main application window."""

    # ─── Theme colours ────────────────────────
    BG    = "#1a1d23"
    FG    = "#d4d8e2"
    ACC   = "#4e9ef7"
    PANEL = "#23272f"
    ERR   = "#e05c5c"

    def __init__(self, root: tk.Tk, config):
        self.root   = root
        self.config = config

        # State reflected in the UI
        self.current_character: str = ""
        self.client_count: int      = 0
        self.active_source: str     = ""
        self.server_version: str    = ""
        self.ws_status: str         = "Idle"

        # Character classification state
        self._ignored_chars:       set[str] = set()
        self._pending_char_prompt: set[str] = set()

        # Pipe activity watchdog
        self._pipe_last_activity: float = 0.0
        self._ws_connected:       bool  = False
        self._PIPE_TIMEOUT:       int   = 15  # seconds of silence = logged out

        # Tray icon (created once, lives for the app lifetime)
        self._tray_icon:   pystray.Icon | None = None
        self._tray_thread: threading.Thread | None = None
        self._tray_status: str = ""   # last icon status set, avoids redundant updates

        self._build_ui()
        self._apply_theme()
        icon_manager.init(self.config.icon_dir, self.config.icon_name)
        self._setup_tray()

        self.ws = self._make_ws_client()
        self.pipe_reader = ZealPipeReader(
            on_message        = self._on_zeal_message,
            on_character      = self._on_character_detected,
            on_log            = self._log,
            on_pipe_activity  = self._on_pipe_activity,
        )

        # WS is not started here — it starts when a character is detected
        self.pipe_reader.start()
        self._set_status("Waiting for game process…")
        self._poll_ui()
        self._pipe_watchdog()

        # X button quits, minimise button (-) hides to tray
        self.root.protocol("WM_DELETE_WINDOW", self._do_quit)
        self.root.bind("<Unmap>", self._on_unmap)

        if self.config.start_minimized:
            self.root.after(100, self._minimize_to_tray)

    def _make_ws_client(self) -> WSClient:
        return WSClient(
            self.config,
            on_log              = self._log,
            on_status           = self._set_ws_status,
            on_server_broadcast = self._on_server_broadcast,
            on_fatal            = self._on_fatal,
            character           = self.current_character,
        )

    # ─── Pipe watchdog / WS lifecycle ────────

    def _on_pipe_activity(self):
        """Called on every Zeal packet — resets the inactivity timer."""
        first_activity = self._pipe_last_activity == 0.0
        self._pipe_last_activity = time.monotonic()
        # First packet means the game process is running — update status
        # if we still don't have a character yet
        if first_activity and not self.current_character:
            self._set_status("Waiting for character login…")

    def _pipe_watchdog(self):
        """Runs every second. Connects WS when character is known,
        disconnects when the pipe has been silent for _PIPE_TIMEOUT seconds."""
        now = time.monotonic()
        has_character = bool(self.current_character)
        pipe_alive    = (now - self._pipe_last_activity) < self._PIPE_TIMEOUT
        pipe_seen     = self._pipe_last_activity > 0

        if has_character and pipe_alive and not self._ws_connected:
            self._ws_connect()
        elif self._ws_connected and pipe_seen and not pipe_alive:
            self._ws_disconnect()

        self.root.after(1000, self._pipe_watchdog)

    def _ws_connect(self):
        """Start the WebSocket connection."""
        self._ws_connected = True
        self.ws.start()
        self._log("[WS] Character in game — connecting")

    def _ws_disconnect(self):
        """Stop the WebSocket connection (pipe went quiet — character logged out)."""
        self._ws_connected = False
        self.current_character = ""
        self.ws.stop()
        self.ws = self._make_ws_client()
        self._set_status("Waiting for character login…")
        self._set_ws_status("Idle")
        self._log("[WS] Pipe inactive — disconnected (character logged out)")

    def shutdown(self):
        """Stop background services and remove the tray icon."""
        self.ws.stop()
        self.pipe_reader.stop()
        if self._tray_icon:
            self._tray_icon.stop()

    # ─── System tray ──────────────────────────

    def _setup_tray(self):
        """Create the pystray icon with a context menu."""
        menu = pystray.Menu(
            pystray.MenuItem("Show", self._restore_from_tray, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit_from_tray),
        )
        self._tray_icon = pystray.Icon(
            name  = APP_NAME,
            icon  = icon_manager.get_icon("red"),
            title = APP_NAME,
            menu  = menu,
        )
        self._tray_status = "red"

    def _start_tray(self):
        """Run the tray icon in its own daemon thread."""
        if self._tray_thread and self._tray_thread.is_alive():
            return
        self._tray_thread = threading.Thread(
            target=self._tray_icon.run,
            daemon=True,
        )
        self._tray_thread.start()

    def _minimize_to_tray(self):
        """Hide the window and show the tray icon."""
        self.root.withdraw()
        self._start_tray()
        self._tray_icon.notify(APP_NAME, "Running in the background")

    def _restore_from_tray(self, icon=None, item=None):
        """Bring the window back from the tray (called from tray thread)."""
        self._schedule(self._do_restore)

    def _do_restore(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _on_unmap(self, event=None):
        """Fired when the window is minimised (iconified) — hide to tray instead."""
        if self.root.state() == "iconic":
            self._minimize_to_tray()

    def _quit_from_tray(self, icon=None, item=None):
        """Quit entirely from the tray menu."""
        self._schedule(self._do_quit)

    def _do_quit(self):
        self.shutdown()
        self.root.destroy()

    # ─── UI Construction ──────────────────────

    def _build_ui(self):
        self.root.title(APP_NAME)
        self.root.geometry("720x560")
        self.root.resizable(True, True)

        style = ttk.Style()
        style.theme_use("clam")

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self._tab_main     = ttk.Frame(nb)
        self._tab_settings = ttk.Frame(nb)
        nb.add(self._tab_main,     text="  Main  ")
        nb.add(self._tab_settings, text="  Settings  ")

        self._build_main_tab()
        self._build_settings_tab()

    def _build_main_tab(self):
        f = self._tab_main
        f.columnconfigure(1, weight=1)

        labels = [
            ("Connection:",     "_lbl_ws_status"),
            ("Character:",      "_lbl_character"),
            ("Clients Online:", "_lbl_clients"),
            ("Active Source:",  "_lbl_active"),
            ("Version:",        "_lbl_version"),
            ("Status:",         "_lbl_status"),
        ]
        for row, (text, attr) in enumerate(labels):
            ttk.Label(f, text=text, anchor="e", width=16).grid(
                row=row, column=0, sticky="e", padx=(10, 4), pady=3
            )
            lbl = ttk.Label(f, text="—", anchor="w")
            lbl.grid(row=row, column=1, sticky="w", padx=(0, 10), pady=3)
            setattr(self, attr, lbl)

        ttk.Label(f, text="Log:").grid(
            row=len(labels), column=0, sticky="ne", padx=(10, 4), pady=(6, 0)
        )
        self._log_box = scrolledtext.ScrolledText(
            f, state="disabled", height=14, wrap="word", font=("Consolas", 9)
        )
        self._log_box.grid(
            row=len(labels), column=0, columnspan=2,
            sticky="nsew", padx=10, pady=(4, 10)
        )
        f.rowconfigure(len(labels), weight=1)

    def _build_settings_tab(self):
        f = self._tab_settings
        f.columnconfigure(1, weight=1)

        ttk.Label(f, text="Server Address:", anchor="e").grid(
            row=0, column=0, sticky="e", padx=(10, 4), pady=8
        )
        self._ent_server = ttk.Entry(f)
        self._ent_server.insert(0, self.config.server_address)
        self._ent_server.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=8)

        ttk.Label(f, text="API Key:", anchor="e").grid(
            row=1, column=0, sticky="e", padx=(10, 4), pady=8
        )
        self._ent_apikey = ttk.Entry(f, show="●")
        self._ent_apikey.insert(0, self.config.api_key)
        self._ent_apikey.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=8)

        # Start minimized checkbox
        ttk.Label(f, text="Start minimized:", anchor="e").grid(
            row=2, column=0, sticky="e", padx=(10, 4), pady=8
        )
        self._var_start_minimized = tk.BooleanVar(value=self.config.start_minimized)
        ttk.Checkbutton(f, variable=self._var_start_minimized).grid(
            row=2, column=1, sticky="w", padx=(0, 10), pady=8
        )

        # Whitelist / Blacklist
        list_frame = ttk.Frame(f)
        list_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=10, pady=4)
        list_frame.columnconfigure(0, weight=1)
        list_frame.columnconfigure(1, weight=1)
        f.rowconfigure(3, weight=1)

        for col, (title, attr_box, is_white) in enumerate([
            ("Whitelisted Characters", "_wl_box", True),
            ("Blacklisted Characters", "_bl_box", False),
        ]):
            lf = ttk.LabelFrame(list_frame, text=title, padding=6)
            lf.grid(row=0, column=col, sticky="nsew",
                    padx=(0, 6) if col == 0 else (6, 0))
            lf.columnconfigure(0, weight=1)
            lf.rowconfigure(0, weight=1)

            lb = tk.Listbox(
                lf, selectmode="single", height=8,
                bg=self.PANEL, fg=self.FG,
                selectbackground=self.ACC, selectforeground="#ffffff",
                highlightthickness=0, borderwidth=0,
                font=("Consolas", 9), relief="flat", activestyle="none",
            )
            lb.grid(row=0, column=0, columnspan=2, sticky="nsew")
            setattr(self, attr_box, lb)

            ttk.Button(
                lf, text="+ Add",
                command=lambda w=is_white: self._manual_add_char(w)
            ).grid(row=1, column=0, sticky="ew", pady=(4, 0), padx=(0, 2))

            ttk.Button(
                lf, text="− Remove",
                command=lambda b=lb, w=is_white: self._remove_char(b, w)
            ).grid(row=1, column=1, sticky="ew", pady=(4, 0))

        self._refresh_char_lists()

        ttk.Button(f, text="Save Settings", command=self._save_settings).grid(
            row=4, column=0, columnspan=2, pady=12
        )

    def _apply_theme(self):
        style = ttk.Style()
        bg, fg, acc, panel = self.BG, self.FG, self.ACC, self.PANEL

        self.root.configure(bg=bg)
        style.configure(".",                 background=bg, foreground=fg,
                                             font=("Segoe UI", 10))
        style.configure("TFrame",            background=bg)
        style.configure("TLabel",            background=bg, foreground=fg)
        style.configure("TLabelframe",       background=bg, foreground=fg,
                                             bordercolor="#2e3340", relief="groove")
        style.configure("TLabelframe.Label", background=bg, foreground=acc)
        style.configure("TNotebook",         background=bg, borderwidth=0)
        style.configure("TNotebook.Tab",     background=panel, foreground=fg,
                                             padding=[12, 6], font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
            background=[("selected", acc)],
            foreground=[("selected", "#ffffff")],
            padding=[("selected", [12, 6])])
        style.configure("TEntry",            fieldbackground=panel, foreground=fg,
                                             insertcolor=fg, borderwidth=1)
        style.configure("TButton",           background=panel, foreground=fg, padding=6)
        style.map("TButton",
            background=[("active", acc)],
            foreground=[("active", "#fff")])
        style.configure("TScrollbar",        background=panel,
                                             troughcolor=bg, arrowcolor=fg)
        style.configure("TCheckbutton",      background=bg, foreground=fg)
        style.map("TCheckbutton",
            background=[("active", bg)],
            foreground=[("active", fg)])

        self._log_box.configure(
            bg=panel, fg=fg, insertbackground=fg,
            selectbackground=acc, borderwidth=0,
        )

    # ─── Logging / status helpers ─────────────

    def _log(self, msg: str):
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        def _append():
            self._log_box.configure(state="normal")
            self._log_box.insert("end", line)
            self._log_box.see("end")
            self._log_box.configure(state="disabled")
        self._schedule(_append)

    def _set_ws_status(self, status: str):
        self.ws_status = status
        self._schedule(lambda: self._lbl_ws_status.config(text=status))

    def _set_status(self, status: str):
        self._schedule(lambda: self._lbl_status.config(text=status))

    def _schedule(self, fn: Callable):
        try:
            self.root.after(0, fn)
        except Exception:
            pass

    def _poll_ui(self):
        """Refresh status labels every second."""
        self._lbl_ws_status.config(text=self.ws_status)
        self._lbl_character.config(text=self.current_character or "—")
        self._lbl_clients.config(
            text=str(self.client_count) if self.client_count else "—"
        )
        self._lbl_active.config(text=self.active_source or "—")

        if self.server_version:
            if self.server_version == APP_VERSION:
                self._lbl_version.config(
                    text=f"{APP_VERSION} ✓", foreground="#4ec97e"
                )
            else:
                self._lbl_version.config(
                    text=f"{APP_VERSION} (server: {self.server_version})",
                    foreground=self.ERR,
                )

        # Keep tray tooltip and icon current
        if self._tray_icon:
            char = self.current_character or "no character"
            self._tray_icon.title = f"{APP_NAME} — {char} ({self.ws_status})"
            # red = not connected, yellow = connected no clients, green = clients online
            if not self._ws_connected:
                new_status = "red"
            elif self.client_count and self.client_count > 0:
                new_status = "green"
            else:
                new_status = "yellow"
            if new_status != self._tray_status:
                self._tray_icon.icon = icon_manager.get_icon(new_status)
                self._tray_status = new_status

        self.root.after(1000, self._poll_ui)

    # ─── Server broadcast ─────────────────────

    def _on_server_broadcast(self, data: dict):
        if SRV_KEY_CLIENTS in data:
            self.client_count = int(data[SRV_KEY_CLIENTS])
        if SRV_KEY_ACTIVE_SOURCE in data:
            self.active_source = str(data[SRV_KEY_ACTIVE_SOURCE])
        if SRV_KEY_VERSION in data:
            self.server_version = str(data[SRV_KEY_VERSION])

    def _on_fatal(self, reason: str):
        """Called by WSClient when the server permanently rejects this client."""
        self._set_ws_status("Disconnected")
        self._set_status("Connection refused")
        self._schedule(lambda: self._show_fatal_dialog(reason))

    def _show_fatal_dialog(self, reason: str):
        # Restore window if it's hidden so the user can see the error
        self._do_restore()

        dialog = tk.Toplevel(self.root)
        dialog.title("Connection Error")
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg=self.BG)

        ttk.Label(
            dialog,
            text="⚠  Connection Refused",
            font=("Segoe UI", 13, "bold"),
            foreground=self.ERR,
        ).pack(padx=28, pady=(22, 6))

        ttk.Label(
            dialog,
            text=reason,
            font=("Segoe UI", 10),
            justify="center",
            wraplength=360,
        ).pack(padx=28, pady=(0, 18))

        ttk.Button(dialog, text="OK", command=dialog.destroy).pack(pady=(0, 18))

        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()  - 420) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 200) // 2
        dialog.geometry(f"420x200+{x}+{y}")

    # ─── Zeal callbacks ───────────────────────

    def _on_character_detected(self, char: str):
        if not char:
            return
        # Strip suffixes like "'s Corpse001" or "'s Pet" -> base character name
        name_match = re.match(r"^(\w+)", char)
        if name_match:
            char = name_match.group(1)
        if self.current_character != char:
            self.current_character = char
            self._log(f"[Character] Detected: {char}")
            self._set_status(f"Active — {char}")
            # Keep WSClient in sync so outgoing messages carry the correct character
            self.ws.character = char

        if (char not in self.config.whitelist
                and char not in self.config.blacklist
                and char not in self._ignored_chars
                and char not in self._pending_char_prompt):
            self._pending_char_prompt.add(char)
            self._schedule(lambda c=char: self._prompt_new_character(c))

    def _on_zeal_message(self, character: str, msg_type: str, text: str, is_sender: bool = False):
        self._log(f"[{msg_type.upper()}] {character}: {text}")

        if character in self.config.blacklist:
            self._log(f"[Filter] Blocked (blacklisted): {character}")
            return
        if self.config.whitelist and character not in self.config.whitelist:
            self._log(f"[Filter] Blocked (not whitelisted): {character}")
            return

        self.ws.send(msg_type, text, is_sender=is_sender)

    # ─── New character dialog ─────────────────

    def _prompt_new_character(self, char: str):
        # Restore window so the prompt is visible
        self._do_restore()

        dialog = tk.Toplevel(self.root)
        dialog.title("New Character Detected")
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg=self.BG)

        ttk.Label(
            dialog,
            text=f"New character detected: {char}\n\nWhat would you like to do?",
            font=("Segoe UI", 11), justify="center",
        ).pack(padx=24, pady=(20, 12))

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=(0, 20))

        def whitelist():
            self.config.whitelist.append(char)
            self.config.save()
            self._refresh_char_lists()
            self._log(f"[Config] {char} added to whitelist")
            self._pending_char_prompt.discard(char)
            dialog.destroy()

        def blacklist():
            self.config.blacklist.append(char)
            self.config.save()
            self._refresh_char_lists()
            self._log(f"[Config] {char} added to blacklist")
            self._pending_char_prompt.discard(char)
            dialog.destroy()

        def ignore():
            self._ignored_chars.add(char)
            self._pending_char_prompt.discard(char)
            self._log(f"[Config] {char} ignored for this session")
            dialog.destroy()

        ttk.Button(btn_frame, text="✅ Whitelist", command=whitelist).grid(
            row=0, column=0, padx=6)
        ttk.Button(btn_frame, text="🚫 Blacklist", command=blacklist).grid(
            row=0, column=1, padx=6)
        ttk.Button(btn_frame, text="⏭ Ignore (session)", command=ignore).grid(
            row=0, column=2, padx=6)

        self.root.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()  - 420) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 180) // 2
        dialog.geometry(f"420x180+{x}+{y}")

    # ─── Settings actions ─────────────────────

    def _save_settings(self):
        self.config.server_address  = self._ent_server.get().strip()
        self.config.api_key         = self._ent_apikey.get().strip()
        self.config.start_minimized = self._var_start_minimized.get()
        self.config.save()
        self._log("[Config] Settings saved.")

        # Only restart the WS connection if it was actually running — keeps
        # _ws_connected in sync so the pipe watchdog doesn't double-start it.
        was_connected = self._ws_connected
        self.ws.stop()
        self._ws_connected = False
        self.ws = self._make_ws_client()
        if was_connected:
            self._log("[Config] Reconnecting…")
            self.ws.start()
            self._ws_connected = True

    def _refresh_char_lists(self):
        for lb, items in [
            (self._wl_box, self.config.whitelist),
            (self._bl_box, self.config.blacklist),
        ]:
            lb.delete(0, "end")
            for c in items:
                lb.insert("end", c)

    def _manual_add_char(self, is_whitelist: bool):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Character")
        dialog.resizable(False, False)
        dialog.configure(bg=self.BG)
        dialog.grab_set()

        ttk.Label(dialog, text="Character name:").pack(padx=16, pady=(14, 4))
        ent = ttk.Entry(dialog, width=24)
        ent.pack(padx=16)
        ent.focus()

        def add():
            name = ent.get().strip()
            if not name:
                return
            lst = self.config.whitelist if is_whitelist else self.config.blacklist
            if name not in lst:
                lst.append(name)
                self.config.save()
                self._refresh_char_lists()
            dialog.destroy()

        ttk.Button(dialog, text="Add", command=add).pack(pady=10)
        dialog.bind("<Return>", lambda e: add())

    def _remove_char(self, lb: tk.Listbox, is_whitelist: bool):
        sel = lb.curselection()
        if not sel:
            return
        name = lb.get(sel[0])
        lst  = self.config.whitelist if is_whitelist else self.config.blacklist
        if name in lst:
            lst.remove(name)
            self.config.save()
            self._refresh_char_lists()