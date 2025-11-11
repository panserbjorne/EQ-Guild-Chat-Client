"""Reads from zeal and sends to websocket"""

import asyncio
import json
import os
import queue
import re
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
from PIL import Image, ImageDraw
import pystray
import pywintypes
import websockets
import win32file
import yaml


VERSION = '0.1.0'
CONFIG_FILE = "config.yaml"

DEFAULT_CONFIG = {
    "server_uri": "127.0.0.1:8765",
    "api_key": "CHANGE_ME",
    "whitelisted_characters": ['ExampleChar1', 'ExampleChar2'],
    "blacklisted_characters": ['ExampleChar3', 'ExampleChar4'],
    "start_minimized": False,
}

GUILD_PATTERN = re.compile(
    r"^(?P<character>\w+) (?:tells the|say to your) guild, '(?P<message>.*)'$"
)

PIPE_BASE_LOCATION = '\\\\.\\pipe'


def load_config_from_file():
    """Loads config from yaml file"""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(DEFAULT_CONFIG, f)
        return DEFAULT_CONFIG.copy()

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # Ensure missing fields are filled
    for k, v in DEFAULT_CONFIG.items():
        data.setdefault(k, v)
    return data


def save_config_to_file(cfg):
    """Saves config from yaml file"""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, sort_keys=False)


class EQClientGUI:
    """TK Window"""
    def __init__(self, root):
        # Load config
        self.pipe_connected = False
        self.config = load_config_from_file()
        self.server_uri = self.config["server_uri"]
        self.api_key = self.config["api_key"]
        self.whitelist = self.config.get("whitelisted_characters", [])
        self.blacklist = self.config.get("blacklisted_characters", [])
        # GUI variables
        self.status_var = tk.StringVar(value="Not logged in")
        self.current_char_var = tk.StringVar(value="Unknown")
        self.connected_var = tk.StringVar(value="0")
        self.active_source_var = tk.StringVar(value="None")
        self.version_var = tk.StringVar(value=f"v{VERSION}")
        # GUI Elements
        self.root = root
        self.root.title('EverQuest Guild Chat Collector')
        self.root.geometry('600x400')
        self.root.resizable(False, False)
        # Tabs
        self.tabs = ttk.Notebook(self.root)
        self.tab_main = ttk.Frame(self.tabs)
        self.tab_settings = ttk.Frame(self.tabs)
        self.tabs.add(self.tab_main, text="Main")
        self.tabs.add(self.tab_settings, text="Settings")
        self.tabs.pack(fill="both", expand=True)
        self.create_main_tab()
        self.create_settings_tab()

        # Minimize to systme tray
        self.setup_tray()
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        self.root.bind("<Unmap>", lambda e: self.hide_window() if self.root.state() == "iconic" else None)
        if self.config.get("start_minimized", False):
            self.root.after(100, self.hide_window)

        # Data
        self.pipe_queue = queue.Queue()
        self.guild_message_queue = asyncio.Queue()
        self.websocket = None
        self.websocket_task = None
        self.stop_requested = False
        self._pipe_task = None
        self.client_character_name = None
        self.character_known = False
        self.character_updated = False
        self.character_whitelisted = True
        self.last_tick = time.time()

        # Threading
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.read_pipe_messages, daemon=True).start()
        threading.Thread(target=self.pipe_message_loop, daemon=True).start()
        self.asyncio_thread = threading.Thread(target=self.start_asyncio_loop, args=(self.loop,), daemon=True)
        self.asyncio_thread.start()

        # Start WebSocket client
        self.run_in_loop(self.run_client())

    def start_asyncio_loop(self, loop):
        """Async Helper"""
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def run_in_loop(self, coro):
        """Safely schedule coroutine in background event loop"""
        if self.websocket_task and not self.websocket_task.done():
            # self.log("⚠️ WebSocket client is already running. Canceling existing task.")
            self.websocket_task.cancel()
        self.websocket_task = asyncio.run_coroutine_threadsafe(coro, self.loop)

    def create_main_tab(self):
        """Main tab"""
        frame_top = ttk.Frame(self.tab_main)
        frame_top.pack(padx=10, pady=10, fill="x")

        # Grid-based stats area
        stats = ttk.Frame(frame_top)
        stats.pack(fill="x", pady=5)
        stats.columnconfigure(0, weight=0, pad=10)
        stats.columnconfigure(1, weight=1)

        ttk.Label(stats, text="Status:").grid(row=0, column=0, sticky="w")
        self.lbl_status = ttk.Label(stats, textvariable=self.status_var, foreground="red")
        self.lbl_status.grid(row=0, column=1, sticky="w")

        ttk.Label(stats, text="Character:").grid(row=1, column=0, sticky="w")
        self.lbl_current_char = ttk.Label(stats, textvariable=self.current_char_var)
        self.lbl_current_char.grid(row=1, column=1, sticky="w")

        ttk.Label(stats, text="Connected Clients:").grid(row=2, column=0, sticky="w")
        ttk.Label(stats, textvariable=self.connected_var).grid(row=2, column=1, sticky="w")

        ttk.Label(stats, text="Active Source:").grid(row=3, column=0, sticky="w")
        ttk.Label(stats, textvariable=self.active_source_var).grid(row=3, column=1, sticky="w")

        ttk.Label(stats, text="Version:").grid(row=4, column=0, sticky="w")
        self.lbl_version = ttk.Label(stats, textvariable=self.version_var)
        self.lbl_version.grid(row=4, column=1, sticky="w")

        ttk.Separator(self.tab_main, orient="horizontal").pack(fill="x", pady=5)

        self.text_log = scrolledtext.ScrolledText(self.tab_main, wrap=tk.WORD, height=15, state="disabled")
        self.text_log.pack(fill="both", expand=True, padx=10, pady=5)

    def create_settings_tab(self):
        """Settings Tab"""
        frm = ttk.Frame(self.tab_settings)
        frm.pack(padx=10, pady=10, fill="both", expand=True)

        ttk.Label(frm, text="Server Address:").pack(anchor="w")
        self.entry_server = ttk.Entry(frm)
        self.entry_server.insert(0, self.config["server_uri"])
        self.entry_server.pack(fill="x", pady=3)

        ttk.Label(frm, text="API Key:").pack(anchor="w")
        self.entry_api = ttk.Entry(frm, show="*")
        self.entry_api.insert(0, self.config["api_key"])
        self.entry_api.pack(fill="x", pady=3)

        chars_frame = ttk.Frame(frm)
        chars_frame.pack(fill="both", expand=True, pady=(10, 5))
        chars_frame.columnconfigure(0, weight=1, uniform="col")
        chars_frame.columnconfigure(1, weight=1, uniform="col")

        lbl_chars_whitelist = ttk.Label(chars_frame, text="Whitelisted Characters")
        lbl_chars_whitelist.grid(row=0, column=0, sticky="w")
        self.text_chars_whitelist = scrolledtext.ScrolledText(chars_frame, height=8, width=30)
        self.text_chars_whitelist.insert(
            "1.0",
            "\n".join(self.config.get("whitelisted_characters", []))
        )
        self.text_chars_whitelist.grid(row=1, column=0, padx=(0, 5), sticky="nsew")

        lbl_chars_blacklist = ttk.Label(chars_frame, text="Blacklisted Characters")
        lbl_chars_blacklist.grid(row=0, column=1, sticky="w")
        self.text_chars_blacklist = scrolledtext.ScrolledText(chars_frame, height=8, width=30)
        self.text_chars_blacklist.insert(
            "1.0",
            "\n".join(self.config.get("blacklisted_characters", []))
        )
        self.text_chars_blacklist.grid(row=1, column=1, padx=(5, 0), sticky="nsew")

        self.start_minimized_var = tk.BooleanVar(value=self.config.get("start_minimized", False))
        ttk.Checkbutton(
            frm,
            text="Start minimized to system tray",
            variable=self.start_minimized_var,
        ).pack(anchor="w", pady=(6, 4))

        ttk.Button(frm, text="Save Settings", command=self.save_settings).pack(pady=10)

    def create_tray_image(self, color=(40, 80, 160), text="EQ"):
        """Create a simple icon for the system tray"""
        img = Image.new('RGB', (64, 64), color=color)
        draw = ImageDraw.Draw(img)
        draw.text((10, 20), "EQ", fill="white")
        return img

    def setup_tray(self):
        """Initialize the tray icon and menu"""
        image = self.create_tray_image((40, 80, 160))
        menu = (
            pystray.MenuItem("Open", self.show_window, default=True),
            pystray.MenuItem("Exit", self.exit_app),
        )
        self.tray_icon = pystray.Icon(
            "EverQuestGuildClient",
            image,
            "EQ Guild Collector",
            menu
        )
        # Run the tray in a background thread
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def hide_window(self):
        """Hide the main window (minimize to tray)"""
        self.root.withdraw()
        self.log("🟡 Minimized to system tray")

    def show_window(self, icon=None, item=None):
        """Restore the main window"""
        self.root.after(0, self.root.deiconify)
        self.root.after(0, self.root.lift)
        self.root.after(0, self.root.focus_force)

    def update_tray_status(self, status):
        """Change tray color based on connection status."""
        color_map = {
            "connected": (0, 150, 50),     # green
            "connecting": (255, 165, 0),   # orange
            "disconnected": (180, 30, 30)  # red
        }
        color = color_map.get(status, (40, 80, 160))
        if hasattr(self, "tray_icon"):
            try:
                self.tray_icon.icon = self.create_tray_image(color)
            except Exception:
                pass

    def exit_app(self, icon=None, item=None):
        """Shutdown cleanly"""
        self.log("🔴 Exiting...")
        self.shutdown()
        try:
            if hasattr(self, "tray_icon"):
                self.tray_icon.stop()
        except Exception:
            pass
        self.root.destroy()

    def log(self, msg):
        """Thread-safe logging to the GUI."""
        self.root.after(0, self._log_to_widget, msg)

    def _log_to_widget(self, msg):
        """Internal method to update text log"""
        self.text_log.configure(state="normal")
        self.text_log.insert(tk.END, f"{time.strftime('%H:%M:%S')} | {msg}\n")
        self.text_log.configure(state="disabled")
        self.text_log.yview(tk.END)

    def update_status(self, text, color):
        """Updates status label."""
        self.status_var.set(text)
        self.lbl_status.config(foreground=color)

        # Determine tray status from text
        if "Connected" in text:
            self.update_tray_status("connected")
        elif "Connecting" in text or "Reconnecting" in text:
            self.update_tray_status("connecting")
        else:
            self.update_tray_status("disconnected")

    def update_character(self, name, color="black"):
        """Updates character label."""
        self.current_char_var.set(name or "Unknown")
        self.lbl_current_char.config(foreground=color)

    def update_stats(self, connected, active):
        """Updates connection stats."""
        self.connected_var.set(str(connected))
        self.active_source_var.set(str(active))

    def update_version(self, text, color="black"):
        """Updates version label."""
        self.version_var.set(text)
        self.lbl_version.config(foreground=color)

    def save_settings(self):
        """Action for save button"""
        new_config = {
            "server_uri": self.entry_server.get().strip(),
            "api_key": self.entry_api.get().strip(),
            "whitelisted_characters": [
                c.strip() for c in self.text_chars_whitelist.get("1.0", tk.END).splitlines() if c.strip()
            ],
            "blacklisted_characters": [
                c.strip() for c in self.text_chars_blacklist.get("1.0", tk.END).splitlines() if c.strip()
            ],
            "start_minimized": self.start_minimized_var.get(),
        }

        save_config_to_file(new_config)
        self.config = new_config
        self.server_uri = new_config["server_uri"]
        self.api_key = new_config["api_key"]
        self.whitelist = self.config.get("whitelisted_characters", [])
        self.blacklist = self.config.get("blacklisted_characters", [])

        self.log("⚙️ Settings updated — reconnecting...")
        self.run_in_loop(self.reconnect())

    def find_pipe(self):
        '''Attempts to find running Zeal pipes'''
        try:
            pipes = os.listdir('\\\\.\\pipe')
            for pipe in pipes:
                if pipe.startswith('zeal_'):
                    return os.path.join(PIPE_BASE_LOCATION, pipe)
        except FileNotFoundError:
            self.log('❌ Pipe directory not found')
        except Exception as e:
            self.log('⚠️ Error searching for pipe: %s', e)
        return False

    def connect_to_pipe(self):
        """Connect to the Zeal pipe."""
        pipe_name = self.find_pipe()
        if not pipe_name:
            return False

        try:
            pipe_file = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_READ,
                0,  # No sharing
                None,  # Default security attributes
                win32file.OPEN_EXISTING,
                0,  # No special attributes
                None  # No template file
            )
            self.log("✅ Connected to pipe.")
            return pipe_file
        except pywintypes.error as e:
            self.log(f"❌ Error connecting to pipe: {e}")
            return False
        except Exception as e:
            self.log(f"❌ Error connecting to pipe: {e}")
            return False

    def read_pipe_messages(self):
        """Reads message from Named Pipe"""
        pipe_name = None
        pipe = None
        while True:
            if self.stop_requested:
                break
            # Find the pipe name if not known
            if not pipe_name:
                pipe_name = self.find_pipe()
                pipe = None
            if not pipe_name:
                if self.pipe_connected:
                    self.log("⌛ Waiting for Zeal")
                    self.pipe_connected = False
                self.character_whitelisted = False
                self.client_character_name = None
                self.root.after(0, self.update_character, "Unknown", "black")
                time.sleep(5)
                continue
            # Connect to the pipe if needed
            if not pipe:
                pipe = self.connect_to_pipe()
            if not pipe:
                time.sleep(1)
                continue
            self.pipe_connected = True
            # Read the pipe, abort if the pipe fails
            while True:
                if self.stop_requested:
                    break
                try:
                    pipe_hr, pipe_data = win32file.ReadFile(pipe, 4096)
                except pywintypes.error as e:
                    self.log(f'⚠️ Error reading pipe message: {e}')
                    pipe_name = None
                    self.character_known = False
                    self.character_updated = True
                    break
                if pipe_hr == 0 and pipe_data:
                    self.pipe_queue.put(pipe_data)
            time.sleep(0)

    def new_char_msgbox(self):
        msg_box = tk.Toplevel(self.root)
        msg_box.geometry("300x100")
        msg_box.title("New Character")

        # Create a label to display the message
        label = tk.Label(msg_box, text="Do you want to log messages with this character?")
        label.pack(pady=10)

        # Create a frame to hold the buttons and center them
        button_frame = tk.Frame(msg_box)
        button_frame.pack(pady=10)

        # Create custom buttons and add them to the frame
        whitelist_button = tk.Button(button_frame, text="Whitelist", command=lambda: self.new_char_msgbox_click("Whitelist", msg_box))
        whitelist_button.pack(side=tk.LEFT, padx=10)

        blacklist_button = tk.Button(button_frame, text="Blacklist", command=lambda: self.new_char_msgbox_click("Blacklist", msg_box))
        blacklist_button.pack(side=tk.LEFT, padx=10)

        ignore_button = tk.Button(button_frame, text="Ignore", command=lambda: self.new_char_msgbox_click("Ignore", msg_box))
        ignore_button.pack(side=tk.LEFT, padx=10)

        button_frame.pack_configure(anchor="center")

        msg_box.lift()
        msg_box.attributes("-topmost", 1)

    def new_char_msgbox_click(self, action, msg_box):
        """Handle button clicks for the message box"""
        if action != "Ignore":
            char_string = '\n' + self.client_character_name
            if action == "Whitelist":
                self.text_chars_whitelist.insert(tk.END, char_string)
            if action == "Blacklist":
                self.text_chars_blacklist.insert(tk.END, char_string)
            self.save_settings()
        msg_box.destroy()  # Close the message box

    def extract_pipe_message(self, pipe_message):
        """Read a message from the pipe."""
        try:
            json_data = json.loads(pipe_message.decode('utf-8'))

            if 'data' not in json_data:
                return False

            if isinstance(json_data['data'], str):
                json_data['data'] = json.loads(json_data['data'])
            else:
                return False

            if json_data['character'] != self.client_character_name:
                # Match name to parse things like "Player's corpse123"
                name_match = re.match(r"^\b(\w+)\b", json_data['character'])
                if not name_match:
                    return False
                self.client_character_name = name_match.group(1)
                self.character_updated = True
                self.root.after(0, self.update_character, self.client_character_name)
                self.log(f"👁️ Detected character: {self.client_character_name}")
                if self.client_character_name not in self.whitelist + self.blacklist:
                    self.root.after(0, self.new_char_msgbox)

            # Auto-reconnect if character changed
            if self.character_updated and self.websocket:
                self.run_in_loop(self.reconnect())

            if json_data['type'] != 0:
                return False

            # Use server tick as a heartbeat
            if json_data['data']['type'] == 0:
                self.last_tick = time.time()
                return False

            # Specified Channels only
            if json_data['data']['type'] not in [
                15,   # Yellow Text "Channel", inc Quake
                259,  # Guild
                310   # Guild Echo
            ]:
                return False

            # Filter for yellow text "Channel"
            if (json_data['data']['type'] == 15
                    and not json_data['data']['text'].startswith("The next earthquake")
                    and not json_data['data']['text'].startswith("PVP Druzzil Ro BROADCASTS")
            ):
                return False

            return json_data['data']['text']

        except json.JSONDecodeError as e:
            return False
            self.log(f"⚠️ JSON decode error: {e}")
            self.log(f"🔍 Raw data: {pipe_message.decode('utf-8')}")
        except Exception as e:
            self.log(f"⚠️ Error processing pipe message: {e}")
            return False

    def process_message(self, pipe_message):
        """Looks for relevant data, modifies as nessacary"""
        # guild_match = re.match(GUILD_PATTERN, pipe_message)
        # if guild_match:
        #     full_message = guild_match.group(0)
        #     if full_message == '':  # Skip empty messages
        #         return False
        #     full_message = re.sub(r'^\b(You)\b', self.client_character_name, full_message)
        #     return (full_message)
        edited_message = re.sub(r'^\b(You)\b', self.client_character_name, pipe_message)
        return edited_message
        return False

    def pipe_message_loop(self):
        """Retrieves messages from queue"""
        while True:
            if self.stop_requested:
                break
            current_time = time.time()
            last_tick_seconds = current_time - self.last_tick
            if last_tick_seconds >= 20 and self.websocket:
                self.log(f'⚠️ No recent server tick, not logged in?')
                self.client_character_name = None
                self.run_in_loop(self.reconnect())
                time.sleep(1)
            if not self.config:
                time.sleep(1)
                continue
            if self.pipe_queue.empty():
                time.sleep(0.05)
                continue
            try:
                new_message = self.pipe_queue.get(block=False)
                extracted_message = self.extract_pipe_message(new_message)

                if not extracted_message:
                    time.sleep(0)
                    continue

                message = self.process_message(extracted_message)
                if message and self.websocket:
                    now = time.time()
                    asyncio.run_coroutine_threadsafe(self.guild_message_queue.put([message, now]), self.loop)
            except queue.Empty:
                pass
            except Exception as e:
                self.log(f"⚠️ Error in pipe message loop: {e}")

            time.sleep(0)

    async def run_client(self):
        """Start background pipe processing"""
        while True:
            if self.stop_requested:
                break

            if not self.pipe_connected:
                await asyncio.sleep(1)
                continue
            if (not self.client_character_name) or (self.client_character_name not in self.whitelist):
                if self.character_whitelisted or self.character_updated:
                    self.character_whitelisted = False
                    self.character_updated = False
                    if self.pipe_connected:
                        status_desc = "Character not whitelisted"
                    else:
                        status_desc = "Not logged in"
                    self.root.after(0, self.update_status, status_desc, "red")
                    self.root.after(0, self.update_character, self.client_character_name, "red")

                    if not self.client_character_name:
                        self.log("❌ Character unknown — WebSocket connection skipped.")
                    else:
                        self.log(f"⛔ Character '{self.client_character_name}' not in whitelist — skipping connection.")
                await asyncio.sleep(1)
                continue
            self.root.after(0, self.update_character, self.client_character_name, "green")
            self.character_whitelisted = True
            self.character_updated = False
            try:
                self.root.after(0, self.update_status, "Connecting...", "orange")

                if self.websocket:
                    self.log("ℹ️ Stale websocket object found, closing...")
                    try:
                        await self.websocket.close()
                    except Exception as e:
                        self.log(f"⚠️ Error closing stale websocket: {e}")
                    self.websocket = None

                async with websockets.connect(
                    "wss://" + self.server_uri,
                    additional_headers={"X-API-Key": self.api_key},
                    ping_interval=30, ping_timeout=10, close_timeout=5
                ) as ws:
                    self.websocket = ws
                    self.last_tick = time.time()
                    self.root.after(0, self.update_status, "Connected", "green")
                    self.log(f"✅ Connected to server as {self.client_character_name or 'Unknown'}")

                    tasks = [
                        asyncio.create_task(self.send_guild_messages(ws)),
                        asyncio.create_task(self.handle_server_messages(ws))
                    ]
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in pending:
                        task.cancel()

            except asyncio.CancelledError:
                self.log("ℹ️ Connection cancelled.")
                break
            except websockets.ConnectionClosed as e:
                self.log(f"⚠️ WebSocket connection closed: {e}")
            except Exception as e:
                self.log(f"❌ Disconnected: {e}")
            finally:
                if self.websocket:
                    try:
                        await asyncio.wait_for(self.websocket.close(), timeout=1.0)
                    except (asyncio.TimeoutError, Exception):
                        pass  # Ignore errors on close

                self.websocket = None
                await asyncio.sleep(5)  # Wait before reconnecting

    async def send_guild_messages(self, ws):
        """Send Parsed Messages to Websocket Server"""
        try:
            while not self.stop_requested:
                if self.guild_message_queue.empty():
                    await asyncio.sleep(0.1)
                    continue

                message, message_time = await self.guild_message_queue.get()

                current_time = time.time()
                mesage_seconds_ago = current_time - message_time
                if mesage_seconds_ago >= 10:
                    self.log("ℹ️ Skipping old message.")
                    await asyncio.sleep(0.1)
                    continue

                payload = {"type": "guild_message", "message": message}

                try:
                    await ws.send(json.dumps(payload))
                    self.log(f"📤 Forwarded message: {message}")
                except websockets.ConnectionClosed:
                    self.log("⚠️ WebSocket connection closed during send — stopping sender.")
                    if self.guild_message_queue.empty():  # Retry if queue is still empty
                        await self.guild_message_queue.put([message, message_time])
                    break
                except Exception as e:
                    self.log(f"⚠️ Failed to send guild message: {e}")
                    if self.guild_message_queue.empty():  # Retry if queue is still empty
                        await self.guild_message_queue.put([message, message_time])
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            self.log("ℹ️ Message sender cancelled cleanly.")
            pass
        except Exception as e:
            self.log(f"Error in send_guild_messages: {e}")

    async def handle_server_messages(self, ws):
        """Handle stats and system messages from the server."""
        try:
            async for msg in ws:
                try:
                    data = json.loads(msg)
                    if data.get("type") == "stats":
                        active = data.get("active_source")
                        connected = data.get("connected")
                        latest_client_version = data.get("latest_client_version")

                        self.root.after(0, self.update_stats, connected, active)

                        if latest_client_version:
                            if latest_client_version != VERSION:
                                version_text = f"v{VERSION} (New Version: v{latest_client_version})"
                                self.root.after(0, self.update_version, version_text, "red")
                                self.log(f"⚠️ A newer client version is available: v{latest_client_version}")
                            else:
                                version_text = f"v{VERSION}"
                                self.root.after(0, self.update_version, version_text, "green")

                except json.JSONDecodeError:
                    self.log(f"⚠️ Bad data from server: {msg}")
        except asyncio.CancelledError:
            pass # Task was cancelled, exit gracefully
        except websockets.ConnectionClosed:
            self.log("ℹ️ Server connection closed, stopping message handler.")
        except Exception as e:
            self.log(f"Error in handle_server_messages: {e}")

    async def reconnect(self):
        self.root.after(0, self.update_status, "Reconnecting...", "orange")
        # If there's an active WebSocket connection, close it
        if self.websocket:
            try:
                await self.websocket.close()
                self.log("ℹ️ Closed existing WebSocket connection.")
            except Exception as e:
                self.log(f"Error closing WebSocket: {e}")
        await asyncio.sleep(2)
        self.run_in_loop(self.run_client())

    def shutdown(self):
        """Gracefully stop background tasks and close connections."""
        if self.stop_requested:
            return
        self.stop_requested = True
        self.log("🛑 Shutting down client...")

        # Cancel asyncio tasks safely
        if self.websocket_task:
            self.websocket_task.cancel()

        # Close websocket if still open
        if self.websocket and not self.websocket.close_code:
            try:
                asyncio.run_coroutine_threadsafe(self.websocket.close(), self.loop)
            except Exception:
                pass

        # Stop the asyncio loop itself
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)


def main():
    root = tk.Tk()
    gui = EQClientGUI(root)
    try:
        root.mainloop()
    finally:
        gui.shutdown()


if __name__ == "__main__":
    main()
