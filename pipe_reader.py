"""
pipe_reader.py — Reads JSON messages from Zeal named pipes (Windows, message-mode).

Architecture
------------
For each discovered pipe, two threads are spawned:

  Reader thread  — does nothing but ReadFile in a tight loop and puts raw
                   bytes onto a Queue as fast as possible. No parsing, no
                   callbacks, minimal work so no packet is ever missed.

  Worker thread  — pulls from the Queue, parses, and dispatches callbacks.
                   Decoupled from the reader so slow processing never causes
                   the reader to fall behind.

Macro substitution
------------------
GUILD_TX messages are sent before the game applies macro substitutions.
The pipe reader maintains a ZealState cache updated from stat/target packets
and performs the substitutions itself before forwarding:

  %t / %target        → target name
  %th / %targethp     → target HP %
  %h / %hp            → self HP %
  %n / %mana          → self mana %
  %loc                → current location (x, y, z)
"""

import os
import ast
import json
import queue
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from config import (
    ZEAL_PACKET_CHAT, ZEAL_PACKET_STATS,
    ZEAL_STAT_HP_PCT, ZEAL_STAT_MANA_PCT, ZEAL_STAT_TARGET, ZEAL_STAT_TARGET_HP,
    ZEAL_TYPE_YELLOW, ZEAL_TYPE_DEFAULT,
    ZEAL_TYPE_GUILD_RX, ZEAL_TYPE_GUILD_TX, ZEAL_TYPE_WHO, MSG_TYPE_GUILD,
    MSG_TYPE_QUAKE, MSG_TYPE_WHO, MSG_TYPE_PVP, MSG_TYPE_TIME,
    RE_TIME_INGAME, RE_QUAKE, RE_PVP,
)

# Sentinel pushed onto the queue to signal the worker to stop
_STOP = object()

# Regex matching all known macro variables (case-insensitive)
_RE_MACRO = re.compile(
    r'%(?:targethp|target|th|mana|loc|hp|[thnt])\b',
    re.IGNORECASE,
)

@dataclass
class ZealState:
    """Cached character and target state from Zeal stat packets."""
    hp_pct:    int   = 0
    mana_pct:  int   = 0
    target:    str   = ""
    target_hp: int   = 0
    loc_x:     float = 0.0
    loc_y:     float = 0.0
    loc_z:     float = 0.0

    def substitute(self, text: str) -> str:
        """Replace EQ macro variables with cached values."""
        if '%' not in text:
            return text

        def _replace(m: re.Match) -> str:
            token = m.group(0).lower()
            if token in ('%t', '%target'):
                return self.target or m.group(0)
            if token in ('%th', '%targethp'):
                return str(self.target_hp)
            if token in ('%h', '%hp'):
                return str(self.hp_pct)
            if token in ('%n', '%mana'):
                return str(self.mana_pct)
            if token == '%loc':
                return f"{self.loc_x:.1f}, {self.loc_y:.1f}, {self.loc_z:.1f}"
            return m.group(0)  # unknown macro — leave as-is

        return _RE_MACRO.sub(_replace, text)


class ZealPipeReader(threading.Thread):
    """
    Scans for zeal_* named pipes every 2 seconds.
    For each pipe found, spawns a reader + worker thread pair.

    Callbacks
    ---------
    on_message(character, msg_type, text, is_sender)
    on_character(character)
    on_log(text)
    """

    PIPE_DIR = r"\\.\pipe"

    def __init__(
        self,
        on_message:      Callable[[str, str, str, bool], None],
        on_character:    Callable[[str], None],
        on_log:          Callable[[str], None],
        on_pipe_activity: Callable[[], None] | None = None,
    ):
        super().__init__(daemon=True)
        self.on_message      = on_message
        self.on_character    = on_character
        self.on_log          = on_log
        self.on_pipe_activity = on_pipe_activity
        self._stop_event  = threading.Event()
        self._active_pipes: dict[str, dict] = {}
        self._state       = ZealState()
        self._state_lock  = threading.Lock()

    def stop(self):
        self._stop_event.set()

    # ─── Scan loop ────────────────────────────

    def run(self):
        while not self._stop_event.is_set():
            self._scan_pipes()
            time.sleep(2)

    def _scan_pipes(self):
        try:
            for pipe_path in self._find_pipes():
                if pipe_path not in self._active_pipes:
                    self._start_pipe(pipe_path)
        except Exception as e:
            self.on_log(f"[Pipe] Scan error: {e}")

    def _find_pipes(self) -> list[str]:
        results = []
        try:
            for name in os.listdir(self.PIPE_DIR):
                if name.lower().startswith("zeal_"):
                    results.append(self.PIPE_DIR + "\\" + name)
        except Exception as e:
            self.on_log(f"[Pipe] Enumeration error: {e}")
        return results

    # ─── Per-pipe setup ───────────────────────

    def _start_pipe(self, pipe_path: str):
        q = queue.Queue()
        reader = threading.Thread(
            target=self._reader_thread, args=(pipe_path, q), daemon=True
        )
        worker = threading.Thread(
            target=self._worker_thread, args=(pipe_path, q), daemon=True
        )
        self._active_pipes[pipe_path] = {"reader": reader, "worker": worker, "queue": q}
        reader.start()
        worker.start()
        self.on_log(f"[Pipe] Connected to {pipe_path}")

    def _cleanup_pipe(self, pipe_path: str):
        self._active_pipes.pop(pipe_path, None)
        self.on_log(f"[Pipe] Disconnected from {pipe_path}")

    # ─── Reader thread ────────────────────────

    def _reader_thread(self, pipe_path: str, q: queue.Queue):
        """Reads raw messages off the pipe as fast as possible and enqueues them.
        Does NO parsing — minimal work keeps this thread always ready for the next packet."""
        try:
            import ctypes
            import ctypes.wintypes as wt
            kernel32 = ctypes.windll.kernel32

            GENERIC_READ          = 0x80000000
            OPEN_EXISTING         = 3
            PIPE_READMODE_MESSAGE = 0x00000002
            ERROR_MORE_DATA       = 234

            handle = kernel32.CreateFileW(
                pipe_path, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None
            )
            if handle == ctypes.c_void_p(-1).value or handle == 0:
                self.on_log(f"[Pipe] Failed to open {pipe_path}")
                q.put(_STOP)
                return

            mode = wt.DWORD(PIPE_READMODE_MESSAGE)
            kernel32.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None)

            while not self._stop_event.is_set():
                chunks: list[bytes] = []
                while True:
                    buf        = ctypes.create_string_buffer(65536)
                    bytes_read = wt.DWORD(0)
                    success    = kernel32.ReadFile(
                        handle, buf, 65535, ctypes.byref(bytes_read), None
                    )
                    err = kernel32.GetLastError()
                    if bytes_read.value:
                        chunks.append(buf.raw[:bytes_read.value])
                    if success:
                        break
                    elif err == ERROR_MORE_DATA:
                        continue
                    else:
                        kernel32.CloseHandle(handle)
                        q.put(_STOP)
                        return

                if chunks:
                    q.put(b"".join(chunks))

        except Exception as e:
            self.on_log(f"[Pipe] Reader error on {pipe_path}: {e}")
        finally:
            q.put(_STOP)

    # ─── Worker thread ────────────────────────

    def _worker_thread(self, pipe_path: str, q: queue.Queue):
        """Pulls raw bytes from the queue, parses, and dispatches callbacks.
        Runs independently so parsing latency never causes the reader to miss a packet."""
        try:
            while True:
                item = q.get()
                if item is _STOP:
                    break
                try:
                    raw = item.decode("utf-8", errors="replace").strip()
                    if raw:
                        self._process_line(raw)
                except Exception as e:
                    self.on_log(f"[Pipe] Worker error on {pipe_path}: {e}")
        finally:
            self._cleanup_pipe(pipe_path)

    # ─── Message processing ───────────────────

    def _process_line(self, raw: str):
        try:
            if self.on_pipe_activity:
                self.on_pipe_activity()
            packet = self._parse_packet(raw)
            if packet is None:
                return

            character  = packet.get("character", "")
            outer_type = packet.get("type", -1)

            if character:
                self.on_character(character)

            if outer_type == ZEAL_PACKET_CHAT:
                try:
                    data = json.loads(packet.get("data", ""))
                except Exception:
                    self.on_log(f"[Pipe] Could not parse chat data: {str(packet)[:80]}")
                    return
                self._handle_chat(character, data)

            elif outer_type == ZEAL_PACKET_STATS:
                self._handle_stats(packet.get("data", ""))

        except Exception as e:
            self.on_log(f"[Pipe] Parse error: {e} | raw={raw[:120]}")

    def _parse_packet(self, raw: str) -> Optional[dict]:
        """Parse a Zeal packet — tries JSON first, falls back to ast.literal_eval."""
        try:
            return json.loads(raw)
        except Exception:
            pass
        try:
            return ast.literal_eval(raw)
        except Exception:
            return None

    # ─── Stat/target caching ──────────────────

    def _handle_stats(self, data_raw: str):
        """Update HP, mana, target name and target HP from the combined stats array."""
        try:
            items = json.loads(data_raw) if isinstance(data_raw, str) else data_raw
            if not isinstance(items, list):
                return
            with self._state_lock:
                for item in items:
                    t = item.get("type")
                    v = item.get("value", "")
                    try:
                        if t == ZEAL_STAT_HP_PCT:
                            self._state.hp_pct = int(v)
                        elif t == ZEAL_STAT_MANA_PCT:
                            self._state.mana_pct = int(v)
                        elif t == ZEAL_STAT_TARGET:
                            self._state.target = str(v)
                        elif t == ZEAL_STAT_TARGET_HP:
                            self._state.target_hp = int(v)
                    except (ValueError, TypeError):
                        pass
        except Exception:
            pass

    # ─── Chat handling ────────────────────────

    def _handle_chat(self, character: str, data: dict):
        zeal_type = data.get("type", -1)
        text      = data.get("text", "")

        if zeal_type == ZEAL_TYPE_GUILD_TX:
            # Apply macro substitutions using cached state before reformatting
            with self._state_lock:
                text = self._state.substitute(text)
            m = re.search(r"'(.+)'$", text, re.DOTALL)
            if m:
                text = f"{character} tells the guild, '{m.group(1)}'"
            self.on_message(character, MSG_TYPE_GUILD, text, True)

        elif zeal_type == ZEAL_TYPE_GUILD_RX:
            self.on_message(character, MSG_TYPE_GUILD, text, False)

        elif zeal_type == ZEAL_TYPE_WHO:
            return
            self.on_message(character, MSG_TYPE_WHO, text, False)

        elif zeal_type == ZEAL_TYPE_DEFAULT:
            if RE_TIME_INGAME.search(text):
                self.on_message(character, MSG_TYPE_TIME, text, False)
                self.on_log(f"[Default/Time] {text}")

        elif zeal_type == ZEAL_TYPE_YELLOW:
            if RE_PVP.search(text):
                self.on_message(character, MSG_TYPE_PVP, text, False)
                self.on_log(f"[Yellow/PVP] {text}")
            elif RE_QUAKE.search(text):
                self.on_message(character, MSG_TYPE_QUAKE, text, False)
                self.on_log(f"[Yellow/Quake] {text}")

