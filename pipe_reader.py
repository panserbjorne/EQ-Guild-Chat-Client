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

Packet capture
--------------
When enabled via set_capture(), every Zeal packet from every pipe is appended
to a log file as one JSON object per line, before any filtering. Used to
discover chat types and packet shapes we don't handle yet (kill messages,
zone info). Non-chat packets are only written when their data changes, since
stats packets repeat constantly.

Kill tracking
-------------
Kill lines (chat type 278) are forwarded as MSG_TYPE_KILL with the mob,
killer, and the character's current zone. Zone state is tracked per
character:

  "You have entered <zone>."   → zone name (zone id comes from the next
                                 player packet, which Zeal only sends on
                                 movement/target change)
  PvP toggle lines             → PvP flag at the moment the zone was entered
  "LOADING, PLEASE WAIT..."    → the zone id and x/y the player left from,
                                 sent as "entry"; the server checks it against
                                 the guild-instance books to tell the Normal,
                                 PvP and Guild copies of a zone apart
  merchant / horse refusals    → "instance" hint: only shown inside a guild
                                 or PvP copy
  camp / log back in           → you return to the same copy, so each
                                 character's zone, entry, hint and PvP flag
                                 are saved to ZONE_STATE_FILE and restored
                                 when they log back into that zone

When the client starts after the character zoned or toggled PvP, the
zone and PvP state are read back from the character's EQ log file
(eq_log.py), which needs logging on in game (/log on). Live lines always
win over the log. If the log has nothing either, pvp is sent as None and
the server treats the kill as non-PvP.
"""

import os
import ast
import codecs
import json
import queue
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

import eq_log

from config import (
    ZONE_STATE_FILE,
    ZEAL_PACKET_CHAT, ZEAL_PACKET_STATS, ZEAL_PACKET_PLAYER,
    ZEAL_TYPE_SYSTEM, ZEAL_TYPE_DEATH, MSG_TYPE_KILL, MSG_TYPE_ZONE,
    RE_KILL_YOU, RE_KILL_OTHER, RE_KILL_DIED, RE_ZONE_ENTER, RE_PVP_ON, RE_PVP_OFF,
    RE_LOADING, RE_CAMPING, RE_NO_MERCHANT, RE_NO_HORSE,
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


@dataclass
class ZoneState:
    """Where a character is, for kill reporting."""
    zone:     str            = ""     # long name from "You have entered"
    zone_id:  Optional[int]  = None   # from player packets
    pvp_flag: Optional[bool] = None   # current PvP toggle; None = not seen yet
    zone_pvp: Optional[bool] = None   # PvP flag when the current zone was entered
    loc:      Optional[tuple] = None  # last (x, y) from player packets
    entry:    Optional[dict] = None   # {zone_id, x, y} the player zoned from
    hint:     str            = ""     # "instance" / "pvp" from in-zone refusals
    login:    bool           = True   # next zone entry is a login, not a trip
    camped:   bool           = False  # camp message seen; logging out


class ZealPipeReader(threading.Thread):
    """
    Scans for zeal_* named pipes every 2 seconds.
    For each pipe found, spawns a reader + worker thread pair.

    Callbacks
    ---------
    on_message(character, msg_type, text, is_sender, extra=None)
    on_character(character)
    on_log(text)
    """

    PIPE_DIR = r"\\.\pipe"

    def __init__(
        self,
        on_message:      Callable[..., None],
        on_character:    Callable[[str], None],
        on_log:          Callable[[str], None],
        on_pipe_activity: Callable[[], None] | None = None,
        eq_dir:          str = "",
        wants_kill:      Callable[[str], bool] | None = None,
    ):
        super().__init__(daemon=True)
        self.on_message      = on_message
        self.on_character    = on_character
        self.on_log          = on_log
        self.on_pipe_activity = on_pipe_activity
        self.wants_kill      = wants_kill        # mob name → worth reporting; None = all
        self._stop_event  = threading.Event()
        self._active_pipes: dict[str, dict] = {}
        self._state       = ZealState()
        self._state_lock  = threading.Lock()
        self._zones: dict[str, ZoneState] = {}   # character → zone state
        self._eq_dir = eq_dir                    # EQ folder; "" = find it from the pipe
        self._char_pipes: dict[str, str] = {}    # character → Zeal pipe path
        self._log_checked: dict[str, float] = {} # character → last EQ log read
        self._saved_zones = self._load_saved_zones()  # character → last copy entered
        self._capture_path: Optional[str] = None
        self._capture_lock = threading.Lock()
        self._capture_last: dict[tuple, str] = {}   # (character, type) → last data written
        self._batched_seen = False                    # logged that reads can hold several packets

    def stop(self):
        self._stop_event.set()

    def set_eq_dir(self, eq_dir: str):
        """Change the EQ folder used to find log files; re-read logs on next use."""
        self._eq_dir = eq_dir
        self._log_checked.clear()

    def set_capture(self, path: Optional[str]):
        """Start writing every packet to `path`, or stop if None."""
        with self._capture_lock:
            self._capture_path = path
            self._capture_last.clear()
        if path:
            self.on_log(f"[Pipe] Packet capture ON → {os.path.abspath(path)}")
        else:
            self.on_log("[Pipe] Packet capture OFF")

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
        # The game closed: whoever logs in next starts with unknown zone state
        for character, pipe in list(self._char_pipes.items()):
            if pipe == pipe_path:
                self._zones.pop(character, None)
                self._char_pipes.pop(character, None)
                self._log_checked.pop(character, None)
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
        Runs independently so parsing latency never causes the reader to miss a packet.

        One read can hold several packets, or part of one (player packets
        arrive many times a second), so the bytes are treated as a stream."""
        utf8  = codecs.getincrementaldecoder("utf-8")(errors="replace")
        buf   = ""
        stuck = False   # the head of buf already failed to parse once
        try:
            while True:
                item = q.get()
                if item is _STOP:
                    break
                try:
                    buf += utf8.decode(item)
                    buf, stuck = self._drain(buf, stuck, pipe_path)
                except Exception as e:
                    buf, stuck = "", False
                    self.on_log(f"[Pipe] Worker error on {pipe_path}: {e}")
        finally:
            self._cleanup_pipe(pipe_path)

    _decoder = json.JSONDecoder()

    def _drain(self, buf: str, stuck: bool, pipe_path: str) -> tuple[str, bool]:
        """Process every complete packet in buf; return what's left and whether it's stuck."""
        count = 0
        while True:
            buf = buf.lstrip(" \t\r\n\x00")
            if not buf:
                break
            try:
                packet, end = self._decoder.raw_decode(buf)
            except ValueError:
                packet = None
            if isinstance(packet, dict):
                count += 1
                if count == 2 and not self._batched_seen:
                    self._batched_seen = True
                    self.on_log("[Pipe] One read held several packets; reading them all now")
                self._process_packet(packet, pipe_path)
                buf, stuck = buf[end:], False
                continue
            # Not JSON: an old-style packet (Python repr) sent whole
            try:
                packet = ast.literal_eval(buf.strip())
            except Exception:
                packet = None
            if isinstance(packet, dict):
                self._process_packet(packet, pipe_path)
                return "", False
            if not stuck:
                # Probably the first half of a packet: wait for the rest
                return buf, True
            # Still unreadable with more data behind it: skip to the next packet
            nxt = buf.find("{", 1)
            self.on_log(f"[Pipe] Dropped unreadable data: {buf[:80] if nxt < 0 else buf[:nxt][:80]}")
            if nxt < 0:
                return "", False
            buf, stuck = buf[nxt:], False
        return "", False

    # ─── Message processing ───────────────────

    def _process_line(self, raw: str, pipe_path: str = ""):
        try:
            if self.on_pipe_activity:
                self.on_pipe_activity()
            packet = self._parse_packet(raw)
            if packet is None:
                return
            self._process_packet(packet, pipe_path, activity=False)
        except Exception as e:
            self.on_log(f"[Pipe] Parse error: {e} | raw={raw[:120]}")

    def _process_packet(self, packet: dict, pipe_path: str = "", activity: bool = True):
        try:
            if activity and self.on_pipe_activity:
                self.on_pipe_activity()
            character  = packet.get("character", "")
            outer_type = packet.get("type", -1)

            if self._capture_path:
                self._capture(packet, character, outer_type)

            if character:
                self._char_pipes.setdefault(character, pipe_path)
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

            elif outer_type == ZEAL_PACKET_PLAYER:
                self._handle_player(character, packet.get("data", ""))

        except Exception as e:
            self.on_log(f"[Pipe] Parse error: {e} | packet={str(packet)[:120]}")

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

    # ─── Packet capture ───────────────────────

    def _capture(self, packet: dict, character: str, outer_type):
        """Append the packet to the capture file as one JSON line."""
        try:
            data = packet.get("data", "")
            with self._capture_lock:
                path = self._capture_path
                if not path:
                    return
                if outer_type != ZEAL_PACKET_CHAT:
                    key = (character, outer_type)
                    if self._capture_last.get(key) == str(data):
                        return
                    self._capture_last[key] = str(data)
                # Decode the nested JSON string so the capture is readable
                if isinstance(data, str):
                    try:
                        data = json.loads(data)
                    except Exception:
                        pass
                line = json.dumps({
                    "ts":        time.strftime("%Y-%m-%d %H:%M:%S"),
                    "character": character,
                    "type":      outer_type,
                    "data":      data,
                }, ensure_ascii=False)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception as e:
            self.on_log(f"[Pipe] Capture error: {e}")

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

    # ─── Zone / PvP / kill tracking ───────────

    def _zone_state(self, character: str) -> ZoneState:
        if character not in self._zones:
            self._zones[character] = ZoneState()
            self._seed_from_log(character)
        return self._zones[character]

    def _seed_from_log(self, character: str):
        """
        Fill in zone / PvP state still unknown from the character's EQ log.
        Read at most every 30s per character, since it's only a fallback.
        """
        now = time.time()
        if now - self._log_checked.get(character, 0) < 30:
            return
        self._log_checked[character] = now

        eq_dir = self._eq_dir or eq_log.eq_dir_for_pipe(self._char_pipes.get(character, ""))
        if not eq_dir:
            self.on_log(f"[Zone] EQ folder unknown for {character} (pipe "
                        f"{self._char_pipes.get(character, '?')}); set it in Settings")
            return
        path = eq_log.find_log(eq_dir, character)
        if not path:
            self.on_log(f"[Zone] No eqlog_{character}_*.txt in {eq_dir} "
                        "or its Logs folder; is /log on?")
            return
        zone, zone_pvp, pvp_flag = eq_log.read_zone_state(path)

        st = self._zones[character]
        if not st.zone and zone:
            st.zone = zone
        if st.pvp_flag is None:
            st.pvp_flag = pvp_flag
        # The log's PvP state only applies if it's describing the same zone visit
        if st.zone_pvp is None and zone and zone.lower() == st.zone.lower():
            st.zone_pvp = zone_pvp
        pvp = {True: "PvP flag on", False: "PvP flag off", None: "PvP flag unknown"}[st.zone_pvp]
        self.on_log(f"[Zone] {character} from EQ log: {st.zone or 'zone unknown'} ({pvp})")

    def _handle_player(self, character: str, data_raw):
        """Pick up the numeric zone id from a player packet."""
        try:
            data = json.loads(data_raw) if isinstance(data_raw, str) else data_raw
            if not isinstance(data, dict):
                return
            st = self._zone_state(character)
            zone_id = data.get("zone")
            if isinstance(zone_id, int):
                st.zone_id = zone_id
            loc = data.get("location") or {}
            if "x" in loc and "y" in loc:
                st.loc = (round(loc["x"], 1), round(loc["y"], 1))
                # Moving around means we're in game (client started mid-session)
                if not st.camped:
                    st.login = False
        except Exception:
            pass

    def _handle_zoning(self, character: str):
        """
        "LOADING, PLEASE WAIT...": remember where the player left from, so the
        server can tell whether they used a guild-instance book (PvP / Guild
        copy) or an ordinary route (normal zone).
        """
        st = self._zone_state(character)
        st.entry = ({"zone_id": st.zone_id, "x": st.loc[0], "y": st.loc[1]}
                    if st.zone_id is not None and st.loc and not st.login else None)
        st.hint = ""
        st.loc  = None

    def _handle_zone_enter(self, character: str, zone: str):
        st = self._zone_state(character)
        st.zone     = zone
        st.zone_id  = None   # stale until the next player packet
        st.zone_pvp = st.pvp_flag
        saved = self._saved_zones.get(character)
        if st.login and saved and saved.get("zone", "").lower() == zone.lower():
            # Logging back in puts you in the copy you camped in
            st.entry, st.hint, st.zone_pvp = saved.get("entry"), saved.get("hint", ""), saved.get("pvp")
            self.on_log(f"[Zone] {character} logged back into the same copy of {zone}")
        st.login = st.camped = False
        self._save_zone(character)
        pvp = {True: "PvP flag on", False: "PvP flag off", None: "PvP flag unknown"}[st.zone_pvp]
        came = (f"from {st.entry['x']:.0f}, {st.entry['y']:.0f} in zone {st.entry['zone_id']}"
                if st.entry else "departure unknown")
        # The server decides Normal / PvP / Guild from this (see zone_versions.py)
        self.on_log(f"[Zone] {character} entered {zone} ({pvp}; {came})")
        # Temporary: the server logs which copy it thinks this is, and why
        self.on_message(character, MSG_TYPE_ZONE, f"entered {zone}", False, {
            "zone":     zone,
            "pvp":      st.zone_pvp,
            "entry":    st.entry,
            "instance": st.hint,
        })

    def _load_saved_zones(self) -> dict:
        try:
            with open(ZONE_STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_zone(self, character: str):
        """Remember which copy of the zone this character is in, for their next login."""
        st = self._zones.get(character)
        if st is None or not st.zone:
            return
        self._saved_zones[character] = {
            "zone": st.zone, "entry": st.entry, "hint": st.hint, "pvp": st.zone_pvp,
        }
        try:
            with open(ZONE_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._saved_zones, f, indent=1)
        except Exception as e:
            self.on_log(f"[Zone] Could not save {ZONE_STATE_FILE}: {e}")

    def _handle_pvp_toggle(self, character: str, on: bool):
        self._zone_state(character).pvp_flag = on
        self.on_log(f"[PvP] {character} PvP {'ON' if on else 'OFF'} (applies from next zone)")

    def _handle_kill(self, character: str, text: str):
        if m := RE_KILL_YOU.match(text):
            mob, killer = m.group("mob"), character
        elif m := RE_KILL_OTHER.match(text):
            mob, killer = m.group("mob"), m.group("killer")
        elif m := RE_KILL_DIED.match(text):
            mob, killer = m.group("mob"), ""
        else:
            return
        if self.wants_kill and not self.wants_kill(mob):
            return   # not a mob the server tracks
        st = self._zone_state(character)
        if st.zone_pvp is None or not st.zone:
            self._seed_from_log(character)
        saved = self._saved_zones.get(character)
        if (st.entry is None and not st.hint and saved and st.zone
                and saved.get("zone", "").lower() == st.zone.lower()):
            # Client started mid-zone: assume the copy this character was last in
            st.entry, st.hint = saved.get("entry"), saved.get("hint", "")
            if st.zone_pvp is None:
                st.zone_pvp = saved.get("pvp")
        self.on_message(character, MSG_TYPE_KILL, text, False, {
            "mob":     mob,
            "killer":  killer,
            "zone":    st.zone,
            "zone_id": st.zone_id,
            "pvp":     st.zone_pvp,
            "entry":   st.entry,
            "instance": st.hint,
        })

    # ─── Chat handling ────────────────────────

    def _handle_chat(self, character: str, data: dict):
        zeal_type = data.get("type", -1)
        text      = data.get("text", "")

        # Logging out (chat type not yet confirmed): the next login isn't a
        # trip from this spot
        if RE_CAMPING.search(text):
            st = self._zone_state(character)
            st.loc, st.login, st.camped = None, True, True

        # Refusals that only happen inside a guild / PvP copy of a zone
        if RE_NO_MERCHANT.search(text) or RE_NO_HORSE.search(text):
            st = self._zone_state(character)
            st.hint = "pvp" if RE_NO_HORSE.search(text) else (st.hint or "instance")
            self._save_zone(character)
            self.on_log(f"[Zone] {character} is in a {'PvP' if st.hint == 'pvp' else 'guild/PvP'} copy")

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

        elif zeal_type == ZEAL_TYPE_DEATH:
            self._handle_kill(character, text)

        elif zeal_type == ZEAL_TYPE_SYSTEM:
            if RE_LOADING.search(text):
                self._handle_zoning(character)

            elif RE_PVP_ON.search(text):
                self._handle_pvp_toggle(character, True)
            elif RE_PVP_OFF.search(text):
                self._handle_pvp_toggle(character, False)

        elif zeal_type == ZEAL_TYPE_DEFAULT:
            if m := RE_ZONE_ENTER.match(text):
                self._handle_zone_enter(character, m.group("zone"))
            elif RE_TIME_INGAME.search(text):
                self.on_message(character, MSG_TYPE_TIME, text, False)
                self.on_log(f"[Default/Time] {text}")

        elif zeal_type == ZEAL_TYPE_YELLOW:
            if RE_PVP.search(text):
                self.on_message(character, MSG_TYPE_PVP, text, False)
                self.on_log(f"[Yellow/PVP] {text}")
            elif RE_QUAKE.search(text):
                self.on_message(character, MSG_TYPE_QUAKE, text, False)
                self.on_log(f"[Yellow/Quake] {text}")

