"""
eq_log.py — Recovers a character's zone and PvP state from their EQ log file.

Zone and PvP state normally come from live Zeal packets, so a client started
after the character zoned or toggled PvP doesn't know them. EverQuest writes
the same lines to eqlog_<Character>_<server>.txt (in the EQ folder, or its
Logs folder on newer clients) when logging is on
(/log on), so the latest "You have entered X." and PvP toggle lines can be
read back from the end of that file.

LogTail follows a log as it grows, for the melee hits Zeal's pipe only shows
shortened when the game's hit display options are set to Abbreviated or
Number Only (the log always gets the full line).

The EQ folder is the one of the EverQuest process that owns the Zeal pipe
(pipe name zeal_<pid>), or failing that app.eq_dir in config.yaml.
"""

import glob
import threading
import os
import re
import time
from typing import Optional

from config import RE_PVP_ON, RE_PVP_OFF, RE_ZONE_ENTER

_RE_LOG_PREFIX = re.compile(r"^\[([^\]]*)\]\s*")
_RE_PIPE_PID   = re.compile(r"zeal_(\d+)", re.IGNORECASE)

# How far back from the end of the log to look
MAX_SCAN_BYTES = 8 * 1024 * 1024
_CHUNK         = 256 * 1024


def eq_dir_for_pipe(pipe_path: str) -> Optional[str]:
    """The EverQuest folder of the process that owns a zeal_<pid> pipe."""
    m = _RE_PIPE_PID.search(pipe_path or "")
    if not m:
        return None
    try:
        import ctypes
        import ctypes.wintypes as wt
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(m.group(1)))
        if not handle:
            return None
        try:
            buf  = ctypes.create_unicode_buffer(1024)
            size = wt.DWORD(len(buf))
            if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return None
            return os.path.dirname(buf.value)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return None


def find_log(eq_dir: str, character: str) -> Optional[str]:
    """The most recently written eqlog_<character>_*.txt in eq_dir or eq_dir/Logs."""
    if not eq_dir or not character:
        return None
    name  = f"eqlog_{glob.escape(character)}_*.txt"
    paths = (glob.glob(os.path.join(glob.escape(eq_dir), name))
             + glob.glob(os.path.join(glob.escape(eq_dir), "Logs", name)))
    return max(paths, key=os.path.getmtime) if paths else None


def _lines_backwards(path: str):
    """Yield the log's lines newest first, up to MAX_SCAN_BYTES from the end."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos, read, tail = f.tell(), 0, b""
        while pos > 0 and read < MAX_SCAN_BYTES:
            step = min(_CHUNK, pos)
            pos -= step
            read += step
            f.seek(pos)
            block = f.read(step) + tail
            lines = block.split(b"\n")
            tail = lines.pop(0)   # may be cut off; finish it with the next block
            for line in reversed(lines):
                yield line.decode("utf-8", errors="replace").strip()
        if pos == 0 and tail:
            yield tail.decode("utf-8", errors="replace").strip()


def _line_time(line: str) -> float:
    """Unix time of a "[Sun Oct 11 22:48:06 2026] ..." log line (local time), 0 if unreadable."""
    m = _RE_LOG_PREFIX.match(line)
    try:
        return time.mktime(time.strptime(m.group(1), "%a %b %d %H:%M:%S %Y")) if m else 0.0
    except (ValueError, OverflowError):
        return 0.0


def read_zone_state(path: str) -> tuple[str, Optional[bool], Optional[bool], float]:
    """
    (zone, zone_pvp, pvp_flag, pvp_flag_at) from the end of a log file:
      zone         last "You have entered X." ("" if none)
      zone_pvp     PvP flag at the moment that zone was entered (None if unknown)
      pvp_flag     latest PvP toggle (None if none seen)
      pvp_flag_at  when that toggle was logged (0 if unknown)
    """
    zone, zone_pvp, pvp_flag, pvp_flag_at = "", None, None, 0.0
    try:
        for line in _lines_backwards(path):
            text = _RE_LOG_PREFIX.sub("", line)
            toggle = True if RE_PVP_ON.search(text) else False if RE_PVP_OFF.search(text) else None
            if toggle is not None:
                if pvp_flag is None:
                    pvp_flag, pvp_flag_at = toggle, _line_time(line)
                if zone:
                    zone_pvp = toggle   # last toggle before the zone entry
                    break
            elif not zone and (m := RE_ZONE_ENTER.match(text)):
                zone = m.group("zone")
    except OSError:
        pass
    return zone, zone_pvp, pvp_flag, pvp_flag_at


class LogTail:
    """
    New lines of a log file from the moment it's opened. Thread safe; read()
    returns (logged at, text) for each complete line written since the last
    call, with the "[Sun Oct 11 22:48:06 2026] " prefix taken off the text.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._f = open(path, "rb")
        self._f.seek(0, os.SEEK_END)
        self._partial = b""

    def read(self) -> list[tuple[float, str]]:
        with self._lock:
            if self._f is None:
                return []
            try:
                if os.fstat(self._f.fileno()).st_size < self._f.tell():
                    self._f.seek(0)   # cleared or replaced: start over
                    self._partial = b""
                data = self._f.read()
            except (OSError, ValueError):
                return []
            if not data:
                return []
            lines = (self._partial + data).split(b"\n")
            self._partial = lines.pop()   # not finished yet
        out = []
        for raw in lines:
            line = raw.decode("utf-8", errors="replace").strip()
            if line:
                out.append((_line_time(line), _RE_LOG_PREFIX.sub("", line)))
        return out

    def close(self):
        with self._lock:
            if self._f is not None:
                self._f.close()
                self._f = None
