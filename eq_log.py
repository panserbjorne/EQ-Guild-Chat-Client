"""
eq_log.py — Recovers a character's zone and PvP state from their EQ log file.

Zone and PvP state normally come from live Zeal packets, so a client started
after the character zoned or toggled PvP doesn't know them. EverQuest writes
the same lines to eqlog_<Character>_<server>.txt (in the EQ folder, or its
Logs folder on newer clients) when logging is on
(/log on), so the latest "You have entered X." and PvP toggle lines can be
read back from the end of that file.

The EQ folder comes from app.eq_dir in config.yaml, or failing that from the
EverQuest process that owns the Zeal pipe (pipe name zeal_<pid>).
"""

import glob
import os
import re
from typing import Optional

from config import RE_PVP_ON, RE_PVP_OFF, RE_ZONE_ENTER

_RE_LOG_PREFIX = re.compile(r"^\[[^\]]*\]\s*")
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


def read_zone_state(path: str) -> tuple[str, Optional[bool], Optional[bool]]:
    """
    (zone, zone_pvp, pvp_flag) from the end of a log file:
      zone      last "You have entered X." ("" if none)
      zone_pvp  PvP flag at the moment that zone was entered (None if unknown)
      pvp_flag  latest PvP toggle (None if none seen)
    """
    zone, zone_pvp, pvp_flag = "", None, None
    try:
        for line in _lines_backwards(path):
            text = _RE_LOG_PREFIX.sub("", line)
            toggle = True if RE_PVP_ON.search(text) else False if RE_PVP_OFF.search(text) else None
            if toggle is not None:
                if pvp_flag is None:
                    pvp_flag = toggle
                if zone:
                    zone_pvp = toggle   # last toggle before the zone entry
                    break
            elif not zone and (m := RE_ZONE_ENTER.match(text)):
                zone = m.group("zone")
    except OSError:
        pass
    return zone, zone_pvp, pvp_flag
