"""
inventory_watcher.py — Uploads <Character>-Inventory.txt files for the website's inventory page.

In game, /output inventory writes <Character>-Inventory.txt to the EverQuest
folder. When "Upload inventory files" is on in Settings, this watcher looks
in the EQ folders (the games behind the Zeal pipes, and the folder from
Settings) every second and sends any file changed since the last upload.

Only files written after the option was turned on are sent: turning it on
records the time, and older files are left for the website's own upload.

A file counts as done once the server answers for it (saved, skipped because
the server already has a newer copy, or blocked by the owner on the website);
otherwise it's sent again on a later pass. What's been sent is kept in
INVENTORY_STATE_FILE so a restart doesn't send everything again.
"""

import glob
import json
import os
import threading
import time
from typing import Callable, Optional

from config import INVENTORY_STATE_FILE

POLL_SECONDS  = 0.5        # a stat of a few files, twice a second
MAX_BYTES     = 200 * 1024  # inventory files are a few KB; anything bigger isn't one
RESULT_WAIT   = 60          # resend a file the server hasn't answered for after this long
RETRY_SECONDS = 60          # wait after a server error before trying a file again

# Server answers that settle a file (no point sending the same copy again)
_DONE = {"saved", "older", "blocked", "name", "invalid"}

_SHOWN = {
    "saved":      "uploaded",
    "older":      "skipped, the website already has a newer copy",
    "blocked":    "not uploaded, blocked on the website",
    "name":       "not uploaded, the file name isn't a character name",
    "invalid":    "not uploaded, the website couldn't read it",
    "no_account": "not uploaded, sign in with Discord in Settings to upload inventories",
    "error":      "not uploaded, the server had an error; trying again later",
}


class InventoryWatcher:
    """
    Callbacks
    ---------
    eq_dirs() -> list[str]
        The EverQuest folders to look in.
    send(filename, text, file_time) -> Optional[str]
        Queue the file for the server; returns its msg_id, or None when there's
        no connection to send it on.
    on_log(text)
    """

    def __init__(self, eq_dirs: Callable[[], list], send: Callable[[str, str, float], Optional[str]],
                 on_log: Callable[[str], None], enabled: bool = False):
        self.eq_dirs = eq_dirs
        self.send    = send
        self.on_log  = on_log

        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._enabled  = False
        self._since    = 0.0                         # files older than this aren't sent
        self._sent: dict[str, float]  = {}           # path → mtime the server has answered for
        self._pending: dict[str, tuple[str, float, float]] = {}   # msg_id → (path, mtime, sent at)
        self._wait_until: dict[str, float] = {}      # path → don't retry before (after an error)
        self._too_big: set[str] = set()
        self._no_account = False
        self._load()
        if enabled and self._since:
            # Already on: files written while the client was closed still go
            self._enabled = True
        else:
            self.set_enabled(enabled)

    # ─── Public API ───────────────────────────

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def set_enabled(self, on: bool):
        """Turn uploading on or off; turning it on only sends files written from now."""
        with self._lock:
            if on == self._enabled:
                return
            self._enabled = on
            if on:
                self._since = time.time()
                self._no_account = False
                self._save()
        if on:
            self.on_log("[Inventory] Uploading inventory files written from now on")
        elif self._thread:
            self.on_log("[Inventory] Inventory uploads OFF")

    def on_result(self, data: dict):
        """The server's answer for a file (called from the websocket thread)."""
        status = data.get("status", "")
        with self._lock:
            entry = self._pending.pop(data.get("msg_id", ""), None)
            if not entry:
                return
            path, mtime, _ = entry
            if status in _DONE:
                self._sent[path] = max(mtime, self._sent.get(path, 0))
                self._save()
            elif status == "no_account":
                self._no_account = True
            else:
                self._wait_until[path] = time.time() + RETRY_SECONDS
        who = data.get("character") or os.path.basename(path)
        self.on_log(f"[Inventory] {who}: {_SHOWN.get(status, status)}")

    # ─── Watching ─────────────────────────────

    def _run(self):
        while not self._stop.wait(POLL_SECONDS):
            try:
                self._scan()
            except Exception as e:
                self.on_log(f"[Inventory] Error: {e}")

    def _scan(self):
        with self._lock:
            if not self._enabled or self._no_account:
                return
            since = self._since
        now = time.time()
        for eq_dir in self.eq_dirs():
            for path in glob.glob(os.path.join(glob.escape(eq_dir), "*-Inventory*.txt")):
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                key = os.path.normcase(os.path.abspath(path))
                if st.st_mtime <= since:
                    continue
                if not self._due(key, st.st_mtime, now):
                    continue
                if st.st_size > MAX_BYTES:
                    if key not in self._too_big:
                        self._too_big.add(key)
                        self.on_log(f"[Inventory] Skipping {os.path.basename(path)}: too big for an inventory file")
                    continue
                self._upload(key, path, st)

    def _due(self, key: str, mtime: float, now: float) -> bool:
        """Whether this copy of the file still needs sending."""
        with self._lock:
            if self._sent.get(key, 0) >= mtime or self._wait_until.get(key, 0) > now:
                return False
            for msg_id, (path, sent_mtime, sent_at) in list(self._pending.items()):
                if path != key:
                    continue
                if sent_mtime >= mtime and now - sent_at < RESULT_WAIT:
                    return False   # still waiting to hear back
                del self._pending[msg_id]
            return True

    def _upload(self, key: str, path: str, st: os.stat_result):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            after = os.stat(path)
        except OSError as e:
            self.on_log(f"[Inventory] Couldn't read {os.path.basename(path)}: {e}")
            return
        if (after.st_mtime, after.st_size) != (st.st_mtime, st.st_size):
            return   # still being written; read again on the next pass
        mtime = st.st_mtime
        msg_id = self.send(os.path.basename(path), text, mtime)
        if not msg_id:
            return   # not connected; tried again on a later pass
        with self._lock:
            self._pending[msg_id] = (key, mtime, time.time())
        self.on_log(f"[Inventory] Sending {os.path.basename(path)}")

    # ─── Persistence ──────────────────────────

    def _load(self):
        try:
            with open(INVENTORY_STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._since = float(data.get("since", 0))
            self._sent  = {str(k): float(v) for k, v in (data.get("sent") or {}).items()}
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        """Write the state (with the lock held)."""
        try:
            tmp = INVENTORY_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"since": self._since, "sent": self._sent}, f, indent=1)
            os.replace(tmp, INVENTORY_STATE_FILE)
        except OSError as e:
            self.on_log(f"[Inventory] Couldn't save {INVENTORY_STATE_FILE}: {e}")
