"""
updater.py — Replace the running exe with a newer GitHub release.

The server tells every client the latest client version. When that is newer
than this build, the GUI shows an update button, which calls download() on a
background thread and then apply_and_restart().

How the swap works without a helper script: Windows won't let a running exe be
overwritten, but it will let it be renamed. So the new exe is downloaded next
to the current one, the running exe is renamed to *.old, the new one takes its
name, and it is started before this process exits. The next start deletes the
*.old file. No batch or PowerShell file is written, since a script that
deletes and relaunches an exe is exactly what antivirus heuristics look for.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

from config import APP_NAME, APP_VERSION

CLIENT_REPO  = "panserbjorne/EQ-Guild-Chat-Client"
ASSET_NAME   = "guildChatClient.exe"   # the file the release workflow uploads
RELEASES_URL = f"https://github.com/{CLIENT_REPO}/releases/latest"
_API         = "https://api.github.com"
_TIMEOUT     = 30


def _parse(version: str) -> tuple[int, ...]:
    """'v0.5.1' -> (0, 5, 1); anything without digits -> ()."""
    return tuple(int(n) for n in re.findall(r"\d+", version or ""))


def is_newer(latest: str, current: str = APP_VERSION) -> bool:
    """True when the server's latest version is ahead of this build."""
    a, b = _parse(latest), _parse(current)
    if not a or not b:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def can_self_update() -> bool:
    """Only a built exe can replace itself; from source, send people to GitHub."""
    return bool(getattr(sys, "frozen", False)) and sys.platform == "win32"


def _old_path(exe: str) -> str:
    return exe + ".old"


def _new_path(exe: str) -> str:
    return exe + ".new"


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Accept":     "application/vnd.github+json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
    })
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        return json.load(resp)


def _find_asset(version: str) -> dict:
    """The release's exe asset. Tags are bare ('0.5.1') but allow 'v0.5.1' too."""
    bare = version.strip().lstrip("vV")
    for tag in (bare, f"v{bare}"):
        try:
            release = _get_json(f"{_API}/repos/{CLIENT_REPO}/releases/tags/{tag}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            raise
        for asset in release.get("assets", []):
            if asset.get("name", "").lower() == ASSET_NAME.lower():
                return asset
        raise RuntimeError(f"Release {tag} has no {ASSET_NAME}")
    raise RuntimeError(f"Release {bare} isn't on GitHub yet")


def download(version: str, on_progress: Callable[[str], None]) -> str:
    """Download the release exe next to the running one; returns its path.

    Checks the size and, when GitHub publishes one, the SHA-256 digest, so a
    cut-off or corrupted download never replaces a working exe.
    """
    exe   = sys.executable
    dest  = _new_path(exe)
    asset = _find_asset(version)
    url   = asset["browser_download_url"]
    size  = int(asset.get("size") or 0)
    want  = (asset.get("digest") or "").lower()   # "sha256:<hex>" on newer releases

    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    sha = hashlib.sha256()
    got = 0
    last_pct = -1
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp, open(dest, "wb") as f:
            while chunk := resp.read(256 * 1024):
                f.write(chunk)
                sha.update(chunk)
                got += len(chunk)
                if size:
                    pct = got * 100 // size
                    if pct != last_pct:
                        last_pct = pct
                        on_progress(f"Downloading {pct}%")
        if size and got != size:
            raise RuntimeError(f"Download incomplete ({got} of {size} bytes)")
        if want.startswith("sha256:") and sha.hexdigest() != want.split(":", 1)[1]:
            raise RuntimeError("Download didn't match the release's checksum")
        with open(dest, "rb") as f:
            if f.read(2) != b"MZ":
                raise RuntimeError("Download isn't a Windows program")
    except BaseException:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise
    return dest


def apply_and_restart(new_exe: str, before_launch: Callable[[], None]) -> None:
    """Swap the new exe into place and start it. The caller then quits.

    before_launch runs once the swap has worked, to let go of the game pipe
    and the server before the new copy starts. If the swap fails, the
    original exe is put back and before_launch never runs.
    """
    exe = sys.executable
    old = _old_path(exe)
    try:
        os.remove(old)
    except OSError:
        pass   # not there, or still locked by a previous run: os.replace overwrites

    os.replace(exe, old)
    try:
        os.replace(new_exe, exe)
    except OSError:
        os.replace(old, exe)
        raise

    before_launch()

    # A onefile exe hands its unpack folder to children through the
    # environment; a fresh copy must unpack its own.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("_PYI") and k != "_MEIPASS2"}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    try:
        subprocess.Popen([exe], cwd=os.getcwd(), env=env, close_fds=True,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    except OSError:
        # Couldn't start the new exe: put the old one back so the PC isn't
        # left with a client that won't open.
        os.replace(exe, new_exe)
        os.replace(old, exe)
        raise


def cleanup_old() -> None:
    """Delete the *.old exe a previous update left behind.

    The old process may still be exiting, so retry for a little while in the
    background instead of holding up start-up.
    """
    if not can_self_update():
        return
    exe = sys.executable

    def _run():
        path = _old_path(exe)
        for _ in range(30):
            if not os.path.exists(path):
                return
            try:
                os.remove(path)
                return
            except OSError:
                time.sleep(1)

    threading.Thread(target=_run, daemon=True, name="update-cleanup").start()
