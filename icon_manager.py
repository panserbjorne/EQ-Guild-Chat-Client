"""
icon_manager.py -- Loads status-variant tray icons for EQ Guild Chat Client.

When running as a PyInstaller bundle, icons are loaded from the embedded
bundle (sys._MEIPASS). When running from source, they are loaded from the
icon directory alongside the script.

Pre-generate the variant icons before building:
    python generate_icons.py

Usage
-----
    import icon_manager
    icon_manager.init("icons", "icon.png")
    img = icon_manager.get_icon("green")   # PIL Image
"""

import os
import sys
from PIL import Image

_icon_dir:  str = "icons"
_icon_name: str = "icon.png"
_cache:     dict = {}


def init(icon_dir: str, icon_name: str) -> None:
    """Call at startup. Loads all variant icons into memory."""
    global _icon_dir, _icon_name
    _icon_dir  = icon_dir
    _icon_name = icon_name
    _load_variants()


def get_icon(status: str) -> Image.Image:
    """Return a PIL Image for the given status: 'red' | 'yellow' | 'green'."""
    if status not in _cache:
        return _fallback_image(status)
    return _cache[status].copy()


# ---- Path helpers ------------------------------------------------------------

def _resource_dir() -> str:
    """
    When frozen (PyInstaller bundle), icons are in sys._MEIPASS.
    When running from source, they are next to this file.
    """
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _variant_path(suffix: str) -> str:
    name, ext = os.path.splitext(_icon_name)
    return os.path.join(_resource_dir(), _icon_dir, f"{name}_{suffix}{ext}")


# ---- Loading ----------------------------------------------------------------

_SUFFIXES = {"red": "r", "yellow": "y", "green": "g"}


def _load_variants() -> None:
    _cache.clear()
    for status, suffix in _SUFFIXES.items():
        path = _variant_path(suffix)
        if os.path.exists(path):
            try:
                _cache[status] = Image.open(path).convert("RGBA")
            except Exception as e:
                print(f"[IconManager] Could not load {path}: {e}")
        else:
            print(f"[IconManager] Missing icon: {path} — using fallback")


def _fallback_image(status: str) -> Image.Image:
    """Plain coloured circle used when no icon file is available."""
    from PIL import ImageDraw
    colours = {"red": "#C0392B", "yellow": "#D4A017", "green": "#27AE60"}
    colour  = colours.get(status, "#888888")
    size    = 74
    img     = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw    = ImageDraw.Draw(img)
    draw.ellipse([2, 2, size - 3, size - 3], fill=colour)
    return img