"""
config.py — App constants and Config (YAML persistence)
"""

import os
import re
import uuid

import yaml

# ─────────────────────────────────────────────
# App info
# ─────────────────────────────────────────────

APP_NAME    = "EQ Guild Chat Client"
APP_VERSION = "0.4.0"
CONFIG_FILE = "config.yaml"

# ─────────────────────────────────────────────
# Zeal pipe constants
# ─────────────────────────────────────────────

# Outer packet types (top-level "type" field in Zeal JSON)
ZEAL_PACKET_CHAT  = 0   # single chat message
ZEAL_PACKET_STATS = 1   # combined stats array (HP, mana, target, etc.)

# Inner channel type IDs (the "type" field inside "data" for chat packets)
ZEAL_TYPE_YELLOW   = 15    # yellow text (quake / pvp announcements)
ZEAL_TYPE_GUILD_RX = 259   # guild chat received
ZEAL_TYPE_DEFAULT  = 273   # default text (time)
ZEAL_TYPE_WHO      = 281   # /who results
ZEAL_TYPE_GUILD_TX = 310   # guild chat sent by us

# Inner type IDs within the stats array (outer type 1)
ZEAL_STAT_HP_PCT    = 19   # HP percent
ZEAL_STAT_MANA_PCT  = 20   # mana percent
ZEAL_STAT_TARGET    = 28   # target name
ZEAL_STAT_TARGET_HP = 29   # target HP percent

# ─────────────────────────────────────────────
# Server → client message types
# ─────────────────────────────────────────────

SRV_TYPE_STATS             = "stats"
SRV_TYPE_ACK               = "ack"
SRV_TYPE_AUTH_ERROR        = "auth_error"
SRV_TYPE_DUPLICATE_SESSION = "duplicate_session"
SRV_TYPE_VERSION_NOTICE    = "version_notice"

# Keys inside the "stats" message
SRV_KEY_CLIENTS       = "connected"
SRV_KEY_ACTIVE_SOURCE = "active_source"
SRV_KEY_VERSION       = "latest_client_version"

# ─────────────────────────────────────────────
# Client → server message types
# ─────────────────────────────────────────────

MSG_TYPE_REGISTER = "register"   # sent once on connect
MSG_TYPE_GUILD    = "guild"
MSG_TYPE_PVP      = "pvp"
MSG_TYPE_QUAKE    = "quake"
MSG_TYPE_TIME     = "time"
MSG_TYPE_WHO      = "who"

# ─────────────────────────────────────────────
# Yellow-text filter patterns
# ─────────────────────────────────────────────

RE_QUAKE = re.compile(
    r"(^The next earthquake|EARTHQUAKE|earth quake|the earth trembles)",
    re.IGNORECASE,
)
RE_PVP = re.compile(r"^\[?PVP\]?", re.IGNORECASE)
RE_TIME_INGAME = re.compile(r"^It is \d+ (?:AM|PM) on [A-Z][a-z]+, the \d+(?:st|nd|th) day of [A-Z][a-z]+, of the year \d+\.$")

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

class Config:
    """Loads and saves application settings to config.yaml."""

    def __init__(self):
        self.server_address:  str       = "ws://localhost:8765"
        self.api_key:         str       = ""
        self.client_id:       str       = ""
        self.whitelist:       list[str] = []
        self.blacklist:       list[str] = []
        self.start_minimized: bool      = False
        self.icon_dir:        str       = "icons"
        self.icon_name:       str       = "icon.png"
        self._load()

    # ─── Persistence ──────────────────────────

    def _load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            except Exception:
                data = {}

            srv  = data.get("server",     {})
            app  = data.get("app",        {})
            char = data.get("characters", {})

            self.server_address  = srv.get("address",        self.server_address)
            self.api_key         = srv.get("api_key",         self.api_key)
            self.client_id       = srv.get("client_id",       "")
            self.start_minimized = bool(app.get("start_minimized", self.start_minimized))
            self.icon_dir        = app.get("icon_dir",        self.icon_dir)
            self.icon_name       = app.get("icon_name",       self.icon_name)
            self.whitelist       = list(char.get("whitelist", []) or [])
            self.blacklist       = list(char.get("blacklist", []) or [])

        if not self.client_id:
            self.client_id = str(uuid.uuid4())
            self.save()

    def save(self):
        data = {
            "server": {
                "address":   self.server_address,
                "api_key":   self.api_key,
                "client_id": self.client_id,
            },
            "app": {
                "start_minimized": self.start_minimized,
                "icon_dir":        self.icon_dir,
                "icon_name":       self.icon_name,
            },
            "characters": {
                "whitelist": self.whitelist,
                "blacklist": self.blacklist,
            },
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)