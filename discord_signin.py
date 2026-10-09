"""
discord_signin.py — Sign the client in with Discord.

The client asks the bridge server for a sign-in link, opens it in the
browser, and waits on the same WebSocket while the member approves this PC
on the web page. The server then sends a token for this PC, which the client
uses in place of an API key.

    → connect with an X-Pair-Device header and no key
    ← {"type": "pair_code", "url": "https://…/client/link?code=…", "expires_in": 600}
    ← {"type": "paired", "token": "…", "name": "<member>"}
    ← {"type": "pair_error", "reason": "…"}
"""

import asyncio
import json
import threading
from typing import Callable, Optional

import websockets

from config import SRV_TYPE_AUTH_ERROR

SRV_TYPE_PAIR_CODE  = "pair_code"
SRV_TYPE_PAIRED     = "paired"
SRV_TYPE_PAIR_ERROR = "pair_error"


class DiscordSignIn:
    """
    Runs one sign-in attempt in a background thread.

    Callbacks (called from the background thread)
    ---------
    on_url(url)               the sign-in page to open in the browser
    on_done(token, name)      approved; save the token and reconnect with it
    on_error(reason)          refused, expired, or the server couldn't be reached
    """

    def __init__(
        self,
        server_address: str,
        on_url:   Callable[[str], None],
        on_done:  Callable[[str, str], None],
        on_error: Callable[[str], None],
    ):
        self.server_address = server_address
        self.on_url   = on_url
        self.on_done  = on_done
        self.on_error = on_error

        self._loop:      Optional[asyncio.AbstractEventLoop] = None
        self._ws         = None
        self._cancelled: bool                                = False
        self._thread:    Optional[threading.Thread]          = None

    def start(self):
        self._thread = threading.Thread(target=self._run_thread, daemon=True)
        self._thread.start()

    def cancel(self):
        """Stop waiting; no callback fires after this."""
        self._cancelled = True
        loop, ws = self._loop, self._ws
        if loop and ws and loop.is_running():
            asyncio.run_coroutine_threadsafe(ws.close(), loop)

    def _run_thread(self):
        try:
            asyncio.run(self._run())
        except Exception as e:
            self._fail(f"Couldn't reach the server: {e}")

    async def _run(self):
        self._loop = asyncio.get_running_loop()
        # Not the computer's name: Windows often names a PC after its owner
        headers = {"X-Pair-Device": "desktop client"}
        async with websockets.connect(self.server_address, additional_headers=headers,
                                      open_timeout=15) as ws:
            self._ws = ws
            if self._cancelled:
                return
            async for raw in ws:
                try:
                    data = json.loads(raw)
                except Exception:
                    continue
                kind = data.get("type", "")
                if kind == SRV_TYPE_PAIR_CODE:
                    if not self._cancelled:
                        self.on_url(str(data.get("url", "")))
                elif kind == SRV_TYPE_PAIRED:
                    if not self._cancelled:
                        self.on_done(str(data.get("token", "")), str(data.get("name", "")))
                    return
                elif kind == SRV_TYPE_PAIR_ERROR:
                    self._fail(str(data.get("reason", "Sign-in failed.")))
                    return
                elif kind == SRV_TYPE_AUTH_ERROR:
                    # A server from before Discord sign-in treats this as a bad API key
                    self._fail("This server doesn't support signing in with Discord yet. "
                               "Use an API key instead.")
                    return
        self._fail("The server closed the sign-in before it was approved.")

    def _fail(self, reason: str):
        if not self._cancelled:
            self.on_error(reason)
