"""
ws_client.py — Async WebSocket client running in a background thread.
"""

import asyncio
import json
import time
import threading
import uuid
from typing import Callable, Optional

import websockets

from config import (
    Config, APP_VERSION,
    MSG_TYPE_REGISTER,
    SRV_TYPE_STATS, SRV_TYPE_ACK, SRV_TYPE_AUTH_ERROR,
    SRV_TYPE_DUPLICATE_SESSION, SRV_TYPE_VERSION_NOTICE,
    SRV_KEY_CLIENTS, SRV_KEY_ACTIVE_SOURCE, SRV_KEY_VERSION,
)

# How long to wait for an ack before logging a warning (seconds)
ACK_TIMEOUT = 10

# Drop queued outgoing messages older than this (seconds) — avoids flooding
# the server with a backlog of stale chat lines after a long disconnect.
MESSAGE_MAX_AGE = 10


class WSClient:
    """
    Manages a persistent WebSocket connection to the bridge server.
    Runs its own asyncio event loop in a daemon thread so it never
    blocks the Tkinter main thread.

    On connect, sends a 'register' handshake. Handles typed server
    messages including auth errors, duplicate session rejection, stats
    broadcasts, version notices, and message acks.

    Callbacks
    ---------
    on_log(text)
    on_status(text)
    on_server_broadcast(data: dict)
        Called for 'stats' messages with the full data dict.
    on_fatal(reason: str)
        Called when the server rejects the connection permanently
        (auth error or duplicate session). The client will stop
        reconnecting and the GUI should surface this prominently.
    """

    def __init__(
        self,
        config:              Config,
        on_log:              Callable[[str], None],
        on_status:           Callable[[str], None],
        on_server_broadcast: Callable[[dict], None],
        on_fatal:            Callable[[str], None],
        character:           str = "",
    ):
        self.config              = config
        self.on_log              = on_log
        self.on_status           = on_status
        self.on_server_broadcast = on_server_broadcast
        self.on_fatal            = on_fatal
        self.character           = character   # updated by GUI as character changes

        self._loop:         Optional[asyncio.AbstractEventLoop] = None
        self._thread:       Optional[threading.Thread]          = None
        self._running:      bool                                = False
        self._send_queue:   Optional[asyncio.Queue]             = None
        self._stop_event:   Optional[asyncio.Event]             = None
        # Set once _loop/_stop_event/_send_queue are initialized, so stop()
        # called right after start() can't race ahead of the new thread.
        self._ready:        threading.Event                     = threading.Event()

        # Pending acks: msg_id → (timestamp, payload_preview)
        self._pending_acks: dict[str, tuple[float, str]]        = {}
        self._acks_lock:    threading.Lock                      = threading.Lock()

    # ─── Public API ───────────────────────────

    def start(self):
        self._ready.clear()
        self._running = True
        self._thread  = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the asyncio loop to exit gracefully, then join the thread."""
        self._running = False
        if self._ready.wait(timeout=2) and self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def send(self, msg_type: str, message: str, is_sender: bool = False):
        """Queue an outgoing message (thread-safe). Includes character, timestamp, client_id.
        is_sender=True indicates this client's character typed the message (GUILD_TX),
        so the server can use it as the canonical version for deduplication.
        """
        if self._loop and self._loop.is_running() and self._send_queue:
            msg_id  = str(uuid.uuid4())
            queued_at = time.time()
            payload = json.dumps({
                "msg_type":  msg_type,
                "message":   message,
                "character": self.character,
                "client_id": self.config.client_id,
                "timestamp": queued_at,
                "msg_id":    msg_id,
                "is_sender": is_sender,
            })
            with self._acks_lock:
                self._pending_acks[msg_id] = (queued_at, f"{msg_type}: {message[:60]}")
            self._loop.call_soon_threadsafe(self._send_queue.put_nowait, (queued_at, payload))

    # ─── Event loop ───────────────────────────

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._send_queue = asyncio.Queue()
        self._stop_event = asyncio.Event()
        self._ready.set()
        try:
            self._loop.run_until_complete(self._main())
        finally:
            self._loop.close()

    async def _main(self):
        connect_task = asyncio.ensure_future(self._connect_loop())
        stop_task    = asyncio.ensure_future(self._stop_event.wait())
        ack_task     = asyncio.ensure_future(self._ack_watchdog())

        _, pending = await asyncio.wait(
            [connect_task, stop_task, ack_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _connect_loop(self):
        while self._running:
            url     = self.config.server_address
            headers = {"X-API-Key": self.config.api_key} if self.config.api_key else {}
            self.on_status("Connecting…")
            try:
                async with websockets.connect(url, additional_headers=headers) as ws:
                    # Send registration handshake immediately on connect
                    await self._send_register(ws)
                    self.on_status("Connected")
                    self.on_log(f"[WS] Connected to {url}")
                    recv_task = asyncio.ensure_future(self._recv_loop(ws))
                    send_task = asyncio.ensure_future(self._send_loop(ws))
                    try:
                        done, pending = await asyncio.wait(
                            [recv_task, send_task],
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        for task in pending:
                            task.cancel()
                            try:
                                await task
                            except asyncio.CancelledError:
                                pass
                        for task in done:
                            if not task.cancelled() and task.exception():
                                raise task.exception()
                    finally:
                        recv_task.cancel()
                        send_task.cancel()
            except Exception as e:
                self.on_log(f"[WS] Connection error: {e}")
                self.on_status("Disconnected — retrying in 5s…")
                await asyncio.sleep(5)

    async def _send_register(self, ws):
        """Send the initial registration/handshake message."""
        payload = json.dumps({
            "msg_type":  MSG_TYPE_REGISTER,
            "client_id": self.config.client_id,
            "character": self.character,
            "version":   APP_VERSION,
            "timestamp": time.time(),
        })
        await ws.send(payload)
        self.on_log(f"[WS] Registered as client_id={self.config.client_id[:8]}…")

    async def _recv_loop(self, ws):
        async for raw in ws:
            try:
                self._handle_server_message(json.loads(raw))
            except Exception as e:
                self.on_log(f"[WS] Bad server message: {e}")

    def _handle_server_message(self, data: dict):
        msg_type = data.get("type", "")

        if msg_type == SRV_TYPE_STATS:
            self.on_server_broadcast(data)

        elif msg_type == SRV_TYPE_ACK:
            msg_id = data.get("msg_id", "")
            with self._acks_lock:
                self._pending_acks.pop(msg_id, None)

        elif msg_type == SRV_TYPE_DUPLICATE_SESSION:
            reason = data.get("reason", "Another client with this API key is already connected.")
            self.on_log(f"[WS] DUPLICATE SESSION: {reason}")
            self.on_fatal(f"Duplicate session detected.\n\n{reason}\n\nClose the other instance and restart.")
            self._running = False

        elif msg_type == SRV_TYPE_AUTH_ERROR:
            reason = data.get("reason", "Authentication failed.")
            self.on_log(f"[WS] AUTH ERROR: {reason}")
            self.on_fatal(f"Authentication failed.\n\n{reason}\n\nCheck your API key in Settings.")
            self._running = False

        elif msg_type == SRV_TYPE_VERSION_NOTICE:
            self.on_log(f"[WS] Version notice: {data.get('message', '')}")

        else:
            # Unknown message type — log it for debugging
            self.on_log(f"[WS] Unknown server message type: {msg_type!r}")

    async def _send_loop(self, ws):
        try:
            while True:
                queued_at, payload = await self._send_queue.get()
                if time.time() - queued_at > MESSAGE_MAX_AGE:
                    self.on_log(f"[WS] Dropping stale queued message (>{MESSAGE_MAX_AGE}s old)")
                    continue
                try:
                    await ws.send(payload)
                    self.on_log(f"[WS] Sent: {payload}")
                except Exception as e:
                    self.on_log(f"[WS] Send error: {e} — requeueing message")
                    # Put it back at the front so it's retried on reconnect
                    await self._send_queue.put((queued_at, payload))
                    raise  # propagate to trigger reconnect
        except asyncio.CancelledError:
            pass

    async def _ack_watchdog(self):
        """Periodically warn about messages that haven't been acked."""
        try:
            while True:
                await asyncio.sleep(5)
                now = time.time()
                with self._acks_lock:
                    stale = [
                        (msg_id, preview) for msg_id, (sent_at, preview) in self._pending_acks.items()
                        if now - sent_at > ACK_TIMEOUT
                    ]
                    for msg_id, _ in stale:
                        del self._pending_acks[msg_id]
                for _, preview in stale:
                    self.on_log(f"[WS] WARNING: No ack received for '{preview}' after {ACK_TIMEOUT}s")
        except asyncio.CancelledError:
            pass