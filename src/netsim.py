"""
Thin socket wrapper that simulates one-way network latency on top of the real
localhost TCP stack, without netem/tc or root network-namespace tricks.

Two delay models:

  "pipelined" (default, matches real networks)
      sendall() returns immediately; the bytes are delivered to the peer one
      one-way-delay later by a background thread. Back-to-back sends overlap,
      exactly like segments on a real link, so a burst of N messages costs ONE
      one-way delay, not N.

  "serial" (legacy, kept only to reproduce the original published CSV)
      sendall() sleeps for the delay *before every call*. Any protocol that
      sends k messages in a row is charged k x delay. That silently penalises
      protocols by message COUNT instead of by round trips: the original
      "signed mode costs an extra round trip" result was this artifact (the
      server sends 3 messages back-to-back -> 3 x delay, + 1 client message
      = 4 x delay, vs 2 x delay for classical).

Call close() (not just the underlying socket's) so queued data is flushed.
"""
import queue
import socket
import threading
import time
from typing import Any, Optional

MODELS = ("pipelined", "serial")


class DelayedSocket:
    """Wraps a socket.socket and delays outgoing data by one_way_delay_s."""

    def __init__(self, sock: socket.socket, one_way_delay_s: float = 0.0, model: str = "pipelined"):
        if model not in MODELS:
            raise ValueError(f"model must be one of {MODELS}")
        self._sock = sock
        self._delay = one_way_delay_s
        self._model = model
        self._q: Optional["queue.Queue"] = None
        self._worker: Optional[threading.Thread] = None
        self._send_error: Optional[BaseException] = None

    # -- sending -------------------------------------------------------------
    def sendall(self, data: Any, flags: int = 0, /) -> None:
        if self._delay <= 0:
            return self._sock.sendall(data)
        if self._model == "serial":
            time.sleep(self._delay)
            return self._sock.sendall(data)
        # pipelined: schedule delivery, return immediately
        if self._send_error is not None:
            raise self._send_error
        if self._q is None:
            self._q = queue.Queue()
            self._worker = threading.Thread(target=self._pump, daemon=True)
            self._worker.start()
        self._q.put((time.perf_counter() + self._delay, bytes(data)))

    def _pump(self) -> None:
        assert self._q is not None
        while True:
            item = self._q.get()
            if item is None:
                return
            deliver_at, data = item
            wait = deliver_at - time.perf_counter()
            if wait > 0:
                time.sleep(wait)
            try:
                self._sock.sendall(data)
            except BaseException as e:  # peer gone; surface on next send/close
                self._send_error = e
                return

    def flush(self) -> None:
        """Block until every queued byte has been handed to the real socket."""
        if self._q is not None and self._worker is not None:
            self._q.put(None)
            self._worker.join()
            self._q = self._worker = None

    # -- receiving / lifecycle -----------------------------------------------
    def recv(self, n: int, flags: int = 0, /) -> bytes:
        return self._sock.recv(n)

    def close(self):
        self.flush()
        self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)
