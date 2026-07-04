"""
Thin socket wrapper that sleeps for a configurable delay before every
send() call, to simulate one-way network latency on top of the real
localhost TCP stack. This lets the benchmark show what handshake cost
looks like under real-world RTTs (same-datacenter, cross-region,
mobile) instead of just idealized loopback numbers, without needing
netem/tc or root network namespace tricks.
"""
import socket
import time
from typing import Any


class DelayedSocket:
    """Wraps a socket.socket; delays every sendall() by one_way_delay_s."""

    def __init__(self, sock: socket.socket, one_way_delay_s: float = 0.0):
        self._sock = sock
        self._delay = one_way_delay_s

    def sendall(self, data: Any, flags: int = 0, /) -> None:
        if self._delay > 0:
            time.sleep(self._delay)
        return self._sock.sendall(data)

    def recv(self, n: int, flags: int = 0, /) -> bytes:
        return self._sock.recv(n)

    def close(self):
        self._sock.close()

    def __getattr__(self, name):
        return getattr(self._sock, name)
