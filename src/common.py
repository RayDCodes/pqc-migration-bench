"""
Shared framing / KDF utilities for the handshake implementations.

All three handshake modes (classical, pqc, hybrid) speak the same
length-prefixed message framing over a raw TCP socket so that the
benchmark harness can time and byte-count them identically.
"""
import struct
import socket
from typing import Any, Protocol
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class SocketLike(Protocol):
    def sendall(self, data: Any, flags: int = 0, /) -> None:
        ...

    def recv(self, n: int, flags: int = 0, /) -> bytes:
        ...


def send_msg(sock: SocketLike, data: bytes) -> int:
    """Send a length-prefixed message. Returns total bytes written on the wire."""
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)
    return len(header) + len(data)


def recv_exact(sock: SocketLike, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before expected bytes arrived")
        buf += chunk
    return buf


def recv_msg(sock: SocketLike) -> bytes:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    return recv_exact(sock, length)


def hkdf_derive(key_material: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a symmetric session key from raw shared secret material."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(key_material)


class ByteCounter:
    """Tiny mutable counter passed into handshake functions so callers can
    read back exactly how many bytes crossed the wire in each direction."""

    def __init__(self):
        self.sent = 0
        self.received = 0

    def note_send(self, n: int):
        self.sent += n

    def note_recv(self, n: int):
        self.received += n
