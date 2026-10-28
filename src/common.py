"""
Shared framing / KDF utilities for the handshake implementations.

All three handshake modes (classical, pqc, hybrid) speak the same
length-prefixed message framing over a raw TCP socket so that the
benchmark harness can time and byte-count them identically.
"""
import struct
from typing import Any, Protocol
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAX_FRAME_BYTES = 64 * 1024


class ProtocolError(ValueError):
    pass


class SocketLike(Protocol):
    def sendall(self, data: Any, flags: int = 0, /) -> None:
        ...

    def recv(self, n: int, flags: int = 0, /) -> bytes:
        ...


def send_msg(sock: SocketLike, data: bytes) -> int:
    """Send a length-prefixed message. Returns total bytes written on the wire."""
    if not 0 < len(data) <= MAX_FRAME_BYTES:
        raise ProtocolError("frame size outside allowed range")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)
    return len(header) + len(data)


def recv_exact(sock: SocketLike, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed before expected bytes arrived")
        buf.extend(chunk)
    return bytes(buf)


def recv_msg(sock: SocketLike) -> bytes:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if not 0 < length <= MAX_FRAME_BYTES:
        raise ProtocolError("frame size outside allowed range")
    return recv_exact(sock, length)


def pack_fields(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(field)) + field for field in fields)


def unpack_fields(data: bytes, count: int) -> tuple[bytes, ...]:
    fields = []
    offset = 0
    for _ in range(count):
        if offset + 4 > len(data):
            raise ProtocolError("truncated field header")
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if not 0 < length <= MAX_FRAME_BYTES or offset + length > len(data):
            raise ProtocolError("invalid field size")
        fields.append(data[offset:offset + length])
        offset += length
    if offset != len(data):
        raise ProtocolError("unexpected trailing data")
    return tuple(fields)


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
