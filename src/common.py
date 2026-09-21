"""
Shared framing / KDF / error utilities for the handshake implementations.

All handshake modes (classical, pqc, hybrid, signed, auth) speak the same
length-prefixed message framing over a raw TCP socket so that the
benchmark harness can time and byte-count them identically.

Hardening notes (added with the adversarial test-suite):
  * recv_msg() refuses frames larger than MAX_FRAME instead of trusting a
    peer-controlled 4-byte length prefix.
  * Every failure is a HandshakeError subclass carrying an `alert_code`, so
    "abort" is a defined behaviour rather than whatever exception happened
    to escape.
  * pack_fields()/unpack_fields() give strict, bounds-checked parsing.
"""
import os
import struct
import socket
from typing import Any, List, Protocol
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Largest single frame we will accept. Biggest legitimate frame in this
# project is an ML-DSA-87 signature (4627 B) or an auth ServerHello (~6.5 KB).
MAX_FRAME = 64 * 1024

# Alert codes sent to the peer when a handshake aborts.
ALERT_PROTOCOL = 0x01      # malformed / unexpected message
ALERT_AUTH = 0x02          # identity or signature check failed
ALERT_CONFIRM = 0x03       # key-confirmation (Finished) check failed
ALERT_NEGOTIATION = 0x04   # no acceptable suite
ALERT_INTERNAL = 0x05


class HandshakeError(Exception):
    """Base class for every handshake failure. Callers should treat any
    HandshakeError as 'no session key was established'."""
    alert_code = ALERT_INTERNAL


class ProtocolError(HandshakeError):
    alert_code = ALERT_PROTOCOL


class AuthenticationError(HandshakeError):
    alert_code = ALERT_AUTH


class KeyConfirmationError(HandshakeError):
    alert_code = ALERT_CONFIRM


class NegotiationError(HandshakeError):
    alert_code = ALERT_NEGOTIATION


class HandshakeTimeout(HandshakeError):
    pass


class TruncatedMessage(ProtocolError, ConnectionError):
    """Peer closed the socket before a full frame arrived. Also a
    ConnectionError so older callers that caught that keep working."""


class PeerAbort(HandshakeError):
    """The peer told us it aborted (received an alert frame)."""

    def __init__(self, code: int = -1):
        super().__init__(f"peer aborted handshake (alert code {code})")
        self.code = code


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
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout as e:
            raise HandshakeTimeout("timed out waiting for peer") from e
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
            raise TruncatedMessage("connection reset by peer") from e
        if not chunk:
            raise TruncatedMessage("socket closed before expected bytes arrived")
        buf += chunk
    return buf


def recv_msg(sock: SocketLike, max_len: int = MAX_FRAME) -> bytes:
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > max_len:
        # Refuse *before* reading: a hostile peer must not be able to make
        # us buffer up to 4 GiB by sending a large length prefix.
        raise ProtocolError(f"frame length {length} exceeds limit {max_len}")
    return recv_exact(sock, length)


def pack_fields(*fields: bytes) -> bytes:
    """Concatenate fields, each prefixed with a 2-byte big-endian length."""
    out = b""
    for f in fields:
        if len(f) > 0xFFFF:
            raise ValueError("field too large for 2-byte length prefix")
        out += struct.pack(">H", len(f)) + f
    return out


def unpack_fields(blob: bytes, n: int) -> List[bytes]:
    """Inverse of pack_fields. Strict: exactly n fields and no trailing bytes."""
    fields, pos = [], 0
    for _ in range(n):
        if pos + 2 > len(blob):
            raise ProtocolError("truncated field header")
        (flen,) = struct.unpack(">H", blob[pos : pos + 2])
        pos += 2
        if pos + flen > len(blob):
            raise ProtocolError("truncated field body")
        fields.append(blob[pos : pos + flen])
        pos += flen
    if pos != len(blob):
        raise ProtocolError("trailing bytes after last field")
    return fields


def hkdf_derive(
    key_material: bytes, info: bytes, length: int = 32, salt: bytes = None
) -> bytes:
    """Derive a symmetric key from raw shared secret material.

    `salt` is optional and defaults to None so the original modes derive
    exactly the same keys as before; the auth mode passes the transcript
    hash here to bind the key to everything both sides saw.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(key_material)


def rng_selfcheck() -> None:
    """Cheap tripwire for a broken OS randomness source. This is NOT an
    entropy-quality test (nothing at this layer can be) -- it only catches
    gross failures: os.urandom returning constants, zeros, or repeating."""
    a, b, c = os.urandom(32), os.urandom(32), os.urandom(32)
    if len({a, b, c}) != 3 or any(x == b"\x00" * 32 for x in (a, b, c)):
        raise RuntimeError("os.urandom failed sanity check (repeating or all-zero output)")


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
