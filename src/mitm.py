"""
Active man-in-the-middle tooling for the adversarial tests. Test-only.

MitmProxy sits between a client and a server, parses the project's
length-prefixed frames, logs every one, and lets a *policy* function decide
what actually gets forwarded:

    policy(direction, index, frame) -> list[bytes]

    direction : "c2s" (client -> server) or "s2c"
    index     : 0-based frame number within that direction
    frame     : the frame payload (without its 4-byte length prefix)
    returns   : frames to forward. [frame] = pass through, [] = drop,
                [a, b] = inject an extra frame, [mutated] = tamper.
                Raise KillConnection to slam both sockets shut.

Frames are re-framed with a correct length prefix after mutation, so this
models payload-level tampering. (Length-prefix abuse is tested separately
against recv_msg() directly in test_correctness.py.)

ReplayServer plays back a previously recorded server flight to a new client,
which is how the replay-attack tests are driven.
"""
import socket
import threading
from typing import Callable, List, Optional, Tuple

from common import send_msg, recv_msg

Policy = Callable[[str, int, bytes], List[bytes]]


class KillConnection(Exception):
    """Raised by a policy to abruptly close both sides."""


def passthrough(direction: str, index: int, frame: bytes) -> List[bytes]:
    return [frame]


def _on(direction: str, index: int, fn) -> Policy:
    def policy(d, i, frame):
        return fn(frame) if (d == direction and i == index) else [frame]
    return policy


def flip_bit(direction: str, index: int, offset: int, bit: int = 0) -> Policy:
    """Flip one bit at `offset`: an int (negative counts from the end) or the
    strings "mid" / "last" (resolved against the actual frame length)."""
    def fn(frame):
        b = bytearray(frame)
        if offset == "mid":
            i = len(b) // 2
        elif offset == "last":
            i = len(b) - 1
        else:
            i = offset % len(b)
        b[i] ^= 1 << bit
        return [bytes(b)]
    return _on(direction, index, fn)


def replace_frame(direction: str, index: int, new) -> Policy:
    """Replace a frame with `new` (bytes, or callable(frame) -> bytes)."""
    return _on(direction, index, lambda f: [new(f) if callable(new) else new])


def drop_frame(direction: str, index: int) -> Policy:
    return _on(direction, index, lambda f: [])


def kill_at(direction: str, index: int) -> Policy:
    def fn(frame):
        raise KillConnection()
    return _on(direction, index, fn)


class MitmProxy:
    def __init__(self, target_port: int, policy: Optional[Policy] = None,
                 host: str = "127.0.0.1", timeout: float = 5.0):
        self.target = (host, target_port)
        self.policy = policy or passthrough
        self.timeout = timeout
        self.log: List[Tuple[str, int, bytes]] = []  # every ORIGINAL frame seen
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind((host, 0))
        self._lsock.listen(1)
        self._lsock.settimeout(timeout)
        self.port = self._lsock.getsockname()[1]
        self._socks: List[socket.socket] = []
        self._threads: List[threading.Thread] = []
        self._lock = threading.Lock()

    def start(self) -> int:
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        self._threads.append(t)
        return self.port

    def frames(self, direction: str) -> List[bytes]:
        return [f for d, _, f in self.log if d == direction]

    def _run(self) -> None:
        try:
            client, _ = self._lsock.accept()
            server = socket.create_connection(self.target, timeout=self.timeout)
        except OSError:
            return
        for s in (client, server):
            s.settimeout(self.timeout)
            self._socks.append(s)
        for args in (("c2s", client, server), ("s2c", server, client)):
            t = threading.Thread(target=self._pump, args=args, daemon=True)
            t.start()
            self._threads.append(t)

    def _pump(self, direction: str, src: socket.socket, dst: socket.socket) -> None:
        index = 0
        try:
            while True:
                frame = recv_msg(src)
                with self._lock:
                    self.log.append((direction, index, frame))
                out = self.policy(direction, index, frame)
                index += 1
                for f in out:
                    send_msg(dst, f)
        except BaseException:
            pass  # EOF, timeout, KillConnection, peer reset: all end the relay
        finally:
            self.close()

    def close(self) -> None:
        for s in self._socks + [self._lsock]:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


class ReplayServer:
    """Accepts one connection, immediately sends the recorded server frames,
    then swallows whatever the client sends until it disconnects."""

    def __init__(self, frames: List[bytes], host: str = "127.0.0.1", timeout: float = 5.0):
        self.frames = frames
        self.timeout = timeout
        self._lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lsock.bind((host, 0))
        self._lsock.listen(1)
        self._lsock.settimeout(timeout)
        self.port = self._lsock.getsockname()[1]
        self.client_frames: List[bytes] = []

    def start(self) -> int:
        threading.Thread(target=self._run, daemon=True).start()
        return self.port

    def _run(self) -> None:
        try:
            conn, _ = self._lsock.accept()
            conn.settimeout(self.timeout)
            for f in self.frames:
                send_msg(conn, f)
            while True:
                self.client_frames.append(recv_msg(conn))
        except BaseException:
            pass
        finally:
            try:
                self._lsock.close()
            except OSError:
                pass
