"""
Shared test harness: run any handshake mode end-to-end over real TCP sockets,
optionally through an active MITM, and capture *everything* about the outcome
(keys, exceptions, frames seen on the wire, byte counters, wall time).

Test-only; bench.py has its own timing-focused loop.
"""
import functools
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

import pytest

import handshake_classical
import handshake_pqc
import handshake_hybrid
import handshake_signed
import handshake_auth
from common import ByteCounter
from mitm import MitmProxy, Policy
from oqs_compat import REAL_OQS

SIG_MECHANISM = "ML-DSA-65"

# Modes that need real ML-KEM / ML-DSA (the fallback shim is not cryptography).
requires_real = pytest.mark.skipif(
    not REAL_OQS, reason="needs real liboqs (ML-KEM + ML-DSA); only the fallback shim is available"
)


@functools.lru_cache(maxsize=None)
def default_identity() -> "handshake_auth.ServerIdentity":
    """One long-term identity per test session (keygen is not the point)."""
    return handshake_auth.ServerIdentity.generate(SIG_MECHANISM)


@dataclass
class Outcome:
    client_key: Optional[bytes] = None
    server_key: Optional[bytes] = None
    client_exc: Optional[BaseException] = None
    server_exc: Optional[BaseException] = None
    client_result: Any = None          # HandshakeResult for auth mode
    server_result: Any = None
    frames: List[tuple] = field(default_factory=list)   # (direction, index, frame) as sent
    client_counter: ByteCounter = field(default_factory=ByteCounter)
    server_counter: ByteCounter = field(default_factory=ByteCounter)
    elapsed: float = 0.0

    @property
    def aborted(self) -> bool:
        """At least one side refused to complete."""
        return self.client_exc is not None or self.server_exc is not None

    @property
    def both_completed(self) -> bool:
        return self.client_key is not None and self.server_key is not None

    @property
    def keys_diverged(self) -> bool:
        return self.both_completed and self.client_key != self.server_key

    def frames_in(self, direction: str) -> List[bytes]:
        return [f for d, _, f in self.frames if d == direction]


def _server_call(mode, conn, counter, mechanism, identity, suites, require_pq):
    if mode == "classical":
        return handshake_classical.server_handshake(conn, counter), None
    if mode == "pqc":
        return handshake_pqc.server_handshake(conn, counter, mechanism), None
    if mode == "hybrid":
        return handshake_hybrid.server_handshake(conn, counter, mechanism), None
    if mode == "signed":
        return handshake_signed.server_handshake(conn, counter, mechanism, SIG_MECHANISM), None
    if mode == "auth":
        kwargs = {"identity": identity or default_identity(), "require_pq": require_pq}
        if suites is not None:
            kwargs["suites"] = suites
        r = handshake_auth.server_handshake_ex(conn, counter, mechanism, **kwargs)
        return r.key, r
    raise ValueError(mode)


def _client_call(mode, conn, counter, mechanism, trusted_pk, offer):
    if mode == "classical":
        return handshake_classical.client_handshake(conn, counter), None
    if mode == "pqc":
        return handshake_pqc.client_handshake(conn, counter, mechanism), None
    if mode == "hybrid":
        return handshake_hybrid.client_handshake(conn, counter, mechanism), None
    if mode == "signed":
        return handshake_signed.client_handshake(conn, counter, mechanism, SIG_MECHANISM), None
    if mode == "auth":
        kwargs = {"trusted_sig_pk": trusted_pk or default_identity().public_key}
        if offer is not None:
            kwargs["offer"] = offer
        r = handshake_auth.client_handshake_ex(conn, counter, mechanism, **kwargs)
        return r.key, r
    raise ValueError(mode)


def run_handshake(
    mode: str,
    mechanism: str = "ML-KEM-768",
    *,
    policy: Optional[Policy] = None,
    timeout: float = 3.0,
    client_timeout: Optional[float] = None,   # shorter client-side timeout, to test the client's own timeout path
    server_identity=None,     # auth: identity the *server* uses (default: the trusted one)
    trusted_pk: Optional[bytes] = None,   # auth: key the *client* has pinned
    client_offer=None,        # auth: suites the client offers
    server_suites=None,       # auth: suites the server supports (preference order)
    require_pq: bool = False,
    connect_to_port: Optional[int] = None,  # e.g. a ReplayServer instead of the real server
) -> Outcome:
    out = Outcome()
    ready = threading.Event()
    port_holder: List[int] = []
    if mode == "auth":
        # Resolve identities on THIS thread before any thread starts. (lru_cache
        # is not single-flight: two threads hitting a cold cache would each mint
        # a different identity and the client would -- correctly -- reject it.)
        server_identity = server_identity or default_identity()
        trusted_pk = trusted_pk or default_identity().public_key

    def server():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(timeout)
        port_holder.append(srv.getsockname()[1])
        ready.set()
        conn = None
        try:
            conn, _ = srv.accept()
            conn.settimeout(timeout)
            out.server_key, out.server_result = _server_call(
                mode, conn, out.server_counter, mechanism, server_identity, server_suites, require_pq
            )
        except BaseException as e:
            out.server_exc = e
        finally:
            if conn is not None:
                conn.close()
            srv.close()

    t0 = time.perf_counter()
    st = threading.Thread(target=server, daemon=True)
    proxy = None
    if connect_to_port is None:
        st.start()
        ready.wait()
        target_port = port_holder[0]
        if policy is not None:
            proxy = MitmProxy(target_port, policy, timeout=timeout)
            target_port = proxy.start()
    else:
        target_port = connect_to_port   # no real server in this scenario

    cs = socket.create_connection(("127.0.0.1", target_port), timeout=timeout)
    cs.settimeout(client_timeout or timeout)
    try:
        out.client_key, out.client_result = _client_call(
            mode, cs, out.client_counter, mechanism, trusted_pk, client_offer
        )
    except BaseException as e:
        out.client_exc = e
    finally:
        cs.close()
    if connect_to_port is None:
        st.join(timeout + 2)
    out.elapsed = time.perf_counter() - t0
    if proxy is not None:
        proxy.close()
        out.frames = list(proxy.log)
    return out


def record_flights(mode: str, mechanism: str = "ML-KEM-768", **kwargs) -> Outcome:
    """A clean, un-tampered run through a passthrough proxy, to capture frames."""
    from mitm import passthrough
    return run_handshake(mode, mechanism, policy=passthrough, **kwargs)
