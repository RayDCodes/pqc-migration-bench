"""
Hardened authenticated handshake ("auth" mode).

handshake_signed.py (the "signed" / v1 mode) proves that a signature covers
a KEM key, but it has no trust anchor: the ML-DSA public key that verifies
the signature arrives *in the same flight* as the signature, so an active
attacker just generates their own ML-DSA key pair and the client accepts it.
It also has no freshness, no transcript binding, no key confirmation and
no negotiation. This module fixes all of that, and is what the adversarial
test-suite (test_adversarial.py) holds to a security standard.

Shape (TLS 1.3-like; client sends its key shares first):

    C -> S  ClientHello   : client_random || offered suites, each with a key share
    S -> C  ServerHello   : server_random || chosen suite || identity_pk ||
                            key-exchange response || signature || Finished_S
    C -> S  ClientFinished: Finished_C

  * PINNED IDENTITY   The client is constructed with `trusted_sig_pk`. A
    ServerHello whose identity key differs is rejected before anything else.
    (Real TLS gets this from a certificate chain; sending the key in-band and
    comparing it to a pinned value is the minimal equivalent and keeps the
    on-wire cost of carrying an ML-DSA public key in the measurement.)
  * TRANSCRIPT BINDING   The server signs H(ClientHello || ServerHello-body).
    Anything an attacker changed in either message (including the list of
    offered suites) makes that hash differ on the two sides -> signature
    fails -> abort. That is what makes downgrade stripping detectable.
  * FRESHNESS   client_random is inside the signed transcript, so a recorded
    ServerHello cannot be replayed to a new ClientHello.
  * KEY CONFIRMATION   Finished_S / Finished_C are HMACs over the transcript
    under keys derived from the shared secret. A ciphertext that was mangled
    in transit (ML-KEM "implicit rejection" hides it otherwise) surfaces here.
  * AUTHENTICATE BEFORE DECAPSULATE   The client verifies identity+signature
    before touching the server's ciphertext.
  * ABORT   Any HandshakeError sends a one-byte-code alert, closes out, and
    re-raises; no session key is ever returned from a failed handshake.

The KEM mechanism (e.g. ML-KEM-768) is configuration, not negotiated; it is
mixed into the key derivation so a mismatch cannot silently agree.
"""
import hashlib
import hmac
import os
import socket
import struct
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from common import (
    SocketLike,
    ByteCounter,
    HandshakeError,
    ProtocolError,
    AuthenticationError,
    KeyConfirmationError,
    NegotiationError,
    HandshakeTimeout,
    TruncatedMessage,
    PeerAbort,
    send_msg,
    recv_msg,
    hkdf_derive,
)
from oqs_compat import KeyEncapsulation, Signature, KEM_SIZES, SIG_SIZES

VERSION = 1

MSG_CLIENT_HELLO = 0x01
MSG_SERVER_HELLO = 0x02
MSG_CLIENT_FINISHED = 0x03
MSG_ALERT = 0xFF

SUITE_X25519 = 0x01
SUITE_MLKEM = 0x02
SUITE_HYBRID = 0x03
SUITE_NAMES = {SUITE_X25519: "x25519", SUITE_MLKEM: "mlkem", SUITE_HYBRID: "x25519+mlkem"}
PQ_SUITES = frozenset({SUITE_MLKEM, SUITE_HYBRID})

DEFAULT_OFFER = (SUITE_HYBRID, SUITE_X25519)  # client: prefer hybrid, allow classical
SERVER_PREFERENCE = (SUITE_HYBRID, SUITE_MLKEM, SUITE_X25519)

LABEL = b"pqc-bench auth v1"
SIG_CONTEXT = b"pqc-bench auth v1 server signature\x00"
X25519_LEN = 32
RANDOM_LEN = 32
FINISHED_LEN = 32
MAX_OFFERS = 8


# ----------------------------------------------------------------------------
# Server long-term identity
# ----------------------------------------------------------------------------
@dataclass(frozen=True)
class ServerIdentity:
    """Long-term ML-DSA identity. Generate ONCE and reuse across handshakes
    (a real server does not mint a new identity per connection)."""

    sig_mechanism: str
    public_key: bytes
    secret_key: bytes = field(repr=False)

    @classmethod
    def generate(cls, sig_mechanism: str = "ML-DSA-65") -> "ServerIdentity":
        with Signature(sig_mechanism) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return cls(sig_mechanism, pk, sk)


@dataclass
class HandshakeResult:
    key: bytes
    suite: int
    transcript_hash: bytes


# ----------------------------------------------------------------------------
# Wire encoding (strict, bounds-checked)
# ----------------------------------------------------------------------------
class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ProtocolError("message truncated")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def done(self) -> None:
        if self.pos != len(self.data):
            raise ProtocolError("trailing bytes")


def encode_client_hello(client_random: bytes, offers: List[Tuple[int, bytes]]) -> bytes:
    out = bytes([MSG_CLIENT_HELLO, VERSION]) + client_random + bytes([len(offers)])
    for suite, share in offers:
        out += bytes([suite]) + struct.pack(">H", len(share)) + share
    return out


def decode_client_hello(frame: bytes) -> Tuple[bytes, List[Tuple[int, bytes]]]:
    r = _Reader(frame)
    if r.u8() != MSG_CLIENT_HELLO:
        raise ProtocolError("expected ClientHello")
    if r.u8() != VERSION:
        raise ProtocolError("unsupported protocol version")
    client_random = r.take(RANDOM_LEN)
    n = r.u8()
    if not 1 <= n <= MAX_OFFERS:
        raise ProtocolError("bad number of offered suites")
    offers, seen = [], set()
    for _ in range(n):
        suite = r.u8()
        share = r.take(r.u16())
        if suite in seen:
            raise ProtocolError("duplicate suite offer")
        seen.add(suite)
        offers.append((suite, share))
    r.done()
    return client_random, offers


def encode_server_hello_body(
    server_random: bytes, suite: int, identity_pk: bytes, response: bytes
) -> bytes:
    return (
        bytes([MSG_SERVER_HELLO, VERSION])
        + server_random
        + bytes([suite])
        + struct.pack(">H", len(identity_pk)) + identity_pk
        + struct.pack(">H", len(response)) + response
    )


def decode_server_hello(frame: bytes):
    """Returns (body, server_random, suite, identity_pk, response, signature,
    finished). `body` is the exact received bytes the signature covers."""
    r = _Reader(frame)
    if r.u8() != MSG_SERVER_HELLO:
        raise ProtocolError("expected ServerHello")
    if r.u8() != VERSION:
        raise ProtocolError("unsupported protocol version")
    server_random = r.take(RANDOM_LEN)
    suite = r.u8()
    identity_pk = r.take(r.u16())
    response = r.take(r.u16())
    body = frame[: r.pos]
    signature = r.take(r.u16())
    finished = r.take(FINISHED_LEN)
    r.done()
    return body, server_random, suite, identity_pk, response, signature, finished


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _send(conn: SocketLike, counter: ByteCounter, payload: bytes) -> None:
    try:
        counter.note_send(send_msg(conn, payload))
    except socket.timeout as e:
        raise HandshakeTimeout("timed out sending to peer") from e
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:
        raise TruncatedMessage("peer closed the connection while we were sending") from e


def _recv(conn: SocketLike, counter: ByteCounter, expected: int) -> bytes:
    frame = recv_msg(conn)
    counter.note_recv(4 + len(frame))
    if not frame:
        raise ProtocolError("empty frame")
    if frame[0] == MSG_ALERT:
        raise PeerAbort(frame[1] if len(frame) > 1 else -1)
    if frame[0] != expected:
        raise ProtocolError(f"unexpected message type {frame[0]:#x}")
    return frame


def _abort(conn: SocketLike, exc: HandshakeError) -> None:
    """Best-effort alert to the peer. Never raises, never returns key material.
    We stay silent if the peer is already gone or already told us it aborted."""
    if isinstance(exc, (PeerAbort, HandshakeTimeout, TruncatedMessage)):
        return
    try:
        send_msg(conn, bytes([MSG_ALERT, exc.alert_code]))
    except Exception:
        pass


def _share_len(suite: int, mechanism: str) -> int:
    """Expected length of the *client* key share for a suite."""
    kem_pk = KEM_SIZES[mechanism][0]
    return {
        SUITE_X25519: X25519_LEN,
        SUITE_MLKEM: kem_pk,
        SUITE_HYBRID: X25519_LEN + kem_pk,
    }[suite]


def _response_len(suite: int, mechanism: str) -> int:
    """Expected length of the *server* key-exchange response for a suite."""
    kem_ct = KEM_SIZES[mechanism][1]
    return {
        SUITE_X25519: X25519_LEN,
        SUITE_MLKEM: kem_ct,
        SUITE_HYBRID: X25519_LEN + kem_ct,
    }[suite]


def _ecdh(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    try:
        secret = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    except ValueError as e:
        raise ProtocolError("invalid X25519 key share") from e
    if secret == b"\x00" * X25519_LEN:  # low-order point -> contributory failure
        raise ProtocolError("X25519 low-order key share")
    return secret


def safe_verify(sig_mechanism: str, message: bytes, signature: bytes, pk: bytes) -> bool:
    """verify() that can only answer True/False; malformed input is 'False'."""
    pk_len, sig_len = SIG_SIZES[sig_mechanism]
    if len(pk) != pk_len or len(signature) != sig_len:
        return False
    try:
        with Signature(sig_mechanism) as sig:
            return bool(sig.verify(message, signature, pk))
    except Exception:
        return False


def _key_schedule(secret: bytes, th1: bytes, suite: int, mechanism: str, signature: bytes):
    """Returns (master, expected_finished_s). Finished_C / session key are
    derived by the callers once Finished_S is known (th3)."""
    info = LABEL + b" master" + bytes([suite]) + mechanism.encode()
    master = hkdf_derive(secret, info, salt=th1)
    th2 = _sha256(th1, signature)
    fin_s = hmac.new(hkdf_derive(master, LABEL + b" finished server"), th2, hashlib.sha256).digest()
    return master, th2, fin_s


def _finish_keys(master: bytes, th2: bytes, fin_s: bytes):
    th3 = _sha256(th2, fin_s)
    fin_c = hmac.new(hkdf_derive(master, LABEL + b" finished client"), th3, hashlib.sha256).digest()
    session_key = hkdf_derive(master, LABEL + b" session", salt=th3)
    return fin_c, session_key, th3


# ----------------------------------------------------------------------------
# Suite selection (server policy)
# ----------------------------------------------------------------------------
def select_suite(offers, supported: Iterable[int], require_pq: bool) -> int:
    offered = {s for s, _ in offers}
    for suite in supported:
        if suite in offered:
            if require_pq and suite not in PQ_SUITES:
                continue
            return suite
    raise NegotiationError("no mutually acceptable suite")


# ----------------------------------------------------------------------------
# Server
# ----------------------------------------------------------------------------
def server_handshake_ex(
    conn: SocketLike,
    counter: ByteCounter,
    mechanism: str,
    *,
    identity: ServerIdentity,
    suites: Iterable[int] = SERVER_PREFERENCE,
    require_pq: bool = False,
) -> HandshakeResult:
    try:
        ch_frame = _recv(conn, counter, MSG_CLIENT_HELLO)
        _client_random, offers = decode_client_hello(ch_frame)
        suite = select_suite(offers, suites, require_pq)
        share = dict(offers)[suite]
        if len(share) != _share_len(suite, mechanism):
            raise ProtocolError("key share has wrong length for suite")

        # --- key exchange (server side) -----------------------------------
        secret = b""
        response = b""
        if suite in (SUITE_X25519, SUITE_HYBRID):
            ec_priv = X25519PrivateKey.generate()
            response += ec_priv.public_key().public_bytes_raw()
            secret += _ecdh(ec_priv, share[:X25519_LEN])
        if suite in PQ_SUITES:
            kem_pk = share[X25519_LEN:] if suite == SUITE_HYBRID else share
            try:
                with KeyEncapsulation(mechanism) as kem:
                    kem_ct, kem_secret = kem.encap_secret(kem_pk)
            except (ValueError, RuntimeError) as e:
                raise ProtocolError("invalid KEM public key") from e
            response += kem_ct
            secret += kem_secret

        # --- sign the transcript ------------------------------------------
        body = encode_server_hello_body(os.urandom(RANDOM_LEN), suite, identity.public_key, response)
        th1 = _sha256(ch_frame, body)
        with Signature(identity.sig_mechanism, identity.secret_key) as sig:
            signature = sig.sign(SIG_CONTEXT + th1)

        master, th2, fin_s = _key_schedule(secret, th1, suite, mechanism, signature)
        fin_c_expected, session_key, th3 = _finish_keys(master, th2, fin_s)

        _send(conn, counter, body + struct.pack(">H", len(signature)) + signature + fin_s)

        # --- key confirmation from the client -----------------------------
        cf = _recv(conn, counter, MSG_CLIENT_FINISHED)
        if len(cf) != 1 + FINISHED_LEN or not hmac.compare_digest(cf[1:], fin_c_expected):
            raise KeyConfirmationError("client Finished did not verify")
        return HandshakeResult(session_key, suite, th3)
    except HandshakeError as e:
        _abort(conn, e)
        raise


def server_handshake(conn, counter, mechanism, **kwargs) -> bytes:
    return server_handshake_ex(conn, counter, mechanism, **kwargs).key


# ----------------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------------
def client_handshake_ex(
    conn: SocketLike,
    counter: ByteCounter,
    mechanism: str,
    *,
    trusted_sig_pk: bytes,
    sig_mechanism: str = "ML-DSA-65",
    offer: Iterable[int] = DEFAULT_OFFER,
) -> HandshakeResult:
    offer = tuple(offer)
    try:
        with ExitStack() as stack:
            # --- build key shares for everything we offer -----------------
            ec_priv = X25519PrivateKey.generate()
            ec_pub = ec_priv.public_key().public_bytes_raw()
            kem, kem_pk = None, b""
            if any(s in PQ_SUITES for s in offer):
                kem = stack.enter_context(KeyEncapsulation(mechanism))
                kem_pk = kem.generate_keypair()
            shares = {
                SUITE_X25519: ec_pub,
                SUITE_MLKEM: kem_pk,
                SUITE_HYBRID: ec_pub + kem_pk,
            }
            offers = [(s, shares[s]) for s in offer]

            ch_frame = encode_client_hello(os.urandom(RANDOM_LEN), offers)
            _send(conn, counter, ch_frame)

            sh_frame = _recv(conn, counter, MSG_SERVER_HELLO)
            body, _srand, suite, identity_pk, response, signature, finished_s = decode_server_hello(sh_frame)

            if suite not in offer:
                raise NegotiationError("server chose a suite we did not offer")
            if len(response) != _response_len(suite, mechanism):
                raise ProtocolError("server response has wrong length for suite")

            # 1. identity: must be exactly the key we pinned
            if not hmac.compare_digest(identity_pk, trusted_sig_pk):
                raise AuthenticationError("server identity key does not match pinned key")
            # 2. signature over the transcript WE saw (our real ClientHello)
            th1 = _sha256(ch_frame, body)
            if not safe_verify(sig_mechanism, SIG_CONTEXT + th1, signature, identity_pk):
                raise AuthenticationError("server signature over transcript is invalid")

            # 3. only now touch the (now authenticated) key-exchange response
            secret = b""
            if suite in (SUITE_X25519, SUITE_HYBRID):
                secret += _ecdh(ec_priv, response[:X25519_LEN])
            if suite in PQ_SUITES:
                kem_ct = response[X25519_LEN:] if suite == SUITE_HYBRID else response
                try:
                    secret += kem.decap_secret(kem_ct)
                except (ValueError, RuntimeError) as e:
                    raise ProtocolError("KEM decapsulation failed") from e

            # 4. key confirmation from the server
            master, th2, fin_s = _key_schedule(secret, th1, suite, mechanism, signature)
            if not hmac.compare_digest(finished_s, fin_s):
                raise KeyConfirmationError("server Finished did not verify")

            fin_c, session_key, th3 = _finish_keys(master, th2, fin_s)
            _send(conn, counter, bytes([MSG_CLIENT_FINISHED]) + fin_c)
            return HandshakeResult(session_key, suite, th3)
    except HandshakeError as e:
        _abort(conn, e)
        raise


def client_handshake(conn, counter, mechanism, **kwargs) -> bytes:
    return client_handshake_ex(conn, counter, mechanism, **kwargs).key
