"""
Adversarial tests: an active attacker sits on the wire (mitm.py) or impersonates
the server, and we assert the handshake fails CLOSED.

Covers the review's "No adversarial testing" list:

    active MITM injection        -> impersonation, key substitution, frame injection
    packet tampering             -> single-bit-flip sweep over every frame
    replay attacks               -> replayed server flight AND replayed client flight
    downgrade attempts           -> suite stripping, server-side PQ policy
    malformed ciphertext         -> random / wrong-length KEM material, low-order X25519
    corrupted signature testing  -> bit flips across the signature, spliced signatures
    handshake abort logic        -> alerts, no key released, no hang, no oracle

NOT covered, on purpose: QKD-style QBER thresholds. QBER is the error rate of
a *quantum* channel in protocols like BB84; nothing in a classical KEM/signature
handshake has a quantum channel or a sifted key to measure it on.

How to read the results
-----------------------
Every property is a statement about what a *secure* handshake does. Each is
run against "auth" (which must satisfy it) and, where meaningful, against the
original "signed" mode. Cases where v1 is KNOWN to violate the property are
marked xfail(strict=True):

    xfailed  = v1 is still vulnerable, exactly as documented   (expected)
    XPASS    = v1 unexpectedly satisfied the property -> the strict marker
               turns that into a failure so the README/docs get updated.

Only auth mode is expected to *pass* every property.
"""
import os
import socket
import struct
import threading
from unittest import mock

import pytest

import common
import handshake_auth as A
import handshake_pqc
from common import (
    ALERT_AUTH,
    ALERT_NEGOTIATION,
    ALERT_PROTOCOL,
    AuthenticationError,
    ByteCounter,
    HandshakeError,
    HandshakeTimeout,
    KeyConfirmationError,
    NegotiationError,
    PeerAbort,
    ProtocolError,
    TruncatedMessage,
    hkdf_derive,
    recv_msg,
    send_msg,
)
from harness import SIG_MECHANISM, default_identity, record_flights, requires_real, run_handshake
from mitm import ReplayServer, drop_frame, flip_bit, kill_at, replace_frame
from oqs_compat import KeyEncapsulation


def known_v1_gap(reason: str):
    return pytest.mark.xfail(strict=True, reason=reason)


def v1_vs_auth(reason: str):
    """Parameter list: v1 'signed' is a known gap, 'auth' must pass."""
    return [pytest.param("signed", marks=known_v1_gap(reason)), "auth"]


# ---------------------------------------------------------------------------
# Frame surgery helpers (operate on the auth wire format)
# ---------------------------------------------------------------------------
def _sh_layout(frame: bytes) -> dict:
    """Byte ranges of each field inside an auth ServerHello frame."""
    pos = 35  # type, version, server_random(32), suite
    out = {}
    for name in ("identity", "response", "signature"):
        (n,) = struct.unpack(">H", frame[pos : pos + 2])
        pos += 2
        out[name] = (pos, pos + n)
        pos += n
    out["finished"] = (pos, pos + A.FINISHED_LEN)
    return out


def _randomize(frame: bytes, region) -> bytes:
    s, e = region
    return frame[:s] + os.urandom(e - s) + frame[e:]


def _rebuild_server_hello(frame: bytes, **override) -> bytes:
    body, srand, suite, ipk, response, sig, fin = A.decode_server_hello(frame)
    body = A.encode_server_hello_body(srand, suite, ipk, override.get("response", response))
    return body + struct.pack(">H", len(sig)) + sig + fin


def _edit_client_hello(fn):
    """Policy that decodes the ClientHello, lets fn(offers)->offers edit it,
    and re-encodes it with correct lengths (a well-formed but doctored hello)."""
    def edit(frame):
        crand, offers = A.decode_client_hello(frame)
        return A.encode_client_hello(crand, fn(offers))
    return replace_frame("c2s", 0, edit)


# =============================================================================
# 1. Active MITM: impersonation / identity substitution
# =============================================================================
@requires_real
@pytest.mark.parametrize(
    "mode",
    v1_vs_auth("v1 has no trust anchor: the verifying key is shipped in-band, so an attacker just brings their own"),
)
def test_impersonator_with_its_own_identity_is_rejected(mode):
    rogue = A.ServerIdentity.generate(SIG_MECHANISM)  # attacker mints a fresh ML-DSA identity
    o = run_handshake(mode, server_identity=rogue)
    assert o.client_key is None, "client completed a handshake with a server it has no reason to trust"
    if mode == "auth":
        assert isinstance(o.client_exc, AuthenticationError)


@requires_real
@pytest.mark.parametrize("mode", ["signed", "auth"])
def test_swapped_server_key_material_is_detected(mode):
    """Attacker swaps the KEM key/response for random bytes of the same length."""
    if mode == "signed":
        policy = replace_frame("s2c", 1, lambda f: os.urandom(len(f)))
    else:
        policy = replace_frame("s2c", 0, lambda f: _randomize(f, _sh_layout(f)["response"]))
    o = run_handshake(mode, policy=policy)
    assert o.client_key is None and o.client_exc is not None
    if mode == "auth":
        assert isinstance(o.client_exc, AuthenticationError)


@requires_real
def test_injected_extra_frame_aborts_the_handshake():
    """Attacker injects a forged ClientFinished right behind the ClientHello."""
    forged = bytes([A.MSG_CLIENT_FINISHED]) + os.urandom(A.FINISHED_LEN)

    def policy(direction, index, frame):
        return [frame, forged] if (direction, index) == ("c2s", 0) else [frame]

    o = run_handshake("auth", policy=policy)
    assert isinstance(o.server_exc, KeyConfirmationError)
    assert o.server_key is None and not o.both_completed


@requires_real
def test_unauthenticated_pqc_lets_a_mitm_read_the_session_key():
    """Documents WHY authentication exists: with plain ML-KEM (no signature) an
    active attacker substitutes its own KEM key, decapsulates the client's
    ciphertext, and derives the client's session key. Expected to succeed."""
    mech = "ML-KEM-768"
    stash = {}
    with KeyEncapsulation(mech) as attacker:
        attacker_pk = attacker.generate_keypair()

        def policy(direction, index, frame):
            if direction == "s2c" and index == 0:
                stash["real_pk"] = frame
                return [attacker_pk]                       # client now encapsulates to the attacker
            if direction == "c2s" and index == 0:
                stash["client_secret"] = attacker.decap_secret(frame)
                with KeyEncapsulation(mech) as k2:          # and the attacker talks to the real server
                    ct2, _ = k2.encap_secret(stash["real_pk"])
                return [ct2]
            return [frame]

        o = run_handshake("pqc", mech, policy=policy)
    assert o.client_key == hkdf_derive(stash["client_secret"], handshake_pqc.HANDSHAKE_LABEL)


# =============================================================================
# 2. Packet tampering: flip one bit in every frame of every flight
# =============================================================================
_SWEEP_FRAMES = {
    "signed": [("s2c", 0), ("s2c", 1), ("s2c", 2), ("c2s", 0)],
    "auth": [("c2s", 0), ("c2s", 1), ("s2c", 0)],
}
# (mode, direction, frame): v1's ciphertext frame carries no MAC / confirmation
_V1_UNPROTECTED = {("signed", "c2s", 0)}

_SWEEP = []
for _mode, _frames in _SWEEP_FRAMES.items():
    for _d, _i in _frames:
        for _off in (0, 1, "mid", "last"):
            _marks = (
                [known_v1_gap("v1 has no key confirmation: a mangled ciphertext silently yields two different keys")]
                if (_mode, _d, _i) in _V1_UNPROTECTED
                else []
            )
            _SWEEP.append(pytest.param(_mode, _d, _i, _off, marks=_marks, id=f"{_mode}-{_d}[{_i}]@{_off}"))


@requires_real
@pytest.mark.parametrize("mode,direction,index,offset", _SWEEP)
def test_single_bit_tamper_never_yields_a_session(mode, direction, index, offset):
    o = run_handshake(mode, policy=flip_bit(direction, index, offset), timeout=2.0)
    assert not o.keys_diverged, "endpoints derived DIFFERENT keys and neither side noticed"
    assert not o.both_completed, "handshake completed despite tampering"


# =============================================================================
# 3. Replay
# =============================================================================
@requires_real
@pytest.mark.parametrize(
    "mode",
    v1_vs_auth("v1 has no freshness: nothing ties the server's flight to THIS client's session"),
)
def test_replayed_server_flight_is_rejected(mode):
    recorded = record_flights(mode)
    assert not recorded.aborted, (recorded.client_exc, recorded.server_exc)
    replay = ReplayServer(recorded.frames_in("s2c"))
    port = replay.start()
    o = run_handshake(mode, connect_to_port=port)
    assert o.client_key is None, "client completed a handshake against a recorded (stale) flight"
    if mode == "auth":
        assert isinstance(o.client_exc, AuthenticationError)


@requires_real
def test_replayed_client_flight_is_rejected_by_server():
    recorded = record_flights("auth").frames_in("c2s")  # [ClientHello, ClientFinished]
    a, b = socket.socketpair()
    a.settimeout(3)
    b.settimeout(3)
    result = {}

    def server():
        try:
            result["ok"] = A.server_handshake_ex(b, ByteCounter(), "ML-KEM-768", identity=default_identity())
        except BaseException as e:
            result["exc"] = e

    t = threading.Thread(target=server)
    t.start()
    send_msg(a, recorded[0])   # replay old ClientHello
    recv_msg(a)                # server answers with a NEW, fresh ServerHello
    send_msg(a, recorded[1])   # replay old Finished, which is bound to the old server flight
    t.join()
    a.close()
    b.close()
    assert isinstance(result.get("exc"), KeyConfirmationError) and "ok" not in result


# =============================================================================
# 4. Downgrade
# =============================================================================
@requires_real
def test_control_honest_client_negotiates_the_pq_suite():
    o = run_handshake("auth")
    assert o.client_result.suite == A.SUITE_HYBRID


@requires_real
def test_stripping_the_pq_offer_is_detected_by_the_transcript_signature():
    o = run_handshake("auth", policy=_edit_client_hello(lambda offers: [x for x in offers if x[0] != A.SUITE_HYBRID]))
    # The server only ever saw a classical-only hello, so it (permissively) fell back...
    server_hello = o.frames_in("s2c")[0]
    assert A.decode_server_hello(server_hello)[2] == A.SUITE_X25519, "attack did not reach the negotiation layer"
    # ...but the signature covers the hello the CLIENT actually sent, so the client aborts.
    assert isinstance(o.client_exc, AuthenticationError)
    assert o.client_key is None and o.server_key is None


@requires_real
def test_server_policy_can_refuse_classical_only_clients():
    o = run_handshake("auth", client_offer=(A.SUITE_X25519,), require_pq=True)
    assert isinstance(o.server_exc, NegotiationError)
    assert isinstance(o.client_exc, PeerAbort) and o.client_exc.code == ALERT_NEGOTIATION
    assert o.client_key is None and o.server_key is None


# =============================================================================
# 5. Malformed key material / ciphertext injection
# =============================================================================
def _inject_random_ciphertext(mode: str):
    """Replace ONLY the ciphertext bytes with random bytes of the same length."""
    if mode in ("pqc", "signed"):
        return replace_frame("c2s", 0, lambda f: os.urandom(len(f)))
    if mode == "hybrid":                       # frame = len(4) || x25519(32) || ct
        return replace_frame("c2s", 0, lambda f: f[:36] + os.urandom(len(f) - 36))
    return replace_frame("s2c", 0, lambda f: _randomize(f, _sh_layout(f)["response"]))  # auth


_NO_CONFIRM = "no key confirmation: ML-KEM implicit rejection turns a bad ciphertext into a silently different key"


@requires_real
@pytest.mark.parametrize(
    "mode",
    [
        pytest.param("pqc", marks=known_v1_gap(_NO_CONFIRM)),
        pytest.param("hybrid", marks=known_v1_gap(_NO_CONFIRM)),
        pytest.param("signed", marks=known_v1_gap(_NO_CONFIRM)),
        "auth",
    ],
)
def test_random_ciphertext_injection_is_detected(mode):
    o = run_handshake(mode, policy=_inject_random_ciphertext(mode))
    assert not o.keys_diverged, "endpoints derived different keys and neither side noticed"
    assert not o.both_completed


@requires_real
@pytest.mark.parametrize("what", ["truncated", "extended", "empty"])
def test_wrong_length_client_key_share_is_rejected_by_server(what):
    def doctor(offers):
        edits = {"truncated": lambda s: s[:-1], "extended": lambda s: s + b"\x00", "empty": lambda s: b""}
        return [(s, edits[what](sh) if s == A.SUITE_HYBRID else sh) for s, sh in offers]

    o = run_handshake("auth", policy=_edit_client_hello(doctor))
    assert isinstance(o.server_exc, ProtocolError) and o.server_key is None
    assert isinstance(o.client_exc, PeerAbort) and o.client_exc.code == ALERT_PROTOCOL


@requires_real
@pytest.mark.parametrize("what", ["truncated", "extended"])
def test_wrong_length_server_response_is_rejected_before_any_crypto(what):
    def doctor(frame):
        resp = A.decode_server_hello(frame)[4]
        return _rebuild_server_hello(frame, response=resp[:-1] if what == "truncated" else resp + b"\x00")

    o = run_handshake("auth", policy=replace_frame("s2c", 0, doctor))
    assert isinstance(o.client_exc, ProtocolError) and o.client_key is None


@requires_real
def test_low_order_x25519_share_is_rejected():
    def doctor(offers):
        return [(s, b"\x00" * 32 + sh[32:] if s == A.SUITE_HYBRID else sh) for s, sh in offers]

    o = run_handshake("auth", policy=_edit_client_hello(doctor))
    assert isinstance(o.server_exc, ProtocolError) and o.server_key is None


@requires_real
def test_wrong_length_key_share_never_reaches_the_kem():
    """Length validation must happen BEFORE the KEM sees attacker-controlled
    bytes. Depending on the liboqs-python version, decapsulation/encapsulation
    may not length-check and would read out of bounds in C, so we do not rely
    on the binding to reject it. (Tested with the KEM replaced by a tripwire.)"""
    bad = A.encode_client_hello(os.urandom(32), [(A.SUITE_HYBRID, os.urandom(32 + 100))])
    a, b = socket.socketpair()
    a.settimeout(2)
    b.settimeout(2)
    send_msg(a, bad)
    tripwire = mock.patch.object(A, "KeyEncapsulation", side_effect=AssertionError("KEM reached with unvalidated input"))
    with tripwire:
        with pytest.raises(ProtocolError):
            A.server_handshake_ex(b, ByteCounter(), "ML-KEM-768", identity=default_identity())
    a.close()
    b.close()


def test_all_zero_x25519_secret_is_rejected_even_if_the_backend_allows_it():
    """Contributory-behaviour check must not depend on OpenSSL raising."""
    class LenientBackendKey:
        def exchange(self, peer):
            return b"\x00" * 32

    with pytest.raises(ProtocolError):
        A._ecdh(LenientBackendKey(), b"\x09" + b"\x00" * 31)


# =============================================================================
# 6. Corrupted signatures
# =============================================================================
@requires_real
@pytest.mark.parametrize("mode", ["signed", "auth"])
@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_corrupted_signature_is_rejected(mode, where):
    index = 2 if mode == "signed" else 0

    def corrupt(frame):
        s, e = (0, len(frame)) if mode == "signed" else _sh_layout(frame)["signature"]
        pos = {"first": s, "middle": (s + e) // 2, "last": e - 1}[where]
        b = bytearray(frame)
        b[pos] ^= 0x80
        return bytes(b)

    o = run_handshake(mode, policy=replace_frame("s2c", index, corrupt))
    assert o.client_key is None and o.client_exc is not None
    if mode == "auth":
        assert isinstance(o.client_exc, AuthenticationError)


@requires_real
def test_signature_spliced_in_from_another_session_is_rejected():
    donor = _sh_layout(record_flights("auth").frames_in("s2c")[0])
    donor_frame = record_flights("auth").frames_in("s2c")[0]
    s, e = donor["signature"]
    donor_sig = donor_frame[s:e]

    def splice(frame):
        a, b = _sh_layout(frame)["signature"]
        return frame[:a] + donor_sig + frame[b:]

    o = run_handshake("auth", policy=replace_frame("s2c", 0, splice))
    assert isinstance(o.client_exc, AuthenticationError) and o.client_key is None


# =============================================================================
# 7. Abort logic
# =============================================================================
@requires_real
def test_abort_alerts_the_peer_releases_no_key_and_leaks_no_oracle():
    o = run_handshake("auth", policy=flip_bit("s2c", 0, "mid"))
    assert isinstance(o.client_exc, AuthenticationError)
    assert isinstance(o.server_exc, PeerAbort) and o.server_exc.code == ALERT_AUTH
    assert o.client_key is None and o.server_key is None
    assert o.client_result is None and o.server_result is None
    sent = o.frames_in("c2s")
    assert [f[0] for f in sent] == [A.MSG_CLIENT_HELLO, A.MSG_ALERT], "client kept talking after it decided to abort"


@requires_real
def test_dropped_server_flight_times_out_instead_of_hanging():
    # Client gives up first (0.4 s) while server/proxy are still willing to wait (3 s),
    # so this deterministically exercises the client's own timeout path.
    o = run_handshake("auth", policy=drop_frame("s2c", 0), timeout=3.0, client_timeout=0.4)
    assert isinstance(o.client_exc, HandshakeTimeout) and o.client_key is None
    assert o.elapsed < 4


@requires_real
def test_connection_killed_mid_handshake_fails_closed():
    o = run_handshake("auth", policy=kill_at("s2c", 0))
    assert isinstance(o.client_exc, TruncatedMessage)
    assert o.client_key is None and o.server_key is None


@requires_real
def test_garbage_in_place_of_the_server_hello_is_rejected():
    o = run_handshake("auth", policy=replace_frame("s2c", 0, lambda f: os.urandom(len(f))))
    assert isinstance(o.client_exc, HandshakeError) and o.client_key is None


@requires_real
def test_oversized_frame_is_refused_without_buffering_it():
    o = run_handshake("auth", policy=replace_frame("s2c", 0, b"\x00" * (common.MAX_FRAME + 1)))
    assert isinstance(o.client_exc, ProtocolError) and "exceeds" in str(o.client_exc)
    assert o.client_key is None
