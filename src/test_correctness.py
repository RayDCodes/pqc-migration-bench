"""
Cryptographic-correctness tests.

Covers the review's "No cryptographic correctness validation" list:

    key agreement correctness        -> KEM / suite / level agreement tests
    signature verification           -> ML-DSA accept/reject tests
    handshake failure modes          -> framing limits, parsers, timeouts
    ephemeral key reuse              -> uniqueness of every per-session value
    entropy quality                  -> smoke test ONLY (see caveat below)
    randomness source integrity      -> real-backend guard + RNG tripwire
    (downgrade resistance / transcript binding live in test_adversarial.py,
     because they only mean something against an active attacker.)

Run:  python3 -m pytest src -v

ENTROPY CAVEAT: nothing at the handshake layer can prove entropy *quality*.
Randomness comes from the OS CSPRNG via liboqs / OpenSSL. The statistical
test below only catches gross failures (stuck, repeating, or heavily biased
output); it is not a NIST SP 800-22 / 800-90B assessment. It deliberately
samples only values that are uniformly random by construction (nonces and
derived keys). It does NOT sample ML-KEM public keys or ciphertexts, whose
compressed-coefficient encoding is legitimately non-uniform at the byte level.
"""
import os
import socket
import struct
import threading
import warnings
from collections import Counter
from unittest import mock

import pytest

import common
import handshake_auth as A
import handshake_pqc
import oqs_compat
from common import (
    ByteCounter,
    HandshakeError,
    HandshakeTimeout,
    KeyConfirmationError,
    ProtocolError,
    TruncatedMessage,
    pack_fields,
    recv_msg,
    unpack_fields,
)
from harness import default_identity, record_flights, requires_real, run_handshake
from oqs_compat import KEM_SIZES, SIG_SIZES, KeyEncapsulation, Signature

KEMS = list(KEM_SIZES)
SIGS = list(SIG_SIZES)


def _flip(data: bytes, i: int) -> bytes:
    b = bytearray(data)
    b[i] ^= 1
    return bytes(b)


# =============================================================================
# Key agreement correctness
# =============================================================================
@requires_real
@pytest.mark.parametrize("mech", KEMS)
def test_kem_roundtrip_and_sizes(mech):
    with KeyEncapsulation(mech) as kem:
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
        assert kem.decap_secret(ct) == ss
    assert (len(pk), len(ct), len(ss)) == (KEM_SIZES[mech][0], KEM_SIZES[mech][1], 32)


@requires_real
def test_kem_encapsulation_is_randomised():
    with KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        ct1, ss1 = kem.encap_secret(pk)
        ct2, ss2 = kem.encap_secret(pk)
    assert ct1 != ct2 and ss1 != ss2


@requires_real
def test_kem_wrong_secret_key_yields_different_secret():
    with KeyEncapsulation("ML-KEM-768") as a, KeyEncapsulation("ML-KEM-768") as b:
        pk_a = a.generate_keypair()
        b.generate_keypair()
        ct, ss = a.encap_secret(pk_a)
        assert b.decap_secret(ct) != ss


@requires_real
@pytest.mark.parametrize("mech", KEMS)
def test_kem_tampered_ciphertext_is_implicitly_rejected(mech):
    """FIPS 203 implicit rejection: a modified ciphertext must NOT raise (that
    would be a decapsulation-failure oracle) and must NOT yield the real
    secret. This is exactly why the plain pqc/hybrid/signed modes cannot see
    ciphertext tampering, and why auth mode adds key confirmation."""
    with KeyEncapsulation(mech) as kem:
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
        ss_bad = kem.decap_secret(_flip(ct, len(ct) // 2))
    assert ss_bad != ss and len(ss_bad) == 32


@requires_real
@pytest.mark.parametrize("mech", KEMS)
def test_signed_v1_keys_match(mech):
    # The original test-suite had no coverage of signed mode at all.
    o = run_handshake("signed", mech)
    assert not o.aborted, (o.client_exc, o.server_exc)
    assert o.client_key == o.server_key and len(o.client_key) == 32


@requires_real
@pytest.mark.parametrize("mech", KEMS)
@pytest.mark.parametrize(
    "offer,expect",
    [
        ((A.SUITE_HYBRID, A.SUITE_X25519), A.SUITE_HYBRID),
        ((A.SUITE_MLKEM,), A.SUITE_MLKEM),
        ((A.SUITE_X25519,), A.SUITE_X25519),
    ],
)
def test_auth_key_agreement_all_suites_and_levels(mech, offer, expect):
    o = run_handshake("auth", mech, client_offer=offer)
    assert not o.aborted, (o.client_exc, o.server_exc)
    assert o.client_key == o.server_key and len(o.client_key) == 32
    assert o.client_result.suite == o.server_result.suite == expect
    assert o.client_result.transcript_hash == o.server_result.transcript_hash


@requires_real
@pytest.mark.parametrize("mode", ["pqc", "hybrid", "signed", "auth"])
def test_sessions_never_repeat_keys(mode):
    keys = {run_handshake(mode).client_key for _ in range(5)}
    assert None not in keys and len(keys) == 5


# =============================================================================
# Signature verification correctness (ML-DSA)
# =============================================================================
@requires_real
@pytest.mark.parametrize("sig_mech", SIGS)
def test_sig_roundtrip_and_sizes(sig_mech):
    with Signature(sig_mech) as s:
        pk = s.generate_keypair()
        sig = s.sign(b"msg")
        assert s.verify(b"msg", sig, pk) is True
    assert (len(pk), len(sig)) == SIG_SIZES[sig_mech]


@requires_real
def test_sig_rejects_wrong_message_wrong_key_and_any_corruption():
    mech = "ML-DSA-65"
    with Signature(mech) as s1, Signature(mech) as s2:
        pk1 = s1.generate_keypair()
        pk2 = s2.generate_keypair()
        sig = s1.sign(b"hello")
    ok = A.safe_verify
    assert ok(mech, b"hello", sig, pk1)
    assert not ok(mech, b"hellp", sig, pk1), "wrong message accepted"
    assert not ok(mech, b"hello", sig, pk2), "wrong public key accepted"
    for i in (0, 1, len(sig) // 2, len(sig) - 1):
        assert not ok(mech, b"hello", _flip(sig, i), pk1), f"corrupted signature (byte {i}) accepted"
    assert not ok(mech, b"hello", sig[:-1], pk1), "truncated signature accepted"
    assert not ok(mech, b"hello", sig + b"\x00", pk1), "extended signature accepted"
    assert not ok(mech, b"hello", b"", pk1), "empty signature accepted"
    assert not ok(mech, b"hello", sig, pk1[:-1]), "truncated public key accepted"


@requires_real
def test_signature_is_domain_separated():
    """A signature over context||hash must not verify as a bare signature over
    the hash, so it can't be lifted into another protocol."""
    mech, h = "ML-DSA-65", b"\x42" * 32
    with Signature(mech) as s:
        pk = s.generate_keypair()
        sig = s.sign(A.SIG_CONTEXT + h)
    assert A.safe_verify(mech, A.SIG_CONTEXT + h, sig, pk)
    assert not A.safe_verify(mech, h, sig, pk)


# =============================================================================
# Handshake failure modes: framing, parsers, timeouts (no crypto needed)
# =============================================================================
def _pair():
    a, b = socket.socketpair()
    a.settimeout(1)
    b.settimeout(1)
    return a, b


def test_recv_msg_rejects_oversized_length_prefix():
    a, b = _pair()
    a.sendall(struct.pack(">I", 0xFFFFFFFF))  # claims a 4 GiB frame
    with pytest.raises(ProtocolError):
        recv_msg(b)


def test_recv_msg_reports_truncation_and_is_still_a_connection_error():
    a, b = _pair()
    a.sendall(struct.pack(">I", 100) + b"x" * 10)
    a.close()
    with pytest.raises(TruncatedMessage):
        recv_msg(b)
    a, b = _pair()
    a.sendall(struct.pack(">I", 100) + b"x" * 10)
    a.close()
    with pytest.raises(ConnectionError):  # backwards compatibility
        recv_msg(b)


def test_recv_times_out_cleanly():
    a, b = _pair()
    b.settimeout(0.2)
    with pytest.raises(HandshakeTimeout):
        recv_msg(b)


@pytest.mark.parametrize(
    "blob,n",
    [
        (b"", 1),
        (b"\x00", 1),
        (b"\x00\x05ab", 1),
        (pack_fields(b"a") + b"x", 1),
        (pack_fields(b"a"), 2),
    ],
)
def test_unpack_fields_is_strict(blob, n):
    with pytest.raises(ProtocolError):
        unpack_fields(blob, n)


_CRAND = b"\x11" * 32
_GOOD_CH = A.encode_client_hello(_CRAND, [(A.SUITE_X25519, b"\x22" * 32)])
MALFORMED_CLIENT_HELLOS = [
    b"",
    b"\x01",
    bytes([A.MSG_SERVER_HELLO]) + _GOOD_CH[1:],   # wrong message type
    _GOOD_CH[:1] + b"\x63" + _GOOD_CH[2:],        # unsupported version
    A.encode_client_hello(_CRAND, []),            # zero offers
    A.encode_client_hello(_CRAND, [(i, b"x") for i in range(1, A.MAX_OFFERS + 2)]),  # too many
    A.encode_client_hello(_CRAND, [(1, b"a"), (1, b"b")]),                          # duplicate
    _GOOD_CH[:-1],                                # truncated share
    _GOOD_CH + b"\x00",                           # trailing byte
]


@pytest.mark.parametrize("frame", MALFORMED_CLIENT_HELLOS)
def test_client_hello_parser_rejects_malformed(frame):
    with pytest.raises(ProtocolError):
        A.decode_client_hello(frame)


def _good_server_hello() -> bytes:
    body = A.encode_server_hello_body(b"\x01" * 32, A.SUITE_X25519, b"pk", b"r" * 32)
    return body + struct.pack(">H", 3) + b"sig" + b"\x00" * A.FINISHED_LEN


def test_server_hello_parser_roundtrips_and_exposes_signed_body():
    frame = _good_server_hello()
    body, srand, suite, ipk, resp, sig, fin = A.decode_server_hello(frame)
    assert (srand, suite, ipk, resp, sig) == (b"\x01" * 32, A.SUITE_X25519, b"pk", b"r" * 32, b"sig")
    assert frame.startswith(body) and len(body) == len(frame) - 2 - 3 - A.FINISHED_LEN


@pytest.mark.parametrize("cut", [0, 1, 34, 36, 40, 75, 78])
def test_server_hello_parser_rejects_truncation(cut):
    with pytest.raises(ProtocolError):
        A.decode_server_hello(_good_server_hello()[:cut])


def test_server_hello_parser_rejects_trailing_bytes():
    with pytest.raises(ProtocolError):
        A.decode_server_hello(_good_server_hello() + b"\x00")


@requires_real
def test_client_gives_up_on_a_silent_server_instead_of_hanging():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    c = socket.create_connection(srv.getsockname(), timeout=0.3)
    with pytest.raises(HandshakeTimeout):
        A.client_handshake(c, ByteCounter(), "ML-KEM-768", trusted_sig_pk=default_identity().public_key)
    c.close()
    srv.close()


# =============================================================================
# Ephemeral key reuse
# =============================================================================
@requires_real
def test_auth_never_reuses_ephemeral_values_but_keeps_long_term_identity():
    n = 25
    seen = {k: [] for k in ("client_random", "server_random", "client_x25519", "client_kem_pk",
                            "server_response", "session_key", "identity_pk")}
    for _ in range(n):
        o = record_flights("auth")
        assert not o.aborted, (o.client_exc, o.server_exc)
        crand, offers = A.decode_client_hello(o.frames_in("c2s")[0])
        share = dict(offers)[A.SUITE_HYBRID]
        _, srand, _, ipk, response, _, _ = A.decode_server_hello(o.frames_in("s2c")[0])
        seen["client_random"].append(crand)
        seen["server_random"].append(srand)
        seen["client_x25519"].append(share[:32])
        seen["client_kem_pk"].append(share[32:])
        seen["server_response"].append(response)
        seen["session_key"].append(o.client_key)
        seen["identity_pk"].append(ipk)
    for name, values in seen.items():
        if name == "identity_pk":
            assert len(set(values)) == 1, "identity must be long-term (same across sessions)"
        else:
            assert len(set(values)) == n, f"{name} was reused across sessions"


@requires_real
@pytest.mark.parametrize("mode,server_frame", [("pqc", 0), ("hybrid", 0), ("signed", 1)])
def test_v1_modes_do_not_reuse_server_ephemeral_keys(mode, server_frame):
    keys = [record_flights(mode).frames_in("s2c")[server_frame] for _ in range(20)]
    assert len(set(keys)) == 20


# =============================================================================
# Entropy smoke test + randomness-source integrity
# =============================================================================
def _chi_square_bytes(data: bytes) -> float:
    counts, expected = Counter(data), len(data) / 256
    return sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(256))


@requires_real
def test_protocol_randomness_smoke_test_gross_failures_only():
    samples = bytearray()
    for _ in range(150):
        o = record_flights("auth")
        crand, _ = A.decode_client_hello(o.frames_in("c2s")[0])
        srand = A.decode_server_hello(o.frames_in("s2c")[0])[1]
        samples += crand + srand + o.client_key
    chi2 = _chi_square_bytes(bytes(samples))
    # df=255 -> mean 255, sd ~22.6. Bounds are ~+-5.5 sd: essentially never
    # flaky for a healthy RNG, but a constant/repeating/biased source blows past them.
    assert 130 < chi2 < 420, f"byte histogram looks non-uniform (chi2={chi2:.1f})"
    ones = sum(bin(b).count("1") for b in samples)
    assert abs(ones / (8 * len(samples)) - 0.5) < 0.01, "bit balance is off"


def test_rng_selfcheck_passes_on_healthy_system():
    common.rng_selfcheck()


def test_rng_selfcheck_detects_a_stuck_urandom():
    with mock.patch("os.urandom", lambda n: b"\x07" * n):
        with pytest.raises(RuntimeError):
            common.rng_selfcheck()


def test_fake_shim_is_refused_unless_explicitly_allowed():
    env = {k: v for k, v in os.environ.items() if k != "PQC_BENCH_ALLOW_SHIM"}
    with mock.patch.object(oqs_compat, "REAL_OQS", False), mock.patch.dict(os.environ, env, clear=True):
        with pytest.raises(RuntimeError):
            oqs_compat.require_real_oqs("unit test")
        os.environ["PQC_BENCH_ALLOW_SHIM"] = "1"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            oqs_compat.require_real_oqs("unit test")
        assert any("INSECURE" in str(w.message) for w in caught)


def test_backend_is_real_liboqs():
    """CI sets PQC_BENCH_REQUIRE_REAL=1 so a missing liboqs FAILS instead of
    silently skipping every security test."""
    if not oqs_compat.REAL_OQS and not os.environ.get("PQC_BENCH_REQUIRE_REAL"):
        pytest.skip("running on the fallback shim (no liboqs)")
    assert oqs_compat.REAL_OQS, "real liboqs bindings are required for security tests"
