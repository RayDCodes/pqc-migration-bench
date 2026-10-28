import struct

import pytest

from common import ByteCounter, ProtocolError, pack_fields
import handshake_signed
from oqs_compat import KeyEncapsulation, Signature, SIG_MECHANISM
from test_protocol import MemorySocket

MECHANISM = "ML-KEM-768"
CHALLENGE = b"a" * 32


@pytest.fixture
def identity():
    with Signature(SIG_MECHANISM) as signer:
        public_key = signer.generate_keypair()
        yield signer, public_key


def response_socket(signer, monkeypatch, challenge=CHALLENGE, mechanism=MECHANISM, tamper=None):
    monkeypatch.setattr(handshake_signed.secrets, "token_bytes", lambda _: CHALLENGE)
    with KeyEncapsulation(MECHANISM) as kem:
        public_key = kem.generate_keypair()
    message = handshake_signed.signed_message(mechanism, SIG_MECHANISM, challenge, public_key)
    signature = signer.sign(message)
    if tamper == "key":
        public_key = bytes([public_key[0] ^ 1]) + public_key[1:]
    if tamper == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    response = pack_fields(public_key, signature)
    finished = b"x" * 32
    return MemorySocket(
        struct.pack(">I", len(response)) + response + struct.pack(">I", len(finished)) + finished
    )


@pytest.mark.parametrize("tamper", ["key", "signature"])
def test_modified_response_rejected_before_encapsulation(identity, monkeypatch, tamper):
    signer, public_key = identity
    conn = response_socket(signer, monkeypatch, tamper=tamper)
    with pytest.raises(ProtocolError, match="signature verification"):
        handshake_signed.client_handshake(conn, ByteCounter(), MECHANISM, SIG_MECHANISM, public_key)
    assert len(conn.sent) == 36


def test_attacker_signing_key_is_not_trusted(identity, monkeypatch):
    _, trusted_key = identity
    with Signature(SIG_MECHANISM) as attacker:
        attacker.generate_keypair()
        conn = response_socket(attacker, monkeypatch)
    with pytest.raises(ProtocolError, match="signature verification"):
        handshake_signed.client_handshake(conn, ByteCounter(), MECHANISM, SIG_MECHANISM, trusted_key)


@pytest.mark.parametrize("old_challenge,old_mechanism", [(b"b" * 32, MECHANISM), (CHALLENGE, "ML-KEM-512")])
def test_replay_and_algorithm_substitution(identity, monkeypatch, old_challenge, old_mechanism):
    signer, public_key = identity
    conn = response_socket(signer, monkeypatch, old_challenge, old_mechanism)
    with pytest.raises(ProtocolError, match="signature verification"):
        handshake_signed.client_handshake(conn, ByteCounter(), MECHANISM, SIG_MECHANISM, public_key)


def test_invalid_finished_is_rejected(identity, monkeypatch):
    signer, public_key = identity
    conn = response_socket(signer, monkeypatch)
    with pytest.raises(ProtocolError, match="key confirmation"):
        handshake_signed.client_handshake(conn, ByteCounter(), MECHANISM, SIG_MECHANISM, public_key)
    assert len(conn.sent) > 36


def test_trust_anchor_required():
    with pytest.raises(ValueError, match="independently provisioned"):
        handshake_signed.client_handshake(MemorySocket(), ByteCounter(), MECHANISM, SIG_MECHANISM, b"")


def test_server_rejects_short_challenge(identity):
    signer, _ = identity
    conn = MemorySocket(struct.pack(">I", 1) + b"x")
    with pytest.raises(ProtocolError, match="challenge length"):
        handshake_signed.server_handshake(conn, ByteCounter(), MECHANISM, SIG_MECHANISM, signer)


@pytest.mark.parametrize("data", [b"", b"short", b"x" * 65536])
def test_invalid_kem_input_lengths(data):
    with KeyEncapsulation(MECHANISM) as kem:
        kem.generate_keypair()
        with pytest.raises(ProtocolError, match="public key length"):
            kem.encap_secret(data)
        with pytest.raises(ProtocolError, match="ciphertext length"):
            kem.decap_secret(data)
