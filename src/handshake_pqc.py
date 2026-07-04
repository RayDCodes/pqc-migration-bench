"""
Post-quantum handshake using ML-KEM (FIPS 203, formerly CRYSTALS-Kyber)
as a drop-in replacement for the ECDH step in TLS-style key exchange.

KEMs work differently from DH: there's no "both sides compute the same
value" symmetry. Instead:
    1. server generates a KEM keypair, sends the public key
    2. client encapsulates against that public key -> (ciphertext, secret)
    3. client sends the ciphertext back
    4. server decapsulates the ciphertext -> the same secret

Wire protocol (2 messages, 1 round trip -- same shape as classical):
    server -> client : kem_public_key
    client -> server : kem_ciphertext
"""
from oqs_compat import KeyEncapsulation

from common import SocketLike, send_msg, recv_msg, hkdf_derive, ByteCounter  # noqa: E402

HANDSHAKE_LABEL = b"pqc-bench mlkem v1"


def server_handshake(conn: SocketLike, counter: ByteCounter, mechanism: str) -> bytes:
    with KeyEncapsulation(mechanism) as kem:
        pk = kem.generate_keypair()
        counter.note_send(send_msg(conn, pk))

        ct = recv_msg(conn)
        counter.note_recv(4 + len(ct))

        shared_secret = kem.decap_secret(ct)
        return hkdf_derive(shared_secret, HANDSHAKE_LABEL)


def client_handshake(conn: SocketLike, counter: ByteCounter, mechanism: str) -> bytes:
    with KeyEncapsulation(mechanism) as kem:
        pk = recv_msg(conn)
        counter.note_recv(4 + len(pk))

        ct, shared_secret = kem.encap_secret(pk)
        counter.note_send(send_msg(conn, ct))

        return hkdf_derive(shared_secret, HANDSHAKE_LABEL)
