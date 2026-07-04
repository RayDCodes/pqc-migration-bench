"""
Hybrid handshake: X25519 + ML-KEM combined in a single round trip, the
same shape as what's actually being deployed today (e.g. Chrome/BoringSSL's
X25519Kyber768, TLS 1.3 draft hybrid groups). The idea: even if ML-KEM
turns out to have an unknown classical weakness, the classical ECDH half
still protects you. Even if a quantum computer breaks the ECDH half, the
KEM half still protects you. You need both broken to lose confidentiality.

Wire protocol (still just 2 messages / 1 round trip -- this is the whole
point of hybrid designs, you don't pay for an extra round trip):
    server -> client : x25519_pubkey || kem_pubkey
    client -> server : x25519_pubkey || kem_ciphertext

Final session key = HKDF(x25519_shared_secret || kem_shared_secret)
"""
import struct

from oqs_compat import KeyEncapsulation

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from common import SocketLike, send_msg, recv_msg, hkdf_derive, ByteCounter  # noqa: E402

HANDSHAKE_LABEL = b"pqc-bench hybrid x25519+mlkem v1"


def _pack(a: bytes, b: bytes) -> bytes:
    return struct.pack(">I", len(a)) + a + b


def _unpack(blob: bytes):
    (alen,) = struct.unpack(">I", blob[:4])
    return blob[4 : 4 + alen], blob[4 + alen :]


def server_handshake(conn: SocketLike, counter: ByteCounter, mechanism: str) -> bytes:
    ec_priv = X25519PrivateKey.generate()
    ec_pub_bytes = ec_priv.public_key().public_bytes_raw()

    with KeyEncapsulation(mechanism) as kem:
        kem_pk = kem.generate_keypair()

        first_msg = _pack(ec_pub_bytes, kem_pk)
        counter.note_send(send_msg(conn, first_msg))

        second_msg = recv_msg(conn)
        counter.note_recv(4 + len(second_msg))
        peer_ec_pub_bytes, kem_ct = _unpack(second_msg)

        peer_ec_pub = X25519PublicKey.from_public_bytes(peer_ec_pub_bytes)
        ec_secret = ec_priv.exchange(peer_ec_pub)
        kem_secret = kem.decap_secret(kem_ct)

    return hkdf_derive(ec_secret + kem_secret, HANDSHAKE_LABEL)


def client_handshake(conn: SocketLike, counter: ByteCounter, mechanism: str) -> bytes:
    ec_priv = X25519PrivateKey.generate()
    ec_pub_bytes = ec_priv.public_key().public_bytes_raw()

    first_msg = recv_msg(conn)
    counter.note_recv(4 + len(first_msg))
    peer_ec_pub_bytes, kem_pk = _unpack(first_msg)

    with KeyEncapsulation(mechanism) as kem:
        kem_ct, kem_secret = kem.encap_secret(kem_pk)

        second_msg = _pack(ec_pub_bytes, kem_ct)
        counter.note_send(send_msg(conn, second_msg))

    peer_ec_pub = X25519PublicKey.from_public_bytes(peer_ec_pub_bytes)
    ec_secret = ec_priv.exchange(peer_ec_pub)

    return hkdf_derive(ec_secret + kem_secret, HANDSHAKE_LABEL)
