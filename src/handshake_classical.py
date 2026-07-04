"""
Classical ephemeral ECDH handshake using X25519 -- the same primitive
TLS 1.3 uses today for its default key exchange. This is the baseline
every PQC / hybrid comparison in this project is measured against.

Wire protocol (2 messages, 1 round trip):
    server -> client : server_pubkey (32 bytes)
    client -> server : client_pubkey (32 bytes)
    both sides then independently compute the same X25519 shared secret
    and run it through HKDF to get a session key.
"""
import socket
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from common import SocketLike, send_msg, recv_msg, hkdf_derive, ByteCounter

HANDSHAKE_LABEL = b"pqc-bench classical x25519 v1"


def server_handshake(conn: SocketLike, counter: ByteCounter) -> bytes:
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()

    counter.note_send(send_msg(conn, pub_bytes))
    peer_pub_bytes = recv_msg(conn)
    counter.note_recv(4 + len(peer_pub_bytes))

    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = priv.exchange(peer_pub)
    return hkdf_derive(shared_secret, HANDSHAKE_LABEL)


def client_handshake(conn: SocketLike, counter: ByteCounter) -> bytes:
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()

    peer_pub_bytes = recv_msg(conn)
    counter.note_recv(4 + len(peer_pub_bytes))
    counter.note_send(send_msg(conn, pub_bytes))

    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_secret = priv.exchange(peer_pub)
    return hkdf_derive(shared_secret, HANDSHAKE_LABEL)
