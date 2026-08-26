"""
Authenticated PQC handshake: ML-KEM (FIPS 203) key exchange with the
server's ephemeral KEM public key signed under ML-DSA (FIPS 204).

handshake_pqc.py establishes confidentiality but not authenticity --
nothing stops a man-in-the-middle from swapping the KEM public key in
transit. This module adds the piece TLS gets from certificates: the
client verifies a signature over the KEM public key before trusting it.

Wire protocol (3 messages, 1.5 round trips):
    server -> client : sig_public_key
    server -> client : kem_public_key || signature(kem_public_key)
    client -> server : kem_ciphertext
"""
from oqs_compat import KeyEncapsulation
from oqs import Signature

from common import SocketLike, send_msg, recv_msg, hkdf_derive, ByteCounter  # noqa: E402

HANDSHAKE_LABEL = b"pqc-bench mlkem-signed v1"


def server_handshake(
    conn: SocketLike, counter: ByteCounter, kem_mechanism: str, sig_mechanism: str
) -> bytes:
    with Signature(sig_mechanism) as sig, KeyEncapsulation(kem_mechanism) as kem:
        sig_pk = sig.generate_keypair()
        counter.note_send(send_msg(conn, sig_pk))

        kem_pk = kem.generate_keypair()
        signature = sig.sign(kem_pk)
        counter.note_send(send_msg(conn, kem_pk))
        counter.note_send(send_msg(conn, signature))

        ct = recv_msg(conn)
        counter.note_recv(4 + len(ct))

        shared_secret = kem.decap_secret(ct)
        return hkdf_derive(shared_secret, HANDSHAKE_LABEL)


def client_handshake(
    conn: SocketLike, counter: ByteCounter, kem_mechanism: str, sig_mechanism: str
) -> bytes:
    with Signature(sig_mechanism) as sig, KeyEncapsulation(kem_mechanism) as kem:
        sig_pk = recv_msg(conn)
        counter.note_recv(4 + len(sig_pk))

        kem_pk = recv_msg(conn)
        counter.note_recv(4 + len(kem_pk))

        signature = recv_msg(conn)
        counter.note_recv(4 + len(signature))

        if not sig.verify(kem_pk, signature, sig_pk):
            raise ValueError("signature verification failed -- kem_pk may be tampered")

        ct, shared_secret = kem.encap_secret(kem_pk)
        counter.note_send(send_msg(conn, ct))

        return hkdf_derive(shared_secret, HANDSHAKE_LABEL)
