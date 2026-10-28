import hashlib
import hmac
import secrets

from oqs_compat import KeyEncapsulation, Signature
from common import (
    ByteCounter, ProtocolError, SocketLike, hkdf_derive,
    pack_fields, recv_msg, send_msg, unpack_fields,
)

HANDSHAKE_LABEL = b"pqc-bench mlkem-signed v2"
NONCE_BYTES = 32


def signed_message(kem_mechanism, sig_mechanism, challenge, kem_public_key):
    return pack_fields(
        HANDSHAKE_LABEL, kem_mechanism.encode(), sig_mechanism.encode(),
        challenge, kem_public_key,
    )


def session_key(secret, message, ciphertext):
    transcript_hash = hashlib.sha256(pack_fields(message, ciphertext)).digest()
    return hkdf_derive(secret, HANDSHAKE_LABEL + transcript_hash)


def server_handshake(
    conn: SocketLike, counter: ByteCounter, kem_mechanism: str,
    sig_mechanism: str, signer,
) -> bytes:
    challenge = recv_msg(conn)
    counter.note_recv(4 + len(challenge))
    if len(challenge) != NONCE_BYTES:
        raise ProtocolError("invalid client challenge length")

    with KeyEncapsulation(kem_mechanism) as kem:
        kem_public_key = kem.generate_keypair()
        message = signed_message(kem_mechanism, sig_mechanism, challenge, kem_public_key)
        response = pack_fields(kem_public_key, signer.sign(message))
        counter.note_send(send_msg(conn, response))

        ciphertext = recv_msg(conn)
        counter.note_recv(4 + len(ciphertext))
        key = session_key(kem.decap_secret(ciphertext), message, ciphertext)

    finished = hmac.digest(key, b"server finished" + hashlib.sha256(message).digest(), "sha256")
    counter.note_send(send_msg(conn, finished))
    return key


def client_handshake(
    conn: SocketLike, counter: ByteCounter, kem_mechanism: str,
    sig_mechanism: str, trusted_signing_key: bytes,
) -> bytes:
    if not trusted_signing_key:
        raise ValueError("an independently provisioned signing key is required")

    challenge = secrets.token_bytes(NONCE_BYTES)
    counter.note_send(send_msg(conn, challenge))
    response = recv_msg(conn)
    counter.note_recv(4 + len(response))
    kem_public_key, signature = unpack_fields(response, 2)
    message = signed_message(kem_mechanism, sig_mechanism, challenge, kem_public_key)

    with Signature(sig_mechanism) as verifier:
        if len(trusted_signing_key) != verifier.length_public_key:
            raise ProtocolError("invalid trusted signing key length")
        if len(signature) != verifier.length_signature:
            raise ProtocolError("invalid signature length")
        if not verifier.verify(message, signature, trusted_signing_key):
            raise ProtocolError("signature verification failed")

    with KeyEncapsulation(kem_mechanism) as kem:
        ciphertext, secret = kem.encap_secret(kem_public_key)
    counter.note_send(send_msg(conn, ciphertext))
    key = session_key(secret, message, ciphertext)

    finished = recv_msg(conn)
    counter.note_recv(4 + len(finished))
    expected = hmac.digest(key, b"server finished" + hashlib.sha256(message).digest(), "sha256")
    if not hmac.compare_digest(finished, expected):
        raise ProtocolError("server key confirmation failed")
    return key
