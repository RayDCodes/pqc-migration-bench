import io
import struct

import pytest

from common import (
    MAX_FRAME_BYTES, ProtocolError, hkdf_derive, pack_fields,
    recv_msg, send_msg, unpack_fields,
)
from handshake_hybrid import _unpack
import oqs_compat


class MemorySocket:
    def __init__(self, data=b"", fragment_size=65536):
        self.data = io.BytesIO(data)
        self.fragment_size = fragment_size
        self.sent = bytearray()

    def recv(self, count):
        return self.data.read(min(count, self.fragment_size))

    def sendall(self, data):
        self.sent.extend(data)


def test_fragmented_tcp_reads():
    sock = MemorySocket(struct.pack(">I", 5) + b"hello", fragment_size=1)
    assert recv_msg(sock) == b"hello"


@pytest.mark.parametrize("size", [0, MAX_FRAME_BYTES + 1, 2 ** 32 - 1])
def test_reject_size_before_reading_payload(size):
    with pytest.raises(ProtocolError, match="frame size"):
        recv_msg(MemorySocket(struct.pack(">I", size)))


@pytest.mark.parametrize("data", [b"", b"\x00\x00", struct.pack(">I", 8) + b"abc"])
def test_truncated_frame(data):
    with pytest.raises(ConnectionError):
        recv_msg(MemorySocket(data))


def test_outgoing_limit():
    with pytest.raises(ProtocolError):
        send_msg(MemorySocket(), b"x" * (MAX_FRAME_BYTES + 1))


@pytest.mark.parametrize("data", [b"", b"\x00", pack_fields(b"a") + b"extra", struct.pack(">I", 50)])
def test_invalid_packed_fields(data):
    with pytest.raises(ProtocolError):
        unpack_fields(data, 1)


def test_fields_round_trip():
    assert unpack_fields(pack_fields(b"one", b"two"), 2) == (b"one", b"two")


@pytest.mark.parametrize("data", [b"", struct.pack(">I", 31) + b"x" * 40, struct.pack(">I", 32) + b"x" * 32])
def test_invalid_hybrid_lengths(data):
    with pytest.raises(ProtocolError):
        _unpack(data)


def test_kdf_separates_protocols():
    assert hkdf_derive(b"secret", b"classical") != hkdf_derive(b"secret", b"hybrid")


def test_missing_backend_fails_without_import(monkeypatch, tmp_path):
    monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path))
    monkeypatch.setattr(oqs_compat.ctypes.util, "find_library", lambda _: None)
    def unexpected_import(name):
        raise AssertionError("must not import auto-installing bindings without native library")
    monkeypatch.setattr(oqs_compat.importlib, "import_module", unexpected_import)
    with pytest.raises(oqs_compat.BackendUnavailable, match="No fallback"):
        oqs_compat.KeyEncapsulation("ML-KEM-768")


def test_unknown_mechanism_is_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        oqs_compat.KeyEncapsulation("Kyber-misspelled")


def test_unloadable_native_library_does_not_trigger_install(monkeypatch, tmp_path):
    library_dir = tmp_path / "lib"
    library_dir.mkdir()
    (library_dir / "liboqs.so").write_bytes(b"invalid shared library")
    monkeypatch.setenv("OQS_INSTALL_PATH", str(tmp_path))
    with pytest.raises(oqs_compat.BackendUnavailable, match="cannot be loaded"):
        oqs_compat.require_backend()


def test_classical_rejects_all_zero_peer_key():
    import handshake_classical
    from common import ByteCounter
    conn = MemorySocket(struct.pack(">I", 32) + b"\0" * 32)
    with pytest.raises(ValueError):
        handshake_classical.client_handshake(conn, ByteCounter())
