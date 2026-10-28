import ctypes.util
import importlib
import os
from pathlib import Path
from common import ProtocolError

KEM_MECHANISMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
SIG_MECHANISM = "ML-DSA-65"


class BackendUnavailable(RuntimeError):
    pass


class _CheckedKEM:
    def __init__(self, implementation):
        self.implementation = implementation

    def __enter__(self):
        self.implementation.__enter__()
        return self

    def __exit__(self, *args):
        return self.implementation.__exit__(*args)

    def generate_keypair(self):
        return self.implementation.generate_keypair()

    def encap_secret(self, public_key):
        if len(public_key) != self.implementation.length_public_key:
            raise ProtocolError("invalid ML-KEM public key length")
        return self.implementation.encap_secret(public_key)

    def decap_secret(self, ciphertext):
        if len(ciphertext) != self.implementation.length_ciphertext:
            raise ProtocolError("invalid ML-KEM ciphertext length")
        return self.implementation.decap_secret(ciphertext)


def require_backend():
    install = Path(os.environ.get(
        "OQS_INSTALL_PATH", Path(__file__).resolve().parent.parent / "liboqs-install"
    ))
    native_paths = [
        install / directory / name
        for directory in ("lib", "lib64", "bin")
        for name in ("liboqs.so", "liboqs.dylib", "oqs.dll")
    ]
    local_library = next((str(path) for path in native_paths if path.is_file()), None)
    library = local_library or ctypes.util.find_library("oqs")
    if not library:
        raise BackendUnavailable("Native liboqs missing; run ./setup.sh. No fallback is permitted.")
    try:
        ctypes.CDLL(library)
    except OSError as error:
        raise BackendUnavailable("Native liboqs cannot be loaded; automatic installation is disabled") from error
    os.environ.setdefault("OQS_INSTALL_PATH", str(install))
    try:
        backend = importlib.import_module("oqs")
        if not callable(getattr(backend, "KeyEncapsulation", None)):
            raise BackendUnavailable("Installed oqs is not the Open Quantum Safe bindings")
        if not callable(getattr(backend, "Signature", None)):
            raise BackendUnavailable("Open Quantum Safe signature support is missing")
        return backend
    except (ImportError, OSError, RuntimeError) as error:
        raise BackendUnavailable("Real liboqs bindings unavailable; run ./setup.sh") from error


def KeyEncapsulation(mechanism: str):
    if mechanism not in KEM_MECHANISMS:
        raise ValueError(f"Unsupported KEM mechanism: {mechanism}")
    backend = require_backend()
    if mechanism not in backend.get_enabled_kem_mechanisms():
        raise BackendUnavailable(f"liboqs does not enable {mechanism}")
    return _CheckedKEM(backend.KeyEncapsulation(mechanism))


def Signature(mechanism: str):
    if mechanism != SIG_MECHANISM:
        raise ValueError(f"Unsupported signature mechanism: {mechanism}")
    backend = require_backend()
    if mechanism not in backend.get_enabled_sig_mechanisms():
        raise BackendUnavailable(f"liboqs does not enable {mechanism}")
    return backend.Signature(mechanism)
