"""Compatibility layer for ML-KEM / liboqs access.

This project expects the Open Quantum Safe Python bindings, but the
environment may instead have an unrelated `oqs` package installed from PyPI.
When the real bindings are unavailable, we fall back to a small in-process
shim that preserves the same API shape for the handshakes and tests.

!! The shim is NOT cryptography. It exists so pure-framing unit tests can run
!! on a machine without liboqs. Anything that produces *results* (bench.py) or
!! makes a *security claim* (the adversarial tests) must call
!! require_real_oqs(), which refuses to proceed on the shim unless you opt in
!! explicitly with PQC_BENCH_ALLOW_SHIM=1.
"""
from __future__ import annotations

import hashlib
import os
import warnings
from pathlib import Path
from typing import Any, Optional

_default_install = Path(__file__).resolve().parent.parent / "liboqs-install"
if "OQS_INSTALL_PATH" not in os.environ and _default_install.exists():
    os.environ["OQS_INSTALL_PATH"] = str(_default_install)

try:  # pragma: no cover - exercised at runtime
    import oqs as _real_oqs  # type: ignore
except Exception:  # pragma: no cover - fallback path
    _real_oqs = None


REAL_OQS: bool = bool(
    _real_oqs is not None
    and callable(getattr(_real_oqs, "KeyEncapsulation", None))
    and callable(getattr(_real_oqs, "Signature", None))
)

# FIPS 203 (ML-KEM): mechanism -> (public key bytes, ciphertext bytes)
KEM_SIZES = {
    "ML-KEM-512": (800, 768),
    "ML-KEM-768": (1184, 1088),
    "ML-KEM-1024": (1568, 1568),
}
# FIPS 204 (ML-DSA): mechanism -> (public key bytes, signature bytes)
SIG_SIZES = {
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
}


def require_real_oqs(what: str = "this operation") -> None:
    """Refuse to run on the fake fallback KEM (see module docstring)."""
    if REAL_OQS:
        return
    if os.environ.get("PQC_BENCH_ALLOW_SHIM") == "1":
        warnings.warn(
            f"{what}: running on the INSECURE in-process shim, not liboqs. "
            "Results/tests are meaningless as security evidence.",
            RuntimeWarning,
            stacklevel=2,
        )
        return
    raise RuntimeError(
        f"{what} requires the real liboqs Python bindings (ML-KEM + ML-DSA), "
        "but only the insecure fallback shim is available. Build liboqs and "
        "`pip install liboqs-python` (see README), or set PQC_BENCH_ALLOW_SHIM=1 "
        "if you really mean it."
    )


def Signature(mechanism: str, secret_key: Optional[bytes] = None):
    """ML-DSA access. There is deliberately no fallback shim for signatures."""
    require_real_oqs("Signature (ML-DSA)")
    if _real_oqs is None or not callable(getattr(_real_oqs, "Signature", None)):
        raise RuntimeError("No ML-DSA implementation available (liboqs missing).")
    if secret_key is None:
        return _real_oqs.Signature(mechanism)
    return _real_oqs.Signature(mechanism, secret_key)


def backend_info() -> dict:
    """Provenance record stamped into results/run_metadata.json."""
    info = {"backend": "liboqs" if REAL_OQS else "INSECURE-SHIM"}
    for key, fn in (("liboqs_version", "oqs_version"), ("liboqs_python_version", "oqs_python_version")):
        f = getattr(_real_oqs, fn, None) if _real_oqs is not None else None
        try:
            info[key] = f() if callable(f) else "unknown"
        except Exception:  # pragma: no cover
            info[key] = "unknown"
    return info


def _mechanism_size(mechanism: str) -> int:
    level = mechanism.rsplit("-", 1)[-1]
    if level == "512":
        return 768
    if level == "768":
        return 1152
    if level == "1024":
        return 1536
    return 1024


class _FallbackKeyEncapsulation:
    def __init__(self, mechanism: str):
        self.mechanism = mechanism
        self._secret = os.urandom(32)

    def __enter__(self) -> "_FallbackKeyEncapsulation":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return False

    def generate_keypair(self) -> bytes:
        size = _mechanism_size(self.mechanism)
        self._secret = os.urandom(32)
        label = self.mechanism.encode("utf-8")
        pk = self._secret + b"\x00" * max(0, size - len(self._secret)) + label
        return pk[:size]

    def encap_secret(self, pk: bytes) -> tuple[bytes, bytes]:
        size = _mechanism_size(self.mechanism)
        label = self.mechanism.encode("utf-8")
        secret_material = pk[:32] if len(pk) >= 32 else pk
        shared_secret = hashlib.sha256(secret_material + label).digest()
        ct = hashlib.sha256(pk + label).digest() * ((size // 32) + 1)
        return ct[:size], shared_secret

    def decap_secret(self, ct: bytes) -> bytes:
        label = self.mechanism.encode("utf-8")
        return hashlib.sha256(self._secret + label).digest()


class KeyEncapsulation:
    def __new__(cls, mechanism: str):
        if _real_oqs is not None:
            key_encapsulation_cls = getattr(_real_oqs, "KeyEncapsulation", None)
            if callable(key_encapsulation_cls):
                return key_encapsulation_cls(mechanism)
        return super().__new__(cls)

    def __init__(self, mechanism: str):
        self._impl = _FallbackKeyEncapsulation(mechanism)

    def __enter__(self) -> "_FallbackKeyEncapsulation":
        return self._impl.__enter__()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return self._impl.__exit__(exc_type, exc, tb)

    def generate_keypair(self) -> bytes:
        return self._impl.generate_keypair()

    def encap_secret(self, pk: bytes) -> tuple[bytes, bytes]:
        return self._impl.encap_secret(pk)

    def decap_secret(self, ct: bytes) -> bytes:
        return self._impl.decap_secret(ct)
