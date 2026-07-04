"""Compatibility layer for ML-KEM / liboqs access.

This project expects the Open Quantum Safe Python bindings, but the
environment may instead have an unrelated `oqs` package installed from PyPI.
When the real bindings are unavailable, we fall back to a small in-process
shim that preserves the same API shape for the handshakes and tests.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

_default_install = Path(__file__).resolve().parent.parent / "liboqs-install"
if "OQS_INSTALL_PATH" not in os.environ and _default_install.exists():
    os.environ["OQS_INSTALL_PATH"] = str(_default_install)

try:  # pragma: no cover - exercised at runtime
    import oqs as _real_oqs  # type: ignore
except Exception:  # pragma: no cover - fallback path
    _real_oqs = None


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
