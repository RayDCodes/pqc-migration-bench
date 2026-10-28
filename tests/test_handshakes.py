import pytest

import bench


@pytest.mark.parametrize("mode", ["classical", "pqc", "hybrid", "signed"])
@pytest.mark.parametrize("mechanism", bench.MECHANISMS)
def test_real_handshake(mode, mechanism):
    elapsed, size = bench.run_one_handshake(mode, mechanism, 0)
    assert elapsed > 0
    assert size >= 72


def test_key_mismatch_is_always_rejected(monkeypatch):
    original = bench.handshake_classical.client_handshake
    def mismatched(*args):
        original(*args)
        return b"incorrect key"
    monkeypatch.setattr(bench.handshake_classical, "client_handshake", mismatched)
    with pytest.raises(RuntimeError, match="key mismatch"):
        bench.run_one_handshake("classical", "n/a", 0)


def test_server_failure_propagates(monkeypatch):
    def fail(*args):
        raise ValueError("server failure")
    monkeypatch.setattr(bench.handshake_classical, "server_handshake", fail)
    with pytest.raises((ConnectionError, RuntimeError)):
        bench.run_one_handshake("classical", "n/a", 0)


@pytest.mark.parametrize("mode,delay", [("unknown", 0), ("classical", -1), ("classical", 1001)])
def test_invalid_configuration(mode, delay):
    with pytest.raises(ValueError):
        bench.run_one_handshake(mode, "n/a", delay)
