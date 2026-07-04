"""
Correctness tests for all three handshake modes.

Run with:  python3 -m pytest test_handshakes.py -v
Or plain:  python3 test_handshakes.py
"""
import socket
import threading
import sys

sys.path.insert(0, ".")
from common import ByteCounter
import handshake_classical
import handshake_pqc
import handshake_hybrid


def _run_pair(mode: str, mechanism: str = "ML-KEM-768"):
    """Spins up a real server+client pair on localhost and returns
    (server_key, client_key, server_counter, client_counter)."""
    ready = threading.Event()
    holder = {}
    port_holder = []

    def server_thread():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port_holder.append(srv.getsockname()[1])
        srv.listen(1)
        ready.set()
        conn, _ = srv.accept()
        counter = ByteCounter()
        if mode == "classical":
            key = handshake_classical.server_handshake(conn, counter)
        elif mode == "pqc":
            key = handshake_pqc.server_handshake(conn, counter, mechanism)
        elif mode == "hybrid":
            key = handshake_hybrid.server_handshake(conn, counter, mechanism)
        holder["server_key"] = key
        holder["server_counter"] = counter
        conn.close()
        srv.close()

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    ready.wait()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port_holder[0]))
    counter = ByteCounter()
    if mode == "classical":
        client_key = handshake_classical.client_handshake(client_sock, counter)
    elif mode == "pqc":
        client_key = handshake_pqc.client_handshake(client_sock, counter, mechanism)
    elif mode == "hybrid":
        client_key = handshake_hybrid.client_handshake(client_sock, counter, mechanism)
    client_sock.close()
    t.join()

    return client_key, holder["server_key"], counter, holder["server_counter"]


def test_classical_keys_match():
    ck, sk, _, _ = _run_pair("classical")
    assert ck == sk
    assert len(ck) == 32  # HKDF output length


def test_pqc_keys_match_all_levels():
    for mech in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        ck, sk, _, _ = _run_pair("pqc", mech)
        assert ck == sk, f"key mismatch for {mech}"


def test_hybrid_keys_match_all_levels():
    for mech in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        ck, sk, _, _ = _run_pair("hybrid", mech)
        assert ck == sk, f"key mismatch for {mech}"


def test_different_runs_produce_different_keys():
    """Ephemeral handshakes must not be deterministic -- two independent
    runs should never derive the same session key."""
    k1, _, _, _ = _run_pair("classical")
    k2, _, _, _ = _run_pair("classical")
    assert k1 != k2


def test_modes_are_not_interchangeable_in_size():
    """Sanity check the core thesis of the project: PQC/hybrid payloads
    are meaningfully larger than classical, at every ML-KEM level."""
    _, _, c_counter, _ = _run_pair("classical")
    for mech in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        _, _, p_counter, _ = _run_pair("pqc", mech)
        assert p_counter.sent + p_counter.received > c_counter.sent + c_counter.received


def test_byte_counter_is_consistent():
    """Client bytes-sent should equal server bytes-received and vice versa."""
    _, _, c_counter, s_counter = _run_pair("hybrid", "ML-KEM-768")
    assert c_counter.sent == s_counter.received
    assert s_counter.sent == c_counter.received


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
