"""
Benchmark harness.

For each (mode, security_level, simulated_latency) combination, spins up
a real TCP server on localhost in a background thread, connects a client,
runs the handshake N times, and records:
    - wall-clock handshake time (ms)
    - bytes sent by the client
    - bytes sent by the server
    - total bytes on the wire

Modes:
    classical -> X25519 only (today's baseline)
    pqc       -> ML-KEM only (pure post-quantum)
    hybrid    -> X25519 + ML-KEM combined (what's actually being deployed)

Usage:
    python3 bench.py --trials 200 --out ../results/handshake_results.csv
"""
import argparse
import csv
import socket
import threading
import time
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC_DIR))
from netsim import DelayedSocket
from common import ByteCounter
import handshake_classical
import handshake_pqc
import handshake_hybrid

__all__ = ["DelayedSocket"]

MECHANISMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
LATENCIES_MS = [0, 20, 75]  # one-way simulated network delay (localhost / same-region / cross-region-ish)
TRIALS_DEFAULT = 60


def run_server(mode, mechanism, delay_s, ready_event, result_holder, port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_holder.append(srv.getsockname()[1])
    srv.listen(1)
    ready_event.set()

    conn, _ = srv.accept()
    dconn = DelayedSocket(conn, delay_s)
    counter = ByteCounter()

    if mode == "classical":
        key = handshake_classical.server_handshake(dconn, counter)
    elif mode == "pqc":
        key = handshake_pqc.server_handshake(dconn, counter, mechanism)
    elif mode == "hybrid":
        key = handshake_hybrid.server_handshake(dconn, counter, mechanism)
    else:
        raise ValueError(mode)

    result_holder["server_key"] = key
    result_holder["server_bytes_sent"] = counter.sent
    result_holder["server_bytes_recv"] = counter.received
    conn.close()
    srv.close()


def run_one_handshake(mode: str, mechanism: str, delay_ms: int):
    delay_s = delay_ms / 1000.0
    ready_event = threading.Event()
    result_holder = {}
    port_holder = []

    t = threading.Thread(
        target=run_server,
        args=(mode, mechanism, delay_s, ready_event, result_holder, port_holder),
        daemon=True,
    )
    t.start()
    ready_event.wait()
    port = port_holder[0]

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    dclient = DelayedSocket(client_sock, delay_s)
    counter = ByteCounter()

    start = time.perf_counter()
    if mode == "classical":
        client_key = handshake_classical.client_handshake(dclient, counter)
    elif mode == "pqc":
        client_key = handshake_pqc.client_handshake(dclient, counter, mechanism)
    elif mode == "hybrid":
        client_key = handshake_hybrid.client_handshake(dclient, counter, mechanism)
    else:
        raise ValueError(mode)
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    client_sock.close()
    t.join()

    assert client_key == result_holder["server_key"], "handshake key mismatch!"

    total_bytes = (
        counter.sent
        + counter.received
        + result_holder["server_bytes_sent"]
        + result_holder["server_bytes_recv"]
    ) // 2  # sent+recv double counts the same wire bytes from both ends

    return elapsed_ms, total_bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=TRIALS_DEFAULT)
    ap.add_argument("--out", type=str, default="results/handshake_results.csv")
    ap.add_argument("--quick", action="store_true", help="Small run for a fast smoke test")
    args = ap.parse_args()

    trials = 10 if args.quick else args.trials
    latencies = [0, 50] if args.quick else LATENCIES_MS
    mechanisms = ["ML-KEM-768"] if args.quick else MECHANISMS

    rows = []
    jobs = [("classical", "n/a", lat) for lat in latencies]
    jobs += [("pqc", m, lat) for m in mechanisms for lat in latencies]
    jobs += [("hybrid", m, lat) for m in mechanisms for lat in latencies]

    for mode, mechanism, lat in jobs:
        print(f"[bench] mode={mode:9s} mech={mechanism:12s} latency={lat:4d}ms  ", end="", flush=True)
        times, sizes = [], []
        # one warmup run to avoid first-call JIT/import overhead skewing results
        run_one_handshake(mode, mechanism, lat)
        for _ in range(trials):
            t_ms, nbytes = run_one_handshake(mode, mechanism, lat)
            times.append(t_ms)
            sizes.append(nbytes)
        for t_ms, nbytes in zip(times, sizes):
            rows.append(
                {
                    "mode": mode,
                    "mechanism": mechanism,
                    "sim_latency_ms": lat,
                    "handshake_time_ms": round(t_ms, 4),
                    "wire_bytes": nbytes,
                }
            )
        avg = sum(times) / len(times)
        avg_bytes = sum(sizes) / len(sizes)
        print(f"avg={avg:7.3f}ms  avg_bytes={avg_bytes:.0f}")

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT_DIR / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "mechanism", "sim_latency_ms", "handshake_time_ms", "wire_bytes"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[bench] wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
