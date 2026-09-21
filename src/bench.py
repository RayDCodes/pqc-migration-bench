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
    signed    -> ML-KEM + ML-DSA signature over the KEM key (v1: no trust anchor,
                 see handshake_signed.py -- kept for comparison)
    auth      -> hybrid X25519+ML-KEM, pinned ML-DSA identity, transcript-bound
                 signature, key confirmation (handshake_auth.py)

Timing definitions (both are wall-clock from the start of the handshake):
    handshake_time_ms : until BOTH endpoints hold the session key
    client_ready_ms   : until the CLIENT holds a verified session key

Network model (--net-model):
    pipelined (default): back-to-back sends overlap like a real link.
    serial   (legacy)  : sleeps before every send; reproduces the original CSV,
                         but charges protocols per message instead of per round trip.

Usage:
    python3 bench.py --trials 60 --out ../results/handshake_results.csv
"""
import argparse
import csv
import json
import platform
import socket
import threading
import time
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC_DIR))
from netsim import DelayedSocket
from common import ByteCounter
import handshake_classical
import handshake_pqc
import handshake_hybrid
import handshake_signed
import handshake_auth
from oqs_compat import require_real_oqs, backend_info
from common import rng_selfcheck

__all__ = ["DelayedSocket"]

MECHANISMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
SIG_MECHANISM = "ML-DSA-65"
LATENCIES_MS = [0, 20, 75]
TRIALS_DEFAULT = 60

_IDENTITY = None


def get_identity():
    """One long-term ML-DSA identity for the whole run, generated OUTSIDE the
    timed region (a real server does not mint a new identity per connection)."""
    global _IDENTITY
    if _IDENTITY is None:
        _IDENTITY = handshake_auth.ServerIdentity.generate(SIG_MECHANISM)
    return _IDENTITY


def run_server(mode, mechanism, delay_s, net_model, ready_event, result_holder, port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port_holder.append(srv.getsockname()[1])
    srv.listen(1)
    ready_event.set()

    conn, _ = srv.accept()
    dconn = DelayedSocket(conn, delay_s, net_model)
    counter = ByteCounter()

    if mode == "classical":
        key = handshake_classical.server_handshake(dconn, counter)
    elif mode == "pqc":
        key = handshake_pqc.server_handshake(dconn, counter, mechanism)
    elif mode == "hybrid":
        key = handshake_hybrid.server_handshake(dconn, counter, mechanism)
    elif mode == "signed":
        key = handshake_signed.server_handshake(dconn, counter, mechanism, SIG_MECHANISM)
    elif mode == "auth":
        key = handshake_auth.server_handshake(dconn, counter, mechanism, identity=get_identity())
    else:
        raise ValueError(mode)

    result_holder["server_done_t"] = time.perf_counter()
    result_holder["server_key"] = key
    result_holder["server_bytes_sent"] = counter.sent
    result_holder["server_bytes_recv"] = counter.received
    dconn.close()  # flushes any queued (delayed) bytes before closing
    srv.close()


def run_one_handshake(mode: str, mechanism: str, delay_ms: int, net_model: str = "pipelined"):
    delay_s = delay_ms / 1000.0
    ready_event = threading.Event()
    result_holder = {}
    port_holder = []

    t = threading.Thread(
        target=run_server,
        args=(mode, mechanism, delay_s, net_model, ready_event, result_holder, port_holder),
        daemon=True,
    )
    t.start()
    ready_event.wait()
    port = port_holder[0]

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(("127.0.0.1", port))
    dclient = DelayedSocket(client_sock, delay_s, net_model)
    counter = ByteCounter()

    start = time.perf_counter()
    if mode == "classical":
        client_key = handshake_classical.client_handshake(dclient, counter)
    elif mode == "pqc":
        client_key = handshake_pqc.client_handshake(dclient, counter, mechanism)
    elif mode == "hybrid":
        client_key = handshake_hybrid.client_handshake(dclient, counter, mechanism)
    elif mode == "signed":
        client_key = handshake_signed.client_handshake(dclient, counter, mechanism, SIG_MECHANISM)
    elif mode == "auth":
        client_key = handshake_auth.client_handshake(
            dclient, counter, mechanism, trusted_sig_pk=get_identity().public_key
        )
    else:
        raise ValueError(mode)
    client_done_t = time.perf_counter()

    dclient.close()  # flush our last (delayed) message so the server can finish
    t.join()
    # Handshake is complete when BOTH sides hold the key.
    elapsed_ms = (max(client_done_t, result_holder["server_done_t"]) - start) * 1000.0
    client_ready_ms = (client_done_t - start) * 1000.0

    assert client_key == result_holder["server_key"], "handshake key mismatch!"

    total_bytes = (
        counter.sent
        + counter.received
        + result_holder["server_bytes_sent"]
        + result_holder["server_bytes_recv"]
    ) // 2  # sent+recv double counts the same wire bytes from both ends

    return elapsed_ms, client_ready_ms, total_bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=TRIALS_DEFAULT)
    ap.add_argument("--out", type=str, default="results/handshake_results.csv")
    ap.add_argument("--quick", action="store_true", help="Small run for a fast smoke test")
    ap.add_argument(
        "--net-model",
        choices=["pipelined", "serial"],
        default="pipelined",
        help="latency model (see netsim.py); 'serial' reproduces the legacy CSV",
    )
    args = ap.parse_args()

    # Results are only meaningful on the real liboqs; refuse the fake shim.
    require_real_oqs("bench.py")
    rng_selfcheck()

    trials = 10 if args.quick else args.trials
    latencies = [0, 50] if args.quick else LATENCIES_MS
    mechanisms = ["ML-KEM-768"] if args.quick else MECHANISMS

    rows = []
    jobs = [("classical", "n/a", lat) for lat in latencies]
    jobs += [("pqc", m, lat) for m in mechanisms for lat in latencies]
    jobs += [("hybrid", m, lat) for m in mechanisms for lat in latencies]
    jobs += [("signed", m, lat) for m in mechanisms for lat in latencies]
    jobs += [("auth", m, lat) for m in mechanisms for lat in latencies]
    get_identity()  # keygen outside every timed region

    for mode, mechanism, lat in jobs:
        print(f"[bench] mode={mode:9s} mech={mechanism:12s} latency={lat:4d}ms  ", end="", flush=True)
        times, readys, sizes = [], [], []
        # one warmup run to avoid first-call JIT/import overhead skewing results
        run_one_handshake(mode, mechanism, lat, args.net_model)
        for _ in range(trials):
            t_ms, ready_ms, nbytes = run_one_handshake(mode, mechanism, lat, args.net_model)
            times.append(t_ms)
            readys.append(ready_ms)
            sizes.append(nbytes)
        for t_ms, ready_ms, nbytes in zip(times, readys, sizes):
            rows.append(
                {
                    "mode": mode,
                    "mechanism": mechanism,
                    "sim_latency_ms": lat,
                    "handshake_time_ms": round(t_ms, 4),
                    "client_ready_ms": round(ready_ms, 4),
                    "wire_bytes": nbytes,
                }
            )
        avg = sum(times) / len(times)
        avg_ready = sum(readys) / len(readys)
        avg_bytes = sum(sizes) / len(sizes)
        print(f"complete={avg:7.3f}ms  client_ready={avg_ready:7.3f}ms  avg_bytes={avg_bytes:.0f}")

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT_DIR / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["mode", "mechanism", "sim_latency_ms", "handshake_time_ms", "client_ready_ms", "wire_bytes"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n[bench] wrote {len(rows)} rows to {out_path}")

    # Provenance: which crypto produced these numbers, and under what model.
    meta = {
        **backend_info(),
        "net_model": args.net_model,
        "trials_per_config": trials,
        "sig_mechanism": SIG_MECHANISM,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    meta_path = out_path.with_name(out_path.stem + "_metadata.json")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    print(f"[bench] wrote provenance to {meta_path}")


if __name__ == "__main__":
    main()
