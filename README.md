# PQC Migration Benchmark: Classical vs Post-Quantum vs Hybrid vs Signed Key Exchange

This project benchmarks classical ECDH (X25519), post-quantum ML-KEM (FIPS 203 / Kyber), hybrid X25519+ML-KEM, and ML-DSA-signed ML-KEM key exchange. Each mode runs as a real handshake over TCP sockets, built on [liboqs](https://github.com/open-quantum-safe/liboqs) and Python's `cryptography` library.

## Why this matters

NIST recently finalized the first post-quantum cryptography standards (FIPS 203/204/205), and the urgency behind that isn't really about quantum computers existing today. It's "harvest now, decrypt later": an adversary can record encrypted traffic now and decrypt it retroactively once a cryptographically relevant quantum computer exists. For data with a long confidentiality shelf life, medical records, infrastructure credentials, state secrets, that threat is already live regardless of when the hardware actually shows up.

That's why most organizations are moving to hybrid key exchange (classical plus PQC combined) rather than jumping straight to pure PQC. You need both primitives broken to lose confidentiality, which is a meaningfully higher bar. Chrome/BoringSSL and OpenSSH already ship hybrid X25519+ML-KEM by default.

What I wanted to actually measure was what that migration costs, in handshake latency and bytes on the wire. And once key exchange is covered, what does the other half of a real handshake cost, actually proving you're talking to the server you think you are?

This project started after reading Rios et al., "[Toward the Quantum-Safe Web: Benchmarking Post-Quantum TLS](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10844321)" (IEEE Network, 2025), which benchmarks full TLS 1.3 handshakes across NIST PQC standards using OpenSSL/liboqs/oqs-provider in Docker. This got even more interesting once I started interning on Wells Fargo's cybersecurity team, where I saw up close how a large financial institution is actually approaching the move to post-quantum cryptography.

## What's actually being measured

This isn't a full TLS 1.3 implementation, just a minimal handshake protocol built directly on `oqs` (for ML-KEM and ML-DSA) and `cryptography` (for X25519). That keeps the comparison focused on the primitives themselves instead of burying them inside a full TLS stack.

Five modes:

| Mode          | Protects                                   | Server → Client                                                                 | Client → Server                     |
| ------------- | ------------------------------------------ | ------------------------------------------------------------------------------- | ----------------------------------- |
| **classical** | Confidentiality only                       | X25519 pubkey                                                                   | X25519 pubkey                       |
| **pqc**       | Confidentiality only                       | ML-KEM pubkey                                                                   | ML-KEM ciphertext                   |
| **hybrid**    | Confidentiality only                       | X25519 pubkey ‖ ML-KEM pubkey                                                   | X25519 pubkey ‖ ML-KEM ciphertext   |
| **signed**    | Authenticity of the KEM key (v1, see below) | ML-DSA pubkey, then ML-KEM pubkey ‖ ML-DSA signature                            | ML-KEM ciphertext                   |
| **auth**      | Full authenticated handshake (v2)          | ServerHello: random, chosen suite, identity pubkey, key share, transcript signature, Finished | Finished (key confirmation) |

The first three modes only give you confidentiality. Nothing stops a man-in-the-middle from swapping the key material mid-transit, which is the same gap you'd have without TLS certificates. `signed` closes part of that gap: the server signs its ephemeral ML-KEM public key with ML-DSA-65, and the client verifies that signature before trusting the key.

### Why there are two authenticated modes

`signed` is deliberately left as the original, minimal design so its cost stays comparable with the first published numbers. Once I wrote adversarial tests against it, it turned out to have real protocol gaps, which the test suite now documents as strict expected-failures (see [Testing](#testing)):

- **No pinned identity.** The client verifies the signature against the public key the server itself sends, so an attacker with their own ML-DSA key pair passes verification. It proves consistency, not identity.
- **No freshness.** The signature covers only the server's ephemeral key, with no client-supplied nonce, so a recorded server flight can be replayed to a new client.
- **No transcript binding.** Nothing ties the signature to the rest of the exchange, so there's nothing to catch a downgrade or tampering with other messages.
- **No key confirmation.** ML-KEM uses implicit rejection: a tampered ciphertext doesn't raise an error, it silently decapsulates to a different secret. Without a confirmation step, both sides finish "successfully" with mismatched keys.

`auth` is the fix, a TLS-1.3-shaped handshake (`src/handshake_auth.py`):

1. **ClientHello**: client random + offered suites (`X25519`, `ML-KEM`, `X25519+ML-KEM`) + key shares.
2. **ServerHello**: server random, chosen suite, long-term identity public key, key-exchange response, an ML-DSA signature over `SHA-256(ClientHello ‖ ServerHello body)`, and a Finished MAC.
3. **ClientFinished**: MAC over the transcript under the derived key.

Properties: the client only trusts a **pinned identity key**; the signature covers the **whole transcript including the client's offer**, so stripping PQ suites (downgrade) or replaying an old flight fails verification; the signature is checked **before** decapsulating anything; **Finished MACs** give explicit key confirmation, so ciphertext tampering is detected instead of silently producing mismatched keys; any failure triggers a defined **abort**: a one-byte alert to the peer, and no session key is ever returned. Server policy can also refuse classical-only clients (`require_pq`).

Every handshake:

1. Spins up a real TCP server thread on `127.0.0.1`
2. Connects a real client socket to it
3. Times wall-clock from the client's first byte sent to deriving its final key
4. Asserts both sides derived an identical session key. A mismatch fails loudly rather than silently
5. Records handshake time and total wire bytes

To separate cryptographic compute cost from network cost, every socket gets wrapped in a `DelayedSocket` that injects configurable one-way latency (0 / 20 / 75 ms), standing in for localhost, same-region, and cross-region-ish conditions.

### Timing metrics

The CSV now has two timing columns, since "done" means different things:

- `handshake_time_ms`: until **both** sides hold the session key.
- `client_ready_ms`: until the **client alone** holds a verified key (what a user actually waits for before sending data).

The schema is `mode,mechanism,sim_latency_ms,handshake_time_ms,client_ready_ms,wire_bytes`. Each run also writes `<name>_metadata.json` (backend, net model, trials, signature mechanism, Python version, platform, UTC timestamp) next to the CSV so results carry their provenance.

### Network models

`netsim.py` supports two delay models (`--net-model`):

- **`pipelined`** (default): `sendall()` returns immediately and the bytes arrive one-way-delay later, so back-to-back sends overlap the way they do on a real link.
- **`serial`** (legacy): `sendall()` sleeps before **every** call. Kept only to reproduce the original published CSV.

## Testing

Two suites cover the two review areas. Both run over real TCP sockets, and most adversarial tests drive a real handshake through an active man-in-the-middle proxy (`src/mitm.py`).

```bash
cd src
python -m pytest -v                       # everything
python -m pytest test_correctness.py -v   # crypto correctness
python -m pytest test_adversarial.py -v   # attacks
```

**`test_correctness.py`**

| Area | What's checked |
| --- | --- |
| Key agreement | ML-KEM round trip, sizes, and randomization at all 3 levels; wrong-key rejection; both sides derive identical keys in `signed` and `auth` (all levels × all suites) |
| Implicit rejection | A tampered ciphertext neither raises nor yields the real secret, documenting why plain modes can't detect it |
| Signature verification | ML-DSA round trip and sizes; wrong message, wrong key, bit-flip sweep, truncated/extended/empty signatures; domain separation (a context-bound signature doesn't verify as a bare one) |
| Failure modes | Oversized length prefix refused before buffering, truncation → `TruncatedMessage`, silent peer → `HandshakeTimeout`, strict parser fuzzing of malformed hellos |
| Ephemeral key reuse | Across 25 sessions: randoms, key shares, KEM keys, server responses, and session keys are all unique; the identity key correctly *is* reused |
| Entropy / RNG integrity | Chi-square + bit-balance smoke test on values that are uniform by construction; `rng_selfcheck()` catches a stuck or all-zero `os.urandom` |

**`test_adversarial.py`**

| Attack | Result |
| --- | --- |
| Active MITM (impersonation with attacker's own ML-DSA key, swapped key material, injected frames) | `auth` rejects; `signed` impersonation is a known gap |
| Packet tampering (bit flips at start/second byte/middle/end of every frame) | `auth` aborts on every frame; `signed` leaves the ciphertext frame unprotected (known gap) |
| Replay (server flight replayed to a new client; client flight replayed to a server) | `auth` rejects; `signed` is replayable (known gap) |
| Downgrade (PQ offers stripped by the attacker; server `require_pq` policy) | Caught by the transcript signature / `NegotiationError` |
| Malformed ciphertext / key material | Random ciphertext detected only by `auth`'s key confirmation; wrong-length shares rejected *before* reaching the KEM; low-order X25519 points rejected |
| Corrupted signatures | Rejected in both; a signature spliced from another session is rejected by `auth` |
| Abort logic | Alert sent to peer, no key released, no reply after abort; dropped flight times out cleanly; killed connection fails closed |

**How to read `xfail`.** Tests for `signed` mode that are marked `xfail(strict=True)` are *documented vulnerabilities*, not test bugs. They're strict, so if `signed` ever starts passing one, the suite fails and forces the docs to be updated. The plain `pqc` MITM test is a passing test that demonstrates the attack *succeeds* against an unauthenticated exchange, which is the whole reason `signed` and `auth` exist.

**Scope note: QKD-style QBER thresholds are intentionally not implemented.** QBER (quantum bit error rate) is a property of quantum channels like BB84, where abort-on-threshold detects eavesdropping. A KEM/signature handshake over TCP has no such quantity. Its equivalent, aborting when the cryptographic checks fail, is what the abort-logic tests cover.

### Guardrails against meaningless results

- `oqs_compat.require_real_oqs()` refuses to run on the fallback KEM shim (which is not real cryptography). Override with `PQC_BENCH_ALLOW_SHIM=1`, which emits a warning.
- `bench.py` calls `require_real_oqs()` and `rng_selfcheck()` at startup, so it can't produce numbers from a fake backend.
- Set `PQC_BENCH_REQUIRE_REAL=1` (as CI does) to turn "skipped because no real liboqs" into a hard failure.
- The long-term server identity is generated once, outside every timed loop.
- Hardening in `common.py`: 64 KB frame cap, strict bounds-checked field parsing, and a typed exception hierarchy (`HandshakeError` → `ProtocolError`, `AuthenticationError`, `KeyConfirmationError`, `NegotiationError`, `HandshakeTimeout`, `TruncatedMessage`, `PeerAbort`).

**What this does and doesn't prove.** The tests show the protocol logic rejects the attacks listed. They aren't a formal proof, and the entropy checks are tripwires, not NIST SP 800-22 statistical validation. Real randomness quality comes from the OS CSPRNG and liboqs.

## Results

All charts and raw data live in `results/`. Each full run covers 60 trials per configuration across the modes, 3 ML-KEM security levels, and 3 latency tiers.

> **Note:** the committed CSVs and charts were generated **before** the `auth` mode and the pipelined network model existed, i.e. with the legacy `serial` model and 4 modes. The compute and wire-byte findings below are unaffected, but the latency finding was revised (section 3). Re-run `bench.py` and `analyze.py` to regenerate results for the current code, including `auth`.

### 1. Compute cost is small and roughly comparable across modes, except signing

At 0ms simulated latency, classical X25519 averages about 0.29ms. ML-KEM alone comes in close behind it, 0.26-0.29ms depending on security level, not meaningfully faster or slower than classical despite being a completely different primitive. Hybrid mode, doing both operations, lands around 0.51-0.59ms, roughly the sum of the two. Adding ML-DSA signing pushes it further, to about 0.71-0.77ms, still under a millisecond, but clearly the most expensive of the four on pure compute.

### 2. The real cost is on the wire, and signing changes that story considerably

Classical X25519 is 72 bytes round trip. ML-KEM-768 alone runs about 2,280 bytes, roughly 32x larger. Hybrid X25519+ML-KEM-768 comes to 2,352 bytes, close to the sum of both. Add ML-DSA-65 signing and it jumps to about 7,549 bytes, more than 3x hybrid mode and well over 100x classical. Most of that increase is the ML-DSA public key and signature themselves, which run into the kilobytes even at NIST security level 3.

### 3. Correction: signed mode's "extra round trip" was a simulator artifact

My original write-up reported that signed mode took about double the latency of the other modes (about 81ms vs 40ms at 20ms latency; about 301ms vs 151ms at 75ms) and concluded it needed a second network round trip. That conclusion was wrong. The cause was `DelayedSocket`, which slept before **every** `sendall()`. Signed mode's server sends three back-to-back messages, so it paid three delays plus one for the client, four in total, versus two for the other modes. It's a per-send cost in the simulator, not an extra round trip in the protocol; on a real network, those three writes travel as one flight.

The new `pipelined` model fixes this by letting sends overlap, and `--net-model serial` still reproduces the old numbers exactly (I verified the 2x/4x pattern comes back). The lesson is probably more useful than the original finding: when a benchmark result looks structurally surprising, check the measurement harness first.

The byte overhead of ML-DSA is real and unchanged, but the latency penalty should be re-measured under `pipelined` before drawing conclusions about deployment cost.

## What this means for a real migration

- On typical internet-facing services, hybrid PQC's wire overhead alone probably isn't your bottleneck. Network RTT and TLS record processing will dwarf it, which lines up with what Cloudflare and Google have reported from real hybrid PQC rollouts at scale.
- Hybrid, not pure PQC, is still the right default for the key exchange side of a migration. The cost gap between pure ML-KEM and hybrid is small enough not to matter much.
- Authentication is where the migration cost shows up: swapping ECDSA or RSA certificates for ML-DSA adds multiple kilobytes per handshake. Whether it also adds latency depends on how the flights are packaged, and a correctly pipelined design shouldn't need an extra round trip.
- Authentication also has to be *designed*, not just added. A signature over the key share alone (`signed`) still fails against impersonation, replay, and downgrade. Pinned identity, transcript binding, and key confirmation (`auth`) are what close those.

## Getting it running

There's one real gotcha here worth calling out up front: `oqs`, the Python bindings for liboqs, needs the underlying C liboqs library actually built and available on your system. Installing the Python package alone doesn't give you that, it just installs the wrapper. Skip this step and the first time you try to import `oqs`, you'll hit `RuntimeError: No oqs shared libraries found`.

Clone the repo:

```bash
git clone https://github.com/RayDCodes/pqc-migration-bench.git
cd pqc-migration-bench
```

Set up a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Install the liboqs Python bindings along with the native library. On Linux, including WSL and GitHub Codespaces, this usually just works as long as you have a build toolchain installed:

```bash
sudo apt install build-essential cmake ninja-build -y
pip install git+https://github.com/open-quantum-safe/liboqs-python.git
```

On native Windows, this same command tends to fail since there's no C build toolchain by default, and even installing Visual Studio Build Tools plus CMake doesn't always get you a clean build. If you run into this, the path of least resistance is developing inside WSL or a GitHub Codespace instead of fighting the native Windows build, which is what I ended up doing.

Verify the install actually worked:

```bash
python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
```

You're looking for `ML-DSA-65` somewhere in that list.

Run a quick smoke test:

```bash
cd src
python bench.py --quick --out ../results/smoke_test.csv
```

This runs a small, fast subset (10 trials, 2 latency tiers, one mechanism) just to confirm everything's wired up correctly. `bench.py` refuses to run on the insecure fallback shim (see [Guardrails](#guardrails-against-meaningless-results)), so a green smoke test also means you're on real liboqs.

Run the full sweep:

```bash
python bench.py --out ../results/handshake_results.csv
```

This covers all 5 modes across 3 ML-KEM security levels and 3 latency tiers at 60 trials each, and takes a few minutes to finish.

Run the correctness and adversarial test suites (needs real liboqs):

```bash
cd src
python -m pytest -v
```

Regenerate the charts and summary:

```bash
python analyze.py
```

## AI Assistance Disclosure

AI tools, including Claude (Anthropic) and ChatGPT (OpenAI), were used throughout this project to support research, planning, and troubleshooting. Their contributions include:

- **Research and learning:** building background understanding of post-quantum cryptography, the NIST standards (FIPS 203/204), the liboqs ecosystem, and the specialized tools and protocols used in this project.
- **Review and planning:** identifying gaps in cryptographic validation and adversarial testing, and outlining the updates needed to address them.
- **Debugging:** locating code that caused packaging and implementation issues.

## Limitations and what's next

- This is a key-exchange and signature microbenchmark, not a full TLS 1.3 implementation. There are no certificates, no record layer, no full cipher suite negotiation (only KEX suite selection in `auth`). That isolation is intentional, but it means these numbers aren't a drop-in substitute for benchmarking an actual PQC-enabled OpenSSL or BoringSSL stack.
- `auth` is a research protocol built for this benchmark. It has not been formally verified or audited; don't deploy it.
- All trials run on localhost with simulated, sleep-based latency, which doesn't account for packet loss or jitter.
- The test suites need real liboqs; without it they skip (or fail under `PQC_BENCH_REQUIRE_REAL=1`).
- Next up: re-run the full sweep with `auth` under the pipelined model; a real TLS 1.3 handshake using OpenSSL's PQC provider for a closer comparison; and signature-verification cost under session resumption, where the per-handshake ML-DSA tax would add up fastest.
