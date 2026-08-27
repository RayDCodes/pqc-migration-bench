# PQC Migration Benchmark: Classical vs Post-Quantum vs Hybrid vs Signed Key Exchange

This project benchmarks classical ECDH (X25519), post-quantum ML-KEM (FIPS 203 / Kyber), hybrid X25519+ML-KEM, and ML-DSA-signed ML-KEM key exchange. Each mode runs as a real handshake over TCP sockets, built on [liboqs](https://github.com/open-quantum-safe/liboqs) and Python's `cryptography` library.

## Why this matters

NIST recently finalized the first post-quantum cryptography standards (FIPS 203/204/205), and the urgency behind that isn't really about quantum computers existing today. It's "harvest now, decrypt later": an adversary can record encrypted traffic now and decrypt it retroactively once a cryptographically relevant quantum computer exists. For data with a long confidentiality shelf life, medical records, infrastructure credentials, state secrets, that threat is already live regardless of when the hardware actually shows up.

That's why most organizations are moving to hybrid key exchange (classical plus PQC combined) rather than jumping straight to pure PQC. You need both primitives broken to lose confidentiality, which is a meaningfully higher bar. Chrome/BoringSSL and OpenSSH already ship hybrid X25519+ML-KEM by default.

What I wanted to actually measure was what that migration costs, in handshake latency and bytes on the wire. And once key exchange is covered, what does the other half of a real handshake cost, actually proving you're talking to the server you think you are?

This project started after reading Rios et al., "[Toward the Quantum-Safe Web: Benchmarking Post-Quantum TLS](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10844321)" (IEEE Network, 2025), which benchmarks full TLS 1.3 handshakes across NIST PQC standards using OpenSSL/liboqs/oqs-provider in Docker. This got even more interesting once I started interning on Wells Fargo's cybersecurity team, where I saw up close how a large financial institution is actually approaching the move to post-quantum cryptography.

## What's actually being measured

This isn't a full TLS 1.3 implementation, just a minimal handshake protocol built directly on `oqs` (for ML-KEM and ML-DSA) and `cryptography` (for X25519). That keeps the comparison focused on the primitives themselves instead of burying them inside a full TLS stack.

Four modes:

| Mode          | Protects                        | Server → Client                                       | Client → Server                     |
| ------------- | --------------------------------- | -------------------------------------------------------- | -------------------------------------- |
| **classical** | Confidentiality only               | X25519 pubkey                                             | X25519 pubkey                          |
| **pqc**       | Confidentiality only               | ML-KEM pubkey                                              | ML-KEM ciphertext                      |
| **hybrid**    | Confidentiality only               | X25519 pubkey ‖ ML-KEM pubkey                              | X25519 pubkey ‖ ML-KEM ciphertext      |
| **signed**    | Confidentiality and authenticity   | ML-DSA pubkey, then ML-KEM pubkey ‖ ML-DSA signature       | ML-KEM ciphertext                      |

The first three modes only give you confidentiality. Nothing stops a man-in-the-middle from swapping the key material mid-transit, which is the same gap you'd have without TLS certificates. Signed mode closes it: the server signs its ephemeral ML-KEM public key with ML-DSA-65, and the client verifies that signature before trusting the key. This step tends to get left out of KEM-only PQC benchmarks, and it turned out to matter quite a bit once I measured it.

Every handshake:

1. Spins up a real TCP server thread on `127.0.0.1`
2. Connects a real client socket to it
3. Times wall-clock from the client's first byte sent to deriving its final key
4. Asserts both sides derived an identical session key, this is the correctness check, and a mismatch fails loudly rather than silently
5. Records handshake time and total wire bytes

To separate cryptographic compute cost from network cost, every socket gets wrapped in a `DelayedSocket` that injects configurable one-way latency (0 / 20 / 75 ms), standing in for localhost, same-region, and cross-region-ish conditions.

## Results

All charts and raw data live in `results/`. Each full run covers 60 trials per configuration across 4 modes, 3 ML-KEM security levels, and 3 latency tiers.

### 1. Compute cost is small and roughly comparable across modes, except signing

At 0ms simulated latency, classical X25519 averages about 0.29ms. ML-KEM alone comes in close behind it, 0.26-0.29ms depending on security level, not meaningfully faster or slower than classical despite being a completely different primitive. Hybrid mode, doing both operations, lands around 0.51-0.59ms, roughly the sum of the two as you'd expect. Adding ML-DSA signing pushes it further, to about 0.71-0.77ms, still under a millisecond, but clearly the most expensive of the four on pure compute.

### 2. Wire bytes scale the way you'd expect, and signing changes that a lot

Classical X25519 is 72 bytes round trip. ML-KEM-768 alone runs about 2,280 bytes, roughly 32x larger. Hybrid X25519+ML-KEM-768 comes to 2,352 bytes, close to the sum of both. Add ML-DSA-65 signing and it jumps to about 7,549 bytes, more than 3x hybrid mode and over 100x classical. Most of that increase is the ML-DSA public key and signature themselves, which run into the kilobytes even at NIST security level 3.

### 3. Signed mode doesn't just cost more bytes, it costs an extra network round trip

This was the most surprising result. Classical, PQC, and hybrid modes all scale with network latency exactly as expected, one round trip, so total handshake time is about 2x the simulated one-way latency (about 40.5ms at 20ms latency, about 150.8ms at 75ms latency). Signed mode doesn't follow that pattern. At the same latencies, it takes about 81.3ms and 301.5ms respectively, almost exactly double. That points to signed mode requiring two network round trips instead of one, likely because the server sends its ML-DSA public key as a separate message before sending the signed ML-KEM key, rather than bundling both into a single flight.

On a fast local network this barely registers. But on any link with real latency, satellite, cellular edge, cross-region, this means the authentication step doesn't just add a few kilobytes, it doubles the network cost of the whole handshake. That's a much bigger deal for real-world deployment planning than the byte overhead alone suggests.

### 1. Compute cost still isn't where the overhead lives

At 0ms simulated latency, classical X25519 averages around 0.29ms. ML-KEM alone comes in close behind it, 0.26-0.29ms depending on security level, not meaningfully faster or slower than classical despite being a completely different kind of primitive. Hybrid mode, doing both operations, lands around 0.51-0.59ms, roughly the sum of the two. Adding ML-DSA signing pushes it further, to around 0.71-0.77ms, still well under a millisecond, but clearly the most expensive of the four on pure compute.

### 2. The real cost is on the wire, and signing changes that story considerably

Classical X25519 is 72 bytes round trip. ML-KEM-768 alone runs about 2,280 bytes, roughly 32x larger. Hybrid X25519+ML-KEM-768 comes to 2,352 bytes, close to the sum of both. Add ML-DSA-65 signing and it jumps to about 7,549 bytes, more than 3x hybrid mode and well over 100x classical. Most of that increase is the ML-DSA public key and signature themselves, which run into the kilobytes even at NIST security level 3.

### 3. Signed mode doesn't just cost more bytes, it costs an extra network round trip

Classical, PQC, and hybrid all scale with network latency the way you'd expect for a single round trip, about 40.5ms total at 20ms simulated latency, about 150.8ms at 75ms. Signed mode breaks that pattern: at the same latencies it takes about 81.3ms and 301.5ms, almost exactly double. That points to signed mode needing two network round trips instead of one, most likely because the server sends its ML-DSA public key as a separate message before sending the signed ML-KEM key, rather than bundling both into a single flight.

At 0ms latency this barely shows up. But on any link with real latency, satellite, cellular edge, cross-region, this means the authentication step doesn't just add kilobytes, it doubles the network cost of the whole handshake. That's a bigger deal for real-world deployment planning than the byte overhead alone would suggest.

## What this means for a real migration

- On typical internet-facing services, hybrid PQC's wire overhead alone probably isn't your bottleneck. Network RTT and TLS record processing will dwarf it, which lines up with what Cloudflare and Google have reported from real hybrid PQC rollouts at scale.
- Hybrid, not pure PQC, is still the right default for the key exchange side of a migration. The cost gap between pure ML-KEM and hybrid is small enough not to matter much.
- Authentication is where the real migration cost shows up, and it's worse than a byte-count comparison suggests. Swapping ECDSA or RSA certificates for ML-DSA isn't just a multi-kilobyte tax, in this implementation it costs an entire extra network round trip. On high-latency links that matters more than the raw byte overhead does. Worth investigating whether the ML-DSA public key and signature could be bundled into the same message flight as the ML-KEM key instead of sent separately, since that round trip may not be structurally necessary.

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

This runs a small, fast subset (10 trials, 2 latency tiers, one mechanism) just to confirm everything's wired up correctly.

Run the full sweep:

```bash
python bench.py --out ../results/handshake_results.csv
```

This covers all 4 modes across 3 ML-KEM security levels and 3 latency tiers at 60 trials each, and takes a few minutes to finish.

Regenerate the charts and summary:

```bash
python analyze.py
```

## Limitations and what's next

- This is a key-exchange and signature microbenchmark, not a full TLS 1.3 implementation. There are no certificates, no record layer, no cipher suite negotiation. That isolation is intentional, but it means these numbers aren't a drop-in substitute for benchmarking an actual PQC-enabled OpenSSL or BoringSSL stack.
- All trials run on localhost with simulated, sleep-based latency, which doesn't account for packet loss or jitter.
- Next up: a real TLS 1.3 handshake using OpenSSL's PQC provider for a closer comparison against this minimal-protocol version, and benchmarking signature verification cost specifically under repeated connection scenarios like session resumption, since that's where the per-handshake ML-DSA tax would add up fastest.
