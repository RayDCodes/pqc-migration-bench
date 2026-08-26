# PQC Migration Benchmark: Classical vs Post-Quantum vs Hybrid vs Signed Key Exchange

This project benchmarks classical ECDH (X25519), post-quantum ML-KEM (FIPS 203 / Kyber), hybrid X25519+ML-KEM, and ML-DSA-signed ML-KEM key exchange. Each mode runs as a real handshake over TCP sockets, built on [liboqs](https://github.com/open-quantum-safe/liboqs) and Python's `cryptography` library.

## Why this matters

NIST recently finalized the first post-quantum cryptography standards (FIPS 203/204/205), and the urgency behind that isn't really about quantum computers existing today. It's "harvest now, decrypt later": an adversary can record encrypted traffic now and decrypt it retroactively once a cryptographically relevant quantum computer exists. For data with a long confidentiality shelf life, medical records, infrastructure credentials, state secrets, that threat is already live regardless of when the hardware actually shows up.

That's why most organizations are moving to hybrid key exchange (classical plus PQC combined) rather than jumping straight to pure PQC. You need both primitives broken to lose confidentiality, which is a meaningfully higher bar. Chrome/BoringSSL and OpenSSH already ship hybrid X25519+ML-KEM by default.

Part of what pulled me into this topic was looking at what quantum security teams at large financial institutions, Wells Fargo among them, are actually working on right now. PQC migration is clearly moving from "something to watch" to an active roadmap item for institutions handling long-lived sensitive data, and I wanted to understand the real engineering tradeoffs behind that shift instead of just reading the standards documents.

What I wanted to actually measure was what that migration costs, in handshake latency and bytes on the wire. And once key exchange is covered, what does the other half of a real handshake cost, actually proving you're talking to the server you think you are?

This project started after reading Rios et al., "[Toward the Quantum-Safe Web: Benchmarking Post-Quantum TLS](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10844321)" (IEEE Network, 2025), which benchmarks full TLS 1.3 handshakes across NIST PQC standards using OpenSSL/liboqs/oqs-provider in Docker.

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

To separate crypto compute cost from network cost, every socket gets wrapped in a `DelayedSocket` that injects configurable one-way latency (0 / 20 / 75 ms), standing in for localhost, same-region, and cross-region-ish conditions.

## Results

All charts and raw data live in `results/`. Each full run covers 60 trials per configuration across 4 modes, 3 ML-KEM security levels, and 3 latency tiers.

### 1. Compute cost still isn't where the overhead lives

At 0ms simulated latency, classical X25519 averages around 0.32ms. ML-KEM alone is actually a bit faster (0.18-0.20ms), since its lattice operations are relatively cheap. Hybrid mode lands around 0.37-0.44ms. Adding ML-DSA signing doesn't change much either, signed handshakes come in around 0.7ms, close to classical, since signature operations aren't especially expensive.

### 2. The real cost is on the wire, and signing changes that story considerably

Classical X25519 is 72 bytes round trip. ML-KEM-768 alone runs about 2,280 bytes, roughly 32x larger. Hybrid X25519+ML-KEM-768 comes to 2,352 bytes, close to the sum of both. Add ML-DSA-65 signing and it jumps to around 7,500 bytes, more than 3x hybrid mode and well over 100x classical. Most of that increase is the ML-DSA public key and signature themselves, which run into the kilobytes even at NIST security level 3.

### 3. Network latency still dominates, but the margin gets tighter

Once realistic network latency is added, the gap between all four modes narrows considerably in relative terms, since a few extra kilobytes is still nothing compared to a full network round trip. At 75ms simulated latency, everything lands in roughly the same range. But signed mode's raw byte overhead is now large enough that on constrained links, satellite, cellular edge, IoT, it's worth reasoning about on its own rather than dismissing it the way pure-KEM overhead mostly can be.

## What this means for a real migration

- On typical internet-facing services, hybrid PQC's wire overhead alone probably isn't your bottleneck. Network RTT and TLS record processing will dwarf it, which lines up with what Cloudflare and Google have reported from real hybrid PQC rollouts at scale.
- Hybrid, not pure PQC, is still the right default for the key exchange side of a migration. The cost gap between pure ML-KEM and hybrid is small enough not to matter much.
- Authentication is where the real migration cost shows up. Swapping ECDSA or RSA certificates for ML-DSA isn't a rounding error the way the KEM swap is, it's a multi-kilobyte tax on every handshake, and it's worth budgeting for separately, especially on bandwidth-constrained links.

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