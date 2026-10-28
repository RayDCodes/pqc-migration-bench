# PQC migration benchmark with security guardrails

A Python research harness comparing X25519, ML-KEM, hybrid X25519 plus ML-KEM, and ML-DSA authenticated ML-KEM over real localhost TCP sockets. The project also demonstrates how to test security failures and check source code, dependencies, container images, and infrastructure changes before merge.

This is a small experimental protocol, not TLS 1.3 or a production encryption library. No application data is encrypted. Use an established TLS implementation for deployed systems. Open Quantum Safe itself positions liboqs as research and prototyping software: https://openquantumsafe.org/liboqs/security.html.

## What changed

| Original behavior | Current behavior | Evidence |
| --- | --- | --- |
| Missing liboqs silently selected a non-cryptographic KEM substitute | Missing native library or bindings raises an error; no simulated backend | `tests/test_protocol.py` |
| Signed mode accepted a signing key sent by the same untrusted peer | Client requires a public key provisioned independently of the socket | `tests/test_signed_security.py` |
| Signature covered only the ephemeral KEM key | Signed content includes protocol version, algorithm names, a fresh client challenge, and KEM key | Replay, modification, and algorithm substitution tests |
| No protocol-level server key confirmation | Client verifies an HMAC produced with the derived session key | Invalid Finished test |
| Unbounded frame lengths and blocking sockets | 64 KiB frame limit, checked field and KEM sizes, socket and thread deadlines | Framing and failure tests |
| Key agreement checked with `assert` | Explicit runtime error survives `python -O` | Optimized-Python mismatch test |
| Mutable upstream builds and no run provenance | Source commits, action commits, scanner archive hashes, Python dependency hashes, and run metadata | `security/toolchain.json`, lockfiles, metadata JSON |

The original six tests passed in an environment without liboqs because they exercised the substitute. Passing a correctness test is therefore insufficient evidence that the intended cryptography was executed. The substitute is now removed entirely, including from benchmarks and tests.

## Protocols and trust

| Mode | Key material | Peer authentication |
| --- | --- | --- |
| classical | X25519, then HKDF-SHA256 | None; vulnerable to an active intermediary |
| pqc | ML-KEM-512, 768, or 1024, then HKDF-SHA256 | None; vulnerable to an active intermediary |
| hybrid | X25519 and ML-KEM secrets combined with HKDF-SHA256 | None; this is an experimental combiner |
| signed v2 | ML-KEM, ML-DSA-65 signature, transcript-bound HKDF, server Finished HMAC | Server authentication relative to an independently trusted signing key |

Signed v2 sends a client challenge, a single server response containing the KEM key and signature, client ciphertext, and server Finished. It does not send a signing key for the client to trust. The harness generates a signing identity and passes its public key directly to the client before starting the timed handshake, modeling provisioning through a trusted channel. Production key distribution, revocation, rotation, certificates, and client authentication are not implemented.

The signature authenticates the server's KEM key and the fresh challenge. The KDF additionally binds the ciphertext. The Finished message demonstrates possession of the derived key; it is particularly useful because an invalid ML-KEM ciphertext can yield a different secret through implicit rejection instead of raising an exception. An in-process key equality check remains a useful benchmark invariant, but does not establish remote identity.

## Run locally

Use Linux or WSL, Python 3.12, Git, a C compiler, CMake, Ninja, and OpenSSL development headers. On Ubuntu, install OS build prerequisites with `sudo apt-get install build-essential cmake ninja-build libssl-dev python3-venv`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
./setup.sh
python -m pytest
python -O -m pytest tests/test_handshakes.py -k key_mismatch
python src/bench.py --quick --out artifacts/smoke.csv
python src/analyze.py --input artifacts/smoke.csv --out-dir artifacts/plots
```

`setup.sh` builds both native liboqs and the Python bindings from the exact commits in `security/toolchain.json`. The build includes all three ML-KEM levels and ML-DSA-65. It requires a virtual environment and does not install into system Python. The wrapper checks for the native library before importing the Python bindings, avoiding their automatic installer when the library is absent.

`--quick` performs 10 measured trials for each of 8 configurations, plus one excluded warmup each: 80 measured rows. A full `python src/bench.py --out artifacts/full.csv` performs 60 trials for each of 30 configurations: 1,800 measured rows. `--trials` changes the full-run count and must be positive.

## Read the measurements correctly

The clock measures client handshake execution, including socket reads, scheduling, and cryptographic work. Zero injected delay is a loopback measurement, not isolated CPU-only cryptographic latency. Server identity key generation occurs before the signed-mode timer. The unsigned modes finish when the client derives its key; signed v2 additionally waits for server key confirmation.

`DelayedSocket` sleeps before every `sendall`. This is a per-send delay model, not a packet-level network simulator. The original signed mode made three separate server sends, so its apparent doubled latency was partly a simulator artifact; it did not demonstrate that adding a signature inherently adds a network round trip. The new server bundles the KEM key and signature. Signed v2 has four causally dependent messages because it adds freshness and confirmation, so its timing is not directly comparable to the original signed protocol.

Each CSV has a companion `.metadata.json` recording protocol version, real backend versions, Python/platform, code revision, working-tree state, trial counts, timing scope, and latency model. The analysis script rejects missing or incompatible metadata by default and reports median and nearest-rank p95 alongside mean and standard deviation.

The committed `results/` directory is preserved as historical protocol v1 evidence. It does not record the backend or prove authenticated identity. Do not combine it with v2 data or present the original signing claim as verified. `--allow-legacy` lets the analysis script read old data deliberately; it does not validate the old run or change its protocol semantics.

## Security automation

`CI` runs on pull requests, pushes to main, a weekly schedule, and manual dispatch. It performs:

- Real native cryptography tests, rejection tests, and a small benchmark.
- A reusable security workflow with local Semgrep rules, Trivy dependency and secrets scans, CycloneDX inventory, OPA/Conftest policies, and tests of deliberately unsafe configurations.
- A Docker build and isolated smoke run, followed by a high/critical image vulnerability gate and image inventory.
- A final `Security gate` that fails if tests, security checks, or container checks fail or are skipped.

The existing CodeQL workflow is retained and pinned. Every external action uses a full commit SHA; checkout does not retain credentials. Workflows use `pull_request`, read-only default tokens, timeouts, and no cloud credentials. Only the CodeQL job requests the security-events permission needed to upload its analysis. Scanner archives are checked against committed SHA256 values; live vulnerability databases remain necessary for current findings.

**A failing workflow blocks merging only after repository rules require its status.** Configure `Security gate` as a required check and require review of workflow and policy changes. CODEOWNERS is included, but owner review also requires repository rule enforcement. These administrative settings are not changed by this code. Semgrep emits file and line annotations in checks; this implementation does not post bot review comments or demonstrate adoption across five repositories.

To run the tools locally on Linux x86_64:

```bash
python -m pip install --require-hashes -r security/requirements.txt
python scripts/install_tools.py conftest trivy actionlint
python scripts/check_workflows.py
.tools/actionlint
python scripts/test_semgrep_rules.py
python scripts/run_semgrep.py
.tools/conftest verify --policy security/policy
python scripts/test_policies.py
.tools/conftest test deploy/kubernetes --policy security/policy
.tools/trivy fs --scanners secret --exit-code 1 .
.tools/trivy fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .
.tools/trivy config --severity HIGH,CRITICAL --exit-code 1 infra/terraform
.tools/trivy config --severity HIGH,CRITICAL --exit-code 1 deploy/kubernetes
```

Keep security tools in a separate virtual environment when updating them. Update `.in` files and regenerate lockfiles using `pip-compile --generate-hashes --strip-extras`; review upgrades rather than replacing pins with floating versions. Semgrep's local rules are project-specific checks, not comprehensive application-security coverage. A source SBOM is an inventory, not proof of safety, and native source-built libraries need separate commit/version provenance.

## Containers and infrastructure examples

The Dockerfile uses a digest-pinned Python base, a separate native build stage, and numeric non-root execution. It needs no listening port or cloud credentials. CI runs it with no external network, a read-only root filesystem, dropped capabilities, and a bounded temporary filesystem. No image is published.

```bash
docker build --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -t pqc-migration-bench:local .
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges pqc-migration-bench:local
```

`deploy/kubernetes/` contains a batch Job and deny-all ingress/egress NetworkPolicy. The Job has non-root execution, RuntimeDefault seccomp, no token mount, no added capabilities, read-only root, requests and limits, and bounded writable volumes. It uses a local image explicitly; load the built image into a development cluster before using it. Policy supports Pods, Deployments, StatefulSets, DaemonSets, Jobs, and CronJobs, and checks init and ephemeral containers too. NetworkPolicy enforcement depends on the cluster's network plugin. No cluster has been provisioned or tested by adding these files.

`infra/terraform/` is an optional AWS results bucket example with all public access blocks, KMS encryption and rotation, versioning, enforced bucket ownership, and HTTPS-only access. Nothing uploads results or runs Terraform apply. The Terraform plan JSON under `tests/fixtures/` is explicitly synthetic: it tests policy behavior without credentials. In a real deployment, evaluate the actual complete `terraform show -json` plan with Conftest. The custom policy conservatively rejects unknown public access settings and missing bucket controls; it is not a general AWS compliance framework. Trivy also scans actual Terraform source in CI.

## Presentation and next work

Start with [the presentation guide](docs/PRESENTATION.md), [the threat model](docs/THREAT_MODEL.md), and [the validation record](docs/VALIDATION.md). These distinguish original work, changes in this branch, verified results, and future work.

Next useful experiments are actual TLS 1.3 measurements, packet-level delay/loss simulation, persisted and rotated signing identities, tests on dedicated hardware, and a reviewed release pipeline with signed image provenance. AWS remediation workflows would be a separate project: automatically changing cloud resources is not needed to make this benchmark safer.
