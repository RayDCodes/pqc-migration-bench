# Threat model and engineering decisions

The assets are benchmark validity, session key material, trusted server identity, CI credentials, and the integrity of source, dependencies, and optional workload configuration. The test peer and incoming pull-request code are untrusted. Local dependency installation and the independently provisioned signing key remain trusted inputs.

| Boundary or failure | What can go wrong | Control in this branch | What it does not establish |
| --- | --- | --- | --- |
| Native cryptography availability | An API-shaped substitute produces plausible but meaningless timings | Remove fallback; fail before importing bindings if the native library is missing | FIPS validation or absence of cryptographic implementation flaws |
| Peer signing identity | An intermediary generates its own signing key and signs a replacement KEM key | Independently provisioned signing key; no key accepted from the socket | A production PKI, revocation, or key rotation |
| Freshness and algorithm context | A valid old signature is replayed or interpreted in a different configuration | Fresh challenge and version/algorithm names in signed content | Resistance to every possible protocol composition attack |
| Ciphertext and shared key | Modified ciphertext yields a different secret without an explicit KEM error | Transcript-bound KDF and checked server Finished HMAC | Client identity or a production record layer |
| Frame parsing | Huge declared sizes, partial reads, ambiguous fields | 64 KiB cap, exact KEM sizes, full field consumption, bounded sockets | Global connection admission or rate limiting |
| Test harness | Server exceptions hang a benchmark or an optimized interpreter drops an invariant | Error propagation, deadlines, cleanup, explicit mismatch error | Timing precision under all scheduler conditions |
| Pull-request code | A contributor executes code in a privileged workflow | Unprivileged PR event, no cloud secrets, read-only default token, no retained checkout credential | Protection from a maintainer approving malicious workflow changes |
| Third-party tooling | A mutable tag or changed archive substitutes unexpected code | Full action/source commits, archive SHA256, hashed Python lockfiles | Authenticity if the upstream publisher and initial trust source are compromised |
| Scanner execution | A tool scans no files and returns success | Semgrep wrapper checks nonempty target list and scanner errors | Complete detection of all source vulnerabilities |
| Infrastructure | A sidecar bypasses checks, missing values pass, or an unsafe workload is deployed | Policy checks all container lists, defaults, positive resources, and plan unknowns | Kubernetes admission enforcement or a running cloud deployment |

The source and image scanners block high and critical findings without blanket suppressions. A live database failure should fail the job rather than produce a clean report. A future exception mechanism should record the finding, owner, justification, compensating control, and expiry; no exception is necessary to bypass a failure for this demonstration.

Trust is the shared theme with the earlier storage-client exercise: checking a returned value answers whether it matches an expectation. It does not answer who provided the expectation. A checksum supplied by an attacker, a signing key received from that same attacker, and an unprotected CI policy all have the same missing trust boundary.

## Scope decisions

Pinning a public key keeps the identity check small enough to explain and test. Real deployments need an established certificate or trusted-key distribution system. Retrying corrupted cryptographic protocol messages is intentionally avoided: a failed signature or Finished terminates the handshake.

The benchmark's server is loopback-only and ephemeral. Timeouts limit one test's duration; they are not a production denial-of-service defense. There are no bearer tokens, user accounts, or real workloads to secure with RBAC inside the Python handshake.

The Terraform example focuses on private encrypted results storage. It does not invent a need for a Kubernetes cluster, cloud-wide scanner, or automatic remediation service. EventBridge, Step Functions, and Lambda from the resume can be discussed as a future reporting/remediation integration, but are not implemented or deployed here.

References: [GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use), [Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/), [Conftest](https://www.conftest.dev/), [Open Quantum Safe security policy](https://openquantumsafe.org/liboqs/security.html).
