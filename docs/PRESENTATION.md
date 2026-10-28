# Project presentation for Brain Co

Use this as an eight to ten minute walkthrough with time for questions. The core story is a cryptography benchmark whose trust assumptions and development workflow were strengthened together. Review and reproduce the changes before presenting them as work you own. The original implementation and this assisted hardening pass should be distinguishable in your explanation.

## Opening in about forty seconds

“I built a small Python harness to compare classical and post-quantum key exchange over TCP. I wanted to measure what migration costs in latency and message size. While reviewing the project, I found that two successful peers deriving the same key did not prove the server's identity, and a missing dependency could silently select code that was not real PQC. I addressed those issues, wrote tests that deliberately exercise the failure paths, and added security checks to the pull-request workflow. The project now connects cryptographic correctness with the practical question of how to prevent an unsafe change from shipping.”

## The problem

Explain the four modes using their inputs and outputs. X25519 establishes a shared secret; ML-KEM encapsulates and decapsulates one; hybrid combines both secrets before deriving a key; signed mode also checks the server's identity relative to a trusted public key.

“The benchmark isolates key exchange so I can see its cost without the rest of TLS hiding the difference. That makes it easier to study, but it also means I must be explicit about the security features that TLS normally supplies.”

Do not call it a complete TLS implementation. No record encryption, certificates, negotiation, client authentication, or resumption is implemented.

## Your contribution

Separate the preexisting harness from the changes you can now explain line by line:

- TCP framing, timing, byte accounting, the four modes, and the historical results were already present.
- This branch removes the simulated backend, requires an independently trusted signing key, binds the signature to a fresh challenge and algorithms, and adds server key confirmation.
- It replaces a removable assertion, checks incoming lengths, and bounds socket/thread waits.
- It adds rejection tests, dependency locks, a reusable GitHub Actions workflow, local Semgrep rules, Trivy scans and inventory, and OPA/Conftest policies.
- It adds a non-root container and reviewable Kubernetes/Terraform examples. These are examples, not evidence of a deployed platform.

For the interview, show the diff and explain which parts you designed, implemented, reviewed, and validated yourself. Repository files cannot establish team ownership or past organizational adoption.

## Motivation and ownership

Adapt this to your actual motivation:

“I was interested in the gap between using a strong cryptographic primitive and building a system that deserves trust. A benchmark can look successful while measuring the wrong implementation or verifying a signature with the attacker's key. I wanted the checks to be repeatable so the next change would preserve those assumptions.”

Connect this to Brain Co's role description: engineers need useful failures and safe defaults in the same tools they already use. Show how a specific error names the fix, how CI runs without cloud credentials, and how a reusable workflow makes the checks easier to apply consistently.

## Technical decisions

**Real liboqs instead of a substitute.** A substitute might test socket plumbing, but it cannot validate algorithm size, performance, or security. Missing dependencies stop the run. The setup builds both native code and bindings from explicit source commits.

**Pinned identity instead of a key received from the socket.** A signature is meaningful only when the verification key is trusted independently. The harness supplies that key before the connection. This models a trust anchor; it does not implement certificate issuance or rotation.

**A fresh challenge and checked server Finished.** The challenge changes every run and is included in the signed content with version and algorithm names. The derived key also depends on the ciphertext. The client checks a server HMAC before returning, so a peer cannot silently agree to different key material.

**Explicit exceptions and bounded parsing.** `python -O` removes assertions, so key agreement uses a runtime error. A four-byte length prefix is not permission to read four gigabytes. The frame limit is 64 KiB, comfortably above these handshakes, and KEM fields must match the selected algorithm's exact sizes.

**Semgrep and Trivy.** Semgrep checks a small set of project-specific unsafe coding patterns. Trivy checks dependency vulnerabilities, secrets, actual infrastructure source, and the built image; it also creates CycloneDX inventories. Neither replaces tests or a cryptographic review. Scanner failure and an empty Semgrep target set cannot count as a successful scan.

**OPA and Conftest.** These make configuration rules reviewable code. Tests prove both that a safe configuration passes and that specific unsafe changes fail. The policy checks init and ephemeral containers as well as application containers, and rejects unknown Terraform public-access settings.

**GitHub Actions permissions.** PR code executes with read-only default permissions and no cloud secrets. Actions are pinned to commits and checkout credentials are not retained. A final status aggregates failures, but a repository rule must require that status before it can prevent merging.

## Problem solving

Choose two concrete examples to explain rather than listing every tool.

First, all six original tests passed without the native PQC library. Trace the wrapper that selected the substitute, explain why its API looked correct, then show the new missing-backend test and the real-cryptography test job. The lesson is to test which implementation ran, not just that two outputs matched.

Second, the README said signing closed the intermediary attack. Trace how the original server sent its signing key over the same connection. An attacker could replace the signing key, KEM key, and signature together. Show the new client parameter and the test in which an attacker signs valid content with an untrusted key; verification must fail before encapsulation.

A third example is measurement interpretation. The simulator sleeps on every `sendall`; three server writes incur three sleeps even when they represent one server flight. The old doubled latency did not establish that signatures inherently require another round trip. The corrected documentation describes the actual model, and v2 results are stored separately.

## Results and evaluation

Use the exact counts and measurements in [VALIDATION.md](VALIDATION.md) and the CSV/metadata under `docs/evidence/`. Explain successful handshakes and rejected attacks separately. Passing tests mean the tested invariants held; they do not prove a custom protocol is production secure.

The meaningful functional result is deterministic rejection: the wrong trust key, a changed signature, a stale challenge, malformed lengths, and an invalid Finished do not return a session key. The platform result is repeatable checks with preserved reports, not an unmeasured percentage reduction in vulnerabilities.

The full sweep has 30 configurations and 60 trials each. ML-DSA-65 is fixed in signed mode: testing ML-KEM-1024 does not make the authentication strength category 5. Latency includes Python scheduling and sockets and should not be presented as isolated primitive execution time.

## Trade offs

Pinning a key is simpler to demonstrate and test than building a PKI, but creates a provisioning and rotation obligation. The test harness models trusted provisioning in memory; it does not solve deployment identity management.

Freshness and key confirmation add messages. They provide security behavior that the unsigned modes do not have, so the performance comparison is deliberately between different guarantees. It is not an isolated measurement of the ML-DSA signature operation.

Pinned dependencies improve repeatability but need maintenance. Vulnerability databases update independently, and a new advisory can fail a previously green build. A scanner must not be silenced just to keep the demonstration green.

Custom policies are focused and explainable, but cover fewer cases than a full platform policy system. Terraform rules run against a synthetic plan in unit tests and actual source with Trivy; a real deployment must evaluate its actual resolved plan. CI checking is also different from Kubernetes admission enforcement.

## Key takeaways

“I learned to make trust assumptions executable. Matching keys did not identify the server, a valid signature did not make an untrusted key trustworthy, and passing tests did not prove real PQC ran. I also learned to question the measurement setup before explaining a timing difference. Starting again, I would define the trust model, failure tests, and run metadata before collecting performance results.”

Next steps are actual TLS 1.3 experiments, a packet-level delay/loss model, identity lifecycle work, and dedicated benchmark hardware. Signed image releases and real cloud plan checks would follow only when there is a deployment to protect.

## Rehearsal runner

Follow the timed [walkthrough](RUN_OF_SHOW.md) for a format-neutral eight minute presentation. Use `python scripts/rehearse.py --part evidence` to display recorded results without installing the cryptographic backend or running a new benchmark. Use protocol and policy modes in their prepared environments to execute the existing rejection checks.

## Five minute live demonstration

1. Run `python -m pytest tests/test_protocol.py -k missing_backend -v`. Explain that missing cryptography stops execution.
2. Run `python -m pytest tests/test_signed_security.py -v`. Open the untrusted-key and replay tests and explain why a valid signature can still be rejected.
3. Run `python -O -m pytest tests/test_handshakes.py -k key_mismatch -v`. Show the explicit runtime check that survives optimization.
4. Run `python scripts/test_policies.py`. Show one safe Job and the mutation that turns on privilege or removes its limit. Explain that these are rejected fixtures, not real failed deployments.
5. Open `.github/workflows/ci.yml`, its reusable workflow, and one actual Actions run if available. Explain what fails the final gate and which repository setting must require it.

Have saved test output and charts available in case installation or network access is unavailable during the interview. Do not run cloud provisioning live.

## Likely technical questions

**Why is key equality insufficient?** An intermediary can create two independent sessions, one with each endpoint. Equality in one test run checks correctness, not the identity of an arbitrary remote peer.

**Why not retry a bad signature like corrupted storage?** Authentication failure ends the handshake. Repeating until something passes can hide an attack and does not repair the trust assumption.

**What does the nonce prevent?** An old signed response is bound to an old challenge and will not verify against the new challenge. This is freshness relative to the client-generated value, not a complete replay database.

**Why check Finished after signature verification?** The signature binds the server to its KEM public key; Finished demonstrates possession of the derived session key for this ciphertext. They answer different questions.

**What happens if the scanner cannot download its database?** The scan fails and the final gate fails. The workflow does not turn an unavailable check into a clean result.

**Can a contributor edit the policy to make a bad change pass?** Yes, CI policy is code and needs protected review. CODEOWNERS suggests reviewers; enforced owner review and required statuses need repository rules.

**Why have an SBOM if we already scan dependencies?** It records the components in a particular scan or image so later advisories can be investigated. It does not establish that those components are safe or that every source-built library was detected.

**What connects this to the other resume projects?** This branch concretely implements the CI guardrails project concepts in this repository. Lambda, Step Functions, and EventBridge are a separate remediation idea, not an implemented deployment here. There is no verified five-repository rollout in this change.
