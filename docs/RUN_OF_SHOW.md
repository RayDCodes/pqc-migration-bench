# Eight minute project walkthrough

This plan works for a verbal walkthrough, screen share, or a small set of slides. It is a suggested rehearsal length, not an interview requirement from Brain Co. Use the longer [presentation guide](PRESENTATION.md) for technical follow-ups.

## Prepare the screen before the call

Keep four things open: the signed client function in `src/handshake_signed.py`, its rejection tests, the results chart, and a successful GitHub Actions run linked from [PR 1](https://github.com/RayDCodes/pqc-migration-bench/pull/1). Avoid spending presentation time installing packages or waiting for a full benchmark.

The Python runner has three separate options:

| Purpose | Command from the repository root | Prerequisites |
| --- | --- | --- |
| Display the recorded measurements | `python scripts/rehearse.py --part evidence` | Standard Python only; recorded source files unchanged |
| Demonstrate rejected protocol inputs | `.venv/bin/python scripts/rehearse.py --part protocol` | Runtime dependencies, pytest, and native liboqs already installed |
| Demonstrate configuration rejection | `.security-venv/bin/python scripts/rehearse.py --part policy` | Security dependencies and the verified Conftest binary already installed |

The default is evidence mode. It reads the saved CSV, verifies its configuration counts and the recorded Python source digest, and recomputes the displayed means and p95 values. It does not execute a new benchmark, install software, call a cloud API, or prove independently that the historical run occurred.

Protocol and policy modes run existing checks with a timeout and stop on failure. A passing rejection test means an unsafe input was rejected as expected; it does not mean the unsafe input was accepted.

## Speaking sequence

| Time | Explain | Show |
| --- | --- | --- |
| 0:00 to 0:45 | The problem: compare migration costs while checking what each handshake actually guarantees | The four-mode table in README |
| 0:45 to 1:30 | Your contribution: distinguish the original TCP harness from the changes you reviewed and can explain | PR files and test names |
| 1:30 to 3:00 | The main security decision: the client must already know which signing key to trust | `trusted_signing_key` and `test_attacker_signing_key_is_not_trusted` |
| 3:00 to 4:00 | A surprising failure: tests passed with a substitute instead of real PQC | Missing-backend test and explicit exception |
| 4:00 to 5:15 | How the checks become part of shipping code | Security workflow, one unsafe policy fixture, aggregate gate |
| 5:15 to 6:30 | Results and evaluation, including what was excluded from timing | Evidence command and one chart |
| 6:30 to 7:30 | Trade-offs: trusted-key provisioning, extra confirmation messages, changing the image base, tool maintenance | One concrete decision and its cost |
| 7:30 to 8:00 | Takeaway and next step | Actual TLS and network simulation as future work |

Use your own reason for choosing and continuing the project. Do not turn the contribution section into a claim that you independently authored every change or deployed the example infrastructure.

## The security explanation in ordinary code terms

Start at the client function. The `trusted_signing_key` argument comes from outside the socket. The client creates a random challenge, sends it, reads the KEM key and signature, and reconstructs exactly the bytes that should have been signed. If verification fails, it raises an exception before sending the KEM ciphertext.

The important distinction is the source of that verification key. If the peer sends both a public key and a signature, an attacker can replace both. Checking that signature would only show that those two attacker-controlled values agree.

Next, point at the Finished check. Once the client derives the session key, it calculates the expected HMAC and compares it with the server's value. This checks agreement on the derived key; it does not establish a client's identity or implement TLS.

For malformed inputs, show the length checks before the call into the native library. For the benchmark invariant, show why an explicit exception stays active under `python -O` while an assertion would disappear.

## A short demonstration with expected outcomes

1. Run evidence mode. Expect 1,800 measured trials in 30 configurations. State that these are saved measurements from the recorded environment.
2. Run protocol mode. Point out the untrusted signing key, replayed challenge, invalid Finished, missing backend, and optimized-Python mismatch tests. They should pass by observing the expected exceptions.
3. If there is time, run policy mode. It prints safe configurations that passed and unsafe mutations that were correctly rejected. Open one mutation, such as `privileged=True`, and its matching deny rule.
4. Open the successful CI run. Explain that each job must succeed for the aggregate status to succeed. Repository rules must require that status before it prevents a merge.

Do not run the entire 1,800-trial sweep during a short presentation. Keep the saved chart and CI evidence ready if the local environment is unavailable.

## How to describe the measurements

For ML-KEM-768, the recorded means at zero injected delay were 0.3062 ms for classical, 0.5209 ms for ML-KEM, 0.7653 ms for hybrid, and 1.1071 ms for signed v2. Their framed protocol sizes were 72, 2,280, 2,352, and 5,669 bytes respectively.

These are client wall-clock results, including sockets and scheduling. Signed mode waits for server key confirmation; the unsigned modes do not. The signing identity is provisioned before the timer, and its public key is not included in the measured socket traffic. These are not end-to-end certificate provisioning costs.

The delay wrapper sleeps before each send call. Do not describe the original signed-mode difference as proof that a signature inherently adds another network round trip.

## Keep these boundaries clear

| You can show | You have not established |
| --- | --- |
| Real liboqs execution and tested rejection paths | A formal proof or a production-ready custom protocol |
| A reusable workflow running in this repository | Adoption across five repositories |
| Policy-checked Kubernetes and Terraform examples | A deployed cluster or an evaluated real cloud plan |
| CI status and a final aggregate gate | Enforced branch protection merely from adding YAML |
| A source digest and saved environment metadata | A signed build attestation or independent proof of execution |

## Practice without the screen

Explain why the original signing-key flow was insufficient in thirty seconds. Explain one failure you reproduced, the code you changed, and the test that catches it. Then name the most important remaining limitation without listing every future feature.

A strong closing is a concrete engineering lesson: identify where a trusted value comes from, check the unsafe path explicitly, and make that check repeatable for the next change.
