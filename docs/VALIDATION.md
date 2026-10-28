# Validation record

This record describes checks actually performed in the preparation environment. GitHub-hosted execution, a Docker daemon, cloud credentials, and a Kubernetes cluster are separate verification environments. A workflow definition is not evidence that it has run successfully or that repository rules require it.

## Functional and security checks

| Check | Observed result |
| --- | --- |
| Original tests before modification, without native liboqs | Six passed using the non-cryptographic fallback |
| Core Python suite with real liboqs before the rehearsal runner | 49 passed at the verified baseline |
| Mismatch regression under `python -O` | Passed; explicit exception remains active |
| Full v2 benchmark | 1,800 measured handshakes, 30 configurations, 60 samples each, plus 30 excluded warmups |
| Quick benchmark | 80 measured handshakes, eight configurations, ten samples each |
| OPA/Conftest Rego unit tests | Five passed |
| Safe and unsafe configuration evaluations | 42 passed, including missing template, List wrapping, sidecars, init containers, zero limits, public ACLs, missing controls, and unknown plan values |
| Actual Kubernetes manifests against custom policies | Passed |
| Semgrep custom rule fixtures | All five unsafe patterns detected; safe fixture accepted |
| Semgrep source and script scan | Completed with nonempty target set and no findings |
| Trivy Terraform and Kubernetes source scan | No high or critical findings in either source directory |
| Actionlint | YAML and expressions passed with external ShellCheck disabled locally |
| Workflow security settings check | Passed for triggers, default permissions, action pins, checkout credentials, and job timeouts |
| Runtime and security dependency lock installation | Installed with required hashes |
| Final Trivy dependency scan | Zero high/critical findings across both lockfiles, covering 19 application and 67 tooling package entries |
| Final Trivy secrets scan | No findings in the source checkout |
| CycloneDX source inventory | Generated with 88 components |

Dependency and secrets scan output and CycloneDX inventory are generated under `artifacts/` and uploaded by CI. The dependency gate evaluates both the application and the scanner toolchain: an initial toolchain candidate exposed vulnerable MCP dependencies, a second exposed vulnerable PyJWT dependencies, and the selected Semgrep release updates those dependencies instead of adding suppressions. The final local scan passed with no high or critical findings and no added vulnerability suppressions.

The Semgrep wrapper exposes packaged scanner dependencies through a managed symlink directory while excluding core C runtime libraries. Putting the entire bundled directory on the path made GitHub's newer Python interpreter load an older bundled libm and fail at startup. Filtering that directory preserves the host runtime ABI. An empty or failed scan is rejected rather than reported as clean.

## Measured v2 results

These values come from `docs/evidence/plots/summary.csv`. Classical uses X25519; the other rows use ML-KEM-768, and signed mode uses ML-DSA-65. Each row has 60 samples. Times are client handshake wall-clock measurements on this environment, not a production latency guarantee.

| Mode | Mean at zero injected delay ms | p95 at zero injected delay ms | Mean at 20 ms per-send delay ms | Framed protocol bytes |
| --- | ---: | ---: | ---: | ---: |
| Classical | 0.3062 | 0.5375 | 40.7761 | 72 |
| ML-KEM | 0.5209 | 0.7312 | 41.0148 | 2,280 |
| Hybrid | 0.7653 | 0.9788 | 41.5378 | 2,352 |
| Signed v2 | 1.1071 | 1.6834 | 82.6333 | 5,669 |

Signed v2 includes server authentication relative to a trusted key, a fresh challenge, and server key confirmation. Unsigned modes do not provide those guarantees and finish earlier in the protocol. The difference cannot be attributed solely to the signature primitive.

The companion metadata identifies real liboqs 0.16.0, liboqs-python 0.16.0, Python 3.12.14, and cryptography 50.0.2. It records the base Git revision with `working_tree_dirty: true` because these measurements were collected from the changes before committing. Its SHA256 covers the recorded files in src and matches that source snapshot; documentation, scripts, tests, and generated results are outside that source hash. The rehearsal command checks the source files against the recorded digest before displaying the saved results.

Historical data in `results/` remains unmodified. Its original backend cannot be established from that data, and its signed mode did not establish a trusted server identity. It should not be used to claim a verified intermediary-attack defense.

## Verified GitHub execution

The complete [CI run for the implementation baseline](https://github.com/RayDCodes/pqc-migration-bench/actions/runs/40627861432) and its [CodeQL run](https://github.com/RayDCodes/pqc-migration-bench/actions/runs/40627861399) both completed successfully for commit `31a8c8418c1144fc60e9c4e69130db95bddff250`. This includes native cryptography tests, negative tests, static analysis, dependency and secrets scans, infrastructure policies, the isolated container run, image vulnerability checking, inventories, and the aggregate gate. This is an observed run result, not a guarantee about future vulnerability databases.

The rehearsal runner adds ten fixture-based regression cases for source drift, incomplete or duplicated trials, invalid durations, an unexpected backend, and unknown configurations. The current PR's CI artifacts are authoritative for the updated total. The committed `tests.xml` remains evidence of the earlier 49-test core run rather than being rewritten to imply it contains the new tests.

## Deployment boundaries

No Docker daemon is available locally. The [first GitHub-hosted run](https://github.com/RayDCodes/pqc-migration-bench/actions/runs/40626513527) successfully built the image and ran its isolated non-root smoke test, then blocked the Debian 12 image on 59 high and two critical OS findings. The second run used an updated Debian 13 base and still found 44 high/critical OS entries with no listed fixed version; its Python package scan was clean. The final implementation uses a digest-verified Alpine Python base with its native toolchain and OpenSSL packages. The [third GitHub-hosted run](https://github.com/RayDCodes/pqc-migration-bench/actions/runs/40627430033) passed all three container checks, including the high/critical image gate and inventory generation. Changing libc is a compatibility trade-off that must be tested, not assumed. No image has been published. The image gate remains enabled with no vulnerability suppressions.

That first run also passed real cryptography tests, policy checks, and CodeQL. It exposed a hosted Semgrep invocation problem in the fixture test and a missing output directory when an earlier step failed. The follow-up invokes Semgrep through the same Python interpreter that imports its package, reads a dedicated JSON report instead of relying on console output, accepts exit codes zero or one only while still requiring all expected findings and no scanner errors, and initializes reports before any scanner can fail. The complete successful GitHub run is linked above.

Terraform source was scanned, but Terraform init/validate/plan/apply was not run locally. The plan JSON used by custom policy tests is synthetic and labeled accordingly. A real deployment must check its actual resolved complete plan, commit an appropriate provider lockfile, use reviewed access roles, and secure remote state. No AWS resources or accounts were changed.

The Kubernetes examples were policy checked and source scanned; they were not applied to a cluster. Admission policy, image loading, scheduling behavior, resource sizing, output retention, and network-plugin enforcement still need an actual cluster test.

Required status checks, enforced CODEOWNERS review, and branch protection were not changed. Enable those repository rules before claiming that the workflow prevents merging. CodeQL is a separate analysis workflow and its alerts are not automatically turned into failures by the aggregate CI job.

The loopback chart error bars show sample standard deviation. The p95 values in the table use nearest rank, rather than confidence intervals or extrapolation.
