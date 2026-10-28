from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile

import yaml

root = Path(__file__).resolve().parent.parent
conftest = str(root / ".tools/conftest")
policy = str(root / "security/policy")


def evaluate(config, expected, name):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as fixture:
        json.dump(config, fixture)
        fixture.flush()
        result = subprocess.run(
            [conftest, "test", fixture.name, "--policy", policy, "--output", "json"],
            capture_output=True, text=True,
        )
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or result.stdout)
    report = json.loads(result.stdout)
    failures = [failure["msg"] for entry in report for failure in entry.get("failures", [])]
    if expected is None:
        if failures:
            raise RuntimeError(f"{name}: unexpectedly rejected: {failures}")
    elif not any(message.startswith(expected + ":") for message in failures):
        raise RuntimeError(f"{name}: expected {expected}, got {failures}")
    print(f"PASS {name}")


def main():
    baseline = yaml.safe_load((root / "deploy/kubernetes/benchmark-job.yaml").read_text())
    evaluate(baseline, None, "safe job")
    evaluate({"kind": "Job", "spec": {}}, "K8S000", "missing pod template")
    evaluate({"kind": "List", "items": [baseline]}, "K8S016", "List cannot bypass workload checks")
    mutations = [
        ("privileged", True, "K8S005"),
        ("allowPrivilegeEscalation", True, "K8S004"),
        ("readOnlyRootFilesystem", False, "K8S006"),
        ("runAsNonRoot", False, "K8S002"),
        ("runAsUser", 0, "K8S003"),
        ("capabilities", {"drop": []}, "K8S007"),
        ("capabilities", {"drop": ["ALL"], "add": ["SYS_ADMIN"]}, "K8S008"),
        ("seccompProfile", {"type": "Unconfined"}, "K8S009"),
    ]
    for field, value, expected in mutations:
        config = deepcopy(baseline)
        config["spec"]["template"]["spec"]["containers"][0]["securityContext"][field] = value
        evaluate(config, expected, field)
    for value in ["0", "0Mi", None]:
        config = deepcopy(baseline)
        config["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"] = value
        evaluate(config, "K8S010", f"invalid memory limit {value}")
    for field in ["hostNetwork", "hostPID", "hostIPC", "automountServiceAccountToken"]:
        config = deepcopy(baseline)
        config["spec"]["template"]["spec"][field] = True
        evaluate(config, "K8S012" if field == "automountServiceAccountToken" else "K8S011", field)
    for field in ["initContainers", "ephemeralContainers"]:
        config = deepcopy(baseline)
        config["spec"]["template"]["spec"][field] = [{"name": "unsafe-extra", "image": "python:latest", "securityContext": {"privileged": True}}]
        evaluate(config, "K8S005", field)
    for image, rule in [("python", "K8S014"), ("python:latest", "K8S015")]:
        config = deepcopy(baseline)
        config["spec"]["template"]["spec"]["containers"][0]["image"] = image
        evaluate(config, rule, image)
    config = deepcopy(baseline)
    config["spec"]["template"]["spec"]["volumes"].append({"name": "host", "hostPath": {"path": "/"}})
    evaluate(config, "K8S013", "hostPath")
    for kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
        spec = deepcopy(baseline["spec"]["template"]["spec"])
        if kind == "Pod":
            config = {"kind": kind, "spec": spec}
        elif kind == "CronJob":
            config = {"kind": kind, "spec": {"jobTemplate": {"spec": {"template": {"spec": spec}}}}}
        else:
            config = {"kind": kind, "spec": {"template": {"spec": spec}}}
        evaluate(config, None, f"safe {kind}")

    plan = json.loads((root / "tests/fixtures/terraform-plan.safe.json").read_text())
    evaluate(plan, None, "safe Terraform plan fixture")
    for field in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]:
        config = deepcopy(plan)
        config["resource_changes"][1]["change"]["after"][field] = False
        evaluate(config, "TF001", field)
        config["resource_changes"][1]["change"]["after_unknown"][field] = True
        evaluate(config, "TF002", f"unknown {field}")
    config = deepcopy(plan)
    config["resource_changes"][0]["change"]["after"]["acl"] = "public-read"
    evaluate(config, "TF003", "public ACL")
    config = deepcopy(plan)
    del config["resource_changes"][1]
    evaluate(config, "TF004", "missing public access block")
    config = deepcopy(plan)
    del config["resource_changes"][2]
    evaluate(config, "TF006", "missing encryption")
    config = deepcopy(plan)
    config["resource_changes"][2]["change"]["after"]["rule"] = []
    evaluate(config, "TF005", "invalid encryption")


if __name__ == "__main__":
    main()
