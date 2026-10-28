from pathlib import Path
import re

import yaml

root = Path(__file__).resolve().parent.parent
for path in (root / ".github/workflows").glob("*.yml"):
    workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    triggers = workflow.get("on", {})
    if "pull_request_target" in triggers:
        raise RuntimeError(f"{path}: privileged pull request execution is forbidden")
    if workflow.get("permissions") != {"contents": "read"}:
        raise RuntimeError(f"{path}: default token must only read contents")
    for job in workflow["jobs"].values():
        if "uses" in job:
            if not job["uses"].startswith("./") and not re.search(r"@[0-9a-f]{40}$", job["uses"]):
                raise RuntimeError(f"{path}: reusable workflow must be SHA pinned")
            continue
        if not job.get("timeout-minutes"):
            raise RuntimeError(f"{path}: job needs a timeout")
        for step in job.get("steps", []):
            action = step.get("uses", "")
            if action and not action.startswith("./") and not re.search(r"@[0-9a-f]{40}$", action):
                raise RuntimeError(f"{path}: action is not pinned: {action}")
            if action.startswith("actions/checkout@"):
                if step.get("with", {}).get("persist-credentials") != "false":
                    raise RuntimeError(f"{path}: checkout must not retain credentials")
print("Workflow permissions, immutable action references, triggers, and timeouts verified")
