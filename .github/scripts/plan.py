"""Bind saved plans to this run/revision/environment/image, and review their scope."""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def metadata(environment, plan):
    if environment not in ("dev", "prod"):
        raise ValueError("Unknown plan environment")
    digest = os.environ["TG_IMAGE_DIGEST"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Invalid image digest")
    return {"environment": environment, "sha": os.environ["GITHUB_SHA"],
            "run_id": os.environ["GITHUB_RUN_ID"], "image_digest": digest,
            "repository": os.environ["TG_ECR_REPOSITORY_URL"],
            "account": os.environ["TG_ACCOUNT_ID"], "region": os.environ["TG_AWS_REGION"],
            "version": os.environ.get("RELEASE_VERSION", ""),
            "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest()}


def record(environment):
    plan = Path(f"dist/plans/{environment}.tfplan")
    data = metadata(environment, plan)
    plan.with_suffix(".json").write_text(json.dumps(data, indent=2) + "\n")
    # Parse in memory: raw plan JSON/state may include secrets and is never uploaded.
    raw = subprocess.check_output(["terragrunt", "run", "--", "show", "-json", str(plan.resolve())],
                                  cwd=f"terraform/environments/{environment}", text=True)
    changes = json.loads(raw).get("resource_changes", [])
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"## {environment} plan\n\nCommit: `{data['sha']}`\n\nImage: `{data['image_digest']}`\n\n")
        if data["version"]:
            summary.write(f"Release: `{data['version']}`\n\n")
        summary.write("| Resource | Actions |\n|---|---|\n")
        for change in changes:
            actions = change["change"]["actions"]
            if actions != ["no-op"]:
                address = change["address"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("\n", " ")
                summary.write(f"| {address} | {', '.join(actions)} |\n")
        summary.write("\nBinary plan is restricted to this run; approval applies this exact plan.\n")


def verify(environment):
    plan = Path(f"dist/plans/{environment}.tfplan")
    if json.loads(plan.with_suffix(".json").read_text()) != metadata(environment, plan):
        raise ValueError("Saved plan metadata/checksum does not match this release")


if __name__ == "__main__":
    if sys.argv[1] == "record":
        record(sys.argv[2])
    elif sys.argv[1] == "verify":
        verify(sys.argv[2])
    else:
        raise SystemExit("Expected record or verify")
