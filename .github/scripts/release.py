#!/usr/bin/env python3
"""
Publish a version for an already dev-verified image in one shared ECR.

Run with GITHUB_SHA, GITHUB_REPOSITORY, GITHUB_OUTPUT, GH_TOKEN,
ECR_REPOSITORY_URL, ECR_ACCOUNT_ID, ECR_REGION and IMAGE_DIGEST set.
Requires a full local checkout with all tags, git, gh (contents:write), and
AWS CLI credentials for describe-images, batch-get-image and put-image.
The caller must verify ECR tag immutability and serialize releases elsewhere.
The immutable git-$GITHUB_SHA image tag must already identify IMAGE_DIGEST.
No builds, deployments, local Git writes, pushes or credential persistence.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path


STABLE = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
HEADER = re.compile(r"^[a-z][a-z0-9-]*(?:\([^()\r\n]+\))?(!)?:[ \t]+")


class ReleaseError(RuntimeError):
    pass


def stable_versions(tags):
    """Return only canonical stable tags, sorted numerically."""
    return sorted(
        (tag for tag in tags if STABLE.fullmatch(tag)),
        key=lambda tag: tuple(map(int, STABLE.fullmatch(tag).groups())),
    )


def next_version(latest, messages):
    if latest is None:
        return "v0.1.0"
    major, minor, patch = map(int, STABLE.fullmatch(latest).groups())
    bump = "patch"
    for message in messages:
        header = message.split("\n", 1)[0]
        match = HEADER.match(header)
        if (match and match.group(1)) or re.search(
            r"^BREAKING(?: CHANGE|-CHANGE):", message, re.MULTILINE
        ):
            bump = "major"
            break
        if match and re.match(r"^feat(?:\(|:)", header):
            bump = "minor"
    if bump == "major":
        return f"v{major + 1}.0.0"
    if bump == "minor":
        return f"v{major}.{minor + 1}.0"
    return f"v{major}.{minor}.{patch + 1}"


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def configuration(env):
    names = (
        "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_OUTPUT", "GH_TOKEN",
        "ECR_REPOSITORY_URL", "ECR_ACCOUNT_ID", "ECR_REGION", "IMAGE_DIGEST",
    )
    for name in names:
        if not env.get(name):
            raise ReleaseError(f"Missing {name}")
    if not re.fullmatch(r"[0-9a-f]{40}", env["GITHUB_SHA"]):
        raise ReleaseError("GITHUB_SHA must be a full commit SHA")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", env["IMAGE_DIGEST"]):
        raise ReleaseError("IMAGE_DIGEST must be a sha256 digest")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", env["GITHUB_REPOSITORY"]):
        raise ReleaseError("Invalid GITHUB_REPOSITORY")
    account, region = env["ECR_ACCOUNT_ID"], env["ECR_REGION"]
    if not re.fullmatch(r"[0-9]{12}", account) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region):
        raise ReleaseError("Invalid ECR account or region")
    registry, separator, repository = env["ECR_REPOSITORY_URL"].partition("/")
    if registry not in (
        f"{account}.dkr.ecr.{region}.amazonaws.com",
        f"{account}.dkr.ecr.{region}.amazonaws.com.cn",
    ) or not separator or not re.fullmatch(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", repository):
        raise ReleaseError("ECR_REPOSITORY_URL must match ECR_ACCOUNT_ID and ECR_REGION")
    return repository


class ECR:
    def __init__(self, env, repository):
        self.base = [
            "aws", "ecr", "--registry-id", env["ECR_ACCOUNT_ID"],
            "--region", env["ECR_REGION"], "--repository-name", repository,
            "--output", "json", "--no-cli-pager",
        ]

    def call(self, operation, *args):
        return json.loads(command(self.base[:2] + [operation] + self.base[2:] + list(args)))

    def digest(self, tag):
        try:
            result = self.call("describe-images", "--image-ids", f"imageTag={tag}")
        except subprocess.CalledProcessError as error:
            if "(ImageNotFoundException)" in (error.stderr or ""):
                return None
            raise
        details = result.get("imageDetails", [])
        if len(details) != 1 or not details[0].get("imageDigest"):
            raise ReleaseError(f"Invalid ECR lookup for {tag}")
        return details[0]["imageDigest"]

    def tag(self, version, digest):
        result = self.call("batch-get-image", "--image-ids", f"imageDigest={digest}")
        images = result.get("images", [])
        if result.get("failures") or len(images) != 1:
            raise ReleaseError("ECR could not retrieve the source image")
        image = images[0]
        if image.get("imageId", {}).get("imageDigest") != digest or not image.get("imageManifest"):
            raise ReleaseError("ECR source image does not match IMAGE_DIGEST")
        args = ["--image-tag", version, "--image-digest", digest,
                "--image-manifest", image["imageManifest"]]
        if image.get("imageManifestMediaType"):
            args += ["--image-manifest-media-type", image["imageManifestMediaType"]]
        self.call("put-image", *args)
        if self.digest(version) != digest:
            raise ReleaseError(f"ECR version {version} does not match IMAGE_DIGEST")


def release(env):
    repository = configuration(env)
    sha, digest = env["GITHUB_SHA"], env["IMAGE_DIGEST"]
    ecr = ECR(env, repository)
    # Check immutable build provenance before any Git commands or writes.
    if ecr.digest(f"git-{sha}") != digest:
        raise ReleaseError("Immutable git-SHA ECR tag must match IMAGE_DIGEST")
    if command(["git", "rev-parse", "--is-shallow-repository"]) != "false":
        raise ReleaseError("A full checkout with all tags is required")
    if command(["git", "rev-parse", "HEAD"]) != sha:
        raise ReleaseError("Checkout HEAD must match GITHUB_SHA")
    tags = stable_versions(command(["git", "tag", "--list"]).splitlines())
    latest = tags[-1] if tags else None
    if latest:
        revision = command(["git", "rev-parse", f"{latest}^{{commit}}"])
        try:
            command(["git", "merge-base", "--is-ancestor", revision, sha])
        except subprocess.CalledProcessError as error:
            if error.returncode != 1:
                raise
            raise ReleaseError(f"Latest version {latest} must be an ancestor of GITHUB_SHA") from error
    current_tags = stable_versions(command(["git", "tag", "--points-at", sha]).splitlines())
    existing = bool(current_tags)
    if existing:
        version = current_tags[-1]
    else:
        revision_range = f"{latest}..{sha}" if latest else sha
        messages = command(["git", "log", "--format=%B%x00", revision_range]).split("\0")
        version = next_version(latest, (message.lstrip("\n") for message in messages))
    mapped = ecr.digest(version)
    if mapped is not None and (not existing or mapped != digest):
        raise ReleaseError(f"ECR version {version} conflicts with Git or IMAGE_DIGEST")
    if not existing:
        # Git first: a failed ECR write is repaired using this mapping on retry.
        command([
            "gh", "api", "--method", "POST",
            f"repos/{env['GITHUB_REPOSITORY']}/git/refs",
            "-f", f"ref=refs/tags/{version}", "-f", f"sha={sha}",
        ])
    if mapped is None:
        ecr.tag(version, digest)
    with Path(env["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"version={version}\ndigest={digest}\n")
    return version, digest


def main():
    try:
        release(os.environ)
    except (ReleaseError, subprocess.CalledProcessError, OSError, ValueError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
