"""Inspect an OCI archive, publish it unchanged, or resolve a promoted version."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path


def inspect_archive(path):
    with tarfile.open(path, "r:*") as archive:
        def read(name):
            member = archive.getmember(name)
            if not member.isfile():
                raise ValueError("OCI entry is not a regular file")
            return archive.extractfile(member).read()

        def blob(digest):
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                raise ValueError("Invalid OCI blob digest")
            data = read("blobs/sha256/" + digest.split(":")[1])
            if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("OCI blob checksum mismatch")
            return json.loads(data)

        index = json.loads(read("index.json"))
        if len(index["manifests"]) != 1:
            raise ValueError("Lambda requires one image, not a multi-platform index")
        digest = index["manifests"][0]["digest"]
        manifest = blob(digest)
        if manifest.get("schemaVersion") != 2 or "manifests" in manifest:
            raise ValueError("Expected a single-platform image manifest")
        config = blob(manifest["config"]["digest"])
        if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
            raise ValueError("Expected linux/amd64 image")
        return digest


def aws(*args):
    return subprocess.check_output([
        "aws", "ecr", *args, "--region", os.environ["ECR_REGION"],
        "--registry-id", os.environ["ECR_ACCOUNT_ID"],
        "--repository-names", os.environ["ECR_REPOSITORY_URL"].split("/", 1)[1],
        "--output", "json"], text=True)


def lookup(tag):
    result = subprocess.run([
        "aws", "ecr", "describe-images", "--region", os.environ["ECR_REGION"],
        "--registry-id", os.environ["ECR_ACCOUNT_ID"], "--repository-name",
        os.environ["ECR_REPOSITORY_URL"].split("/", 1)[1], "--image-ids", "imageTag=" + tag,
        "--output", "json"], text=True, capture_output=True)
    if result.returncode:
        if "(ImageNotFoundException)" in result.stderr:
            return None
        raise RuntimeError("ECR lookup failed: " + result.stderr)
    return json.loads(result.stdout)["imageDetails"][0]["imageDigest"]


def publish(path, digest):
    if inspect_archive(path) != digest:
        raise ValueError("OCI artifact does not match CI digest")
    # A shared, immutable repository makes semantic versions trustworthy selectors.
    config = json.loads(aws("describe-repositories"))["repositories"][0]
    if config["imageTagMutability"] != "IMMUTABLE":
        raise ValueError("Shared ECR must enforce IMMUTABLE tags (without exclusions)")
    tag = "git-" + os.environ["GITHUB_SHA"]
    existing = lookup(tag)
    if existing is not None:
        if existing != digest:
            raise ValueError("Commit tag already points at a different digest")
        return
    authfile = Path(os.environ["RUNNER_TEMP"]) / "ecr-auth.json"
    try:
        password = subprocess.check_output(["aws", "ecr", "get-login-password", "--region", os.environ["ECR_REGION"]])
        subprocess.run(["skopeo", "login", "--authfile", str(authfile), "--username", "AWS", "--password-stdin",
                        os.environ["ECR_REPOSITORY_URL"].split("/")[0]], input=password, check=True)
        subprocess.run(["skopeo", "copy", "--preserve-digests", "--dest-authfile", str(authfile),
                        "oci-archive:" + str(Path(path).resolve()),
                        "docker://" + os.environ["ECR_REPOSITORY_URL"] + ":" + tag], check=True)
        if lookup(tag) != digest:
            raise ValueError("Published manifest digest differs from CI")
    finally:
        authfile.unlink(missing_ok=True)


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "inspect":
        print(inspect_archive(sys.argv[2]))
    elif command == "publish":
        publish(sys.argv[2], os.environ["TG_IMAGE_DIGEST"])
    elif command == "resolve":
        version = os.environ["RELEASE_VERSION"]
        if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
            raise SystemExit("Invalid release version")
        if lookup(version) != os.environ["TG_IMAGE_DIGEST"]:
            raise SystemExit("Version does not resolve to the verified dev digest")
    else:
        raise SystemExit("Expected inspect, publish, or resolve")
