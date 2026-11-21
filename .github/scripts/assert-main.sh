#!/usr/bin/env bash
set -euo pipefail
head_sha="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq '.object.sha')"
[[ "$GITHUB_REF" == refs/heads/main && "$GITHUB_SHA" == "$head_sha" ]] || {
  printf '%s\n' 'Refusing release: revision is no longer the head of main.' >&2
  exit 1
}
