#!/usr/bin/env python3
"""Resolve a community-scan target to a pinned, validated commit SHA.

Reads the target id and an optional requested ref from the environment
(never from an interpolated shell string), validates the ref shape, and
resolves it to a full 40-character commit SHA using the GitHub API. Emits a
JSON object on stdout with the resolved repository, requested ref, and the
resolved commit SHA. Exits non-zero on any validation or resolution failure
so the workflow step fails closed.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(__file__))

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

from validate_targets import is_safe_ref, resolve_commit_sha


def main() -> int:
    target = (os.environ.get("MATRIX_TARGET") or "").strip()
    requested = (os.environ.get("REQUESTED_REF") or "").strip()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or None

    if yaml is None:
        print("::error::PyYAML is required", file=sys.stderr)
        return 2

    manifest_path = os.path.join(os.path.dirname(__file__), "..", "targets.yml")
    with open(manifest_path, "r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh)

    entry = next((t for t in data.get("targets", []) if t.get("id") == target), None)
    if entry is None:
        print(f"::error::unknown target id: {target!r}", file=sys.stderr)
        return 2

    repo = entry["repository"]

    if requested:
        if not is_safe_ref(requested):
            print(f"::error::requested ref is not a safe git ref: {requested!r}", file=sys.stderr)
            return 2
        ref_to_resolve = requested
        requested_out = requested
    else:
        ref_to_resolve = entry["default_ref"]
        requested_out = entry["default_ref"]

    try:
        sha = resolve_commit_sha(repo, ref_to_resolve, token)
    except ValueError as exc:
        print(f"::error::{target}: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "repository": repo,
        "requested_ref": requested_out,
        "resolved_ref": sha,
        "resolved_commit_sha": sha,
        "security_policy_url": entry.get("security_policy_url", ""),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
