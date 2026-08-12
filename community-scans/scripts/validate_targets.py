#!/usr/bin/env python3
"""Validate the community-scan target manifest.

This script checks that:
  * the YAML parses and matches the expected schema shape,
  * every configured target resolves to a public repository,
  * the default ref (or an explicit override) resolves to a commit SHA,
  * the security-policy URL is reachable where present.

It never pushes, forks, or executes any target code. It only performs
read-only network lookups against the GitHub API.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore

try:
    import urllib.request
except ImportError:  # pragma: no cover
    urllib = None  # type: ignore


def _http_json(url: str, token: str | None = None, timeout: int = 20) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "safeai-community-scan"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def validate_yaml_structure(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["manifest root must be a mapping"]
    if data.get("version") != 1:
        errors.append("manifest version must be 1")
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("manifest must contain a non-empty 'targets' list")
        return errors
    seen_ids = set()
    for idx, target in enumerate(targets):
        if not isinstance(target, dict):
            errors.append(f"target[{idx}] must be a mapping")
            continue
        tid = target.get("id")
        if not tid:
            errors.append(f"target[{idx}] missing 'id'")
        elif tid in seen_ids:
            errors.append(f"duplicate target id: {tid}")
        else:
            seen_ids.add(tid)
        for required in ("repository", "display_name", "default_ref", "upstream_url"):
            if not target.get(required):
                errors.append(f"target {tid or idx} missing required field: {required}")
        repo = target.get("repository", "")
        if repo and repo.count("/") != 1:
            errors.append(f"target {tid} repository must be 'owner/name': {repo}")
    return errors


def resolve_repository(repo: str, token: str | None) -> dict[str, Any]:
    """Return basic repository metadata for a public repo."""
    data = _http_json(f"https://api.github.com/repos/{repo}", token)
    # The GitHub REST API exposes visibility via the ``private`` boolean (and,
    # on newer payloads, a ``visibility`` string). There is no top-level
    # ``public`` field, so check ``private`` instead.
    if data.get("private"):
        raise ValueError(f"repository is not public: {repo}")
    return data


def resolve_commit_sha(repo: str, ref: str, token: str | None) -> str:
    """Resolve a ref/branch/tag/SHA to a full 40-char commit SHA."""
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return ref
    try:
        data = _http_json(f"https://api.github.com/repos/{repo}/commits/{ref}", token)
        return data["sha"]
    except Exception as exc:
        raise ValueError(f"could not resolve ref '{ref}' for {repo}: {exc}") from exc


def validate_security_policy(url: str, token: str | None) -> tuple[bool, int]:
    """Check the declared security-policy URL is reachable and GitHub-hosted.

    Returns ``(ok, http_status)``. ``ok`` is False when the URL is missing,
    unreachable, or redirects off GitHub-owned hosts. The caller decides
    whether a missing policy is fatal.
    """
    if not url:
        return (False, 0)
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "github.com",
        "security.advisories.githubusercontent.com",
    }:
        # We only validate GitHub-hosted security policy pages.
        return (False, 0)
    try:
        # Public policy pages are fetched anonymously; never attach the token
        # to a non-API HTML request.
        headers = {"Accept": "text/html,application/json", "User-Agent": "safeai-community-scan"}
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=20) as resp:
            final_url = resp.geturl()
            final_host = urlparse(final_url).hostname
            if final_host not in {
                "github.com",
                "githubusercontent.com",
                "security.advisories.githubusercontent.com",
            }:
                return (False, resp.status)
            return (True, resp.status)
    except Exception:
        # The policy endpoint may require auth or not exist; treat as a warning only.
        return (False, 0)


def is_safe_ref(ref: str) -> bool:
    """Return True if ``ref`` looks like a safe git ref or 40-char SHA."""
    if not ref:
        return False
    if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref):
        return True
    return bool(re.match(r"^[A-Za-z0-9._/-]{1,200}$", ref))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate SafeAI community-scan targets.")
    parser.add_argument("--manifest", default="community-scans/targets.yml")
    parser.add_argument("--write-resolved", default="", help="Optional path to write resolved SHAs JSON")
    parser.add_argument("--fail-on-missing-policy", action="store_true")
    args = parser.parse_args(argv)

    if yaml is None:
        print("::error::PyYAML is required to validate the manifest", file=sys.stderr)
        return 2
    if urllib is None:
        print("::error::urllib is required to validate repositories", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("SAFEAI_GITHUB_TOKEN")

    try:
        with open(args.manifest, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        print(f"::error::manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    errors = validate_yaml_structure(data)
    if errors:
        for err in errors:
            print(f"::error::{err}", file=sys.stderr)
        return 1

    resolved: dict[str, Any] = {"targets": {}}
    for target in data["targets"]:
        tid = target["id"]
        repo = target["repository"]
        print(f"Validating {tid} ({repo})...")
        try:
            repo_meta = resolve_repository(repo, token)
        except Exception as exc:
            print(f"::error::{tid}: repository invalid: {exc}", file=sys.stderr)
            errors.append(f"{tid}: repository invalid")
            continue
        default_branch = repo_meta.get("default_branch", target["default_ref"])
        try:
            sha = resolve_commit_sha(repo, target["default_ref"], token)
        except Exception as exc:
            print(f"::error::{tid}: ref resolution failed: {exc}", file=sys.stderr)
            errors.append(f"{tid}: ref resolution failed")
            continue
        policy_ok, policy_status = validate_security_policy(target.get("security_policy_url", ""), token)
        if not policy_ok and args.fail_on_missing_policy:
            errors.append(f"{tid}: security policy unreachable")
        resolved["targets"][tid] = {
            "repository": repo,
            "default_branch": default_branch,
            "resolved_commit_sha": sha,
            "security_policy_reachable": policy_ok,
            "security_policy_status": policy_status,
        }
        print(f"  resolved {repo}@{target['default_ref']} -> {sha[:12]}")

    if args.write_resolved:
        with open(args.write_resolved, "w", encoding="utf-8") as fh:
            json.dump(resolved, fh, indent=2)

    if errors:
        print(f"::error::validation failed with {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("All targets validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
