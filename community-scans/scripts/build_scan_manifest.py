#!/usr/bin/env python3
"""Build the provenance manifest for a single community scan target.

The manifest records the resolved commit SHA, SafeAI version, execution
context, configuration, and disclosure status. It is written even when the
scan fails so that the run remains reproducible and auditable.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
from typing import Any


def build_manifest(
    target_id: str,
    repository: str,
    upstream_url: str,
    requested_ref: str,
    resolved_commit_sha: str,
    safeai_version: str,
    safeai_action_ref: str,
    safeai_action_commit: str,
    rule_set_version: str,
    scan_timestamp_utc: str,
    fail_on: str,
    no_registry: bool,
    github_run_id: str,
    python_version: str,
    disclosure_status: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "target_id": target_id,
        "repository": repository,
        "upstream_url": upstream_url,
        "requested_ref": requested_ref,
        "resolved_commit_sha": resolved_commit_sha,
        "scan_timestamp_utc": scan_timestamp_utc,
        "safeai_version": safeai_version,
        "safeai_action_ref": safeai_action_ref,
        "safeai_action_commit": safeai_action_commit,
        "rule_set_version": rule_set_version,
        "configuration": {
            "fail_on": fail_on,
            "no_registry": no_registry,
        },
        "execution": {
            "github_run_id": github_run_id,
            "runner_os": platform.system(),
            "python_version": python_version,
        },
        "disclosure_status": disclosure_status,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a scan provenance manifest.")
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--upstream-url", required=True)
    parser.add_argument("--requested-ref", required=True)
    parser.add_argument("--resolved-commit-sha", required=True)
    parser.add_argument("--safeai-version", required=True)
    parser.add_argument("--safeai-action-ref", default="ikaruscareer/SafeAI@v1")
    parser.add_argument("--safeai-action-commit", default="")
    parser.add_argument("--rule-set-version", default="")
    parser.add_argument("--scan-timestamp-utc", required=True)
    parser.add_argument("--fail-on", default="critical")
    parser.add_argument("--no-registry", action="store_true", default=True)
    parser.add_argument("--github-run-id", default="")
    parser.add_argument("--python-version", default=platform.python_version())
    parser.add_argument("--disclosure-status", default="private")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    manifest = build_manifest(
        target_id=args.target_id,
        repository=args.repository,
        upstream_url=args.upstream_url,
        requested_ref=args.requested_ref,
        resolved_commit_sha=args.resolved_commit_sha,
        safeai_version=args.safeai_version,
        safeai_action_ref=args.safeai_action_ref,
        safeai_action_commit=args.safeai_action_commit,
        rule_set_version=args.rule_set_version,
        scan_timestamp_utc=args.scan_timestamp_utc,
        fail_on=args.fail_on,
        no_registry=args.no_registry,
        github_run_id=args.github_run_id,
        python_version=args.python_version,
        disclosure_status=args.disclosure_status,
    )

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"Wrote manifest: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
