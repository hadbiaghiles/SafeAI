#!/usr/bin/env python3
"""Sanitise a private SafeAI report into a public-safe summary.

This module performs classification and redaction. It never writes raw
secret values, tokens, API keys, or personal data into the public summary.
It is pure static processing of the SafeAI JSON report.
"""
from __future__ import annotations

import argparse
import json
import re
from typing import Any

# Patterns that strongly suggest secret material. Redacted before any public output.
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
    re.compile(r"(?i)api[_-]?key[\"'=:\s]+[A-Za-z0-9._-]{16,}"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
]

_SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "apikey", "api_key", "credential",
    "privatekey", "private_key", "passphrase", "auth", "authorization",
]


def redact_secret(text: str) -> str:
    """Return text with any obvious secret material replaced by a placeholder."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED_SECRET]", text)
    return text


def looks_sensitive(finding: dict[str, Any]) -> bool:
    blob = json.dumps(finding, default=str).lower()
    return any(kw in blob for kw in _SENSITIVE_KEYWORDS)


def classify(finding: dict[str, Any]) -> str:
    """Classify a finding into one of the five disclosure categories."""
    severity = str(finding.get("severity", "")).lower()
    if looks_sensitive(finding):
        return "potentially_sensitive"
    if severity in ("critical", "high"):
        # Clear static evidence may be high confidence, but remains review
        # unless a human confirms. Default to review_recommended.
        return "review_recommended"
    if severity in ("medium", "low"):
        return "informational"
    return "informational"


def classify_all(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {
        "informational": 0,
        "review_recommended": 0,
        "high_confidence_security_concern": 0,
        "potentially_sensitive": 0,
        "not_publishable": 0,
    }
    for f in findings:
        cls = classify(f)
        counts[cls] += 1
    return counts


def sanitise_report(report: dict[str, Any]) -> dict[str, Any]:
    """Produce a public-safe summary object derived from a private report."""
    findings = report.get("findings", []) or []
    counts = classify_all(findings)

    public_findings = []
    for f in findings:
        cls = classify(f)
        if cls in ("potentially_sensitive", "not_publishable"):
            continue
        public_findings.append({
            "id": f.get("id") or f.get("rule_id"),
            "rule_id": f.get("rule_id"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "classification": cls,
            "location": _safe_location(f.get("location")),
            "summary": redact_secret(str(f.get("summary", ""))),
        })

    score = report.get("safeai_security_scorecard", {}).get("score")
    if score is None:
        score = report.get("score")

    return {
        "display_name": report.get("display_name", "unknown"),
        "repository": report.get("repository"),
        "resolved_commit_sha": report.get("resolved_commit_sha"),
        "safeai_version": report.get("safeai_version"),
        "scan_timestamp_utc": report.get("scan_timestamp_utc"),
        "scope": report.get("scope"),
        "safeai_score": score,
        "status": report.get("status", "REVIEW"),
        "finding_counts": counts,
        "review_count": counts["review_recommended"],
        "high_confidence_count": counts["high_confidence_security_concern"],
        "sensitive_count": counts["potentially_sensitive"] + counts["not_publishable"],
        "main_themes": _derive_themes(public_findings),
        "findings": public_findings,
    }


def _safe_location(loc: Any) -> Any:
    if isinstance(loc, dict):
        return {
            "file": loc.get("file"),
            "line": loc.get("line"),
        }
    return loc


def _derive_themes(findings: list[dict[str, Any]]) -> list[str]:
    themes: dict[str, int] = {}
    for f in findings:
        cat = f.get("category") or "uncategorized"
        themes[cat] = themes.get(cat, 0) + 1
    return [f"{cat} ({n})" for cat, n in sorted(themes.items(), key=lambda kv: kv[1], reverse=True)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitise a private SafeAI report.")
    parser.add_argument("--report", required=True, help="Path to private SafeAI JSON report")
    parser.add_argument("--out", required=True, help="Path to write the public summary JSON")
    args = parser.parse_args(argv)

    with open(args.report, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    summary = sanitise_report(report)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(f"Wrote sanitised summary to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
