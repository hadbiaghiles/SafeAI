"""Baseline comparison: classify findings against a prior manifest/report.

A baseline is either:
  * a canonical ``safeai-manifest.json`` (preferred), or
  * a legacy SafeAI JSON report (fingerprints are computed on load).

Classification:
  * ``new``       — fingerprint absent from the baseline.
  * ``existing``  — fingerprint present in the baseline.
  * ``resolved``  — baseline fingerprint no longer present (reported in
                    the comparison summary, not an active finding).
  * ``regressed`` — previously resolved and reintroduced; only derivable
                    with registry history, otherwise treated as ``new``.
  * ``suppressed``— set by the suppression workflow, never by baselining.
"""

import json

from safeai.kya.fingerprints import compute_fingerprint


def load_baseline(path):
    """Load a baseline file and return ``(fingerprints_set, raw_document)``.

    Raises ``ValueError`` with a user-facing message on unreadable input.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read baseline file {path}: {exc}") from exc

    if not isinstance(document, dict):
        raise TypeError(f"Baseline file {path} is not a JSON object.")

    if document.get("manifest_type") == "safeai.kya":
        fps = {
            f.get("fingerprint")
            for f in (document.get("findings") or [])
            if f.get("fingerprint")
        }
        return fps, document

    # Legacy SafeAI JSON report: compute fingerprints from its findings.
    fps = set()
    for finding in document.get("findings") or []:
        fps.add(compute_fingerprint(
            finding.get("rule_id"),
            finding.get("file"),
            finding.get("line"),
            finding.get("evidence") or finding.get("message") or "",
        ))
    return fps, document


def compare_with_baseline(findings, baseline_fingerprints):
    """Classify findings against baseline fingerprints.

    Mutates each finding's ``status`` (``new``/``existing``) unless the
    finding is already ``suppressed``. Returns a summary dict including
    resolved fingerprints (present in baseline, absent now).
    """
    current_fps = set()
    new_count = existing_count = 0
    new_high_critical = 0

    for finding in findings:
        fp = finding.get("fingerprint")
        if not fp:
            continue
        current_fps.add(fp)
        if finding.get("status") == "suppressed":
            continue
        if fp in baseline_fingerprints:
            finding["status"] = "existing"
            existing_count += 1
        else:
            finding["status"] = "new"
            new_count += 1
            if finding.get("severity") in {"critical", "high"}:
                new_high_critical += 1

    resolved = sorted(baseline_fingerprints - current_fps)

    return {
        "baseline_available": True,
        "new": new_count,
        "existing": existing_count,
        "resolved": len(resolved),
        "resolved_fingerprints": resolved,
        "new_high_critical": new_high_critical,
    }
