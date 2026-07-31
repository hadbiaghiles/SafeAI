"""Deterministic finding fingerprints.

Fingerprint algorithm (documented contract):

    fingerprint = SHA-256(
        normalized_rule_id      + "\\n" +
        normalized_rel_path     + "\\n" +
        normalized_line         + "\\n" +
        normalized_evidence
    ).hexdigest()

Where:
  * ``normalized_rule_id``  — upper-cased, whitespace-trimmed rule ID.
  * ``normalized_rel_path`` — project-relative path, forward slashes,
                              lower-cased drive-free form.
  * ``normalized_line``     — decimal line number (``0`` when unknown).
  * ``normalized_evidence`` — whitespace-collapsed, secret-redacted
                              evidence string (see ``util.normalize_evidence``).

Properties:
  * Independent of timestamps, absolute paths, scan IDs, and dict ordering.
  * Survives whitespace-only formatting changes in evidence.
  * A material change to rule, location, or matched evidence yields a new
    fingerprint — which is exactly what baseline diffing needs.
"""

from safeai.kya.util import normalize_evidence, sha256_text


def normalize_path(path):
    """Normalize a finding path for fingerprinting: relative, POSIX-style."""
    if not path:
        return ""
    return str(path).replace("\\", "/").lstrip("./").strip()


def normalize_rule_id(rule_id):
    """Normalize a rule ID for fingerprinting."""
    return str(rule_id or "UNKNOWN").strip().upper()


def compute_fingerprint(rule_id, path, line, evidence=""):
    """Compute the deterministic SHA-256 fingerprint for a finding."""
    material = "\n".join([
        normalize_rule_id(rule_id),
        normalize_path(path),
        str(int(line or 0)),
        normalize_evidence(evidence),
    ])
    return sha256_text(material)


def fingerprint_finding(finding):
    """Compute and attach ``fingerprint``/``finding_id`` to a finding dict.

    Returns the fingerprint. Idempotent: an existing fingerprint is kept
    so re-processing never churns identities.
    """
    existing = finding.get("fingerprint")
    if existing:
        return existing
    fp = compute_fingerprint(
        finding.get("rule_id"),
        finding.get("file"),
        finding.get("line"),
        finding.get("evidence") or finding.get("message") or "",
    )
    finding["fingerprint"] = fp
    finding.setdefault("finding_id", fp)
    return fp
