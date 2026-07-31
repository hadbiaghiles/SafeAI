"""Tests for deterministic finding fingerprints."""

from safeai.kya.enrich import normalize_findings
from safeai.kya.fingerprints import compute_fingerprint, fingerprint_finding


def _finding(**overrides):
    base = {
        "rule_id": "CAP_shell",
        "severity": "high",
        "message": "Capability detected",
        "file": "src/agent.py",
        "line": 10,
        "evidence": "subprocess.run(user_input, shell=True)",
    }
    base.update(overrides)
    return base


def test_fingerprint_stable_for_identical_input():
    a = compute_fingerprint("CAP_shell", "src/agent.py", 10, "evidence text")
    b = compute_fingerprint("CAP_shell", "src/agent.py", 10, "evidence text")
    assert a == b
    assert len(a) == 64  # full SHA-256 hex


def test_fingerprint_ignores_whitespace_only_changes():
    a = compute_fingerprint("CAP_shell", "src/agent.py", 10, "subprocess.run(x,   shell=True)")
    b = compute_fingerprint("CAP_shell", "src/agent.py", 10, "subprocess.run(x, shell=True)\n")
    assert a == b


def test_fingerprint_differs_for_material_changes():
    base = compute_fingerprint("CAP_shell", "src/agent.py", 10, "evidence")
    assert base != compute_fingerprint("CAP_http", "src/agent.py", 10, "evidence")
    assert base != compute_fingerprint("CAP_shell", "src/other.py", 10, "evidence")
    assert base != compute_fingerprint("CAP_shell", "src/agent.py", 11, "evidence")
    assert base != compute_fingerprint("CAP_shell", "src/agent.py", 10, "different evidence")


def test_fingerprint_ignores_absolute_path_prefixes():
    a = compute_fingerprint("CAP_shell", "src/agent.py", 10, "ev")
    b = compute_fingerprint("CAP_shell", "src\\agent.py", 10, "ev")
    assert a == b


def test_fingerprint_redacts_secret_material():
    a = compute_fingerprint("DATA_LEAKAGE", "a.py", 1, 'API_KEY = "sk-aaaabbbbccccdddd"')
    b = compute_fingerprint("DATA_LEAKAGE", "a.py", 1, 'API_KEY = "sk-aaaabbbbccccdddd"')
    assert a == b
    # A *different* secret value on the same line normalizes to the same
    # redacted evidence, so fingerprints survive secret rotation.
    c = compute_fingerprint("DATA_LEAKAGE", "a.py", 1, 'API_KEY = "sk-zzzzyyyyxxxxwwww"')
    assert a == c


def test_fingerprint_finding_idempotent():
    finding = _finding()
    fp1 = fingerprint_finding(finding)
    fp2 = fingerprint_finding(finding)
    assert fp1 == fp2
    assert finding["finding_id"] == fp1


def test_normalize_findings_adds_kya_fields():
    findings = normalize_findings([_finding()])
    f = findings[0]
    assert f["fingerprint"]
    assert f["confidence_label"] in {"high", "medium", "low"}
    assert f["status"] in {"new", "existing", "regressed", "resolved", "suppressed", "unknown"}
    assert f["remediation"]
    assert f["provenance"]["analyzer"] == "capability"


def test_normalize_findings_redacts_evidence():
    finding = _finding(evidence='API_KEY = "sk-1234567890abcdefghij"')
    normalize_findings([finding])
    assert "sk-1234567890abcdefghij" not in str(finding["evidence"])
    assert "***MASKED***" in finding["evidence"]


def test_remediation_defaults_for_high_value_rules():
    findings = normalize_findings([_finding(rule_id="DATA_LEAKAGE", remediation=None)])
    assert "secret" in findings[0]["remediation"].lower()
