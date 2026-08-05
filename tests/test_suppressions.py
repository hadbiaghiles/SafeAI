"""Tests for the suppression workflow."""

import os
from datetime import UTC, datetime, timedelta

import pytest

from safeai.cmd.cli import main
from safeai.kya.suppressions import (
    SuppressionError,
    apply_suppressions,
    load_suppressions,
    suppression_template,
)


def _write(tmp_path, content):
    path = os.path.join(str(tmp_path), "suppressions.yml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _finding(fp="a" * 64, rule="CAP_shell", path="src/agent.py"):
    return {
        "fingerprint": fp,
        "rule_id": rule,
        "file": path,
        "severity": "high",
        "status": "new",
    }


def test_valid_suppression_applies(tmp_path):
    path = _write(tmp_path, """
version: "1"
suppressions:
  - fingerprint: "%s"
    reason: "Accepted risk in fixture"
    owner: "security-team"
    created: "2026-01-01"
""" % ("a" * 64))
    entries, warnings = load_suppressions(path)
    assert not warnings
    findings = [_finding()]
    summary = apply_suppressions(findings, entries)
    assert summary["suppressed"] == 1
    assert findings[0]["status"] == "suppressed"
    assert findings[0]["suppression"]["owner"] == "security-team"


def test_missing_reason_rejected(tmp_path):
    path = _write(tmp_path, """
suppressions:
  - fingerprint: "%s"
    owner: "team"
    created: "2026-01-01"
""" % ("a" * 64))
    with pytest.raises(SuppressionError, match="reason"):
        load_suppressions(path)


def test_missing_owner_rejected(tmp_path):
    path = _write(tmp_path, """
suppressions:
  - rule_id: CAP_shell
    reason: "x"
    created: "2026-01-01"
""")
    with pytest.raises(SuppressionError, match="owner"):
        load_suppressions(path)


def test_missing_identifier_rejected(tmp_path):
    path = _write(tmp_path, """
suppressions:
  - reason: "x"
    owner: "team"
    created: "2026-01-01"
""")
    with pytest.raises(SuppressionError, match="fingerprint.*rule_id|rule_id.*fingerprint"):
        load_suppressions(path)


def test_expired_suppression_warns_and_does_not_apply(tmp_path):
    yesterday = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
    path = _write(tmp_path, f"""
suppressions:
  - rule_id: CAP_shell
    reason: "old"
    owner: "team"
    created: "2025-01-01"
    expires: "{yesterday}"
""")
    entries, warnings = load_suppressions(path)
    assert warnings and "expired" in warnings[0]
    findings = [_finding()]
    summary = apply_suppressions(findings, entries)
    assert summary["suppressed"] == 0
    assert findings[0]["status"] == "new"


def test_rule_id_and_path_scope_matching(tmp_path):
    path = _write(tmp_path, """
suppressions:
  - rule_id: CAP_shell
    reason: "scoped"
    owner: "team"
    created: "2026-01-01"
    path: "examples/**"
""")
    entries, _ = load_suppressions(path)
    in_scope = _finding(path="examples/demo.py")
    out_scope = _finding(path="src/agent.py")
    apply_suppressions([in_scope, out_scope], entries)
    assert in_scope["status"] == "suppressed"
    assert out_scope["status"] == "new"


def test_carrying_inventory_finding_not_suppressible(tmp_path):
    # The ENV_DEP_INVENTORY finding carries the dependency inventory payload;
    # a suppression must never blank it (CE 1.5 review #3).
    path = _write(tmp_path, """
suppressions:
  - rule_id: ENV_DEP_INVENTORY
    reason: "noise"
    owner: "team"
    created: "2026-01-01"
""")
    entries, _ = load_suppressions(path)
    carrying = {
        "rule_id": "ENV_DEP_INVENTORY",
        "file": "src/app.py",
        "severity": "info",
        "dep_inventory": [{"name": "DATABASE_URL"}],
    }
    dep_finding = _finding(rule="DEP_ORPHANED_TOOL")
    apply_suppressions([carrying, dep_finding], entries)
    assert carrying.get("status") != "suppressed"
    assert "dep_inventory" in carrying
    assert dep_finding["status"] == "new"


def test_suppressed_findings_stay_in_json_output(kya_project, tmp_path):
    # First scan to learn a fingerprint.
    first_json = os.path.join(str(tmp_path), "first.json")
    main(["scan", kya_project["root"], "--json", first_json,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    import json
    with open(first_json) as fh:
        report = json.load(fh)
    carrying = {"ENV_DEP_INVENTORY", "MCP_ASSETS_DISCOVERED"}
    fp = next(
        f["fingerprint"]
        for f in report["findings"]
        if f.get("rule_id") not in carrying
    )

    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    os.makedirs(safeai_dir, exist_ok=True)
    with open(os.path.join(safeai_dir, "suppressions.yml"), "w") as fh:
        fh.write(f"""
suppressions:
  - fingerprint: "{fp}"
    reason: "test"
    owner: "team"
    created: "2026-01-01"
""")

    second_json = os.path.join(str(tmp_path), "second.json")
    main(["scan", kya_project["root"], "--json", second_json,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    with open(second_json) as fh:
        report2 = json.load(fh)
    suppressed = [f for f in report2["findings"] if f.get("status") == "suppressed"]
    assert len(suppressed) == 1
    assert suppressed[0]["fingerprint"] == fp


def test_suppression_template(tmp_path):
    snippet = suppression_template(_finding())
    assert "fingerprint:" in snippet
    assert "reason:" in snippet
    assert "owner:" in snippet
