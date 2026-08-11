"""Tests for the canonical KYA manifest."""

import json
import os

import safeai
from safeai.cmd.cli import main
from safeai.kya import MANIFEST_SCHEMA_VERSION, MANIFEST_TYPE
from safeai.kya.manifest import build_manifest, serialize_manifest


def _scan_and_manifest(project_root, tmp_path):
    manifest_path = os.path.join(project_root, "safeai-manifest.json")
    rc = main(["scan", project_root, "--manifest", manifest_path,
               "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc in (0, 1)
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def test_manifest_top_level_contract(kya_project, tmp_path):
    manifest = _scan_and_manifest(kya_project["root"], str(tmp_path))

    assert manifest["schema_version"] == MANIFEST_SCHEMA_VERSION
    assert manifest["manifest_type"] == MANIFEST_TYPE
    assert manifest["generated_at"]
    for key in ("safeai", "project", "scan", "agents", "components",
                "findings", "summary", "limitations"):
        assert key in manifest

    assert manifest["safeai"]["version"]
    assert manifest["safeai"]["ruleset_version"]
    assert manifest["safeai"]["config_hash"]
    assert manifest["project"]["project_id"]
    assert manifest["scan"]["scan_id"]
    assert manifest["scan"]["files_scanned"] >= 1
    assert isinstance(manifest["summary"]["policy_decision"]["outcome"], str)


def test_manifest_agent_record_shape(kya_project, tmp_path):
    manifest = _scan_and_manifest(kya_project["root"], str(tmp_path))
    assert len(manifest["agents"]) >= 1
    agent = manifest["agents"][0]
    for key in ("agent_id", "name", "agent_type", "framework", "source_locations",
                "capabilities", "tools", "confidence", "provenance"):
        assert key in agent
    assert agent["framework"] == "langgraph"
    assert agent["confidence"] in {"high", "medium", "low"}
    for loc in agent["source_locations"]:
        assert not os.path.isabs(loc["path"])
        assert "\\" not in loc["path"]


def test_manifest_finding_shape(kya_project, tmp_path):
    manifest = _scan_and_manifest(kya_project["root"], str(tmp_path))
    assert manifest["findings"], "expected findings in fixture project"
    for finding in manifest["findings"]:
        for key in ("finding_id", "rule_id", "severity", "title", "message",
                    "remediation", "confidence", "provenance", "location",
                    "fingerprint", "status"):
            assert key in finding, f"missing {key}"
        assert finding["confidence"] in {"high", "medium", "low"}
        assert finding["status"] in {"new", "existing", "regressed", "resolved",
                                     "suppressed", "unknown"}
        assert not os.path.isabs(finding["location"]["path"])


def test_manifest_never_contains_raw_secret(kya_project, tmp_path):
    manifest_path = os.path.join(kya_project["root"], "safeai-manifest.json")
    main(["scan", kya_project["root"], "--manifest", manifest_path,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    with open(manifest_path, encoding="utf-8") as fh:
        raw = fh.read()
    assert "sk-1234567890abcdefghij" not in raw
    assert "***MASKED***" in raw


def test_manifest_deterministic_serialization(kya_project, tmp_path):
    m1 = _scan_and_manifest(kya_project["root"], str(tmp_path))
    m2 = _scan_and_manifest(kya_project["root"], str(tmp_path))

    # Volatile fields excluded, the manifests must be identical.
    for volatile in ("generated_at",):
        m1.pop(volatile)
        m2.pop(volatile)
    m1["scan"].pop("scan_id")
    m2["scan"].pop("scan_id")
    m1["scan"].pop("started_at")
    m2["scan"].pop("started_at")
    m1["scan"].pop("completed_at")
    m2["scan"].pop("completed_at")

    assert serialize_manifest(m1) == serialize_manifest(m2)


def test_manifest_limitations_present(kya_project, tmp_path):
    manifest = _scan_and_manifest(kya_project["root"], str(tmp_path))
    text = " ".join(manifest["limitations"]).lower()
    assert "static analysis evidence" in text
    assert "do not verify" in text


def test_build_manifest_from_minimal_report():
    report = {
        "findings": [],
        "files_scanned": 3,
        "detected_frameworks": ["langgraph"],
        "trust_score": {"overall_ai_risk_score": 100},
        "normalized_capabilities": [],
        "components": [],
    }
    manifest = build_manifest(
        report,
        project={"project_id": "p1", "name": "demo", "source_root": ".", "repository": {}},
        scan_meta={"scan_id": "s1", "started_at": "t0", "completed_at": "t1"},
        safeai_meta={"version": safeai.__version__, "ruleset_version": "x", "config_hash": "h"},
        agents=[],
    )
    assert manifest["summary"]["agent_count"] == 0
    assert manifest["summary"]["risk_score"] == 100
    json.dumps(manifest)  # must be JSON-serializable
