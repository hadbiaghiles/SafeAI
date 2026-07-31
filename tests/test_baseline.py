"""Tests for baseline comparison and --fail-on-new semantics."""

import json
import os

import pytest

from safeai.cmd.cli import main
from safeai.kya.baseline import compare_with_baseline, load_baseline


def _scan_manifest(project_root, tmp_path, name="safeai-manifest.json", extra=None):
    path = os.path.join(project_root, name)
    argv = ["scan", project_root, "--manifest", path,
            "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"]
    if extra:
        argv += extra
    main(argv)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh), path


def test_load_baseline_manifest(kya_project, tmp_path):
    _, path = _scan_manifest(kya_project["root"], str(tmp_path))
    fps, doc = load_baseline(path)
    assert doc["manifest_type"] == "safeai.kya"
    assert len(fps) == len(doc["findings"])


def test_load_baseline_legacy_report(kya_project, tmp_path):
    report_path = os.path.join(str(tmp_path), "legacy.json")
    main(["scan", kya_project["root"], "--json", report_path,
          "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    fps, doc = load_baseline(report_path)
    assert "findings" in doc
    assert len(fps) >= 1


def test_baseline_invalid_top_level_object_fails_cleanly(tmp_path):
    bad = os.path.join(str(tmp_path), "bad-baseline.json")
    with open(bad, "w", encoding="utf-8") as fh:
        fh.write("[]")

    with pytest.raises(SystemExit) as exc:
        main([
            "scan",
            str(tmp_path),
            "--baseline",
            bad,
            "--no-registry",
            "--sarif",
            os.path.join(tmp_path, "r.sarif"),
        ])
    assert exc.value.code == 2


def test_baseline_new_existing_resolved(kya_project, tmp_path):
    # Baseline = v1 scan.
    _, baseline_path = _scan_manifest(kya_project["root"], str(tmp_path))

    # Current = v2 scan (secret removed, requests added, lines shifted).
    kya_project["write_version"](kya_project["v2"])
    manifest_v2, _ = _scan_manifest(kya_project["root"], str(tmp_path), name="m2.json")

    baseline_fps, _ = load_baseline(baseline_path)
    findings = [{**f} for f in manifest_v2["findings"]]
    summary = compare_with_baseline(findings, baseline_fps)

    statuses = {f["rule_id"]: f["status"] for f in findings}
    assert summary["new"] >= 1
    assert summary["existing"] >= 1
    assert summary["resolved"] >= 1  # the DATA_LEAKAGE finding disappeared
    assert summary["new_high_critical"] >= 1
    assert any(s == "new" for s in statuses.values())
    assert any(s == "existing" for s in statuses.values())


def test_baseline_identical_scan_all_existing(kya_project, tmp_path):
    _, baseline_path = _scan_manifest(kya_project["root"], str(tmp_path))
    manifest_same, _ = _scan_manifest(kya_project["root"], str(tmp_path), name="m2.json")

    baseline_fps, _ = load_baseline(baseline_path)
    findings = [{**f} for f in manifest_same["findings"]]
    summary = compare_with_baseline(findings, baseline_fps)

    assert summary["new"] == 0
    assert summary["resolved"] == 0
    assert summary["existing"] == len(findings)


def test_fail_on_new_exit_codes(kya_project, tmp_path):
    _, baseline_path = _scan_manifest(kya_project["root"], str(tmp_path))

    # Same code: no new findings -> pass even with critical findings present.
    rc_same = main(["scan", kya_project["root"], "--baseline", baseline_path,
                    "--fail-on-new", "--fail-on", "high",
                    "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc_same == 0

    # Changed code: new findings at high/critical -> fail.
    kya_project["write_version"](kya_project["v2"])
    rc_changed = main(["scan", kya_project["root"], "--baseline", baseline_path,
                       "--fail-on-new", "--fail-on", "high",
                       "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc_changed == 1

    # Without --fail-on-new the unchanged tree still fails on critical
    # (backward-compatible --fail-on semantics).
    kya_project["write_version"](kya_project["v1"])
    rc_legacy = main(["scan", kya_project["root"], "--baseline", baseline_path,
                      "--fail-on", "critical",
                      "--sarif", os.path.join(tmp_path, "r.sarif"), "--no-registry"])
    assert rc_legacy == 1
