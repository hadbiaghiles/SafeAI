"""Tests for WS2: safeai init, custom rule scaffold, and per-scan rule-pack tracking."""

import os

import yaml

# ---------------------------------------------------------------------------
# safeai init
# ---------------------------------------------------------------------------

class TestSafeAIInit:
    def test_init_creates_files(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            ret = main(["init"])
            assert ret == 0

            assert (tmp_path / ".safeai" / "config.yml").exists()
            assert (tmp_path / ".safeai" / "policy.yml").exists()
            assert (tmp_path / ".safeai" / "suppressions.yml").exists()
            assert (tmp_path / ".safeai" / "rules" / "example_rules.yaml").exists()
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")

    def test_init_config_has_defaults(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            main(["init"])
            config = yaml.safe_load((tmp_path / ".safeai" / "config.yml").read_text())
            assert config["agent_name"] == tmp_path.name
            assert config["environment"] == "development"
            assert config["lifecycle_status"] == "active"
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")

    def test_init_idempotent_by_default(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            main(["init"])
            (tmp_path / ".safeai" / "config.yml").write_text("custom: true\n")
            ret = main(["init"])
            assert ret == 0
            # File should NOT be overwritten
            assert (tmp_path / ".safeai" / "config.yml").read_text() == "custom: true\n"
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")

    def test_init_force_overwrites(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            main(["init"])
            (tmp_path / ".safeai" / "config.yml").write_text("custom: true\n")
            ret = main(["init", "--force"])
            assert ret == 0
            config = yaml.safe_load((tmp_path / ".safeai" / "config.yml").read_text())
            assert "agent_name" in config  # Should be overwritten
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")

    def test_init_strict_ci_profile(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            ret = main(["init", "--profile", "strict-ci"])
            assert ret == 0
            policy = yaml.safe_load((tmp_path / ".safeai" / "policy.yml").read_text())
            assert policy["description"] is not None
            assert "policies" in policy
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")

    def test_init_preserves_existing_identity(self, tmp_path):
        from safeai.cmd.cli import main

        os.chdir(tmp_path)
        try:
            # First init creates identity
            main(["init"])
            config1 = yaml.safe_load((tmp_path / ".safeai" / "config.yml").read_text())
            uuid1 = config1.get("local_project_uuid")

            # Second init preserves it
            main(["init", "--force"])
            config2 = yaml.safe_load((tmp_path / ".safeai" / "config.yml").read_text())
            assert config2.get("local_project_uuid") == uuid1
        finally:
            os.chdir("C:/Projects/SafeAI/safeai")


# ---------------------------------------------------------------------------
# Rule loader: auto-discovery and validation
# ---------------------------------------------------------------------------

class TestRuleLoader:
    def test_auto_discovers_safeai_rules(self, tmp_path):
        from safeai.rules.loader import load_rules

        rules_dir = tmp_path / ".safeai" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "custom.yml").write_text(
            "- id: AUTO_DISCOVERED\n  description: Test\n  severity: low\n"
        )
        rules, meta = load_rules(scan_root=str(tmp_path))
        ids = [r["id"] for r in rules if r.get("id") == "AUTO_DISCOVERED"]
        assert len(ids) == 1
        assert meta["custom_rules_count"] == 1
        assert meta["custom_rules_dir"] == str(rules_dir)

    def test_explicit_dir_takes_precedence(self, tmp_path):
        from safeai.rules.loader import load_rules

        explicit = tmp_path / "explicit"
        explicit.mkdir()
        (explicit / "e.yml").write_text(
            "- id: EXPLICIT_RULE\n  description: Test\n  severity: medium\n"
        )
        safeai_rules = tmp_path / ".safeai" / "rules"
        safeai_rules.mkdir(parents=True)
        (safeai_rules / "s.yml").write_text(
            "- id: SAFEAI_RULE\n  description: Test\n  severity: low\n"
        )
        rules, meta = load_rules(custom_dir=str(explicit), scan_root=str(tmp_path))
        ids = {r["id"] for r in rules if r["id"] in {"EXPLICIT_RULE", "SAFEAI_RULE"}}
        assert "EXPLICIT_RULE" in ids
        assert "SAFEAI_RULE" not in ids
        assert meta["custom_rules_dir"] == str(explicit)

    def test_validates_required_fields(self, tmp_path):
        from safeai.rules.loader import load_rules

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Missing description and severity
        (rules_dir / "bad.yml").write_text("- id: BAD_RULE\n")
        rules, meta = load_rules(custom_dir=str(rules_dir))
        ids = [r["id"] for r in rules if r.get("id") == "BAD_RULE"]
        assert len(ids) == 0  # Should be skipped
        assert meta["custom_rules_count"] == 0

    def test_validates_severity(self, tmp_path):
        from safeai.rules.loader import load_rules

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "bad_sev.yml").write_text(
            "- id: BAD_SEV\n  description: Test\n  severity: invalid\n"
        )
        rules, _meta = load_rules(custom_dir=str(rules_dir))
        ids = [r["id"] for r in rules if r.get("id") == "BAD_SEV"]
        assert len(ids) == 0

    def test_metadata_includes_rule_pack_ids(self, tmp_path):
        from safeai.rules.loader import load_rules

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.yml").write_text("- id: A\n  description: A\n  severity: low\n")
        _, meta = load_rules(custom_dir=str(rules_dir))
        assert any("custom:" in pid for pid in meta["rule_pack_ids"])
        assert meta["builtin_rules_count"] > 0

    def test_empty_custom_dir(self, tmp_path):
        from safeai.rules.loader import load_rules

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        _rules, meta = load_rules(custom_dir=str(rules_dir))
        assert meta["custom_rules_count"] == 0
        assert meta["builtin_rules_count"] > 0


# ---------------------------------------------------------------------------
# Per-scan rule-pack metadata in manifest
# ---------------------------------------------------------------------------

class TestRulePackManifest:
    def test_manifest_includes_rule_pack_metadata(self):
        from safeai.kya.manifest import build_manifest

        report = {
            "findings": [],
            "trust_score": {"overall_ai_risk_score": 0},
            "files_scanned": 10,
            "detected_frameworks": [],
            "components": [],
            "dependency_inventory": [],
        }
        safeai_meta = {
            "version": "1.9.0",
            "ruleset_version": "sha256:abc123",
            "config_hash": "def456",
            "custom_rules_dir": "/tmp/rules",
            "custom_rules_count": 3,
            "builtin_rules_count": 57,
            "rule_pack_ids": ["built-in:base_rules.yaml", "custom:my_rules.yml"],
        }
        manifest = build_manifest(
            report,
            project={"project_id": "p1", "name": "test", "source_root": "."},
            scan_meta={"scan_id": "s1", "started_at": "2026-01-01T00:00:00Z",
                        "completed_at": "2026-01-01T00:01:00Z"},
            safeai_meta=safeai_meta,
            agents=[],
        )
        assert manifest["safeai"]["custom_rules_count"] == 3
        assert manifest["safeai"]["builtin_rules_count"] == 57
        assert "custom:my_rules.yml" in manifest["safeai"]["rule_pack_ids"]
        assert manifest["safeai"]["custom_rules_dir"] == "/tmp/rules"
