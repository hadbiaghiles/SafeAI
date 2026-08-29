"""Release validation tests — rule counts, version consistency, unmapped rules."""

import os

import yaml


def _load_rules():
    path = os.path.join(os.path.dirname(__file__), "..", "safeai", "rules", "base_rules.yaml")
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_rule_ids():
    return {r["id"] for r in _load_rules() if isinstance(r, dict) and "id" in r}


class TestRuleCount:
    def test_rule_count_derived_not_hardcoded(self):
        """Rule count must come from the YAML, not a hard-coded literal."""
        rule_ids = _load_rule_ids()
        assert len(rule_ids) > 0

    def test_all_rules_have_required_fields(self):
        for rule in _load_rules():
            if not isinstance(rule, dict):
                continue
            assert "id" in rule, f"Rule missing 'id': {rule}"
            assert "severity" in rule, f"Rule {rule.get('id')} missing 'severity'"
            assert rule["severity"] in ("critical", "high", "medium", "low", "info"), (
                f"Rule {rule['id']} has invalid severity: {rule['severity']}"
            )


class TestVersionConsistency:
    def test_version_py_matches_changelog(self):
        from safeai.version import SAFEAI_VERSION
        changelog_path = os.path.join(os.path.dirname(__file__), "..", "CHANGELOG.md")
        with open(changelog_path, encoding="utf-8") as fh:
            content = fh.read()
        assert f"[{SAFEAI_VERSION}]" in content, (
            f"Version {SAFEAI_VERSION} from version.py not found in CHANGELOG.md"
        )

    def test_version_py_exists(self):
        from safeai.version import SAFEAI_VERSION
        assert SAFEAI_VERSION
        assert "." in SAFEAI_VERSION


class TestUnmappedRules:
    def test_gov_rules_have_mapping(self):
        """All GOV_* rules should have a control mapping."""
        from safeai.controls.mappings import RULE_MAPPINGS

        rule_ids = _load_rule_ids()
        gov_rules = {r for r in rule_ids if r.startswith("GOV_")}
        mapped = set(RULE_MAPPINGS.keys())
        unmapped_gov = gov_rules - mapped
        assert not unmapped_gov, f"GOV rules without mappings: {sorted(unmapped_gov)}"

    def test_dataflow_rules_have_mapping(self):
        """All DATAFLOW_* rules should have a control mapping."""
        from safeai.controls.mappings import RULE_MAPPINGS

        rule_ids = _load_rule_ids()
        df_rules = {r for r in rule_ids if r.startswith("DATAFLOW_")}
        mapped = set(RULE_MAPPINGS.keys())
        unmapped_df = df_rules - mapped
        assert not unmapped_df, f"DATAFLOW rules without mappings: {sorted(unmapped_df)}"


class TestCatalogVersions:
    def test_catalog_version_constants_exist(self):
        from safeai.controls.catalogs import (
            NIST_AI_RMF_VERSION,
            OWASP_AGENTIC_VERSION,
            OWASP_LLM_VERSION,
        )
        assert OWASP_LLM_VERSION == "2025"
        assert OWASP_AGENTIC_VERSION == "2025"
        assert NIST_AI_RMF_VERSION == "1.0"

    def test_frameworks_match_constants(self):
        from safeai.controls.catalogs import (
            FRAMEWORKS,
            NIST_AI_RMF_VERSION,
            OWASP_AGENTIC_VERSION,
            OWASP_LLM_VERSION,
        )
        assert FRAMEWORKS["owasp_llm"]["version"] == OWASP_LLM_VERSION
        assert FRAMEWORKS["owasp_agentic"]["version"] == OWASP_AGENTIC_VERSION
        assert FRAMEWORKS["nist_ai_rmf"]["version"] == NIST_AI_RMF_VERSION


class TestMCPUAssuranceNotes:
    def test_external_package_server_noted(self):
        from safeai.kya.assurance import build_assurance_boundary

        report = {
            "mcp_assets": [
                {"name": "ext-server", "assurance": "external-package"},
            ],
        }
        boundary = build_assurance_boundary(report)
        notes = boundary["coverage_notes"]
        assert any("external packages" in n for n in notes)

    def test_unresolved_command_server_noted(self):
        from safeai.kya.assurance import build_assurance_boundary

        report = {
            "mcp_assets": [
                {"name": "local-server", "assurance": "unresolved-command"},
            ],
        }
        boundary = build_assurance_boundary(report)
        notes = boundary["coverage_notes"]
        assert any("could not be resolved" in n for n in notes)

    def test_resolved_server_no额外note(self):
        from safeai.kya.assurance import build_assurance_boundary

        report = {
            "mcp_assets": [
                {"name": "ok-server", "assurance": "resolved"},
            ],
        }
        boundary = build_assurance_boundary(report)
        notes = boundary["coverage_notes"]
        # Should not add MCP-specific note for fully resolved servers
        assert not any("MCP" in n for n in notes)


class TestFindingMetadata:
    def test_gov_finding_has_metadata(self):
        from safeai.analyzers.governance.analyzer import GovernanceAnalyzer

        analyzer = GovernanceAnalyzer()
        rules = [
            {"id": "GOV_TIMEOUT_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
        ]
        agent_models = [{
            "file": "a.py",
            "data": {"tools": [{"name": "t1"}]},
        }]
        findings = analyzer.run({}, rules, agent_models=agent_models)
        assert len(findings) >= 1
        f = findings[0]
        assert f["confidence"] == "heuristic"
        assert f["scope"] == "static-analysis"
        assert "limitation" in f

    def test_dataflow_finding_has_metadata(self):
        from safeai.analyzers.dataflow.analyzer import DataFlowAnalyzer

        analyzer = DataFlowAnalyzer()
        content = "user_input = input()\nos.system(user_input)"
        findings = analyzer.run({"a.py": content}, [])
        assert len(findings) >= 1
        for f in findings:
            assert f["confidence"] == "heuristic"
            assert f["scope"] == "static-analysis"
            assert "limitation" in f
