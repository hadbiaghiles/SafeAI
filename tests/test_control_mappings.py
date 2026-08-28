"""Tests for WS4: Control Mappings — OWASP LLM, OWASP Agentic, NIST AI RMF."""

import pytest


class TestControlCatalogs:
    def test_owasp_llm_has_10_controls(self):
        from safeai.controls.catalogs import OWASP_LLM
        assert len(OWASP_LLM) == 10

    def test_owasp_agentic_has_10_controls(self):
        from safeai.controls.catalogs import OWASP_AGENTIC
        assert len(OWASP_AGENTIC) == 10

    def test_nist_ai_rmf_has_controls(self):
        from safeai.controls.catalogs import NIST_AI_RMF
        assert len(NIST_AI_RMF) >= 10

    def test_get_control_owasp_llm(self):
        from safeai.controls.catalogs import get_control
        control = get_control("owasp_llm", "LLM01")
        assert control is not None
        assert control["framework"] == "owasp_llm"
        assert control["id"] == "LLM01"
        assert "Prompt Injection" in control["title"]

    def test_get_control_owasp_agentic(self):
        from safeai.controls.catalogs import get_control
        control = get_control("owasp_agentic", "AGENTIC02")
        assert control is not None
        assert control["framework"] == "owasp_agentic"
        assert "Tool Misuse" in control["title"]

    def test_get_control_nist(self):
        from safeai.controls.catalogs import get_control
        control = get_control("nist_ai_rmf", "GOVERN_1")
        assert control is not None
        assert control["framework"] == "nist_ai_rmf"

    def test_get_control_unknown_returns_none(self):
        from safeai.controls.catalogs import get_control
        assert get_control("unknown", "X1") is None

    def test_list_frameworks(self):
        from safeai.controls.catalogs import list_frameworks
        frameworks = list_frameworks()
        assert len(frameworks) == 3
        ids = {f["id"] for f in frameworks}
        assert ids == {"owasp_llm", "owasp_agentic", "nist_ai_rmf"}


class TestControlMappings:
    def test_map_prompt_injection(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        frameworks = {m["framework"] for m in mappings}
        assert "owasp_llm" in frameworks
        assert "owasp_agentic" in frameworks

    def test_map_cap_shell(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("CAP_shell")
        assert len(mappings) >= 1
        control_ids = {m["control_id"] for m in mappings}
        assert "LLM06" in control_ids

    def test_map_gov_timeout_missing(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("GOV_TIMEOUT_MISSING")
        frameworks = {m["framework"] for m in mappings}
        assert "owasp_agentic" in frameworks
        assert "nist_ai_rmf" in frameworks

    def test_map_unknown_rule_returns_empty(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("UNKNOWN_RULE")
        assert mappings == []

    def test_mapping_has_required_fields(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        for m in mappings:
            assert "framework" in m
            assert "control_id" in m
            assert "family" in m
            assert "title" in m
            assert "description" in m

    def test_deduplicates_mappings(self):
        from safeai.controls.mappings import map_rule_to_controls
        mappings = map_rule_to_controls("PROMPT_INJECTION")
        keys = {(m["framework"], m["control_id"]) for m in mappings}
        assert len(keys) == len(mappings)

    def test_map_findings_to_controls(self):
        from safeai.controls.mappings import map_findings_to_controls
        findings = [
            {"rule_id": "PROMPT_INJECTION", "severity": "critical"},
            {"rule_id": "CAP_shell", "severity": "high"},
        ]
        enriched = map_findings_to_controls(findings)
        assert len(enriched) == 2
        assert "control_mappings" in enriched[0]
        assert "control_mappings" in enriched[1]
        assert len(enriched[0]["control_mappings"]) >= 2

    def test_enriched_finding_preserves_original_data(self):
        from safeai.controls.mappings import map_findings_to_controls
        findings = [{"rule_id": "PROMPT_INJECTION", "severity": "critical", "file": "test.py"}]
        enriched = map_findings_to_controls(findings)
        assert enriched[0]["file"] == "test.py"
        assert enriched[0]["severity"] == "critical"

    def test_get_framework_summary(self):
        from safeai.controls.mappings import get_framework_summary
        summary = get_framework_summary()
        assert len(summary) == 3
        for fw in summary:
            assert "id" in fw
            assert "name" in fw
            assert "control_count" in fw

    def test_all_rules_have_mappings(self):
        from safeai.controls.mappings import RULE_MAPPINGS
        for rule_id, mappings in RULE_MAPPINGS.items():
            assert len(mappings) >= 1, f"Rule {rule_id} has no mappings"
            for framework, control_id in mappings:
                assert framework in {"owasp_llm", "owasp_agentic", "nist_ai_rmf"}
                assert isinstance(control_id, str)
