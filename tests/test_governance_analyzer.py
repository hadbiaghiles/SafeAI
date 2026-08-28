"""Tests for WS3: GovernanceAnalyzer — timeout, retry, approval, audit, rate-limit detection."""


class TestGovernanceAnalyzer:
    def _make_analyzer(self):
        from safeai.analyzers.governance.analyzer import GovernanceAnalyzer
        return GovernanceAnalyzer()

    def _default_rules(self):
        return [
            {"id": "GOV_TIMEOUT_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
            {"id": "GOV_RETRY_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
            {"id": "GOV_APPROVAL_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
            {"id": "GOV_AUDIT_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
            {"id": "GOV_RATE_LIMIT_MISSING", "severity": "medium", "owasp_llm": "LLM05"},
        ]

    def test_empty_no_findings(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({}, self._default_rules())
        assert findings == []

    def test_no_tools_no_findings(self):
        analyzer = self._make_analyzer()
        agent_models = [{"file": "agent.py", "data": {}}]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        assert findings == []

    def test_tool_missing_timeout(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [{"name": "search_tool", "line": 10}],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" in rule_ids

    def test_tool_missing_all_controls(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [{"name": "bare_tool", "line": 5}],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        assert len(rule_ids) == 5

    def test_tool_with_timeout_no_finding(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [{"name": "search_tool", "kwargs": {"timeout": 30}, "line": 10}],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" not in rule_ids

    def test_tool_with_retry_in_config(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [{"name": "api_tool", "config": {"max_retries": 3}, "line": 5}],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_RETRY_MISSING" not in rule_ids

    def test_string_tool_entry_skipped(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": ["not_a_dict"],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        assert findings == []

    def test_finding_has_governance_risk_category(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {"tools": [{"name": "tool1"}]},
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        for f in findings:
            assert f["risk_category"] == "Governance"

    def test_finding_has_medium_severity(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {"tools": [{"name": "tool1"}]},
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        for f in findings:
            assert f["severity"] == "medium"

    def test_deduplicates_findings(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [
                    {"name": "tool1"},
                    {"name": "tool2"},
                ],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        # Each distinct tool missing timeout yields its own finding (no
        # cross-tool collapse), so two tools produce two findings.
        assert rule_ids.count("GOV_TIMEOUT_MISSING") == 2

    def test_same_tool_not_duplicated(self):
        analyzer = self._make_analyzer()
        agent_models = [{
            "file": "agent.py",
            "data": {
                "tools": [
                    {"name": "tool1"},
                    {"name": "tool1"},
                ],
            },
        }]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        # The same tool declared twice collapses to a single finding.
        assert rule_ids.count("GOV_TIMEOUT_MISSING") == 1

    def test_multiple_models(self):
        analyzer = self._make_analyzer()
        agent_models = [
            {"file": "a.py", "data": {"tools": [{"name": "t1"}]}},
            {"file": "b.py", "data": {"tools": [{"name": "t2", "kwargs": {"timeout": 10}}]}},
        ]
        findings = analyzer.run({}, self._default_rules(), agent_models=agent_models)
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" in rule_ids
