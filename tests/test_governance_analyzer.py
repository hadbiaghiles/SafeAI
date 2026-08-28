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

    def test_empty_file_cache_no_tools(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({}, self._default_rules())
        assert isinstance(findings, list)

    def test_source_missing_timeout(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\nprint('hello')\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" in rule_ids

    def test_source_missing_retry(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_RETRY_MISSING" in rule_ids

    def test_source_missing_approval(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_APPROVAL_MISSING" in rule_ids

    def test_source_missing_audit(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_AUDIT_MISSING" in rule_ids

    def test_source_missing_rate_limit(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_RATE_LIMIT_MISSING" in rule_ids

    def test_source_with_timeout_no_finding(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "timeout = 30\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" not in rule_ids

    def test_source_with_retry_no_finding(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "retry = 3\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_RETRY_MISSING" not in rule_ids

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

    def test_finding_has_governance_risk_category(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        for f in findings:
            assert f["risk_category"] == "Governance"

    def test_finding_has_medium_severity(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "import os\n"},
            self._default_rules(),
        )
        for f in findings:
            assert f["severity"] == "medium"

    def test_deduplicates_findings(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"a.py": "import os\n", "b.py": "import os\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert rule_ids.count("GOV_TIMEOUT_MISSING") == 1

    def test_none_content_skipped(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": None},
            self._default_rules(),
        )
        assert isinstance(findings, list)

    def test_multiple_controls_detected(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run(
            {"agent.py": "timeout = 30\n"},
            self._default_rules(),
        )
        rule_ids = [f["rule_id"] for f in findings]
        assert "GOV_TIMEOUT_MISSING" not in rule_ids
        assert "GOV_RETRY_MISSING" in rule_ids
        assert "GOV_APPROVAL_MISSING" in rule_ids
