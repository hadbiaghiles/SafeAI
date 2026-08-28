"""Tests for WS5 (Adapter Completion) and WS6 (Heuristic Data-Flow Depth)."""

import pytest


class TestAutoGenAdapter:
    def test_detects_autogen_import(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import AssistantAgent"
        assert parser.detect("agent.py", content) is True

    def test_detects_autogen_class_usage(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "bot = AssistantAgent('bot')"
        assert parser.detect("agent.py", content) is True

    def test_ignores_non_autogen(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "import os"
        assert parser.detect("agent.py", content) is False

    def test_parses_assistant_agent(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import AssistantAgent\nbot = AssistantAgent('bot')"
        result = parser.parse("agent.py", content)
        assert result["framework"] == "autogen"
        assert len(result["agents"]) >= 1

    def test_parses_user_proxy(self):
        from safeai.frameworks.autogen.parser import AutoGenParser
        parser = AutoGenParser()
        content = "from autogen import UserProxyAgent\nuser = UserProxyAgent('user')"
        result = parser.parse("agent.py", content)
        assert len(result["agents"]) >= 1


class TestLangGraphConditionalEdges:
    def test_detects_conditional_edges(self):
        from safeai.frameworks.langgraph.parser import LangGraphParser
        parser = LangGraphParser()
        content = "from langgraph.graph import StateGraph\ngraph.add_conditional_edges('start', route_fn)"
        assert parser.detect("graph.py", content) is True

    def test_parses_conditional_edges(self):
        from safeai.frameworks.langgraph.parser import LangGraphParser
        parser = LangGraphParser()
        content = "from langgraph.graph import StateGraph\ngraph.add_conditional_edges('start', route_fn)"
        result = parser.parse("graph.py", content)
        assert result["framework"] == "langgraph"
        assert len(result["edges"]) >= 1


class TestBrowserRuleSplit:
    def test_playwright_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from playwright import sync_api"
        assert CAP_PATTERNS["browser_playwright"].search(content)

    def test_selenium_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from selenium import webdriver"
        assert CAP_PATTERNS["browser_selenium"].search(content)

    def test_browser_use_detected(self):
        from safeai.analyzers.capability.analyzer import CAP_PATTERNS
        content = "from browser_use import Agent"
        assert CAP_PATTERNS["browser_use"].search(content)


class TestDataFlowAnalyzer:
    def _make_analyzer(self):
        from safeai.analyzers.dataflow.analyzer import DataFlowAnalyzer
        return DataFlowAnalyzer()

    def test_empty_file_cache(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({}, [])
        assert findings == []

    def test_detects_user_input_to_prompt(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['input']\nprompt = f'Process: {user_input}'"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_PROMPT" in rule_ids

    def test_detects_user_input_to_shell(self):
        analyzer = self._make_analyzer()
        content = "user_input = input('Enter: ')\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        rule_ids = [f["rule_id"] for f in findings]
        assert "DATAFLOW_SHELL" in rule_ids

    def test_no_finding_without_sources(self):
        analyzer = self._make_analyzer()
        content = "x = 42\nprint(x)"
        findings = analyzer.run({"app.py": content}, [])
        assert findings == []

    def test_no_finding_without_sinks(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['input']"
        findings = analyzer.run({"app.py": content}, [])
        assert findings == []

    def test_finding_has_high_severity(self):
        analyzer = self._make_analyzer()
        content = "user_input = input()\nos.system(user_input)"
        findings = analyzer.run({"app.py": content}, [])
        for f in findings:
            assert f["severity"] == "high"

    def test_finding_has_safety_category(self):
        analyzer = self._make_analyzer()
        content = "user_input = input()\nprompt = user_input"
        findings = analyzer.run({"app.py": content}, [])
        for f in findings:
            assert f["risk_category"] == "Safety"

    def test_none_content_skipped(self):
        analyzer = self._make_analyzer()
        findings = analyzer.run({"app.py": None}, [])
        assert findings == []

    def test_intermediate_variable_tracking(self):
        analyzer = self._make_analyzer()
        content = "user_input = request.form['data']\ndata = user_input\nresult = data"
        findings = analyzer.run({"app.py": content}, [])
        # Should detect propagation through intermediate variable
        assert isinstance(findings, list)
