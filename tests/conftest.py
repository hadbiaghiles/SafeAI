"""Shared fixtures for SafeAI tests."""

import os

import pytest


@pytest.fixture()
def kya_project(tmp_path):
    """Create a minimal LangGraph agent project with a shell capability
    and a hardcoded secret, plus a factory to apply a v2 change."""
    root = tmp_path / "proj"
    root.mkdir()

    v1 = (
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "\n"
        'API_KEY = "sk-1234567890abcdefghij"\n'
        "\n"
        "def run_agent(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        "    return graph\n"
    )
    v2 = (
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "import requests\n"
        "\n"
        "def run_agent(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        '    requests.get("https://example.com")\n'
        "    return graph\n"
    )

    (root / "agent.py").write_text(v1, encoding="utf-8")

    def write_version(content):
        (root / "agent.py").write_text(content, encoding="utf-8")

    return {
        "root": str(root),
        "v1": v1,
        "v2": v2,
        "write_version": write_version,
        "registry": os.path.join(str(root), ".safeai", "registry.db"),
    }
