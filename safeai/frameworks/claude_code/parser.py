"""Claude Code framework adapter.

Detects Claude Code agent files via ``CLAUDE.md``, ``.claude/`` config
files, and ``claude-code`` references in source. Extracts agent
definitions, tool calls, model references, and MCP integrations.
"""

import json
import re

import yaml

from safeai.analysis.capabilities import make_capability
from safeai.frameworks import register_parser


@register_parser
class ClaudeCodeParser:
    name = "claude_code"

    def detect(self, path, content, scan_ctx=None):
        fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        if fname == "claude.md":
            return True
        if ".claude/" in path.replace("\\", "/"):
            return True
        return bool("claude-code" in content.lower() or "claude_code" in content.lower())

    def parse(self, path, content, scan_ctx=None):
        result = {
            "framework": "claude_code",
            "agents": [],
            "tools": [],
            "models": [],
            "mcp_assets": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "filename" if path.lower().endswith("claude.md") else "content",
            "parser_confidence": 0.82,
            "detection_evidence": [],
        }

        fname = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        result["detection_evidence"].append(fname)

        # CLAUDE.md — extract agent/tool/model info from markdown
        if fname == "claude.md":
            self._parse_claude_md(content, result)
        elif path.endswith((".yaml", ".yml")):
            self._parse_yaml_config(content, result)
        elif path.endswith(".json"):
            self._parse_json_config(content, result)
        elif path.endswith(".py"):
            self._parse_python(content, result)

        return result

    def _parse_claude_md(self, content, result):
        """Extract agent, tool, and model references from CLAUDE.md."""
        # Tool references: @tool-name or tool: name
        for m in re.finditer(r"@([a-z][a-z0-9_-]+)", content):
            result["tools"].append(m.group(1))
        for m in re.finditer(r"tool:\s*([a-z][a-z0-9_-]+)", content, re.IGNORECASE):
            result["tools"].append(m.group(1))

        # Model references
        for m in re.finditer(r"claude-(sonnet|opus|haiku)-[\d-]+", content, re.IGNORECASE):
            result["models"].append(m.group(0))

        # Agent/workflow references
        for m in re.finditer(r"agent:\s*(.+)", content, re.IGNORECASE):
            result["agents"].append(m.group(1).strip())

        # MCP references
        if re.search(r"\bmcp\b", content, re.IGNORECASE):
            result["mcp_assets"].append({"type": "reference", "source": "claude.md"})

        # Capabilities
        low = content.lower()
        if re.search(r"shell|exec|command|subprocess", low):
            result["capabilities"].append(
                make_capability("shell", "Shell", "claude_code", "CLAUDE.md shell reference", confidence=0.75, source="config")
            )
        if re.search(r"file|filesystem|read.*file|write.*file", low):
            result["capabilities"].append(
                make_capability("filesystem", "Filesystem", "claude_code", "CLAUDE.md file reference", confidence=0.75, source="config")
            )
        if re.search(r"mcp|model.context.protocol", low):
            result["capabilities"].append(
                make_capability("mcp", "MCP", "claude_code", "CLAUDE.md MCP reference", confidence=0.75, source="config")
            )

    def _parse_yaml_config(self, content, result):
        try:
            data = yaml.safe_load(content)
        except Exception:
            return
        if isinstance(data, dict):
            if "model" in data:
                result["models"].append(str(data["model"]))
            if "tools" in data:
                tools = data["tools"]
                if isinstance(tools, list):
                    result["tools"].extend(str(t) for t in tools)
            if "agents" in data:
                agents = data["agents"]
                if isinstance(agents, list):
                    result["agents"].extend(str(a) for a in agents)

    def _parse_json_config(self, content, result):
        try:
            data = json.loads(content)
        except Exception:
            return
        if isinstance(data, dict):
            if "model" in data:
                result["models"].append(str(data["model"]))
            if "tools" in data:
                tools = data["tools"]
                if isinstance(tools, list):
                    result["tools"].extend(str(t) for t in tools)

    def _parse_python(self, content, result):
        for m in re.finditer(r"claude-(sonnet|opus|haiku)-[\d-]+", content, re.IGNORECASE):
            result["models"].append(m.group(0))
        if re.search(r"\bmcp\b", content, re.IGNORECASE):
            result["mcp_assets"].append({"type": "reference", "source": "python"})
