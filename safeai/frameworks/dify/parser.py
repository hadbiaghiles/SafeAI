"""Dify framework adapter.

Detects Dify workflow and agent configurations via YAML/JSON files
containing Dify-specific keys, and ``dify`` references in Python.
Extracts workflows, tools, and model references.
"""

import json
import re

import yaml

from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.frameworks import register_parser


@register_parser
class DifyParser:
    name = "dify"

    def detect(self, path, content, scan_ctx=None):
        low = content.lower()
        if re.search(r"\bdify(?:-|_|\b)|dify\.ai", low):
            return True
        if path.endswith((".yaml", ".yml")):
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict) and (
                    "app" in data and isinstance(data["app"], (dict, str))
                    or "dify" in data
                    or ("workflow" in data and "graph" in data)
                ):
                    return True
            except Exception:
                pass
        return False

    def parse(self, path, content, scan_ctx=None):
        result = {
            "framework": "dify",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "config",
            "parser_confidence": 0.80,
            "detection_evidence": [],
        }

        caps = []

        if path.endswith((".yaml", ".yml")):
            try:
                data = yaml.safe_load(content)
            except Exception:
                data = None
            if isinstance(data, dict):
                self._parse_config(data, result, caps)
        elif path.endswith(".json"):
            try:
                data = json.loads(content)
            except Exception:
                data = None
            if isinstance(data, dict):
                self._parse_config(data, result, caps)
        elif path.endswith(".py"):
            self._parse_python(content, result, caps)

        result["capabilities"] = dedupe_capabilities(caps)
        return result

    def _parse_config(self, data, result, caps):
        if "name" in data:
            result["workflows"].append(str(data["name"]))
            result["detection_evidence"].append(f"Workflow: {data['name']}")

        for key in ("model", "model_name", "llm"):
            if key in data:
                result["models"].append(str(data[key]))

        for key in ("tools", "plugins", "providers"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, dict) and "name" in item:
                        result["tools"].append(str(item["name"]))
                    elif isinstance(item, str):
                        result["tools"].append(item)

        if "agents" in data and isinstance(data["agents"], list):
            for agent in data["agents"]:
                if isinstance(agent, dict) and "name" in agent:
                    result["agents"].append(str(agent["name"]))
                elif isinstance(agent, str):
                    result["agents"].append(agent)

        # Capability inference from config keys
        config_text = json.dumps(data, default=str).lower()
        if re.search(r"shell|exec|command|subprocess", config_text):
            caps.append(make_capability("shell", "Shell", "dify", "config shell reference", confidence=0.7, source="config"))
        if re.search(r"http|api|request|fetch", config_text):
            caps.append(make_capability("external_apis", "External APIs", "dify", "config HTTP reference", confidence=0.7, source="config"))
        if re.search(r"database|sql|postgres|mysql", config_text):
            caps.append(make_capability("databases", "Databases", "dify", "config DB reference", confidence=0.7, source="config"))

    def _parse_python(self, content, result, caps):
        for m in re.finditer(r"DifyClient|dify_client", content, re.I):
            result["detection_evidence"].append(f"Dify client: {m.group(0)}")
        for m in re.finditer(r"model\s*=\s*['\"]([^'\"]+)['\"]", content, re.I):
            result["models"].append(m.group(1))
