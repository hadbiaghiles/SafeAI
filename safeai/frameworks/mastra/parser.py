"""Mastra framework adapter.

Detects Mastra agent files via ``mastra`` imports and ``Agent()`` /
``Workflow()`` / ``Tool()`` calls. Extracts agents, tools, workflows,
and model references.
"""


from safeai.analysis.capabilities import dedupe_capabilities, make_capability
from safeai.analysis.semantic import build_semantic_document, resolve_symbol
from safeai.frameworks import register_parser


@register_parser
class MastraParser:
    name = "mastra"

    def detect(self, path, content, scan_ctx=None):
        if not path.endswith(".py"):
            return False
        if "mastra" in content.lower():
            return True
        doc = build_semantic_document(path, content, module_name="")
        for imported in list(doc.imports.values()) + list(doc.from_imports.values()):
            if imported.startswith("mastra"):
                return True
        return False

    def parse(self, path, content, scan_ctx=None):
        module_name = ""
        if scan_ctx:
            module_name = scan_ctx.get("module_by_file", {}).get(path, "")
        doc = build_semantic_document(path, content, module_name=module_name)

        result = {
            "framework": "mastra",
            "agents": [],
            "tools": [],
            "workflows": [],
            "models": [],
            "capabilities": [],
            "relationships": [],
            "discovery_method": "ast",
            "parser_confidence": 0.82,
            "detection_evidence": [],
        }

        caps = []

        for call in doc.calls:
            resolved = resolve_symbol(doc, call["name"])
            base = resolved.rsplit(".", 1)[-1] if "." in resolved else resolved

            if base == "Agent":
                agent_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if agent_name:
                    result["agents"].append(str(agent_name))
                    result["detection_evidence"].append(f"Agent: {agent_name}")

            if base == "Workflow":
                wf_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if wf_name:
                    result["workflows"].append(str(wf_name))

            if base in ("Tool", "createTool"):
                tool_name = call.get("kwargs", {}).get("name") or (call.get("args") or [None])[0]
                if tool_name:
                    result["tools"].append(str(tool_name))

            if base in ("Mastra", "MastraClient"):
                result["detection_evidence"].append(f"Mastra: {base}")

            if base in ("AgentNetwork", "Network"):
                caps.append(make_capability(
                    "multi_agent", "Multi-Agent", "mastra",
                    f"{base} call", confidence=0.8, source="ast",
                ))

            if base in ("RAG", "VectorStore", "Retriever"):
                caps.append(make_capability(
                    "rag", "RAG", "mastra",
                    f"{base} call", confidence=0.8, source="ast",
                ))

            if base in ("OpenAI", "Anthropic", "Gemini", "ChatOpenAI"):
                model_name = call.get("kwargs", {}).get("model") or (call.get("args") or [None])[0]
                result["models"].append(str(model_name or base))
                caps.append(make_capability(
                    "external_model_api", "External APIs", "mastra",
                    f"{base} model call", confidence=0.8, source="ast",
                ))

        result["capabilities"] = dedupe_capabilities(caps)
        return result
