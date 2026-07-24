# SafeAI — Release Notes

## v1.1.0-beta (2026-07-24)

Phase 1.5 AI Component Security and stabilization release for SafeAI, the Static AI Capability & Risk Analyzer. This release remains entirely offline and static: SafeAI does not execute agents, invoke tools, call LLMs, or contact reputation services.

### New Features

- **AI Component Security**
  - Discovers skills, prompt files, tool definitions, model configurations, and workflow templates.
  - Reports component inventories in JSON, project graphs, terminal summaries, and HTML reports.

- **Skill Analysis**
  - Detects embedded prompts, hardcoded secrets, excessive permissions, insecure defaults, and risky capabilities.

- **Prompt File Analysis**
  - Scans prompt and system-instruction files for injection-prone placeholders, system prompt exposure, role overrides, and untrusted input interpolation.
  - Supports `CLAUDE.md`, `prompt.md`, `system_prompt.md`, `.prompt`, `.prompt.md`, and `.prompt.txt` artifacts.

- **Tool Definition Analysis**
  - Detects missing input validation, dangerous parameters, shell execution, and excessive tool permissions.

- **Model Configuration Analysis**
  - Detects unsafe temperature settings and explicitly disabled safety controls.
  - Applies provider-aware checks for Google, Bedrock, and Azure model safety settings.

- **Workflow Template Analysis**
  - Detects missing approval gates, insecure defaults, capability sprawl, and missing validation.

- **Deep MCP Analysis**
  - Adds per-tool broad-permission analysis.
  - Detects resources that may expose sensitive data.
  - Detects insecure MCP transports.

- **Framework Coverage**
  - Adds early-preview adapters for Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, and n8n.
  - SafeAI now includes 15 built-in framework parsers.

- **Capability Diff**
  - Compares the current normalized capability inventory with a previous JSON report.
  - Use `safeai scan <directory> --baseline previous-report.json`.

### Stabilization Improvements

- Parser registry now supports installed third-party parsers through the `safeai.parsers` entry-point group.
- Duplicate parser names and invalid parser interfaces are rejected safely.
- Component paths are normalized to scan-relative paths for portable reports.
- Component extraction diagnostics are exposed in scan reports.
- Dify and n8n detection was tightened to reduce generic configuration false positives.
- Framework dependency extraction includes the new early-preview frameworks.
- README, framework support documentation, roadmap, and release metadata now distinguish established and early-preview adapters.

### Verification

- 51 automated tests passing.
- Ruff checks passing.
- Wheel and source distribution build successfully.

### Known Limitations

- The seven new framework adapters are early-preview integrations with limited framework-specific depth.
- Capability diff compares serialized static inventories; it does not infer runtime behavior.
- JavaScript/TypeScript source analysis remains limited.
- Runtime prompt injection, jailbreak, hallucination, and tool execution testing remain outside the scope of SafeAI.

## v1.0.0-beta (2026-07-14)

Initial beta release of SafeAI — the Static AI Capability & Risk Analyzer for AI agent codebases.

### Features

- **Multi-Framework Scanning**
  - LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents
  - Microsoft Agent, Azure AI Foundry, Bedrock Agent
  - Automatic framework detection (AST + config + dependency analysis)

- **Prompt Injection Detection**
  - Direct user input interpolation into prompts (LLM01)
  - Missing delimiters between system and user content
  - System prompt leakage detection
  - Role override / instruction override attempts

- **Capability Analysis**
  - Shell execution, filesystem, HTTP, database, code execution
  - Autonomous agent loop detection
  - OWASP LLM06 (Excessive Agency) coverage

- **Data Leakage Detection**
  - Hardcoded API keys, tokens, passwords
  - Environment variable references to secrets

- **MCP (Model Context Protocol) Analysis**
  - Configuration discovery across project files
  - Schema validation (v1.0, v1.1)
  - Authentication and permissions gap detection
  - Endpoint exposure and secret detection

- **Trust Score**
  - Deterministic, reproducible risk scoring (0–100)
  - 7 risk categories with configurable weights
  - Confidence-weighted findings

- **Report Output**
  - Terminal (human-readable summary)
  - JSON (machine-readable)
  - SARIF 2.1.0 (GitHub Advanced Security compatible)
  - HTML (self-contained interactive report)

- **Custom Rules**
  - User-defined YAML rule overrides via `--rules`
  - Merge with built-in rules

- **Exit Code Integration**
  - Configurable `--fail-on` threshold for CI/CD pipelines

### Known Limitations (Beta)

- Dynamic prompt injection at runtime is not detectable via static analysis
- Framework detection is heuristic-based; some complex configurations may not be detected
- Python-only source analysis (JavaScript/TypeScript agent code not yet supported)
- MCP analysis supports v1.0 and v1.1 schemas only
- Dependency scanning is framework-agnostic (name/version extraction only; no CVE matching)

### Installation

```bash
pip install git+https://github.com/ikaruscareer/SafeAI.git
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json report.json
safeai scan /path/to/project --html report.html --fail-on medium
```
