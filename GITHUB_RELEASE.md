# SafeAI — GitHub Release

## v1.8.0

Static AI Capability & Risk Analyzer for AI agents and workflows. Detects
prompt injection, data leakage, excessive agency, MCP misconfigurations, and
credential/capability mismatches — entirely offline and static. This curated
release bundles the remaining CE 1.4, CE 1.5, and CE 1.8 gaps into four
cohesive workstreams — the gate for starting CE 2.0.

### Installation

```bash
pip install SafeAI-Static-Analyzer
```

### Quick Start

```bash
safeai scan /path/to/project
safeai scan /path/to/project --json results.json --html report.html
safeai scan /path/to/project --scorecard scorecard.md --scorecard-fail-under 7.0
```

### GitHub Action

```yaml
- uses: ikaruscareer/SafeAI@v1
  with:
    path: .
    fail-on: critical
```

### What's New in 1.8.0

**Workstream 1 — Lifecycle & Ownership (CE 1.4)**
- **Finding Lifecycle Event Engine** — `finding_lifecycle` table (schema v4)
  tracking state transitions: `introduced → persisting → resolved → reopened`.
  `ESC_RECURRING_RISK` escalation rule fires when a previously resolved finding
  is reintroduced.
- **Stale Suppression Guard** — `detect_stale_suppressions()` binds waivers to
  exact code fingerprints; `--strict-suppressions` fails on expired or moved
  suppressions.
- **Agent Enrichment Schema** — `safeai registry metadata set` for
  owner/environment stored in a decoupled `agent_metadata` table and shown in
  HTML reports.

**Workstream 2 — Code-Level Authority (CE 1.5)**
- **Tool ↔ Implementation Mapping** — correlates declared tools with their
  implementations; surfaces orphan states (`TOOL_ORPHAN_DECLARED`,
  `TOOL_ORPHAN_IMPLEMENTED`) with full file/line provenance.
- **Command-Aware MCP Resolution** — statically resolves local MCP server
  commands; labels output `assurance: resolved` vs `unresolved-command` vs
  `external-package`.
- **Target Taxonomy Engine** — aggregates external-network capabilities into
  destination buckets (Database, Object Storage, SaaS APIs, Cloud Services,
  Messaging).

**Workstream 3 — Detection Depth**
- **Prompt risk depth** — multi-line concatenation, cross-file interpolation,
  indirect injection via tool calls, XML/HTML tag injection, template variable
  injection in `.md` files.
- **Data leakage depth** — RSA/JWT/AWS keys, connection strings,
  base64/hex-encoded secrets with per-pattern severity differentiation.
- **Cross-component analysis** — directed skill→tool→workflow→MCP→model
  relationship graph with orphan detection and coupling analysis.

**Workstream 4 — Community & Onboarding**
- Expanded community scan targets from 5 to 25 AI tools.
- `safeai welcome` guided first-run experience.

### Exit Criterion

A reviewer can see, for any tool or MCP server, where it is declared and where
it is implemented, and SafeAI flags mismatches. Suppressions are provably valid
against the current code, and every finding carries its longitudinal history.

---

### What It Detects

| Category | Examples |
|----------|----------|
| Prompt Injection | User input in prompts, missing delimiters, system prompt leaks |
| Data Leakage | Hardcoded API keys, tokens, passwords (masked in all outputs) |
| Excessive Agency | Shell exec, filesystem access, HTTP, database, code exec, autonomous loops |
| MCP Misconfig | Missing auth, weak permissions, exposed endpoints, hardcoded secrets |
| Capability Escalation | Per-tool authority diffs between scans (14 `ESC_*` rules) |
| Dependency Correlation | Undeclared capabilities, orphaned tools (`DEP_*`) |
| Supply Chain | AI framework dependency detection |

### Supported Frameworks

LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents, Microsoft Agent,
Azure AI Foundry, Bedrock Agent, Claude Code, Google ADK, Mastra, Haystack,
LlamaIndex, Dify, n8n (15 adapters).

### Output Formats

- Terminal (human-readable)
- JSON (machine-readable)
- SARIF 2.1.0 (GitHub Advanced Security)
- HTML (self-contained interactive report)
- KYA manifest (`safeai-manifest.json`)
- PR comment (reviewer-facing escalation summary)
- Security Scorecard (Markdown / JSON)

### Links

- [Landing Page](https://safeai-analyzer.ikaruscareer.com)
- [Source Code](https://github.com/ikaruscareer/SafeAI)
- [Issue Tracker](https://github.com/ikaruscareer/SafeAI/issues)
- [Changelog](RELEASE_NOTES.md)

### Assets

- `safeai_static_analyzer-1.8.0-py3-none-any.whl`
- `safeai_static_analyzer-1.8.0.tar.gz`
