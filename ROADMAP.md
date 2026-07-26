# SafeAI — Roadmap

SafeAI is a **Static AI Capability & Risk Analyzer** — think SonarQube for AI agents and workflows.

This document describes the planned roadmap across five phases. Phases are not strictly sequential; work may proceed in parallel where dependencies allow.

---

## Phase 1 — Static AI Risk Scanner (OSS)

*Current state — Phase 1 scope substantially complete; Phase 1.5 stabilization and community-driven depth improvements ongoing.*

**Static analyzers implemented:**

| Analyzer | Coverage | Status |
|----------|----------|--------|
| **Capabilities** | Shell, filesystem, HTTP, database, code execution, Docker, K8s, Redis, S3, Slack, Jira, browser automation, GCP | ✅ |
| **Prompts** | Injection patterns, delimiter issues, system leaks, role overrides, untrusted placeholders | ✅ |
| **Tools** | Agent-bound tool definitions, missing validation, dangerous params, shell access, excessive permissions | ✅ |
| **Memory** | Checkpointer and memory object usage (framework parsers) | ✅ |
| **Workflows** | Composition, approval gaps, insecure defaults, capability sprawl | ✅ |
| **Identities** | Credential and secret exposure (hardcoded secrets, env references) | ✅ |
| **Models** | LLM provider references, unsafe temperature, missing content filters, disabled safety | ✅ |
| **Autonomy** | Loop detection, unbounded execution | ✅ |
| **MCP** | Schema validation (v1.0/v1.1), auth gaps, exposed endpoints, tool misuse, sensitive resources, insecure transports | ✅ |

**Outputs implemented:** JSON, HTML, SARIF 2.1.0, capability graph (project_graph), trust score, capability diff (`--baseline`)

**Still planned in Phase 1:**

- **Governance signals** — timeout, retry policy, approval workflow, audit logging, rate limiting detection
- **Heuristic data flows** — deeper untrusted input propagation into prompts
- **PR capability escalation diff** — automatically compare a PR branch's capabilities against the base branch, flagging newly introduced shell, network, filesystem, or write access. Building on the existing `--baseline` diff.
- **Governed finding suppressions** — every suppression carries rule_id, file, location, reason, owner, and expiry. CI fails when code moves or waiver expires. Stale-detection for forgotten suppressions.
- **Better terminal output** — structured, readable scan summary with severity grouping, improved layout, and clearer signal-to-noise ratio
- **Trust score improvements** — weighted scoring giving higher impact to critical and high-severity findings

---

## Phase 1.5 — AI Component Security (Stabilization)

*Partially complete — deep component analysis shipped in v1.1.0-beta; continued refinements.*

**Artifact analysis implemented:**

| Artifact | Analysis Focus | Status |
|----------|---------------|--------|
| **Skills** | Embedded prompts, excessive permissions, risky capabilities, insecure defaults, hardcoded secrets | ✅ |
| **Prompts** | Injection resistance, system prompt exposure, role isolation, untrusted input | ✅ |
| **MCP servers** | Auth gaps, endpoint exposure, tool misuse, sensitive resources, insecure transports | ✅ |
| **Workflow templates** | Insecure defaults, capability sprawl, approval gaps, missing validation | ✅ |
| **Tool definitions** | Overly broad permissions, missing validation, shell access, dangerous params | ✅ |
| **Model configurations** | Unsafe parameters, content filter enforcement (provider-aware), disabled safety | ✅ |

**Framework adapters (15 total):**

| Tier | Frameworks |
|------|-----------|
| Earliest (v1.0) | LangGraph, CrewAI, LangChain, Semantic Kernel, OpenAI Agents SDK, Microsoft Agent, Azure AI Foundry, Bedrock Agent |
| Phase 1.5 | Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, n8n |

**Eight new capability detectors:** Docker, Kubernetes, Redis, S3, Slack, Jira, browser automation, GCP

**Still planned in Phase 1.5:**

| Item | Status |
|------|--------|
| AutoGen framework adapter | Not yet implemented |
| LangGraph conditional edge detection | Partially implemented — `add_edge` detected; `add_conditional_edges` not handled |
| Governance detectors (timeout, retry, audit, rate limiting) | Not yet implemented |
| Teams, SharePoint, OneDrive detection (MCP-based) | Deferred — requires MCP asset analysis expansion |
| Split browser automation into separate rules (Playwright, Selenium, browser_use) | Under consideration |

---

## Phase 2 — AI Security Testing (optional future)

Runtime and dynamic analysis capabilities:

- Runtime sandbox for safe execution of agent workflows
- Hallucination and jailbreak testing
- Prompt injection resilience testing
- Goal hijacking detection
- Tool misuse detection
- Data exfiltration monitoring
- Reliability and consistency testing

---

## Phase 3 — Test Packs

Curated test suites for compliance and security validation:

| Pack | Coverage |
|------|----------|
| OWASP LLM | OWASP Top 10 for LLM Applications |
| Agent Security | Agent-specific threat patterns |
| MCP Security | Model Context Protocol misconfiguration |
| RAG Security | Retrieval-Augmented Generation risks |
| Healthcare | HIPAA, patient data handling |
| Finance | PCI, transaction security |
| GDPR | Data protection, consent, right-to-deletion |
| Custom | Organization-specific rule packs |

---

## Phase 4 — Enterprise (Commercial)

Scalability and management capabilities for enterprise adoption:

- Fleet-wide scanning across repositories and projects
- Central policy management with role-based access control
- Trend analysis and risk dashboards over time
- Enterprise integrations (Azure DevOps, GitLab, Jenkins, etc.)
- Reporting dashboards with executive summaries

---

## Phase 5 — Community Intelligence

Community-powered threat intelligence:

- Reputation services for MCP servers, tools, and prompts
- Known malicious prompts, skills, and MCP servers database
- Community-shared detection rules
- AI vulnerability database (curated from public sources)
- Public risk intelligence feeds

---

## Philosophy

SafeAI is intentionally:

- **Lightweight** — no external services, no runtime, no LLM calls
- **Environment agnostic** — works in any CI/CD pipeline, on any OS
- **CI/CD friendly** — SARIF output, exit codes, GitHub Actions ready
- **Plugin based** — frameworks, analyzers, and rules are all pluggable
- **Community driven** — built by and for the AI security community

The product is consistently described as a **Static AI Capability & Risk Analyzer** — emphasizing that it analyzes *capabilities* (what an agent *can do*) and *risk* (what could go wrong) entirely through static analysis, without executing code or calling external services.
