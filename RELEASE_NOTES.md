# SafeAI — Release Notes

## v1.5.0 (2026-08-11)

First **stable** release (`5 - Production/Stable`). In addition to the CE 1.5
environment dependency inventory work, this release makes SafeAI consumable
as a GitHub Actions **Marketplace action**.

### Major Additions

- **GitHub Actions Marketplace action** (`action.yml` composite action):
  - Inputs: `path`, `version`, `fail-on`, `sarif`, `rules`, `baseline`,
    `fail-on-new`, `fail-on-escalation`, `no-registry`, `extra-args`.
  - Output: `sarif-path`.
  - Installs `SafeAI-Static-Analyzer` from PyPI and runs `python -m safeai
    scan` on the repository; native exit codes are preserved.
  - Inputs are passed as environment variables to a pure-Python driver
    (`scripts/safeai-action.py`) and forwarded as an argv list — nothing is
    ever evaluated by a shell. Least-privilege (`contents: read` only).
  - SARIF is written even when a scan fails, so `if: always()` upload steps
    still produce code-scanning alerts. `no-registry: true` is the default to
    keep scans ephemeral.
- **Self-validating CI** (`.github/workflows/action-test.yml`): exercises the
  action itself against fixture repositories, builds/installs the wheel, and
  validates SARIF on every commit. 24 new tests in `tests/test_github_action.py`.
- **Environment and credential dependency inventory** with
  dependency-to-capability correlation (`DEP_UNDECLARED_CAPABILITY`,
  `DEP_ORPHANED_TOOL`).

### Fixed

- Packaging: version → `1.5.0`, classifier → `5 - Production/Stable`;
  `_safeai_version()` resolves through `SafeAI-Static-Analyzer` metadata;
  wheel package-data verified (`safeai/rules/base_rules.yaml`).

### Usage

```yaml
- uses: ikaruscareer/SafeAI@v1.0.0
  with:
    path: .
    fail-on: critical
```

### Verification Snapshot

- Full test suite passing (373 tests, 1 skip).
- Lint passing (`ruff check safeai/ tests/ scripts/`).
- Wheel and source distribution build successfully.
- End-to-end published-style install validated (build → venv install → scan →
  SARIF + exit-code checks) for both a clean fixture (exit 0) and a risky
  fixture (exit 1, SARIF preserved).

## v1.3.0-beta (2026-07-31)

Release 1.3 introduces **KYA (Know Your Agent)** baseline and local registry
capabilities while preserving SafeAI's offline-first static-analysis model.

### Major Additions

- **Canonical manifest**: `safeai-manifest.json` (`schema_version: "1.0"`,
  `manifest_type: "safeai.kya"`) as the portable contract.
- **Deterministic finding identity**: stable `finding_id`/`fingerprint`
  generation, confidence labels (`high|medium|low`), provenance, and
  remediation normalization.
- **Baseline diffing**: `--baseline` and `--fail-on-new` for PR-focused
  gating (new/regressed findings only).
- **Suppressions**: `.safeai/suppressions.yml` with required reason/owner/
  created date, optional expiry and path scope.
- **Policy-as-code**: `.safeai/policy.yml` with actions `allow`, `warn`,
  `require_review`, `deny` and deterministic evaluation.
- **Local SQLite registry**: `.safeai/registry.db` with append-only scan
  history and agent snapshots.
- **Registry CLI**:
  - `safeai registry list`
  - `safeai registry show <agent-id>`
  - `safeai registry history <agent-id>`
  - `safeai registry diff <agent-id> --from previous --to latest`
  - `safeai registry export --format json --output <path>`

### New Scan Flags

- `--manifest`
- `--baseline`
- `--fail-on-new`
- `--registry`
- `--no-registry`
- `--strict-registry`
- `--policy`
- `--suppressions`

### Behavior and Compatibility Notes

- Existing `--fail-on` behavior is preserved unless `--fail-on-new` is
  explicitly used.
- Registry persistence is local-only and enabled by default for interactive
  scans; it is auto-disabled when `CI` is detected unless `--registry` is
  explicitly provided.
- Report schema changes are additive.

### Verification Snapshot

- Full test suite passing (141 tests)
- Lint checks passing (`ruff check safeai/ tests/`)
- End-to-end CLI flows validated for scan, manifest, baseline, suppressions,
  policy, registry, and export.

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
