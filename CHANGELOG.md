# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0-beta] - 2026-07-31

### Added — KYA Baseline & Local Registry

- **Canonical KYA manifest** (`safeai-manifest.json`, schema v1.0): the
  portable public contract for scan-derived agent evidence, written via
  `--manifest`. See `KYA_MANIFEST.md`.
- **Local SQLite KYA registry** at `.safeai/registry.db`, created/updated
  automatically on interactive scans (auto-disabled when `CI` is set).
  Historical snapshots are append-only. See `REGISTRY.md`.
- **`safeai registry` command group**: `list`, `show`, `history`, `diff`,
  `export` with `--registry PATH` and `--format table|json`.
- **Deterministic finding fingerprints** (documented SHA-256 algorithm),
  stable `finding_id`s, confidence labels (`high|medium|low`), provenance
  records, and remediation defaults for high-value rules.
- **Baseline comparison** (`--baseline`): classifies findings as
  new/existing/resolved; accepts manifests or legacy JSON reports.
- **`--fail-on-new`**: opt-in gating on new/regressed findings only.
  Existing `--fail-on` semantics are unchanged without it.
- **Suppression workflow** (`.safeai/suppressions.yml`): required
  reason/owner/created, optional expiry and path scope; expired entries
  warn; suppressed findings stay visible and are excluded from gating.
- **Minimal policy-as-code** (`.safeai/policy.yml`): `allow|warn|
  require_review|deny` with rule/severity/capability/framework/agent/path/
  MCP-posture selectors; deterministic evaluation; outcome in terminal,
  manifest, HTML, and JSON. `deny` fails the scan.
- New scan flags: `--manifest`, `--registry`, `--no-registry`,
  `--strict-registry`, `--policy`, `--suppressions`, `--fail-on-new`.
- Terminal/HTML/SARIF output: KYA section, registry status, policy
  outcome, baseline counters, SARIF `partialFingerprints` and rule help
  text.
- Docs: `KYA_MANIFEST.md`, `REGISTRY.md`, `LIMITATIONS.md`; maturity
  categories in `FRAMEWORK_SUPPORT.md`; README/USER_GUIDE KYA sections.
- 66 new tests covering manifest determinism, fingerprints, baseline,
  suppressions, policy, registry persistence/queries/CLI, redaction, and
  CI behavior.

### Changed

- Scan engine skips `.safeai/` and SafeAI-generated artifacts (manifests,
  JSON reports) to prevent findings feedback loops. The JSON report now
  carries a `report_type: safeai.scan` marker (additive).
- JSON report findings gain additive keys (`fingerprint`, `finding_id`,
  `status`, `confidence_label`, `provenance`); no keys removed or retyped.
- `--baseline` still feeds legacy capability diff when given a legacy JSON
  report, and now also drives fingerprint comparison.
- Version bumped to `1.3.0b0` (`safeai/__init__.py` now matches
  `pyproject.toml`).

### Backward compatibility

- Existing CLI usage, exit codes, and JSON/HTML/SARIF shapes are preserved;
  all schema changes are additive. The manifest is a new artifact, versioned
  independently (`schema_version: 1.0`).
- Registry write failures never fail a scan unless `--strict-registry` is
  passed (exit code 2).

## [1.2.0] - 2026-07-26

### Added
- Eight new capability detectors (contributed by @yugaaank):
  - Docker (`CAP_docker`): `import docker`, `DockerClient`, `containers.run`
  - Kubernetes (`CAP_kubernetes`): `import kubernetes`, `kubectl`, `kube_config`, `k8s`
  - Redis (`CAP_redis`): `import redis`, `Redis()`, `StrictRedis`
  - S3 / Cloud Storage (`CAP_s3`): `import boto3`, `boto3.client('s3')`
  - Slack (`CAP_slack`): `import slack`, `slack_sdk`, `SlackClient`
  - Jira (`CAP_jira`): `import jira`, `JIRA()`, `jira.Client`
  - Browser Automation (`CAP_browser`): `playwright`, `selenium`, `webdriver`, `browser_use`
  - Google Cloud (`CAP_gcp`): `google.cloud`, `BigQuery`, `gcsfs`
- New capability categories: `Container` and `Collaboration`
- 20 tests in `tests/test_capability_detection.py` covering detection, false positives, multi-capability, and deduplication

### Changed
- `safeai/analysis/capabilities.py`: added `container` and `collaboration` categories
- `safeai/analyzers/capability/analyzer.py`: 8 new `CAP_PATTERNS`, `RULE_BY_CAP`, and `CATEGORY_BY_CAP` entries
- `safeai/rules/base_rules.yaml`: 8 new capability rules

## [1.1.0-beta] - 2026-07-24

### Added
- AI Component Security: skill, prompt file, tool definition, model config, and workflow template analysis
- Deep MCP analysis: per-tool broad permissions, sensitive resource detection, insecure transport detection
- Seven early-preview framework adapters: Claude Code, Google ADK, Mastra, Haystack, LlamaIndex, Dify, n8n (15 total)
- Capability diff (`--baseline` flag) comparing current scan against a previous JSON report
- Parser registry with `@register_parser` decorator and `safeai.parsers` entry-point group for third-party plugins
- Diagnostics reporting in scan output

### Changed
- Component and integration paths are relativized to scan root in all report formats
- Provider-aware model safety checks (`MODEL_MISSING_CONTENT_FILTER` scoped to Google/Bedrock/Azure)
- Dify and n8n detection tightened to reduce false positives
- Guard against `IndexError` in parser arg extraction

### Security
- Masked credential values in findings evidence across all report formats

## [1.0.0-beta] - 2026-07-18

### Added
- Multi-framework scanning: LangGraph, CrewAI, LangChain, Semantic Kernel,
  OpenAI Agents SDK, Microsoft Agent Framework, Azure AI Foundry, Bedrock Agent
- Prompt injection detection (LLM01): input interpolation, missing delimiters,
  system prompt leakage, role override attempts
- Capability analysis (LLM06): shell, filesystem, HTTP, database, code
  execution, autonomous loops, `subprocess` with `shell=True`, file writes
- Data leakage detection (LLM02): hardcoded API keys, tokens, passwords,
  environment secret references
- MCP analysis: config discovery, schema validation (v1.0/v1.1), missing auth,
  weak auth, missing permissions, exposed endpoints, hardcoded secrets
- Deterministic trust scoring across 7 risk categories (0–100)
- Reports: terminal, JSON, SARIF 2.1.0, HTML
- Custom YAML rules via `--rules`
- CI/CD exit codes via `--fail-on`
- GitHub Actions workflow with self-scan SARIF dogfooding
- Installable package with `safeai` console script and `python -m safeai`

### Security
- Credential values in findings evidence are masked in all report formats
- Scans exclude VCS directories, dependency caches, and oversized files
