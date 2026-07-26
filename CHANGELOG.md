# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
