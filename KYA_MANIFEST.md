# SafeAI KYA Manifest — `safeai-manifest.json` (Schema v1.0)

The KYA manifest is SafeAI's **canonical portable artifact** for scan-derived
"Know Your Agent" evidence. It is the public contract consumed by the local
registry, JSON output, capability/agent comparison, and future integrations.

> The SQLite registry schema is an implementation detail. Integrations should
> consume this manifest, not the database.

## Guarantees

- **Offline** — generated without any network, API, or LLM call.
- **Source-private** — contains no raw source code and no unredacted secrets.
- **Deterministic** — same repository, configuration, ruleset, and commit
  produce an equivalent manifest (except `generated_at`, `scan.scan_id`, and
  scan timestamps, which identify the event, not the artifact).
- **Versioned** — `schema_version` follows semver semantics for the document
  contract. `1.x` consumers can read any `1.y` manifest; unknown optional
  fields must be ignored.

## Top-Level Structure

```json
{
  "schema_version": "1.0",
  "manifest_type": "safeai.kya",
  "generated_at": "2026-07-31T12:00:00Z",
  "safeai": {
    "version": "1.3.0b0",
    "ruleset_version": "sha256:abc123...",
    "config_hash": "sha256-of-normalized-effective-config"
  },
  "project": {
    "project_id": "git-0123abcd...-ef45",
    "name": "my-agent-app",
    "source_root": ".",
    "repository": {
      "remote_fingerprint": "sha256-of-normalized-remote-or-null",
      "commit_sha": "optional",
      "branch": "optional",
      "tag": "optional"
    }
  },
  "scan": {
    "scan_id": "uuid-per-run",
    "started_at": "ISO-8601 UTC",
    "completed_at": "ISO-8601 UTC",
    "files_scanned": 12,
    "analysis_coverage": {
      "languages": ["python"],
      "frameworks_detected": ["langgraph"],
      "limitations": ["..."]
    }
  },
  "agents": [],
  "components": [],
  "findings": [],
  "summary": {
    "risk_score": 92,
    "severity_counts": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1},
    "capability_counts": {"Shell": 1},
    "agent_count": 1,
    "component_count": 0,
    "policy_decision": {"outcome": "warn", "reasons": ["..."], "matches": []}
  },
  "limitations": [
    "SafeAI results are static analysis evidence and do not verify deployed runtime permissions, identities, or behavior."
  ]
}
```

## Agent Records

Each agent/workflow discovered in source or configuration:

| Field | Description |
|---|---|
| `agent_id` | Deterministic ID: `sha256(project_id, framework, name, primary path, type)` |
| `name` | Discovered or derived human-readable name |
| `agent_type` | `agent` \| `workflow` \| `application` \| `unknown` |
| `framework` | e.g. `langgraph`, `crewai` |
| `source_locations` | Project-relative `{path, line_start, line_end}` list |
| `first_seen` | Managed by the registry (scan time when new) |
| `capabilities` | `[{name, category}]` detected in source/configuration |
| `tools` | Discovered tool names |
| `resources`, `mcp_assets`, `autonomy_signals`, `governance_evidence`, `authority_evidence` | Evidence lists (may be empty) |
| `confidence` | `high` \| `medium` \| `low` |
| `provenance` | Which parser/discovery method produced the record |

Renaming or moving the primary source file creates a **new** agent identity.
Aliasing/migration is deferred to a future release.

## Finding Records

| Field | Description |
|---|---|
| `finding_id` / `fingerprint` | Deterministic SHA-256 (see below) |
| `rule_id` | Stable rule identifier (e.g. `CAP_shell`, `DATA_LEAKAGE`) |
| `severity` | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `title`, `message`, `remediation` | Human-readable, actionable text |
| `confidence` | `high` \| `medium` \| `low` |
| `provenance` | `{analyzer, heuristic, evidence[]}` — evidence is redacted |
| `location` | `{path, line_start, line_end}` — project-relative |
| `status` | `new` \| `existing` \| `regressed` \| `resolved` \| `suppressed` \| `unknown` |

## Fingerprint Algorithm

```
fingerprint = SHA-256(
    UPPER(rule_id)      + "\n" +
    relative_path       + "\n" +   # forward slashes
    line_number         + "\n" +
    normalized_evidence            # whitespace-collapsed, secret-redacted (full mask)
).hexdigest()
```

Fingerprints never depend on timestamps, absolute paths, scan IDs, or
ordering. Whitespace-only formatting changes and secret rotation do not
change a fingerprint; a material change to rule, location, or matched
evidence does.

## Redaction & Privacy

- Secret values are masked (`sk-1***MASKED***`) before any evidence is
  written to the manifest, SARIF, exports, or the registry.
- `repository.remote_fingerprint` is a one-way hash — the raw remote URL
  (which may embed credentials or private hostnames) is never stored.
- No raw file contents, environment values, or credentials are included.

## Example (fictional, safe values)

```json
{
  "schema_version": "1.0",
  "manifest_type": "safeai.kya",
  "generated_at": "2026-07-31T12:00:00Z",
  "safeai": {"version": "1.3.0b0", "ruleset_version": "sha256:1111", "config_hash": "2222"},
  "project": {"project_id": "local-00000000-0000-4000-8000-000000000000", "name": "demo", "source_root": ".", "repository": {}},
  "scan": {"scan_id": "33333333-3333-4333-8333-333333333333", "started_at": "2026-07-31T11:59:59Z", "completed_at": "2026-07-31T12:00:00Z", "files_scanned": 1, "analysis_coverage": {"languages": ["python"], "frameworks_detected": ["langgraph"], "limitations": []}},
  "agents": [{
    "agent_id": "researcher-0123456789ab",
    "name": "researcher",
    "agent_type": "agent",
    "framework": "langgraph",
    "source_locations": [{"path": "agent.py", "line_start": 1, "line_end": 1}],
    "first_seen": "2026-07-31T12:00:00Z",
    "capabilities": [{"name": "shell_execution", "category": "Shell"}],
    "tools": [],
    "resources": [],
    "mcp_assets": [],
    "autonomy_signals": [],
    "governance_evidence": [],
    "authority_evidence": [],
    "confidence": "high",
    "provenance": [{"framework": "langgraph", "discovery_method": "ast", "note": "detected in source/configuration (static evidence)"}]
  }],
  "components": [],
  "findings": [{
    "finding_id": "aaaa...",
    "rule_id": "CAP_subprocess_shell",
    "severity": "critical",
    "title": "subprocess invoked with shell=True",
    "message": "subprocess invoked with shell=True",
    "remediation": "Avoid shell=True; pass argument arrays and validate every interpolated value.",
    "confidence": "medium",
    "provenance": {"analyzer": "capability", "heuristic": true, "evidence": ["subprocess.run(user_input, shell=True)"]},
    "location": {"path": "agent.py", "line_start": 8, "line_end": 8},
    "fingerprint": "aaaa...",
    "status": "new"
  }],
  "summary": {
    "risk_score": 90,
    "severity_counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    "capability_counts": {"Shell": 1},
    "agent_count": 1,
    "component_count": 0,
    "policy_decision": {"outcome": "warn", "reasons": ["No policy file supplied; default posture 'warn'."], "matches": []}
  },
  "limitations": ["SafeAI results are static analysis evidence and do not verify deployed runtime permissions, identities, or behavior."]
}
```
