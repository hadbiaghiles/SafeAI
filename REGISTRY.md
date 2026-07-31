# SafeAI Local KYA Registry

The KYA registry is a **private, local, SQLite** store of scan-derived agent
records and evidence. It is created and updated automatically by
`safeai scan` — no server, no account, no network call, no source upload.

> Everything in the registry is **static analysis evidence**: things detected
> in source/configuration. It never reflects deployed runtime state,
> effective IAM permissions, live identities, or runtime behavior.

## Location & Lifecycle

- Default path: `<scan-root>/.safeai/registry.db`
- First scan creates `.safeai/` and initializes the database (a one-line
  message is printed). Existing databases are never destroyed.
- Every subsequent scan **appends** a new snapshot — history is never
  overwritten.
- Add `.safeai/registry.db` to your `.gitignore` (SafeAI prints a hint on
  first initialization; it never edits your `.gitignore` for you).

### CI behavior

When the `CI` environment variable is set, registry persistence is
**auto-disabled** so CI jobs don't write local state into checkouts.
Options:

```bash
safeai scan . --no-registry                          # explicit ephemeral scan
safeai scan . --registry "$RUNNER_TEMP/registry.db"  # persist to workspace/artifact storage
```

`--registry PATH` always overrides both the default location and CI
auto-disable. A scan still succeeds and produces reports if persistence
fails (a warning is printed); use `--strict-registry` to fail instead
(exit code 2).

## Commands

```bash
safeai registry list                          # known agents/workflows
safeai registry show <agent-id>               # latest KYA record
safeai registry show <agent-id> --scan <id>   # historical record
safeai registry history <agent-id>            # all scans for an agent
safeai registry diff <agent-id> --from previous --to latest
safeai registry export --format json --output inventory.json
```

All commands accept `--registry PATH` and `--format table|json`.
`diff` exit codes: `0` = no risk-relevant change, `1` = capability/finding
changes exist, `2` = usage/registry error.

### `registry diff` reports

- Added/removed capabilities and tools
- New / resolved / regressed findings
- Confidence changes

### `registry export`

Produces a versioned (`schema_version: 1.0`) inventory document containing
project metadata, current agent records, current posture, latest scan
references, and optionally history (`--include-history`) and suppressed
findings (`--include-suppressed`, excluded by default).

## What is stored

- Project metadata (ID, name, sanitized source root, remote fingerprint)
- Scan metadata (IDs, timestamps, tool/ruleset/config versions, commit)
- Full canonical manifest + its SHA-256 hash
- Agent snapshots, capabilities, tools
- Findings with fingerprints, statuses, redacted evidence
- Policy decisions and matched policies

## What is never stored

- Raw source file contents
- Credentials, API keys, tokens, or unredacted secret values
- Telemetry of any kind
- Runtime activity data

## Schema & migrations

The schema is versioned via the `schema_migrations` table. Migrations are
additive and applied automatically on open. Current version: **1**.

Tables: `schema_migrations`, `projects`, `scans`, `agents`,
`agent_snapshots`, `findings`, `scan_findings`, `policy_decisions`,
`policy_matches`, `metadata`. Indexes cover project, agent ID, scan ID,
finding fingerprint, and scan timestamp. WAL journal mode is enabled for
safe local CLI concurrency.

## Backup

The registry is a single SQLite file (plus `-wal`/`-shm` sidecars while
open). To back up, close any running scans and copy the file, or use
`safeai registry export` for a portable JSON inventory.

## Limitations

Agent identity derives from project, framework, discovered name, primary
source path, and type. Renaming or moving the primary source file creates
a new agent identity; aliasing/migration is future work.
