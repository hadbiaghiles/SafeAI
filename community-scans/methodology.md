# SafeAI Community Scans Methodology

## Scan Scope

Each target repository is scanned using SafeAI Static Analyzer in read-only mode. The scanner examines source code for:

- Capability overexposure (tool usage, agent patterns)
- Risk indicators (hardcoded secrets, insecure endpoints)
- Policy violations (framework-specific capability limits)
- Sarif-compatible findings with locations and severity

## Execution Environment

- GitHub Actions runner with `contents: read` and `security-events: write` permissions
- Pinned commit SHA resolution before checkout
- Shallow checkout where safe
- Python 3.11+ environment with SafeAI installed from the local source

## Findings Classification

Findings are classified into these categories (not solely based on SafeAI severity):

| Classification | Description |
|---|---|
| `high_confidence_security_concern` | Clear static evidence with safe public explanation |
| `review_recommended` | Findings requiring runtime validation or context-dependent |
| `potentially_sensitive` | Involves secrets, personal data, private endpoints |
| `not_publishable` | Cannot be safely published in any form |

## Sanitisation Pipeline

1. Private SafeAI report is loaded
2. All secret values, tokens, API keys, and personal data are redacted
3. Finding locations are generalized (file paths relative to repo root)
4. Exploit chains are described at a high level only
5. Public summary is generated with aggregate counts and main themes
6. Reddit draft is generated for human review
7. Maintainer notification draft is generated privately

## Report Classifications

- **`informational`**: General observations, not security concerns
- **`review_recommended`**: Requires maintainer review
- **`high_confidence_security_concern`**: Clear static evidence
- **`potentially_sensitive`**: May contain sensitive data
- **`not_publishable`**: Cannot be safely published

## Limitations

- Static analysis only; runtime behavior not assessed
- Findings require maintainer validation
- Not a complete security audit or proof of exploitability
- False positives are possible
- Context-dependent findings remain `review_recommended`

## Output Artifacts Per Target

```
reports/raw/<target-id>.sarif          # Raw SARIF output
reports/raw/<target-id>.json           # Raw JSON report
reports/raw/<target-id>.md             # Raw Markdown scorecard
reports/manifests/<target-id>.json     # Provenance manifest
reports/public/<target-id>-reddit-draft.md  # Reddit draft (human review)
reports/private/<target-id>-maintainer-notification.md  # Maintainer notification
```