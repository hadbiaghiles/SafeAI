# SafeAI Community Scans Disclosure Policy

## Philosophy

SafeAI scan results are automated static-analysis observations, not proof of exploitability and not a substitute for a maintainer-led security review. All findings require human validation before any public claim.

## Public Report Criteria

A finding may be included in a public summary only if ALL of the following hold:

1. The finding has clear static evidence in the source code.
2. A safe public explanation can be formulated without revealing secrets or private data.
3. The classification is `high_confidence_security_concern` or `review_recommended`.
4. The finding does not involve secrets, tokens, API keys, or personal data.

## Private Maintainer Notifications

Maintainer notifications are generated privately and contain:

- Repository name and commit SHA
- SafeAI version and scan timestamp
- Rule ID and finding location (file, line number)
- Safe evidence excerpt (redacted of secrets)
- Why the finding may matter
- Confidence level (`high`, `medium`, `review`)
- Recommended remediation
- Link to the project's security policy
- Explicit statement that this is an automated static-analysis result requiring validation

## No Automatic Publication

- No automatic posting to Reddit
- No automatic creation of GitHub Issues or PRs in target repositories
- No automatic fork creation
- No automatic publishing of public reports

## Maintainer Feedback Loop

- Maintainers can request report corrections or removal
- All removal requests require human validation
- Feedback is tracked in the SafeAI repository
- Corrections are applied and versions are bumped

## Reddit Publication Guidance

Reddit posts are generated as Markdown drafts at `reports/public/<target-id>-reddit-draft.md`. A human reviewer must:

1. Read the draft for accuracy and safety
2. Validate that no secrets or sensitive data are included
3. Approve the post for publication
4. Manually publish to Reddit (outside GitHub Actions)

## Requesting Correction or Removal

To request a report correction or removal:

1. Open an issue in the SafeAI repository
2. Reference the target ID and report
3. Provide justification (e.g., false positive, sensitive data exposed)
4. Await human reviewer validation
5. Report will be updated or removed per validation outcome