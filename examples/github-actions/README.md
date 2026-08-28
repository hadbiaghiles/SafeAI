# GitHub Actions example

This directory is a small, synthetic LangGraph-style agent used by the
workflow at `.github/workflows/safeai-example.yml`. The workflow runs SafeAI
on every push or pull request that changes this example and stores the SARIF
report as a downloadable artifact.

The fixture is intentionally deterministic and has no credentials, network
calls, shell commands, or private data. SafeAI analyzes the source statically;
the workflow never executes the agent.

## Reuse in another repository

1. Copy `agent.py` and this directory's README into the target repository.
2. Copy `.github/workflows/safeai-example.yml` into the target repository.
3. Change the `path` input if the fixture lives somewhere else.
4. Review the `safeai-results.sarif` artifact after each run.

The workflow uses `contents: read` and does not require secrets. A clean scan
is evidence for human review, not proof that an application is secure,
compliant, or production-ready.
