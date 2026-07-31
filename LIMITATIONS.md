# SafeAI Limitations

SafeAI is a **static** analyzer. Understanding what static analysis can and
cannot tell you is essential to using its results responsibly.

## What static analysis cannot prove

- **Runtime permissions** — code that *can* call a shell is not proof a
  deployed agent *did* or *will be allowed to*.
- **Live identity** — SafeAI does not verify which identity an agent assumes
  in production, nor effective IAM/RBAC permissions.
- **Executed behavior** — no tool calls are executed, no models are invoked,
  no MCP servers are probed.
- **Data classification** — detected flows are pattern-based; SafeAI does not
  inspect actual data at rest or in transit.
- **Model behavior** — hallucination, jailbreak resistance, and output safety
  are out of scope (use evaluation/red-teaming tools).
- **Deployment configuration** — containers, gateways, and environment
  overrides are only visible where expressed in scanned source/config.
- **Policy enforcement** — a SafeAI policy outcome describes whether static
  evidence matched local policy rules. It is **not** a compliance claim and
  never means "this application is safe".

## Coverage caveats

- **Dynamic language patterns** — agents constructed via factories, dynamic
  imports, decorators, metaprogramming, or custom wrappers may reduce
  discovery coverage.
- **Framework maturity varies** — see `FRAMEWORK_SUPPORT.md`. Early-preview
  adapters have lower detection confidence than LangGraph/CrewAI/LangChain.
- **Regex fallback** — capability findings produced by regex fallback are
  heuristic and may include false positives; they carry lower confidence and
  are marked as heuristic in finding provenance.

## Confidence levels

| Level | Meaning |
|---|---|
| `high` | AST/semantic resolution with strong evidence |
| `medium` | Structured config or partial semantic evidence |
| `low` | Regex/heuristic fallback only |

Confidence reflects *evidence quality for the detection*, not the
probability that a risk is real.

## False positives / false negatives

- Prefer suppression with a documented reason over deleting findings (see
  `.safeai/suppressions.yml` in `USER_GUIDE.md`).
- Report suspected false negatives with a minimal reproducing fixture —
  they directly improve parser maturity.

## The right mental model

SafeAI answers: **"What does the source and configuration say this agent
system can do, and where are the risky patterns?"**

It does not answer: "What is this agent doing in production right now?"
For that, pair SafeAI with runtime governance tools such as the Microsoft
Agent Governance Toolkit.
