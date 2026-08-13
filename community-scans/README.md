# SafeAI Community Scans Programme

## Purpose

This programme conducts static security and capability scans of publicly available AI-agent frameworks and tools using the SafeAI Static Analyzer. The goal is to produce research artifacts that help maintainers understand potential risks and guide responsible disclosure.

## Scope

Currently scanning five prominent frameworks:

1. **n8n** (`n8n-io/n8n`) - TypeScript workflow and agent platform
2. **LangChain** (`langchain-ai/langchain`) - Python LLM application framework
3. **CrewAI** (`crewAIInc/crewAI`) - Python multi-agent framework
4. **LlamaIndex** (`run-llama/llama_index`) - Python RAG and agent framework
5. **LangGraph** (`langchain-ai/langgraph`) - Python stateful agent orchestration

## Selection Rationale

These five projects were selected based on current public GitHub popularity rankings (presenc.ai AI-Agent Framework Github Rankings 2026) and represent diverse architectures: Python libraries, TypeScript tooling, graph orchestration, multi-agent systems, and workflow automation. Popularity rankings are dynamic; this is a starting selection, not a permanent ranking.

## Static-Analysis Only

All scans are read-only static analysis. No target code is executed, no dependencies are installed, no Dockerfiles are run, and no target workflows are triggered. Results require maintainer validation and do not constitute confirmed vulnerabilities.

## How to Reproduce a Scan

```bash
# From the SafeAI repository root
python -m safeai.cmd.cli /path/to/repo --scorecard --scorecard-json --no-registry
```

Artifacts are generated in `reports/` directories.

## Artifact Retention

- Private artifacts (raw reports, manifests, maintainer notifications): retained per GitHub Actions retention policy
- Public summaries: retained for review and Reddit draft generation
- No automatic publishing to Reddit or third-party platforms

## Feedback and Corrections

Maintainers can request report corrections or removal via the SafeAI issue tracker. All removals require human validation.