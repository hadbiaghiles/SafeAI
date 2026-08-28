"""Control mappings — maps SafeAI rule IDs to control framework entries.

Provides a structured mapping layer between SafeAI's internal rule taxonomy
and external control frameworks (OWASP LLM, OWASP Agentic, NIST AI RMF).

This is a taxonomy-only layer — never a compliance or coverage claim.
"""

from safeai.controls.catalogs import ALL_CATALOGS, FRAMEWORKS

# Rule-to-control mapping table.
# Each entry maps a SafeAI rule_id to a list of (framework, control_id) pairs.
RULE_MAPPINGS = {
    # Prompt injection
    "PROMPT_INJECTION": [
        ("owasp_llm", "LLM01"),
        ("owasp_agentic", "AGENTIC01"),
        ("nist_ai_rmf", "GOVERN_1"),
    ],
    # Capability detection
    "CAP_shell": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_code_exec": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_http": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_filesystem": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_db": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_docker": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_kubernetes": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "CAP_redis": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_s3": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "CAP_slack": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    "CAP_jira": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    "CAP_browser": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "CAP_gcp": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Data leakage
    "DATA_private_key": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_aws_key": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_connection_string": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    "DATA_jwt": [
        ("owasp_llm", "LLM02"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Governance signals
    "GOV_TIMEOUT_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_RETRY_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    "GOV_APPROVAL_MISSING": [
        ("owasp_agentic", "AGENTIC05"),
        ("nist_ai_rmf", "GOVERN_3"),
    ],
    "GOV_AUDIT_MISSING": [
        ("owasp_agentic", "AGENTIC10"),
        ("nist_ai_rmf", "GOVERN_2"),
    ],
    "GOV_RATE_LIMIT_MISSING": [
        ("owasp_agentic", "AGENTIC08"),
        ("nist_ai_rmf", "MANAGE_1"),
    ],
    # Environment dependencies
    "ENV_DEP_INVENTORY": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC07"),
    ],
    # Component analysis
    "SKILL_RISKY_TOOL": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC02"),
    ],
    "SKILL_IMPLICIT_DEPENDENCY": [
        ("owasp_llm", "LLM03"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    "TOOL_ORPHAN_DECLARED": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    "TOOL_ORPHAN_IMPLEMENTED": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC09"),
    ],
    # MCP analysis
    "MCP_UNTRUSTED_CONFIG": [
        ("owasp_llm", "LLM03"),
        ("owasp_agentic", "AGENTIC06"),
    ],
    # Escalation detections
    "ESC_NEW_CAPABILITY": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
    ],
    "ESC_SEVERITY_INCREASE": [
        ("owasp_llm", "LLM06"),
        ("owasp_agentic", "AGENTIC03"),
        ("nist_ai_rmf", "MEASURE_2"),
    ],
    "ESC_RECURRING_RISK": [
        ("owasp_llm", "LLM09"),
        ("nist_ai_rmf", "MANAGE_2"),
    ],
}


def map_rule_to_controls(rule_id, severity=None):
    """Map a SafeAI rule ID to its control framework entries.

    Args:
        rule_id: The SafeAI rule ID (e.g., "PROMPT_INJECTION")
        severity: Optional severity for context (not used in mapping)

    Returns:
        List of dicts with keys: framework, control_id, family, title, description
    """
    mappings = RULE_MAPPINGS.get(rule_id, [])
    results = []
    seen = set()

    for framework, control_id in mappings:
        key = (framework, control_id)
        if key in seen:
            continue
        seen.add(key)

        control = ALL_CATALOGS.get(control_id)
        if control:
            results.append({
                "framework": framework,
                "control_id": control_id,
                "family": control["family"],
                "title": control["title"],
                "description": control["description"],
            })

    return results


def map_findings_to_controls(findings):
    """Enrich a list of findings with control mapping metadata.

    Adds a ``control_mappings`` key to each finding with the mapped controls.
    """
    for finding in findings:
        rule_id = finding.get("rule_id", "")
        severity = finding.get("severity")
        finding["control_mappings"] = map_rule_to_controls(rule_id, severity)

    return findings


def get_framework_summary():
    """Get a summary of available control frameworks."""
    return [
        {
            "id": fid,
            "name": f["name"],
            "version": f["version"],
            "control_count": len(f["controls"]),
        }
        for fid, f in FRAMEWORKS.items()
    ]
