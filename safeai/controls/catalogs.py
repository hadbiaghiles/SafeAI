"""Control catalogs for OWASP LLM, OWASP Agentic, and NIST AI RMF.

Each catalog is a dict mapping control IDs to structured entries with
framework, family, title, and description. The catalogs are designed for
taxonomy-only use — filtering, grouping, and policy selection — never as
compliance or coverage claims.

References:
- OWASP Top 10 for LLM Applications (2025): https://owasp.org/www-project-top-10-for-large-language-model-applications/
- OWASP Top 10 for Agentic Applications (2025): https://owasp.org/www-project-top-10-for-agentic-applications/
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1): https://www.nist.gov/itl/ai-risk-management-framework
"""

OWASP_LLM_VERSION = "2025"
OWASP_AGENTIC_VERSION = "2025"
NIST_AI_RMF_VERSION = "1.0"

# OWASP Top 10 for LLM Applications (2025)
OWASP_LLM = {
    "LLM01": {
        "framework": "owasp_llm",
        "id": "LLM01",
        "family": "Prompt Injection",
        "title": "Prompt Injection",
        "description": "Untrusted input manipulates LLM behavior through crafted prompts.",
    },
    "LLM02": {
        "framework": "owasp_llm",
        "id": "LLM02",
        "family": "Sensitive Information Disclosure",
        "title": "Sensitive Information Disclosure",
        "description": "LLM reveals confidential data through inference or extraction.",
    },
    "LLM03": {
        "framework": "owasp_llm",
        "id": "LLM03",
        "family": "Supply Chain Vulnerabilities",
        "title": "Supply Chain Vulnerabilities",
        "description": "Compromised training data, models, or plugins affect LLM behavior.",
    },
    "LLM04": {
        "framework": "owasp_llm",
        "id": "LLM04",
        "family": "Data and Model Poisoning",
        "title": "Data and Model Poisoning",
        "description": "Training or fine-tuning data is manipulated to alter LLM behavior.",
    },
    "LLM05": {
        "framework": "owasp_llm",
        "id": "LLM05",
        "family": "Improper Output Handling",
        "title": "Improper Output Handling",
        "description": "LLM output is used without proper validation or sanitization.",
    },
    "LLM06": {
        "framework": "owasp_llm",
        "id": "LLM06",
        "family": "Excessive Agency",
        "title": "Excessive Agency",
        "description": "LLM is granted excessive permissions or capabilities beyond necessity.",
    },
    "LLM07": {
        "framework": "owasp_llm",
        "id": "LLM07",
        "family": "System Prompt Leakage",
        "title": "System Prompt Leakage",
        "description": "System prompt or configuration is exposed to unauthorized parties.",
    },
    "LLM08": {
        "framework": "owasp_llm",
        "id": "LLM08",
        "family": "Vector and Embedding Weaknesses",
        "title": "Vector and Embedding Weaknesses",
        "description": "RAG or embedding systems are vulnerable to manipulation.",
    },
    "LLM09": {
        "framework": "owasp_llm",
        "id": "LLM09",
        "family": "Misinformation",
        "title": "Misinformation",
        "description": "LLM generates false or misleading information with high confidence.",
    },
    "LLM10": {
        "framework": "owasp_llm",
        "id": "LLM10",
        "family": "Unbounded Consumption",
        "title": "Unbounded Consumption",
        "description": "LLM resources are consumed without limits, causing denial of service.",
    },
}

# OWASP Top 10 for Agentic Applications (2025)
OWASP_AGENTIC = {
    "AGENTIC01": {
        "framework": "owasp_agentic",
        "id": "AGENTIC01",
        "family": "Agentic Prompt Injection",
        "title": "Agentic Prompt Injection",
        "description": "Multi-step prompt injection targeting agent orchestration loops.",
    },
    "AGENTIC02": {
        "framework": "owasp_agentic",
        "id": "AGENTIC02",
        "family": "Tool Misuse",
        "title": "Tool Misuse",
        "description": "Agent tools are invoked with unexpected or harmful parameters.",
    },
    "AGENTIC03": {
        "framework": "owasp_agentic",
        "id": "AGENTIC03",
        "family": "Privilege Escalation",
        "title": "Privilege Escalation",
        "description": "Agent gains unauthorized access through tool chain exploitation.",
    },
    "AGENTIC04": {
        "framework": "owasp_agentic",
        "id": "AGENTIC04",
        "family": "Autonomous Goal Drift",
        "title": "Autonomous Goal Drift",
        "description": "Agent pursues goals that deviate from original intent through self-modification.",
    },
    "AGENTIC05": {
        "framework": "owasp_agentic",
        "id": "AGENTIC05",
        "family": "Inadequate Human Oversight",
        "title": "Inadequate Human Oversight",
        "description": "Agent operates without sufficient human review or approval gates.",
    },
    "AGENTIC06": {
        "framework": "owasp_agentic",
        "id": "AGENTIC06",
        "family": "Agent Communication Manipulation",
        "title": "Agent Communication Manipulation",
        "description": "Inter-agent messages are intercepted, forged, or manipulated.",
    },
    "AGENTIC07": {
        "framework": "owasp_agentic",
        "id": "AGENTIC07",
        "family": "Data Exfiltration via Agents",
        "title": "Data Exfiltration via Agents",
        "description": "Agent pipelines leak data through tool calls or external APIs.",
    },
    "AGENTIC08": {
        "framework": "owasp_agentic",
        "id": "AGENTIC08",
        "family": "Resource Exhaustion",
        "title": "Resource Exhaustion",
        "description": "Agent consumes excessive compute, memory, or API quotas.",
    },
    "AGENTIC09": {
        "framework": "owasp_agentic",
        "id": "AGENTIC09",
        "family": "Inconsistent State Management",
        "title": "Inconsistent State Management",
        "description": "Agent state is corrupted or lost during multi-step operations.",
    },
    "AGENTIC10": {
        "framework": "owasp_agentic",
        "id": "AGENTIC10",
        "family": "Insufficient Audit Trail",
        "title": "Insufficient Audit Trail",
        "description": "Agent actions lack adequate logging for investigation.",
    },
}

# NIST AI Risk Management Framework 1.0 (NIST AI 100-1)
NIST_AI_RMF = {
    "MAP_1": {
        "framework": "nist_ai_rmf",
        "id": "MAP_1",
        "family": "Govern",
        "title": "AI Risk Management Strategy",
        "description": "Organization defines AI risk management strategy and objectives.",
    },
    "MAP_2": {
        "framework": "nist_ai_rmf",
        "id": "MAP_2",
        "family": "Govern",
        "title": "Roles and Responsibilities",
        "description": "Organization assigns roles and responsibilities for AI risk management.",
    },
    "MAP_3": {
        "framework": "nist_ai_rmf",
        "id": "MAP_3",
        "family": "Govern",
        "title": "Risk Culture",
        "description": "Organization promotes a culture of AI risk awareness.",
    },
    "MAP_4": {
        "framework": "nist_ai_rmf",
        "id": "MAP_4",
        "family": "Map",
        "title": "Context",
        "description": "Organization maps the context in which AI systems operate.",
    },
    "MAP_5": {
        "framework": "nist_ai_rmf",
        "id": "MAP_5",
        "family": "Map",
        "title": "Stakeholder Impact",
        "description": "Organization identifies and assesses stakeholder impacts.",
    },
    "MAP_6": {
        "framework": "nist_ai_rmf",
        "id": "MAP_6",
        "family": "Map",
        "title": "Benefits and Risks",
        "description": "Organization documents AI benefits and risks.",
    },
    "MEASURE_1": {
        "framework": "nist_ai_rmf",
        "id": "MEASURE_1",
        "family": "Measure",
        "title": "Risk Assessment",
        "description": "Organization assesses AI risks using identified methods.",
    },
    "MEASURE_2": {
        "framework": "nist_ai_rmf",
        "id": "MEASURE_2",
        "family": "Measure",
        "title": "Risk Tracking",
        "description": "Organization tracks identified AI risks over time.",
    },
    "MEASURE_3": {
        "framework": "nist_ai_rmf",
        "id": "MEASURE_3",
        "family": "Measure",
        "title": "Risk Communication",
        "description": "Organization communicates AI risk information to stakeholders.",
    },
    "MANAGE_1": {
        "framework": "nist_ai_rmf",
        "id": "MANAGE_1",
        "family": "Manage",
        "title": "Risk Response",
        "description": "Organization responds to identified AI risks.",
    },
    "MANAGE_2": {
        "framework": "nist_ai_rmf",
        "id": "MANAGE_2",
        "family": "Manage",
        "title": "Risk Treatment",
        "description": "Organization treats AI risks through mitigation strategies.",
    },
    "MANAGE_3": {
        "framework": "nist_ai_rmf",
        "id": "MANAGE_3",
        "family": "Manage",
        "title": "Recovery",
        "description": "Organization has recovery plans for AI system failures.",
    },
    "GOVERN_1": {
        "framework": "nist_ai_rmf",
        "id": "GOVERN_1",
        "family": "Govern",
        "title": "AI Governance",
        "description": "Organization establishes AI governance structures.",
    },
    "GOVERN_2": {
        "framework": "nist_ai_rmf",
        "id": "GOVERN_2",
        "family": "Govern",
        "title": "Policies and Procedures",
        "description": "Organization documents AI policies and procedures.",
    },
    "GOVERN_3": {
        "framework": "nist_ai_rmf",
        "id": "GOVERN_3",
        "family": "Govern",
        "title": "Oversight",
        "description": "Organization provides oversight of AI systems.",
    },
}

# Combined catalog lookup
ALL_CATALOGS = {**OWASP_LLM, **OWASP_AGENTIC, **NIST_AI_RMF}

# Framework summaries
FRAMEWORKS = {
    "owasp_llm": {
        "name": "OWASP Top 10 for LLM Applications",
        "version": "2025",
        "controls": OWASP_LLM,
    },
    "owasp_agentic": {
        "name": "OWASP Top 10 for Agentic Applications",
        "version": "2025",
        "controls": OWASP_AGENTIC,
    },
    "nist_ai_rmf": {
        "name": "NIST AI Risk Management Framework 1.0",
        "version": "1.0",
        "controls": NIST_AI_RMF,
    },
}


def get_control(framework, control_id):
    """Get a control entry by framework and ID."""
    catalog = {
        "owasp_llm": OWASP_LLM,
        "owasp_agentic": OWASP_AGENTIC,
        "nist_ai_rmf": NIST_AI_RMF,
    }.get(framework)
    if catalog:
        return catalog.get(control_id)
    return ALL_CATALOGS.get(control_id)


def list_frameworks():
    """List all available control frameworks."""
    return [
        {"id": fid, "name": f["name"], "version": f["version"], "control_count": len(f["controls"])}
        for fid, f in FRAMEWORKS.items()
    ]
