"""Terminal (stdout) report writer.

Prints a human-readable summary of the scan including file count,
detected frameworks, MCP asset count, overall risk score, finding
severity counts, and a per-finding list.
"""


def print_summary(report):
    print("SafeAI Scan Summary")
    print("Files:", report["files_scanned"])
    if report.get("detected_frameworks"):
        print("Frameworks:", ", ".join(report["detected_frameworks"]))
    if report.get("mcp_assets") is not None:
        print("MCP assets:", len(report.get("mcp_assets", [])))
    if report.get("components") is not None:
        component_counts = {}
        for component in report.get("components", []):
            kind = component.get("type", "unknown")
            component_counts[kind] = component_counts.get(kind, 0) + 1
        print("Components:", ", ".join(f"{k}={v}" for k, v in sorted(component_counts.items())) or "none")
    if report.get("diagnostics"):
        print("Diagnostics:", len(report["diagnostics"]))
    if report.get("capability_diff"):
        diff = report["capability_diff"]["counts"]
        print("Capability diff:", f"+{diff['added']} / -{diff['removed']} / ~{diff['changed']}")
    if report.get("trust_score"):
        print("Overall AI Risk Score:", report["trust_score"].get("overall_ai_risk_score"))
    for k, v in report["counts"].items():
        print(f"{k}: {v}")
    print("Findings:")
    for f in report["findings"]:
        print(f"[{f['severity']}] {f['file']}:{f['line']} - {f['message']}")
