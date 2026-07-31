"""Registry export: produce a portable project inventory document.

The export contains project metadata, current agent records, current
posture, latest scan references, and optionally scan history. It never
contains raw source code or unredacted secret values.
"""

import json

from safeai.kya import STATIC_ANALYSIS_DISCLAIMER
from safeai.kya.registry import (
    agent_history,
    get_agent,
    get_scan_findings,
    latest_scan_id,
    list_agents,
    list_projects,
)
from safeai.kya.util import utc_now_iso

EXPORT_SCHEMA_VERSION = "1.0"


def export_inventory(conn, *, project_id=None, include_history=False, include_suppressed=False):
    """Build the export document from an open registry connection."""
    projects = list_projects(conn)
    if project_id:
        projects = [p for p in projects if p["project_id"] == project_id]

    export_projects = []
    for project in projects:
        pid = project["project_id"]
        agents = []
        for agent_row in list_agents(conn, pid):
            record = get_agent(conn, agent_row["agent_id"])
            if not record:
                continue
            snapshot = record.get("snapshot") or {}
            entry = {
                "agent_id": record["agent_id"],
                "name": record.get("name"),
                "agent_type": record.get("agent_type"),
                "framework": record.get("framework"),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen"),
                "source_locations": snapshot.get("source_locations") or [],
                "capabilities": snapshot.get("capabilities") or [],
                "tools": snapshot.get("tools") or [],
                "confidence": snapshot.get("confidence"),
                "latest_scan": record.get("scan"),
                "findings": [
                    f for f in (record.get("findings") or [])
                    if include_suppressed or f.get("status") != "suppressed"
                ],
            }
            if include_history:
                entry["history"] = agent_history(conn, record["agent_id"])
            agents.append(entry)

        latest = latest_scan_id(conn, pid)
        latest_findings = get_scan_findings(conn, latest) if latest else []
        if not include_suppressed:
            latest_findings = [f for f in latest_findings if f.get("status") != "suppressed"]

        export_projects.append({
            "project_id": pid,
            "name": project.get("name"),
            "source_root": project.get("source_root"),
            "agents": agents,
            "latest_scan_id": latest,
            "latest_findings": latest_findings,
        })

    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "export_type": "safeai.kya.inventory",
        "generated_at": utc_now_iso(),
        "projects": export_projects,
        "limitations": [STATIC_ANALYSIS_DISCLAIMER],
    }


def write_export(document, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
