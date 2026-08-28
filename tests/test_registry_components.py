"""Tests for the ``safeai registry components`` command."""

import json

from safeai.cmd.cli import main
from safeai.kya.registry import init_registry


def _component_registry(tmp_path):
    registry = str(tmp_path / "registry.db")
    conn, _ = init_registry(registry)
    conn.execute(
        "INSERT INTO projects(project_id, name, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("project-1", "demo", "2026-01-01", "2026-01-02"),
    )
    for scan_id, completed_at in (("scan-1", "2026-01-01"), ("scan-2", "2026-01-02")):
        conn.execute(
            "INSERT INTO scans(scan_id, project_id, completed_at, manifest_json, manifest_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, "project-1", completed_at, "{}", scan_id),
        )
    conn.execute(
        "INSERT INTO agents(agent_id, project_id, name, framework, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("agent-1", "project-1", "Demo agent", "langgraph", "2026-01-01", "2026-01-02"),
    )
    conn.execute(
        "INSERT INTO agent_snapshots(agent_id, scan_id, snapshot_json) VALUES (?, ?, ?)",
        ("agent-1", "scan-2", "{}"),
    )
    components = [
        ("scan-1", "skill", "summarize", "skills/summarize.md", "scan-1", "scan-1"),
        ("scan-2", "skill", "summarize", "skills/summarize.md", "scan-1", "scan-2"),
        ("scan-2", "prompt", "review", "prompts/review.md", "scan-2", "scan-2"),
    ]
    conn.executemany(
        "INSERT INTO component_snapshots("
        "scan_id, component_type, name, file_path, first_seen_scan, last_seen_scan"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        components,
    )
    conn.commit()
    conn.close()
    return registry


def test_registry_components_groups_latest_snapshots(tmp_path, capsys):
    registry = _component_registry(tmp_path)

    assert main(["registry", "components", "--registry", registry]) == 0

    output = capsys.readouterr().out
    assert "Known components (2)" in output
    assert "[prompt]" in output and "[skill]" in output
    assert "scan-1" in output and "scan-2" in output


def test_registry_components_filters_by_type(tmp_path, capsys):
    registry = _component_registry(tmp_path)

    assert (
        main(
            [
                "registry",
                "components",
                "--registry",
                registry,
                "--type",
                "prompt",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "review" in output
    assert "summarize" not in output


def test_registry_components_shows_consuming_agents(tmp_path, capsys):
    registry = _component_registry(tmp_path)

    assert (
        main(
            [
                "registry",
                "components",
                "--registry",
                registry,
                "--agents",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "AGENTS" in output
    assert "agent-1" in output


def test_registry_components_json_output(tmp_path, capsys):
    registry = _component_registry(tmp_path)

    assert (
        main(
            [
                "registry",
                "components",
                "--registry",
                registry,
                "--agents",
                "--json",
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert len(payload["components"]) == 2
    summarize = next(
        item for item in payload["components"] if item["name"] == "summarize"
    )
    assert summarize["last_seen_scan"] == "scan-2"
    assert summarize["agents"][0]["agent_id"] == "agent-1"
