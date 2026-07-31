"""Tests for `safeai registry` CLI commands and export."""

import json
import os

from safeai.cmd.cli import main


def _two_scans(kya_project, tmp_path):
    main([
        "scan",
        kya_project["root"],
        "--registry",
        kya_project["registry"],
        "--sarif",
        os.path.join(tmp_path, "r.sarif"),
    ])
    kya_project["write_version"](kya_project["v2"])
    main([
        "scan",
        kya_project["root"],
        "--registry",
        kya_project["registry"],
        "--sarif",
        os.path.join(tmp_path, "r.sarif"),
    ])


def _agent_id(registry_path):
    from safeai.kya.registry import connect, list_agents
    conn = connect(registry_path)
    try:
        return list_agents(conn)[0]["agent_id"]
    finally:
        conn.close()


def test_registry_list_table_and_json(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]

    assert main(["registry", "list", "--registry", reg]) == 0
    out = capsys.readouterr().out
    assert "AGENT ID" in out and "langgraph" in out

    assert main(["registry", "list", "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agents"]
    assert "disclaimer" in payload


def test_registry_show(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)

    assert main(["registry", "show", agent_id, "--registry", reg]) == 0
    out = capsys.readouterr().out
    assert "Capabilities" in out
    assert "static analysis evidence" in out

    assert main(["registry", "show", agent_id, "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agent_id"] == agent_id
    assert payload["snapshot"]["source_locations"]

    assert main(["registry", "show", "nonexistent", "--registry", reg]) == 2


def test_registry_history(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    capsys.readouterr()  # discard scan output before capturing JSON

    assert main(["registry", "history", agent_id, "--registry", reg, "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["history"]) == 2
    assert payload["history"][0]["scan_id"]


def test_registry_diff(kya_project, tmp_path, capsys):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    capsys.readouterr()  # discard scan output before capturing JSON

    rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest",
               "--registry", reg, "--format", "json"])
    assert rc == 1  # documented: 1 when risk-relevant changes exist
    payload = json.loads(capsys.readouterr().out)
    assert payload["from_scan"] != payload["to_scan"]
    assert "capabilities" in payload and "findings" in payload


def test_registry_diff_identical(kya_project, tmp_path):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    reg = kya_project["registry"]
    agent_id = _agent_id(reg)
    rc = main(["registry", "diff", agent_id, "--from", "previous", "--to", "latest", "--registry", reg])
    assert rc == 0  # no changes


def test_registry_export(kya_project, tmp_path):
    _two_scans(kya_project, tmp_path)
    reg = kya_project["registry"]
    out_path = os.path.join(str(tmp_path), "inventory.json")

    rc = main(["registry", "export", "--registry", reg, "--format", "json",
               "--output", out_path, "--include-history"])
    assert rc == 0
    with open(out_path) as fh:
        document = json.load(fh)
    assert document["export_type"] == "safeai.kya.inventory"
    assert document["schema_version"] == "1.0"
    project = document["projects"][0]
    assert project["agents"]
    assert project["agents"][0]["history"]
    assert project["latest_findings"]
    assert "limitations" in document

    with open(out_path, encoding="utf-8") as fh:
        raw = fh.read()
    assert "sk-1234567890abcdefghij" not in raw


def test_registry_export_excludes_suppressed_by_default(kya_project, tmp_path):
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])
    reg = kya_project["registry"]

    from safeai.kya.registry import connect, get_scan_findings, latest_scan_id
    conn = connect(reg)
    findings = get_scan_findings(conn, latest_scan_id(conn))
    fp = findings[0]["fingerprint"]
    conn.close()

    safeai_dir = os.path.join(kya_project["root"], ".safeai")
    with open(os.path.join(safeai_dir, "suppressions.yml"), "w") as fh:
        fh.write(f"""
suppressions:
  - fingerprint: "{fp}"
    reason: "test suppression"
    owner: "team"
    created: "2026-01-01"
""")
    main(["scan", kya_project["root"], "--registry", kya_project["registry"],
          "--sarif", os.path.join(tmp_path, "r.sarif")])

    out_default = os.path.join(str(tmp_path), "inv_default.json")
    out_with = os.path.join(str(tmp_path), "inv_with.json")
    main(["registry", "export", "--registry", reg, "--format", "json", "--output", out_default])
    main(["registry", "export", "--registry", reg, "--format", "json", "--output", out_with,
          "--include-suppressed"])

    with open(out_default) as fh:
        default_doc = json.load(fh)
    with open(out_with) as fh:
        with_doc = json.load(fh)
    default_fps = {f["fingerprint"] for f in default_doc["projects"][0]["latest_findings"]}
    with_fps = {f["fingerprint"] for f in with_doc["projects"][0]["latest_findings"]}
    assert fp not in default_fps
    assert fp in with_fps


def test_registry_missing_error(kya_project, tmp_path, capsys):
    missing = os.path.join(str(tmp_path), "nope", "registry.db")
    rc = main(["registry", "list", "--registry", missing])
    assert rc == 2
    assert "Registry not found" in capsys.readouterr().err


def test_registry_diff_is_agent_scoped(tmp_path, capsys):
    root = tmp_path / "multi"
    root.mkdir()
    (root / "agent_a.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "\n"
        "def run_a(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        "    return graph\n",
        encoding="utf-8",
    )
    (root / "agent_b.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "\n"
        "def run_b(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    return graph\n",
        encoding="utf-8",
    )

    sarif = os.path.join(tmp_path, "r.sarif")
    reg = os.path.join(str(root), ".safeai", "registry.db")
    main(["scan", str(root), "--registry", reg, "--sarif", sarif])

    # Change only agent_a file between scans.
    (root / "agent_a.py").write_text(
        "from langgraph.graph import StateGraph\n"
        "import subprocess\n"
        "import requests\n"
        "\n"
        "def run_a(user_input):\n"
        "    graph = StateGraph(dict)\n"
        "    subprocess.run(user_input, shell=True)\n"
        '    requests.get("https://example.com")\n'
        "    return graph\n",
        encoding="utf-8",
    )
    main(["scan", str(root), "--registry", reg, "--sarif", sarif])

    capsys.readouterr()
    main(["registry", "list", "--registry", reg, "--format", "json"])
    listing = json.loads(capsys.readouterr().out)

    # Resolve the agent tied to agent_b.py.
    agent_a = next(a for a in listing["agents"] if a.get("primary_path") == "agent_a.py")
    agent_b = next(a for a in listing["agents"] if a.get("primary_path") == "agent_b.py")

    # Risk in registry list must be agent-scoped, not project-wide.
    assert agent_a["risk_score"] is not None
    assert agent_b["risk_score"] is not None
    assert agent_a["risk_score"] > agent_b["risk_score"]

    capsys.readouterr()
    rc = main([
        "registry",
        "diff",
        agent_b["agent_id"],
        "--from",
        "previous",
        "--to",
        "latest",
        "--registry",
        reg,
        "--format",
        "json",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["findings"]["new"] == []
    assert payload["findings"]["resolved"] == []
