"""Tests for the CE 1.5 env-dependency inventory and capability correlation."""

import json
import os

from safeai.analysis.dependency_correlation import (
    RULE_ORPHAN,
    RULE_UNDECLARED,
    correlate_dependencies,
    family_of_capability,
    family_of_config,
)
from safeai.analyzers.env_dependency.analyzer import EnvDependencyAnalyzer
from safeai.cmd.cli import main

_RULES = [{"id": "ENV_DEP_INVENTORY", "severity": "info", "owasp_llm": "LLM02"}]


def _run(code, rules=_RULES, path="./app.py"):
    analyzer = EnvDependencyAnalyzer()
    return analyzer.run({path: code}, rules or [])


def test_detects_getenv_reference():
    findings = _run("import os\nk = os.getenv('DATABASE_URL')\n")
    inv = findings[0]["dep_inventory"]
    assert any(e["name"] == "DATABASE_URL" for e in inv)


def test_detects_os_environ_and_process_env():
    findings = _run(
        "import os\nx = os.environ['AWS_SECRET']\n"
        "// js\nconst t = process.env.OPENAI_API_KEY;\n"
    )
    inv = {e["name"] for e in findings[0]["dep_inventory"]}
    assert "AWS_SECRET" in inv
    assert "OPENAI_API_KEY" in inv


def test_flags_secret_names_only_never_values():
    # A value is present in the dotenv source line, but only the name may surface.
    findings = _run("DATABASE_URL=postgres://u:password123@host/db\n",
                    rules=[], path="./.env")
    raw = json.dumps(findings[0]["dep_inventory"])
    assert "password123" not in raw
    assert "DATABASE_URL" in raw


def test_flags_secret_backed_detectors():
    findings = _run(
        "import boto3\nx = boto3.client('secretsmanager').get_secret_value('prod/mysql')\n"
    )
    inv = findings[0]["dep_inventory"]
    assert any(e["name"] == "prod/mysql" and e["secret"] for e in inv)


def test_secret_by_name_keyword():
    findings = _run("import os\np = os.getenv('AWS_SECRET_ACCESS_KEY')\n")
    inv = findings[0]["dep_inventory"]
    assert any(e["name"] == "AWS_SECRET_ACCESS_KEY" and e["secret"] for e in inv)


def test_k8s_secret_ref():
    findings = _run("apiVersion: v1\nkind: Pod\nspec:\n  secretKeyRef: {name: db-creds}\n")
    inv = findings[0]["dep_inventory"]
    assert any(e["name"] == "db-creds" and e["secret"] for e in inv)


def test_family_of_config():
    assert family_of_config("DATABASE_URL") == "database"
    assert family_of_config("OPENAI_API_KEY") == "api"
    assert family_of_config("AWS_SECRET_ACCESS_KEY") == "cloud"
    assert family_of_config("DEBUG") is None


def test_family_matching_is_word_segment_based():
    # Short tokens must not match inside unrelated words (CE 1.5 review #2):
    # "jdbc" contains "db" and "rabbit_mq" contains "rabbit" but neither is a
    # segment-level match on the family axis.
    assert family_of_config("JDBC_URL") == "api"  # via url, not database
    assert family_of_config("MYJIRA_EMAIL") is None
    assert family_of_config("RABBIT_QUEUE") == "messaging"
    assert family_of_config("SLACK_TOKEN") == "messaging"
    # Provider families take precedence over the generic api suffix tokens so a
    # SLACK_TOKEN stays aligned with a declared slack capability.
    assert family_of_config("DATABASE_SSL") == "database"


def test_family_of_capability():
    assert family_of_capability("databases") == "database"
    assert family_of_capability("external_apis") == "api"
    assert family_of_capability("s3") == "cloud"


def test_correlate_undeclared_capability():
    report = {
        "findings": [{
            "rule_id": "ENV_DEP_INVENTORY",
            "dep_inventory": [
                {"name": "DATABASE_URL", "secret": False,
                 "sources": [{"file": "app.py", "line": 5}]},
            ],
        }],
        "tool_surface": [],
    }
    findings, summary = correlate_dependencies(report)
    assert any(f["rule_id"] == RULE_UNDECLARED for f in findings)
    assert summary["counts"]["undeclared"] == 1


def test_correlate_declared_capability_not_flagged():
    report = {
        "findings": [{
            "rule_id": "ENV_DEP_INVENTORY",
            "dep_inventory": [
                {"name": "OPENAI_API_KEY", "secret": True,
                 "sources": [{"file": "app.py", "line": 6}]},
            ],
        }],
        "tool_surface": [
            {"tool_key": "t:llm", "capabilities": [{"name": "external_apis"}]},
        ],
    }
    findings, _ = correlate_dependencies(report)
    assert not any(f["rule_id"] == RULE_UNDECLARED for f in findings)


def test_correlate_orphaned_tool():
    report = {
        "findings": [{
            "rule_id": "ENV_DEP_INVENTORY",
            "dep_inventory": [],
        }],
        "tool_surface": [
            {"tool_key": "t:s3", "capabilities": [{"name": "s3"}]},
        ],
    }
    findings, _ = correlate_dependencies(report)
    assert any(f["rule_id"] == RULE_ORPHAN for f in findings)


def test_cli_scan_includes_inventory():
    # End-to-end: a scan surfaces the inventory + correlation in the manifest.
    root = os.path.join(os.path.dirname(__file__), "fixtures", "ce15_project")
    if not os.path.isdir(root):
        import tempfile

        temp = tempfile.mkdtemp()
        with open(os.path.join(temp, "agent.py"), "w", encoding="utf-8") as fh:
            fh.write("import os\nk = os.getenv('DATABASE_URL')\n")
        root = temp
    manifest_path = os.path.join(root, "safeai-manifest.json")
    rc = main(["scan", root, "--manifest", manifest_path, "--no-registry",
               "--sarif", os.path.join(root, "out.sarif")])
    assert rc in (0, 1)
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert "dependency_inventory" in manifest
    assert isinstance(manifest["summary"]["dependency_count"], int)