"""Tests for WS1: component content hashing, registry components CLI, and hash-based diff."""

import json
import os
import tempfile

# ---------------------------------------------------------------------------
# Component content hashing
# ---------------------------------------------------------------------------

class TestComponentContentHash:
    def test_hash_computed_for_python_file(self, tmp_path):
        from safeai.analysis.components import extract_components

        py = tmp_path / "agent.py"
        py.write_text("from langchain import tool\n\n@tool\ndef my_tool(): pass\n")
        files = [str(py)]
        file_cache = {str(py): py.read_text()}
        comps = extract_components(files, file_cache)
        assert len(comps) >= 1
        for c in comps:
            assert "content_hash" in c
            assert c["content_hash"] is not None
            assert len(c["content_hash"]) == 16

    def test_hash_computed_for_yaml_file(self, tmp_path):
        from safeai.analysis.components import extract_components

        yml = tmp_path / "workflow.yml"
        yml.write_text("name: test\nsteps:\n  - run: echo hello\n")
        files = [str(yml)]
        file_cache = {str(yml): yml.read_text()}
        comps = extract_components(files, file_cache)
        for c in comps:
            assert "content_hash" in c
            assert c["content_hash"] is not None

    def test_same_content_same_hash(self, tmp_path):
        from safeai.analysis.components import extract_components

        content = "system_prompt: You are helpful\nsteps:\n  - run: echo\n"
        py1 = tmp_path / "a.yml"
        py2 = tmp_path / "b.yml"
        py1.write_text(content)
        py2.write_text(content)
        files = [str(py1), str(py2)]
        file_cache = {str(py1): content, str(py2): content}
        comps = extract_components(files, file_cache)
        hashes = {c["content_hash"] for c in comps if c.get("content_hash")}
        assert len(hashes) >= 1
        assert len(hashes) == 1

    def test_different_content_different_hash(self, tmp_path):
        from safeai.analysis.components import extract_components

        py1 = tmp_path / "a.py"
        py2 = tmp_path / "b.py"
        py1.write_text("import os\n")
        py2.write_text("import sys\n")
        files = [str(py1), str(py2)]
        file_cache = {str(py1): py1.read_text(), str(py2): py2.read_text()}
        comps = extract_components(files, file_cache)
        hashes = [c["content_hash"] for c in comps if c.get("content_hash")]
        if len(hashes) >= 2:
            assert hashes[0] != hashes[1]

    def test_empty_content_returns_none(self):
        from safeai.analysis.components import _component_content_hash

        assert _component_content_hash("") is None
        assert _component_content_hash(None) is None

    def test_hash_deterministic(self, tmp_path):
        from safeai.analysis.components import _component_content_hash

        content = "x = 42\n"
        h1 = _component_content_hash(content)
        h2 = _component_content_hash(content)
        assert h1 == h2


# ---------------------------------------------------------------------------
# Registry components CLI
# ---------------------------------------------------------------------------

class TestRegistryComponentsCLI:
    def _make_registry(self, tmp_path):
        """Create a minimal registry with components."""
        from safeai.kya.registry.connection import init_registry

        db = str(tmp_path / "registry.db")
        conn, _ = init_registry(db)
        now = "2026-01-01T00:00:00Z"

        conn.execute(
            "INSERT INTO projects(project_id, name, source_root, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("p1", "test", "/tmp", now, now),
        )
        conn.execute(
            "INSERT INTO scans(scan_id, project_id, completed_at, files_scanned, "
            "manifest_json, manifest_hash, agent_count, finding_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("scan1", "p1", now, 10, "{}", "abc", 1, 0),
        )
        conn.execute(
            "INSERT INTO agents(agent_id, project_id, name, agent_type, framework, primary_path, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("agent1", "p1", "test-agent", "workflow", "langgraph", "/tmp/a.py", now, now),
        )
        conn.execute(
            "INSERT INTO agent_snapshots(agent_id, scan_id, snapshot_json, capability_count, finding_count, confidence) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("agent1", "scan1", "{}", 3, 0, "high"),
        )
        conn.execute(
            "INSERT INTO component_snapshots("
            "scan_id, component_type, component_subtype, name, file_path, "
            "source, line, data_json, first_seen_scan, last_seen_scan, content_hash"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("scan1", "mcp", "config_file", "my-mcp", "/tmp/mcp.json", "config_keys", 1,
             "{}", "scan1", "scan1", "abc123def456"),
        )
        conn.commit()
        conn.close()
        return db

    def test_components_list(self, tmp_path):
        from safeai.cmd.registry_cli import cmd_components

        db = self._make_registry(tmp_path)

        class Args:
            registry_path = db
            component_type = None
            agents = False
            format = "json"

        args = Args()
        # Capture stdout
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ret = cmd_components(args)
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout

        assert ret == 0
        data = json.loads(output)
        assert "components" in data
        assert len(data["components"]) == 1
        comp = data["components"][0]
        assert comp["type"] == "mcp"
        assert comp["name"] == "my-mcp"
        assert comp["content_hash"] == "abc123def456"

    def test_components_filter_by_type(self, tmp_path):
        from safeai.cmd.registry_cli import cmd_components

        db = self._make_registry(tmp_path)

        class Args:
            registry_path = db
            component_type = "skill"  # No skills in registry
            agents = False
            format = "json"

        args = Args()
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ret = cmd_components(args)
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout

        assert ret == 0
        data = json.loads(output)
        assert data["components"] == []

    def test_components_with_agents_flag(self, tmp_path):
        from safeai.cmd.registry_cli import cmd_components

        db = self._make_registry(tmp_path)

        class Args:
            registry_path = db
            component_type = None
            agents = True
            format = "json"

        args = Args()
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ret = cmd_components(args)
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout

        assert ret == 0
        data = json.loads(output)
        assert len(data["components"]) == 1
        comp = data["components"][0]
        assert "agents" in comp
        # agent1 co-occurred with scan1, so should be listed
        assert len(comp["agents"]) == 1
        assert comp["agents"][0]["agent_id"] == "agent1"

    def test_components_empty_registry(self, tmp_path):
        from safeai.cmd.registry_cli import cmd_components
        from safeai.kya.registry.connection import init_registry

        db = str(tmp_path / "empty.db")
        conn, _ = init_registry(db)
        conn.close()

        class Args:
            registry_path = db
            component_type = None
            agents = False
            format = "json"

        args = Args()
        import io
        import sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            ret = cmd_components(args)
        finally:
            output = sys.stdout.getvalue()
            sys.stdout = old_stdout

        assert ret == 0
        data = json.loads(output)
        assert data["components"] == []


# ---------------------------------------------------------------------------
# Hash-based component diff
# ---------------------------------------------------------------------------

class TestHashBasedComponentDiff:
    def test_changed_when_hash_differs(self):
        from safeai.analysis.component_diff import _has_changed

        prev = {"type": "mcp", "name": "a", "content_hash": "aaa"}
        curr = {"type": "mcp", "name": "a", "content_hash": "bbb"}
        assert _has_changed(prev, curr) is True

    def test_unchanged_when_hash_matches(self):
        from safeai.analysis.component_diff import _has_changed

        prev = {"type": "mcp", "name": "a", "content_hash": "aaa"}
        curr = {"type": "mcp", "name": "a", "content_hash": "aaa"}
        assert _has_changed(prev, curr) is False

    def test_falls_back_to_data_when_no_hash(self):
        from safeai.analysis.component_diff import _has_changed

        prev = {"type": "mcp", "name": "a", "data": {"key": 1}}
        curr = {"type": "mcp", "name": "a", "data": {"key": 2}}
        assert _has_changed(prev, curr) is True

    def test_falls_back_unchanged_when_no_hash(self):
        from safeai.analysis.component_diff import _has_changed

        prev = {"type": "mcp", "name": "a", "data": {"key": 1}}
        curr = {"type": "mcp", "name": "a", "data": {"key": 1}}
        assert _has_changed(prev, curr) is False

    def test_fallback_name_change(self):
        from safeai.analysis.component_diff import _has_changed

        prev = {"type": "mcp", "name": "old", "data": {}}
        curr = {"type": "mcp", "name": "new", "data": {}}
        assert _has_changed(prev, curr) is True


# ---------------------------------------------------------------------------
# list_components_deduped query
# ---------------------------------------------------------------------------

class TestListComponentsDeduped:
    def test_dedupes_by_type_and_path(self):
        from safeai.kya.registry.connection import init_registry
        from safeai.kya.registry.queries import list_components_deduped

        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "test.db")
            conn, _ = init_registry(db)
            now = "2026-01-01T00:00:00Z"
            conn.execute(
                "INSERT INTO projects(project_id, name, source_root, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("p1", "t", "/tmp", now, now),
            )
            # Two scans with the same component
            for scan_id in ("s1", "s2"):
                conn.execute(
                    "INSERT INTO scans(scan_id, project_id, completed_at, files_scanned, "
                    "manifest_json, manifest_hash, agent_count, finding_count) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, "p1", now, 5, "{}", "h", 0, 0),
                )
                conn.execute(
                    "INSERT INTO component_snapshots("
                    "scan_id, component_type, component_subtype, name, file_path, "
                    "source, line, data_json, first_seen_scan, last_seen_scan, content_hash"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, "mcp", "cfg", "srv", "/x.json", "f", 1, "{}", "s1", scan_id, "h1"),
                )
            conn.commit()

            result = list_components_deduped(conn, component_type="mcp")
            assert len(result) == 1
            assert result[0]["scan_count"] == 2
            conn.close()

    def test_filter_by_type(self):
        from safeai.kya.registry.connection import init_registry
        from safeai.kya.registry.queries import list_components_deduped

        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "test.db")
            conn, _ = init_registry(db)
            now = "2026-01-01T00:00:00Z"
            conn.execute(
                "INSERT INTO projects(project_id, name, source_root, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                ("p1", "t", "/tmp", now, now),
            )
            conn.execute(
                "INSERT INTO scans(scan_id, project_id, completed_at, files_scanned, "
                "manifest_json, manifest_hash, agent_count, finding_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("s1", "p1", now, 5, "{}", "h", 0, 0),
            )
            conn.execute(
                "INSERT INTO component_snapshots("
                "scan_id, component_type, component_subtype, name, file_path, "
                "source, line, data_json, first_seen_scan, last_seen_scan, content_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("s1", "mcp", "cfg", "srv", "/x.json", "f", 1, "{}", "s1", "s1", "h1"),
            )
            conn.execute(
                "INSERT INTO component_snapshots("
                "scan_id, component_type, component_subtype, name, file_path, "
                "source, line, data_json, first_seen_scan, last_seen_scan, content_hash"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("s1", "skill", "f", "sk", "/y.py", "f", 1, "{}", "s1", "s1", "h2"),
            )
            conn.commit()

            result = list_components_deduped(conn, component_type="skill")
            assert len(result) == 1
            assert result[0]["component_type"] == "skill"
            conn.close()
