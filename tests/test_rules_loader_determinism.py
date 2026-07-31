"""Rule loading determinism tests."""

from safeai.rules.loader import load_rules


def test_custom_rule_files_loaded_in_lexical_order(tmp_path):
    custom = tmp_path / "rules"
    custom.mkdir()

    # Intentionally create in reverse lexical order.
    (custom / "z_second.yml").write_text(
        "- id: CUSTOM_B\n"
        "  severity: low\n",
        encoding="utf-8",
    )
    (custom / "a_first.yml").write_text(
        "- id: CUSTOM_A\n"
        "  severity: high\n",
        encoding="utf-8",
    )

    rules = load_rules(str(custom))
    ids = [r.get("id") for r in rules if r.get("id") in {"CUSTOM_A", "CUSTOM_B"}]
    assert ids == ["CUSTOM_A", "CUSTOM_B"]


def test_ruleset_version_stable_for_same_inputs(tmp_path):
    custom = tmp_path / "rules"
    custom.mkdir()
    (custom / "one.yml").write_text("- id: CUSTOM_1\n  severity: medium\n", encoding="utf-8")
    (custom / "two.yml").write_text("- id: CUSTOM_2\n  severity: high\n", encoding="utf-8")

    # load_rules should produce a stable ordering on repeated calls.
    first = load_rules(str(custom))
    second = load_rules(str(custom))
    assert first == second
