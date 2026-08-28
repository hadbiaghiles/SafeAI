"""Rule loading determinism tests."""

from safeai.rules.loader import load_rules


def test_custom_rule_files_loaded_in_lexical_order(tmp_path):
    custom = tmp_path / "rules"
    custom.mkdir()

    # Intentionally create in reverse lexical order.
    (custom / "z_second.yml").write_text(
        "- id: CUSTOM_B\n"
        "  description: Second custom rule\n"
        "  severity: low\n",
        encoding="utf-8",
    )
    (custom / "a_first.yml").write_text(
        "- id: CUSTOM_A\n"
        "  description: First custom rule\n"
        "  severity: high\n",
        encoding="utf-8",
    )

    rules, metadata = load_rules(str(custom))
    ids = [r.get("id") for r in rules if r.get("id") in {"CUSTOM_A", "CUSTOM_B"}]
    assert ids == ["CUSTOM_A", "CUSTOM_B"]
    assert metadata["custom_rules_count"] == 2


def test_ruleset_version_stable_for_same_inputs(tmp_path):
    custom = tmp_path / "rules"
    custom.mkdir()
    (custom / "one.yml").write_text(
        "- id: CUSTOM_1\n  description: Rule one\n  severity: medium\n", encoding="utf-8"
    )
    (custom / "two.yml").write_text(
        "- id: CUSTOM_2\n  description: Rule two\n  severity: high\n", encoding="utf-8"
    )

    # load_rules should produce a stable ordering on repeated calls.
    first, _ = load_rules(str(custom))
    second, _ = load_rules(str(custom))
    assert first == second
