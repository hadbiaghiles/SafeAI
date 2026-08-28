import pytest
import yaml

from safeai.cmd.cli import main


def test_init_creates_default_configuration(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    assert main(["init"]) == 0

    config_dir = tmp_path / ".safeai"
    config = yaml.safe_load((config_dir / "config.yml").read_text(encoding="utf-8"))
    policy = yaml.safe_load((config_dir / "policy.yml").read_text(encoding="utf-8"))
    suppressions = yaml.safe_load((config_dir / "suppressions.yml").read_text(encoding="utf-8"))
    assert config == {
        "agent_name": tmp_path.name,
        "environment": "development",
        "lifecycle": "active",
    }
    assert policy["description"].startswith("Balanced defaults")
    assert suppressions == {"suppressions": []}
    assert "safeai scan ." in capsys.readouterr().out


def test_init_is_idempotent_without_force(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    config_path = tmp_path / ".safeai" / "config.yml"
    config_path.write_text("custom: true\n", encoding="utf-8")

    assert main(["init"]) == 0

    assert config_path.read_text(encoding="utf-8") == "custom: true\n"
    assert "Skipped existing .safeai/config.yml" in capsys.readouterr().out


def test_init_force_overwrites_with_selected_profile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    policy_path = tmp_path / ".safeai" / "policy.yml"
    policy_path.write_text("custom: true\n", encoding="utf-8")
    capsys.readouterr()

    assert main(["init", "--force", "--profile", "strict-ci"]) == 0

    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    assert policy["description"].startswith("Strict CI gating")
    assert "Skipped existing" not in capsys.readouterr().out


def test_init_rejects_unknown_profile(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit):
        main(["init", "--profile", "unknown"])
