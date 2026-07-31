"""Rule loader for SafeAI scan rules.

Loads rules from built-in ``base_rules.yaml`` merged with optional
user-provided rule files. Custom rules with the same ID override
the built-in severity and OWASP category.
"""

import os

import yaml


def _iter_rule_files(directory):
    """Yield YAML rule filenames in deterministic lexical order."""
    for filename in sorted(os.listdir(directory)):
        if filename.endswith((".yml", ".yaml")):
            yield filename


def load_rules(custom_dir=None):
    rules = []
    base = os.path.dirname(__file__)
    for d in [base, custom_dir]:
        if not d:
            continue
        for filename in _iter_rule_files(d):
            try:
                with open(os.path.join(d, filename), "r", encoding="utf-8") as fh:
                    rules.extend(yaml.safe_load(fh) or [])
            except (OSError, yaml.YAMLError):
                pass
    return rules
