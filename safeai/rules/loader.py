"""Rule loader for SafeAI scan rules.

Loads rules from built-in ``base_rules.yaml`` merged with optional
user-provided rule files. Custom rules with the same ID override
the built-in severity and OWASP category.

Auto-discovery:
  When no explicit ``--rules`` directory is passed, the loader also
  checks ``.safeai/rules/`` in the scan root (if it exists). This
  lets ``safeai init`` scaffold a rules directory that is picked up
  automatically.

Validation:
  Each rule must have ``id``, ``description``, and ``severity``.
  Rules missing required fields are skipped with a warning.
"""

import logging
import os

import yaml

logger = logging.getLogger("safeai")

_REQUIRED_FIELDS = {"id", "description", "severity"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _iter_rule_files(directory):
    """Yield YAML rule filenames in deterministic lexical order."""
    for filename in sorted(os.listdir(directory)):
        if filename.endswith((".yml", ".yaml")):
            yield filename


def _validate_rule(rule, source):
    """Validate a single rule dict. Returns the rule if valid, None otherwise."""
    if not isinstance(rule, dict):
        return None
    missing = _REQUIRED_FIELDS - set(rule.keys())
    if missing:
        rule_id = rule.get("id", "<unknown>")
        logger.warning("Rule %s in %s missing required fields %s, skipping", rule_id, source, missing)
        return None
    severity = rule.get("severity", "")
    if severity not in _VALID_SEVERITIES:
        rule_id = rule.get("id", "<unknown>")
        logger.warning("Rule %s in %s has invalid severity %r, skipping", rule_id, source, severity)
        return None
    return rule


def load_rules(custom_dir=None, scan_root=None):
    """Load and merge rules from built-in and custom directories.

    Parameters
    ----------
    custom_dir : str, optional
        Explicit custom rules directory (from ``--rules``).
    scan_root : str, optional
        Scan root directory. When provided and ``custom_dir`` is None,
        ``.safeai/rules/`` under scan_root is checked for auto-discovery.

    Returns
    -------
    tuple[list, dict]
        ``(rules, metadata)`` where ``metadata`` contains:
        ``custom_rules_dir``, ``custom_rules_count``, ``builtin_rules_count``,
        ``rule_pack_ids`` (list of rule file basenames loaded).
    """
    rules = []
    rule_pack_ids = []
    base = os.path.dirname(__file__)
    seen_ids = {}

    # 1. Load built-in rules
    for filename in _iter_rule_files(base):
        try:
            with open(os.path.join(base, filename), "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or []
            validated = []
            for rule in loaded:
                v = _validate_rule(rule, f"built-in:{filename}")
                if v:
                    validated.append(v)
            rules.extend(validated)
            rule_pack_ids.append(f"built-in:{filename}")
        except (OSError, yaml.YAMLError):
            pass

    builtin_count = len(rules)

    # 2. Determine custom directory: explicit > auto-discover > None
    effective_custom_dir = custom_dir
    if not effective_custom_dir and scan_root:
        auto = os.path.join(scan_root, ".safeai", "rules")
        if os.path.isdir(auto):
            effective_custom_dir = auto

    # 3. Load custom rules
    custom_count = 0
    if effective_custom_dir and os.path.isdir(effective_custom_dir):
        for filename in _iter_rule_files(effective_custom_dir):
            try:
                with open(os.path.join(effective_custom_dir, filename), "r", encoding="utf-8") as fh:
                    loaded = yaml.safe_load(fh) or []
                validated = []
                for rule in loaded:
                    v = _validate_rule(rule, f"custom:{filename}")
                    if v:
                        rule_id = v.get("id")
                        if rule_id in seen_ids:
                            logger.info(
                                "Custom rule %s in %s overrides built-in", rule_id, filename
                            )
                        seen_ids[rule_id] = f"custom:{filename}"
                        validated.append(v)
                rules.extend(validated)
                custom_count += len(validated)
                rule_pack_ids.append(f"custom:{filename}")
            except (OSError, yaml.YAMLError):
                pass

    metadata = {
        "custom_rules_dir": effective_custom_dir,
        "custom_rules_count": custom_count,
        "builtin_rules_count": builtin_count,
        "rule_pack_ids": sorted(rule_pack_ids),
    }
    return rules, metadata
