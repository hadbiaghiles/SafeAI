"""Dependency-to-capability correlation (CE 1.5).

Answers two questions that the capability analyzer cannot answer alone:

1. **Undeclared dependency** — a credential/config name is referenced but no
   declared tool or capability plausibly consumes it. Static evidence that the
   agent reaches past its declared surface — a candidate undeclared capability.
2. **Orphaned declared tool** — a tool/capability that by nature needs a
   credential or backing service (database, cloud, API) has no matching
   dependency or config reference anywhere in the repository. Usually dead or
   misconfigured.

Both combine static evidence already in the report. Nothing executes code,
reads a secret, or verifies runtime behaviour — results are labelled heuristic
correlations, consistent with the assurance boundary.

Matching uses name-family keyword tables below, kept reviewable rather than
data-driven. Weak correlations stay silent.
"""

import re

#: Correlation finding rule ids.
RULE_UNDECLARED = "DEP_UNDECLARED_CAPABILITY"
RULE_ORPHAN = "DEP_ORPHANED_TOOL"

#: Keyword families map names to a capability family. A name matches only when
#: a token occurs as a whole word/segment (see ``_parse_words``), never as a
#: bare substring — this avoids false positives like ``jdbc`` -> database (via
#: ``db``) or ``rabbit_mq`` strings that merely contain a short token.
#:
#: Precedence is provider-specific first, generic ``api`` last. This keeps a
#: ``SLACK_TOKEN`` (provider ``slack`` -> messaging) aligned with a declared
#: ``slack`` capability instead of being pulled into ``api`` by its ``token``
#: suffix — the prior order produced simultaneous false undeclared + orphan.
_FAMILIES = (
    ("cloud", ("aws", "azure", "gcp", "google", "s3")),
    ("database", ("database", "postgres", "mysql", "sql", "redis", "mongo",
                  "oracle", "mssql", "maria", "sqlite")),
    ("messaging", ("slack", "kafka", "rabbit", "sqs", "pubsub")),
    ("api", ("api", "http", "url", "endpoint", "key", "token", "secret",
             "auth", "client", "openai", "anthropic", "gemini", "claude",
             "ollama", "vertex")),
)

#: Families whose declared tools need backing config or credentials. Only
#: these drive orphan detection (avoid flagging stateless tools). ``api`` is
#: intentionally excluded — generic HTTP/external APIs are matched against a
#: declared capability and should not be re-flagged.
_CREDENTIAL_DEMANDING = {"cloud", "database", "messaging"}

#: Capability family derived from the capability name — same vocabulary as
#: ``_FAMILIES`` so declared and referenced sides compare on a shared axis.
_CAP_FAMILY = {
    "s3": "cloud",
    "cloud": "cloud",
    "kubernetes": "cloud",
    "gcp": "cloud",
    "docker": "cloud",
    "databases": "database",
    "db": "database",
    "redis": "database",
    "external_apis": "api",
    "http": "api",
    "slack": "messaging",
    "jira": "api",
    "filesystem": "filesystem",
    "file_write": "filesystem",
}


def _parse_words(key):
    """Split a name into whole lowercase word segments.

    Breaks on non-alphanumeric characters (``_``, ``.``, ``-``, spaces) so
    ``AWS_SECRET_ACCESS_KEY`` -> ``{"aws", "secret", "access", "key"}``. This
    guarantees segment-exact matching (``db`` never matches ``jdbc``).
    """
    return {w for w in re.split(r"[^A-Za-z0-9]+", key) if w}


def _family_via_tokens(key, table):
    words = _parse_words(key)
    for prop, tokens in table:
        if any(token in words for token in tokens):
            return prop
    return None


def family_of_capability(name):
    """Return the correlation family of a declared capability name, or None."""
    key = str(name or "").lower()
    if key in _CAP_FAMILY:
        return _CAP_FAMILY[key]
    return _family_via_tokens(key, _FAMILIES)


def family_of_config(name):
    """Return the family of a referenced config/credential name, or None."""
    key = str(name or "").lower()
    return _family_via_tokens(key, _FAMILIES)


def _cap_name(entry):
    if isinstance(entry, dict):
        return entry.get("name")
    return str(entry)


def _gather_declared(report):
    """Collect declared capability families from the report.

    Uses the tool_surface (v1.4 attribution) when present, else normalized
    capabilities. Returns (set of families, dict family -> set of tool keys).
    """
    families = set()
    by_family = {}
    surface = report.get("tool_surface")
    if surface:
        tools = surface if isinstance(surface, list) else surface.get("tools") or []
        for entry in tools:
            tool_key = entry.get("tool_key") or entry.get("name")
            caps = entry.get("capabilities") or []
            for cap in caps:
                fam = family_of_capability(_cap_name(cap))
                if fam:
                    families.add(fam)
                    by_family.setdefault(fam, set()).add(str(tool_key))
        return families, by_family

    for cap in report.get("normalized_capabilities") or []:
        fam = family_of_capability(_cap_name(cap))
        if fam:
            families.add(fam)
    return families, by_family


def _inventory_from_report(report):
    """Return the env-dependency inventory carried by the scan report."""
    for finding in report.get("findings") or []:
        if finding.get("rule_id") == "ENV_DEP_INVENTORY":
            return finding.get("dep_inventory") or []
    return []


def _inventory_family_map(inventory):
    """Map family -> list of inventory entries for that family."""
    fam_map = {}
    for entry in inventory:
        fam = family_of_config(entry.get("name"))
        if fam:
            fam_map.setdefault(fam, []).append(entry)
    return fam_map


def correlate_dependencies(report):
    """Correlate the dependency inventory against the declared capability
    surface.

    Returns ``(findings, summary)``. Findings target DEP_UNDECLARED_CAPABILITY
    and DEP_ORPHANED_TOOL, ready for the post-scan pipeline. summary carries
    the correlation model and per-family counts for report rendering.
    """
    inventory = _inventory_from_report(report)
    declared_families, declared_by_family = _gather_declared(report)
    referenced = _inventory_family_map(inventory)

    findings = []
    counts = {"families": {}, "undeclared": 0, "orphaned": 0}

    # 1. Undeclared capability candidates — referenced config/credential
    #    family with no declared capability to consume it.
    for fam in sorted(referenced):
        entries = referenced[fam]
        consumed = fam in declared_families
        counts["families"][fam] = {
            "referenced": len(entries),
            "declared": consumed,
        }
        if consumed:
            continue
        entry = entries[0]
        source = (entry.get("sources") or [{}])[0]
        names = sorted({e.get("name") for e in entries})
        findings.append({
            "rule_id": RULE_UNDECLARED,
            "severity": "medium",
            "message": "Referenced credential/config has no matching declared capability",
            "file": source.get("file", "<scan>"),
            "line": source.get("line", 1),
            "owasp_llm": "LLM02",
            "evidence": f"family={fam} names={', '.join(names[:4])}",
            "reason": (
                f"Configuration/credential family '{fam}' is referenced "
                f"({len(entries)} name(s)) but no declared tool or capability "
                "in this family was found; this is a likely undeclared capability."
            ),
            "risk_category": "Identity",
            "affected_framework": "generic",
            "affected_capability": "Environment",
            "score_contribution": 6,
            "remediation": (
                "Confirm the referenced credential/config is consumed by a declared "
                "tool or capability; add the declaration or remove the orphaned reference."
            ),
            "confidence": 0.6,
            "dependency_family": fam,
            "dependency_names": names,
        })
        counts["undeclared"] += 1

    # 2. Orphaned declared tool — a credential-demanding family is declared
    #    but no matching config/credential is referenced anywhere.
    for fam in sorted(declared_families):
        if fam not in _CREDENTIAL_DEMANDING:
            continue
        if fam in referenced:
            continue
        tool_keys = sorted(declared_by_family.get(fam, ()))
        findings.append({
            "rule_id": RULE_ORPHAN,
            "severity": "low",
            "message": "Declared capability lacks a matching credential/config",
            "file": "<scan>",
            "line": 1,
            "owasp_llm": "LLM06",
            "evidence": f"family={fam} tools={', '.join(tool_keys) or 'unknown'}",
            "reason": (
                f"Capability family '{fam}' requires a credential, service, or backend "
                "configuration, but no matching environment variable, secret-manager "
                "entry, or config reference was found; the tool may be dead or misconfigured."
            ),
            "risk_category": "Integration",
            "affected_framework": "generic",
            "affected_capability": fam,
            "score_contribution": 3,
            "remediation": (
                "Verify the capability is real: add the expected credential/config "
                "reference, or remove the stale tool declaration."
            ),
            "confidence": 0.5,
            "dependency_family": fam,
        })
        counts["orphaned"] += 1

    findings.sort(key=lambda f: (f.get("file", ""), int(f.get("line") or 0), f.get("rule_id", "")))
    return findings, {
        "schema_version": 1,
        "correlation_model": "name-family keyword families",
        "counts": counts,
        "referenced_families": sorted(referenced),
        "declared_families": sorted(declared_families),
    }