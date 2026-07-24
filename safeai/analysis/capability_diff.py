"""Static comparison of capability inventories between scan reports."""


def _key(capability):
    return (
        str(capability.get("name", "capability")).lower(),
        str(capability.get("category", "Capability")).lower(),
    )


def compute_capability_diff(current_report, baseline_report):
    """Compare normalized capabilities from two reports.

    The comparison is deterministic and uses only serialized report data.
    Capabilities are identified by case-insensitive name and category.
    """
    current = {_key(cap): cap for cap in current_report.get("normalized_capabilities", [])}
    baseline = {_key(cap): cap for cap in baseline_report.get("normalized_capabilities", [])}

    added = [current[key] for key in sorted(current.keys() - baseline.keys())]
    removed = [baseline[key] for key in sorted(baseline.keys() - current.keys())]
    changed = []
    for key in sorted(current.keys() & baseline.keys()):
        before = baseline[key]
        after = current[key]
        fields = {}
        for field in ("confidence", "risk_weight", "source_frameworks", "sources", "evidence"):
            if before.get(field) != after.get(field):
                fields[field] = {"before": before.get(field), "after": after.get(field)}
        if fields:
            changed.append({"key": {"name": after.get("name"), "category": after.get("category")}, "changes": fields})

    return {
        "baseline_available": True,
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
        },
    }
