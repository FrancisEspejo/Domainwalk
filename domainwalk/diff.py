from __future__ import annotations

from domainwalk.findings import ORDER, flatten_findings

# Campos de DNS que se comparan como conjuntos.
RECORD_FIELDS = ("a", "aaaa", "mx", "ns", "caa", "ds", "spf", "dmarc", "txt", "www", "www_cname")


def _by_id(report: dict) -> dict[str, dict]:
    return {f["id"]: f for f in flatten_findings(report)}


def _effective(item: dict) -> str:
    """Nivel antes de silenciar: un empeoramiento silenciado sigue siendo noticia."""
    return item.get("original_level", item["level"])


def diff_reports(old: dict, new: dict) -> dict:
    old_f, new_f = _by_id(old), _by_id(new)

    appeared = [new_f[i] for i in sorted(set(new_f) - set(old_f)) if _effective(new_f[i]) != "ok"]
    resolved = [old_f[i] for i in sorted(set(old_f) - set(new_f)) if _effective(old_f[i]) != "ok"]

    changed: list[dict] = []
    for fid in sorted(set(old_f) & set(new_f)):
        before, after = _effective(old_f[fid]), _effective(new_f[fid])
        if before == after:
            continue
        changed.append(
            {
                "id": fid,
                "from": before,
                "to": after,
                "msg": new_f[fid]["msg"],
                "direction": "worse" if ORDER.index(after) < ORDER.index(before) else "better",
                "fix": new_f[fid].get("fix"),
            }
        )

    records: dict[str, dict] = {}
    old_dns, new_dns = old.get("dns", {}), new.get("dns", {})
    for field in RECORD_FIELDS:
        before = set(old_dns.get(field) or [])
        after = set(new_dns.get(field) or [])
        if before == after:
            continue
        records[field] = {"added": sorted(after - before), "removed": sorted(before - after)}

    grade_before = old.get("summary", {}).get("grade")
    grade_after = new.get("summary", {}).get("grade")

    return {
        "domain": new.get("domain"),
        "from": old.get("generated_at"),
        "to": new.get("generated_at"),
        "grade": {"from": grade_before, "to": grade_after, "changed": grade_before != grade_after},
        "findings": {"new": appeared, "resolved": resolved, "changed": changed},
        "records": records,
        "unchanged": not (appeared or resolved or changed or records),
    }
