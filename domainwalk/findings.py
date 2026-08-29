from __future__ import annotations

# Orden de severidad, de más grave a menos. Se usa para ordenar la tabla
# y para decidir el grade global. "info" nunca empeora el grade.
ORDER = ("fail", "warn", "info", "ok")
LEVELS = frozenset(ORDER)

SECTIONS = ("dns", "tls", "http", "well_known")


def finding(level: str, id: str, msg: str, fix: str | None = None) -> dict:
    """Crea un hallazgo. `fix` es la acción concreta para cerrarlo."""
    if level not in LEVELS:
        raise ValueError(f"nivel desconocido: {level!r}")
    item = {"level": level, "id": id, "msg": msg}
    if fix:
        item["fix"] = fix
    return item


def flatten_findings(report: dict) -> list[dict]:
    out: list[dict] = []
    for section in SECTIONS:
        out.extend(report.get(section, {}).get("findings", []))
    return out


def sort_findings(findings: list[dict]) -> list[dict]:
    """fail → warn → info → ok, y dentro de cada nivel por id."""
    return sorted(findings, key=lambda f: (ORDER.index(f["level"]), f["id"]))


def score(findings: list[dict]) -> dict:
    counts = {level: 0 for level in ORDER}
    for f in findings:
        counts[f["level"]] += 1
    if counts["fail"]:
        grade = "FAIL"
    elif counts["warn"]:
        grade = "WARN"
    else:
        grade = "OK"
    return {
        "ok": counts["ok"],
        "warn": counts["warn"],
        "fail": counts["fail"],
        "info": counts["info"],
        "grade": grade,
    }
