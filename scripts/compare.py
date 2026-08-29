"""Compara dos informes y escribe el cuerpo del issue en markdown.

Uso: python scripts/compare.py ANTERIOR.json ACTUAL.json SALIDA.md

Imprime `changed=true|false` en stdout, en el formato que espera GITHUB_OUTPUT.
Se escribe el markdown a un archivo en vez de pasarlo como salida multilínea
porque `gh issue create --body-file` no necesita escapado alguno.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from domainwalk.diff import diff_reports

ARROW = {"worse": "🔻", "better": "🔼"}


def render(delta: dict) -> str:
    lines: list[str] = []
    lines.append(f"Comparación de **{delta['domain']}** entre `{delta['from']}` y `{delta['to']}`.")
    lines.append("")

    grade = delta["grade"]
    if grade["changed"]:
        lines.append(f"El grade pasa de **{grade['from']}** a **{grade['to']}**.")
        lines.append("")

    changed = delta["findings"]["changed"]
    if changed:
        lines.append("### Cambios de nivel")
        lines.append("")
        lines.append("| | id | antes | ahora | detalle |")
        lines.append("|---|---|---|---|---|")
        for item in changed:
            lines.append(
                f"| {ARROW[item['direction']]} | `{item['id']}` | {item['from']} | "
                f"**{item['to']}** | {item['msg']} |"
            )
        lines.append("")
        fixes = [i for i in changed if i["direction"] == "worse" and i.get("fix")]
        if fixes:
            lines.append("**Cómo arreglarlo**")
            lines.append("")
            for item in fixes:
                lines.append(f"- `{item['id']}` — {item['fix']}")
            lines.append("")

    for key, title in (("new", "Hallazgos nuevos"), ("resolved", "Hallazgos que ya no aparecen")):
        items = delta["findings"][key]
        if not items:
            continue
        lines.append(f"### {title}")
        lines.append("")
        for item in items:
            lines.append(f"- `{item['id']}` ({item['level']}) — {item['msg']}")
        lines.append("")

    if delta["records"]:
        lines.append("### Registros DNS")
        lines.append("")
        for field, change in delta["records"].items():
            for value in change["added"]:
                lines.append(f"- **+** `{field}` — {value}")
            for value in change["removed"]:
                lines.append(f"- **−** `{field}` — {value}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Generado por el chequeo semanal. Al abrir este issue se actualiza "
        "`baseline.json`, así que la próxima comparación parte de este estado y "
        "no se repetirá el aviso."
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    old_path, new_path, body_path = argv[1], argv[2], argv[3]

    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    if not Path(old_path).is_file():
        # Primera ejecución: no hay con qué comparar, se toma el estado actual.
        print("changed=false")
        print("first_run=true")
        return 0

    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    delta = diff_reports(old, new)
    Path(body_path).write_text(render(delta), encoding="utf-8")
    print(f"changed={'false' if delta['unchanged'] else 'true'}")
    print("first_run=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
