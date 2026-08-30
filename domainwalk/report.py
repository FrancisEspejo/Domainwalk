from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from domainwalk.findings import flatten_findings, sort_findings

LEVEL_STYLE = {"ok": "green", "warn": "yellow", "fail": "red", "info": "cyan"}
LEVEL_MARK = {"ok": "OK", "warn": "WARN", "fail": "FAIL", "info": "INFO"}
DIR_STYLE = {"worse": "red", "better": "green"}

# A real CSP can run past 3,000 characters and bury the rest of the report.
HEADER_LIMIT = 160


def _short(value: str, limit: int = HEADER_LIMIT) -> str:
    value = str(value)
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def print_report(report: dict, console: Console | None = None) -> None:
    console = console or Console()
    summary = report["summary"]
    grade_style = LEVEL_STYLE.get(summary["grade"].lower(), "white")

    console.print(f"\n[bold]domainwalk[/bold]  {report['domain']}  [{grade_style}]{summary['grade']}[/]")
    counts = f"ok={summary['ok']}  warn={summary['warn']}  fail={summary['fail']}  info={summary.get('info', 0)}"
    if summary.get("muted"):
        counts += f"  ({summary['muted']} muted)"
    console.print(f"{counts}  |  {report.get('generated_at', '')}\n")

    findings = sort_findings(flatten_findings(report))

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("level", width=6)
    table.add_column("id", style="dim", no_wrap=True)
    table.add_column("detail")
    for item in findings:
        mark = Text(LEVEL_MARK[item["level"]], style=LEVEL_STYLE[item["level"]])
        msg = item["msg"]
        if item.get("muted"):
            msg += f"  [dim](muted: {item['mute_reason']})[/dim]"
        table.add_row(mark, item["id"], msg)
    console.print(table)

    pending = [f for f in findings if f.get("fix") and f["level"] in {"fail", "warn"}]
    if pending:
        console.print("\n[bold]How to fix[/bold]")
        for item in pending:
            console.print(f"  [{LEVEL_STYLE[item['level']]}]•[/] [dim]{item['id']}[/dim]  {item['fix']}")

    dns = report.get("dns", {})
    if dns:
        console.print("\n[bold]DNS[/bold]")
        for label, key in (("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"), ("CAA", "caa"), ("DS", "ds")):
            console.print(f"  {label:<6} {_short(', '.join(dns.get(key) or []), 300) or '-'}")

    tls = report.get("tls", {})
    console.print("\n[bold]TLS[/bold]")
    if tls.get("issuer"):
        verified = "verified" if tls.get("verified") else "[red]not verified[/red]"
        console.print(f"  issuer {tls['issuer']}  {tls.get('tls_version')}  days_left={tls.get('days_left')}  {verified}")
    elif tls.get("findings"):
        console.print(f"  {tls['findings'][0]['msg']}")

    http = report.get("http", {})
    console.print("\n[bold]HTTP[/bold]")
    if http.get("skipped"):
        console.print("  [cyan]not evaluated, TLS does not validate[/cyan]")
    else:
        console.print(f"  status {http.get('status', '-')}")
        for key, value in (http.get("headers") or {}).items():
            console.print(f"  {key}: {_short(value)}")
    console.print()


def print_diff(result: dict, console: Console | None = None) -> None:
    console = console or Console()
    console.print(f"\n[bold]domainwalk diff[/bold]  {result['domain']}")
    console.print(f"[dim]{result.get('from') or '?'}  ->  {result.get('to') or '?'}[/dim]\n")

    if result["unchanged"]:
        console.print("No changes.\n")
        return

    grade = result["grade"]
    if grade["changed"]:
        console.print(f"grade  {grade['from']} -> [bold]{grade['to']}[/bold]\n")

    changed = result["findings"]["changed"]
    if changed:
        console.print("[bold]Severity changes[/bold]")
        for item in changed:
            style = DIR_STYLE[item["direction"]]
            arrow = "v" if item["direction"] == "worse" else "^"
            console.print(f"  [{style}]{arrow}[/] [dim]{item['id']}[/dim]  {item['from']} -> {item['to']}  {item['msg']}")

    if result["findings"]["new"]:
        console.print("\n[bold]New findings[/bold]")
        for item in result["findings"]["new"]:
            console.print(f"  [{LEVEL_STYLE[item['level']]}]+[/] [dim]{item['id']}[/dim]  {item['msg']}")

    if result["findings"]["resolved"]:
        console.print("\n[bold]Gone[/bold]")
        for item in result["findings"]["resolved"]:
            console.print(f"  [green]-[/] [dim]{item['id']}[/dim]  {item['msg']}")

    if result["records"]:
        console.print("\n[bold]DNS records[/bold]")
        for field, delta in result["records"].items():
            for value in delta["added"]:
                console.print(f"  [green]+[/] {field}  {value}")
            for value in delta["removed"]:
                console.print(f"  [red]-[/] {field}  {value}")
    console.print()
