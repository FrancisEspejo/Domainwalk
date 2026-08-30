from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

from domainwalk import __version__
from domainwalk.config import apply_mutes, load_config
from domainwalk.diff import diff_reports
from domainwalk.dns_checks import DomainNotResolved, collect_dns
from domainwalk.findings import flatten_findings, score
from domainwalk.http_checks import collect_http, collect_tls, collect_well_known
from domainwalk.report import print_diff, print_report

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    if "://" in raw:
        host = urlparse(raw).hostname
    else:
        host = raw.split("/")[0]
        if host.startswith("[") and "]" in host:  # literal IPv6
            host = host[1 : host.index("]")]
        elif host.count(":") == 1:  # host:puerto
            host = host.split(":", 1)[0]
    if not host:
        raise ValueError("empty domain")
    host = host.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid domain: {exc}") from exc
    return host


def run(domain: str, timeout: float) -> dict:
    # First wave. DNS and TLS depend on nothing.
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_dns = pool.submit(collect_dns, domain, timeout)
        f_tls = pool.submit(collect_tls, domain, timeout)
        dns_result = f_dns.result()
        tls_result = f_tls.result()

    # Second wave. If TLS does not verify, HTTP and well-known are marked as not
    # evaluated instead of repeating the same OpenSSL error four times.
    tls_ok = tls_result.get("verified") is True
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_http = pool.submit(collect_http, domain, timeout, tls_ok)
        f_wk = pool.submit(collect_well_known, domain, timeout, tls_ok)
        http_result = f_http.result()
        wk_result = f_wk.result()

    report = {
        "tool": "domainwalk",
        "version": __version__,
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dns": dns_result,
        "tls": tls_result,
        "http": http_result,
        "well_known": wk_result,
    }
    report["summary"] = score(flatten_findings(report))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domainwalk",
        description="Public surface auditor for a domain (DNS, mail, TLS, headers).",
    )
    parser.add_argument("domain", help="domain to audit, e.g. example.com")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("-o", "--output", help="write the report as JSON to a file")
    parser.add_argument("--diff", metavar="INFORME.json", help="compare this run against a previous report")
    parser.add_argument("--diff-output", metavar="DIFF.json", help="write the comparison result to a file")
    parser.add_argument("--timeout", type=float, default=None, help="timeout in seconds (default 8)")
    parser.add_argument("--config", help="path to the config file (default ./.domainwalk.toml)")
    parser.add_argument("--no-config", action="store_true", help="ignore any config file")
    parser.add_argument("--version", action="version", version=f"domainwalk {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        domain = normalize_domain(args.domain)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    try:
        config = load_config(None if args.no_config else args.config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    timeout = args.timeout if args.timeout is not None else (config.timeout or 8.0)

    previous = None
    if args.diff:
        try:
            with open(args.diff, encoding="utf-8") as fh:
                previous = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read {args.diff}: {exc}", file=sys.stderr)
            return EXIT_ERROR

    try:
        report = run(domain, timeout)
    except DomainNotResolved as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001, CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report = apply_mutes(report, config.mute)

    delta = diff_reports(previous, report) if previous else None

    def dump(path: str, data: dict) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
            return True
        except OSError as exc:
            print(f"error: could not write {path}: {exc}", file=sys.stderr)
            return False

    # -o writes the plain report, never the report wrapped with its diff, so
    # today's file works as the baseline for tomorrow's comparison.
    if args.output and not dump(args.output, report):
        return EXIT_ERROR
    if args.diff_output:
        if delta is None:
            print("error: --diff-output requires --diff", file=sys.stderr)
            return EXIT_ERROR
        if not dump(args.diff_output, delta):
            return EXIT_ERROR

    if args.json:
        print(json.dumps({"report": report, "diff": delta} if delta else report, ensure_ascii=False, indent=2))
    else:
        print_report(report)
        if delta:
            print_diff(delta)

    return EXIT_FINDINGS if report["summary"]["fail"] else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
