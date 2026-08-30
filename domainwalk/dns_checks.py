from __future__ import annotations

import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver

from domainwalk.findings import finding

COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "protonmail",
    "protonmail2",
    "pm1",
    "k1",
    "s1",
    "s2",
    "mail",
    "dkim",
)

# dns.resolver.Resolver makes no thread-safety promise, so use one per thread.
_local = threading.local()


class DomainNotResolved(Exception):
    """The domain has no records at all, so it probably does not exist."""


def _resolver(timeout: float) -> dns.resolver.Resolver:
    res = getattr(_local, "resolver", None)
    if res is None:
        res = dns.resolver.Resolver()
        _local.resolver = res
    res.lifetime = timeout
    res.timeout = timeout
    return res


# Hostnames are case insensitive. Without normalizing, a capitalization change
# from your provider shows up in the diff as a record added and removed.
CASE_INSENSITIVE = frozenset({"MX", "NS", "CNAME", "DS", "PTR"})


def _sorted_records(rdtype: str, values: list[str]) -> list[str]:
    if rdtype in CASE_INSENSITIVE:
        values = [v.lower() for v in values]
    """Stable ordering. Without it two consecutive runs produce different JSON,
    because the resolver rotates the RRset."""
    if rdtype in {"A", "AAAA"}:
        try:
            return sorted(values, key=ipaddress.ip_address)
        except ValueError:
            return sorted(values)
    if rdtype == "MX":

        def mx_key(value: str) -> tuple[int, str]:
            parts = value.split(None, 1)
            try:
                return (int(parts[0]), parts[1].lower() if len(parts) > 1 else "")
            except (ValueError, IndexError):
                return (0, value.lower())

        return sorted(values, key=mx_key)
    return sorted(values, key=str.lower)


def _answers(name: str, rdtype: str, timeout: float) -> list[str]:
    resolver = _resolver(timeout)
    try:
        resp = resolver.resolve(name, rdtype, lifetime=timeout)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.SyntaxError,
    ):
        return []
    out: list[str] = []
    for rr in resp:
        if rdtype == "TXT":
            out.append(
                "".join(
                    part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                    for part in rr.strings
                )
            )
        else:
            out.append(rr.to_text().rstrip("."))
    return _sorted_records(rdtype, out)


def _query_all(domain: str, timeout: float, workers: int = 8) -> dict[str, list[str]]:
    plan: dict[str, tuple[str, str]] = {
        "a": (domain, "A"),
        "aaaa": (domain, "AAAA"),
        "mx": (domain, "MX"),
        "txt": (domain, "TXT"),
        "ns": (domain, "NS"),
        "caa": (domain, "CAA"),
        "ds": (domain, "DS"),
        "dnskey": (domain, "DNSKEY"),
        "dmarc": (f"_dmarc.{domain}", "TXT"),
        "www_a": (f"www.{domain}", "A"),
        "www_aaaa": (f"www.{domain}", "AAAA"),
        "www_cname": (f"www.{domain}", "CNAME"),
    }
    for sel in COMMON_DKIM_SELECTORS:
        plan[f"dkim:{sel}"] = (f"{sel}._domainkey.{domain}", "TXT")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {key: pool.submit(_answers, name, rdtype, timeout) for key, (name, rdtype) in plan.items()}
        return {key: fut.result() for key, fut in futures.items()}


def _dmarc_policy(record: str) -> str:
    for part in record.split(";"):
        part = part.strip().lower()
        if part.startswith("p="):
            return part.split("=", 1)[1].strip()
    return "none"


def collect_dns(domain: str, timeout: float) -> dict:
    raw = _query_all(domain, timeout)

    a, aaaa, mx, txt, ns, caa = (raw["a"], raw["aaaa"], raw["mx"], raw["txt"], raw["ns"], raw["caa"])
    ds, dnskey = raw["ds"], raw["dnskey"]

    if not any((a, aaaa, mx, ns)):
        raise DomainNotResolved(f"{domain} does not resolve (no A, AAAA, MX or NS)")

    spf = sorted(t for t in txt if t.lower().startswith("v=spf1"))
    dmarc = sorted(t for t in raw["dmarc"] if "V=DMARC1" in t.upper())

    dkim_found: dict[str, str] = {}
    for sel in COMMON_DKIM_SELECTORS:
        recs = [t for t in raw[f"dkim:{sel}"] if "V=DKIM1" in t.upper() or "p=" in t.lower()]
        if recs:
            dkim_found[sel] = recs[0]

    www = _sorted_records("A", raw["www_a"]) + _sorted_records("AAAA", raw["www_aaaa"])
    www_cname = raw["www_cname"]

    findings: list[dict] = []

    if not a and not aaaa:
        findings.append(
            finding("fail", "dns.address", "No A or AAAA record", "Publish an A or AAAA record for the apex domain.")
        )
    else:
        findings.append(finding("ok", "dns.address", f"A={len(a)} AAAA={len(aaaa)}"))

    # Having no MX is not a problem, it is a fact. This used to be a WARN whose
    # own message admitted it was normal.
    if not mx:
        findings.append(finding("info", "dns.mx", "No MX (this domain does not receive mail)"))
    else:
        findings.append(finding("ok", "dns.mx", f"{len(mx)} MX"))

    if not www and not www_cname:
        findings.append(
            finding("info", "dns.www", f"www.{domain} does not resolve", f"Add a CNAME www -> {domain} if you expect that host.")
        )
    else:
        findings.append(finding("ok", "dns.www", ", ".join(www_cname or www)))

    # SPF, DMARC and DKIM matter even with no MX. Without them anyone can put
    # your domain in the From header.
    spf_fix = 'Publish TXT "v=spf1 -all" if the domain sends no mail, or include your provider.'
    if spf:
        rec = spf[0].rstrip()
        if rec.endswith("-all"):
            findings.append(finding("ok", "mail.spf", rec))
        elif rec.endswith("~all"):
            findings.append(
                finding(
                    "warn",
                    "mail.spf",
                    f"SPF softfail: {rec}",
                    "Switch ~all to -all once you confirm all legitimate mail passes.",
                )
            )
        else:
            findings.append(finding("warn", "mail.spf", rec, "End the record with -all."))
    elif mx:
        findings.append(finding("fail", "mail.spf", "MX present but no SPF", spf_fix))
    else:
        findings.append(finding("warn", "mail.spf", "No SPF", spf_fix))

    dmarc_fix = 'Publish TXT at _dmarc with "v=DMARC1; p=reject; rua=mailto:you@example.com".'
    if dmarc:
        rec = dmarc[0]
        policy = _dmarc_policy(rec)
        if policy in {"quarantine", "reject"}:
            findings.append(finding("ok", "mail.dmarc", rec))
        else:
            findings.append(
                finding("warn", "mail.dmarc", f"DMARC p={policy}: {rec}", "Raise the policy to p=quarantine, then to p=reject.")
            )
    elif mx:
        findings.append(finding("fail", "mail.dmarc", "MX present but no DMARC", dmarc_fix))
    else:
        findings.append(finding("warn", "mail.dmarc", "No DMARC", dmarc_fix))

    if dkim_found:
        findings.append(finding("ok", "mail.dkim", "Selectors: " + ", ".join(sorted(dkim_found))))
    elif mx:
        findings.append(
            finding(
                "warn",
                "mail.dkim",
                "No DKIM found in the usual selectors",
                "Enable DKIM signing at your provider and publish the selector (Proton uses protonmail).",
            )
        )

    if ds:
        findings.append(finding("ok", "dns.dnssec", f"DS published ({len(ds)}), DNSKEY={len(dnskey)}"))
    elif dnskey:
        findings.append(
            finding(
                "warn",
                "dns.dnssec",
                "DNSKEY present but no DS in the parent zone, so the signature is never validated",
                "Publish the DS record at your registrar to close the chain of trust.",
            )
        )
    else:
        findings.append(
            finding("warn", "dns.dnssec", "No DNSSEC", "Enable it at your registrar and publish the DS in the parent zone.")
        )

    if caa:
        findings.append(finding("ok", "dns.caa", "; ".join(caa)))
    else:
        findings.append(
            finding(
                "warn",
                "dns.caa",
                "No CAA",
                'Add CAA: 0 issue "letsencrypt.org" (adjust for your CA) to limit who can issue.',
            )
        )

    return {
        "a": a,
        "aaaa": aaaa,
        "mx": mx,
        "ns": ns,
        "txt": sorted(txt, key=str.lower),
        "caa": caa,
        "ds": ds,
        "dnskey_count": len(dnskey),
        "www": www,
        "www_cname": www_cname,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dict(sorted(dkim_found.items())),
        "findings": findings,
    }
