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

# dns.resolver.Resolver no promete ser thread-safe, así que damos uno por hilo.
_local = threading.local()


class DomainNotResolved(Exception):
    """El dominio no tiene ningún registro: probablemente no existe."""


def _resolver(timeout: float) -> dns.resolver.Resolver:
    res = getattr(_local, "resolver", None)
    if res is None:
        res = dns.resolver.Resolver()
        _local.resolver = res
    res.lifetime = timeout
    res.timeout = timeout
    return res


def _sorted_records(rdtype: str, values: list[str]) -> list[str]:
    """Orden estable: sin esto, dos ejecuciones seguidas dan JSON distinto
    porque el resolver rota el RRset."""
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
        raise DomainNotResolved(f"{domain} no resuelve (sin A, AAAA, MX ni NS)")

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
            finding("fail", "dns.address", "No hay A ni AAAA", "Publica un A o AAAA para el dominio raíz.")
        )
    else:
        findings.append(finding("ok", "dns.address", f"A={len(a)} AAAA={len(aaaa)}"))

    # No tener MX no es un problema: es un dato. Antes esto era un WARN cuyo
    # propio mensaje decía que era normal.
    if not mx:
        findings.append(finding("info", "dns.mx", "Sin MX (el dominio no recibe correo)"))
    else:
        findings.append(finding("ok", "dns.mx", f"{len(mx)} MX"))

    if not www and not www_cname:
        findings.append(
            finding("info", "dns.www", f"www.{domain} no resuelve", f"Añade un CNAME www → {domain} si esperas ese host.")
        )
    else:
        findings.append(finding("ok", "dns.www", ", ".join(www_cname or www)))

    # SPF, DMARC y DKIM importan aunque no haya MX: sin ellos cualquiera puede
    # poner tu dominio en el From.
    spf_fix = 'Publica TXT "v=spf1 -all" si el dominio no envía correo, o incluye tu proveedor.'
    if spf:
        rec = spf[0].rstrip()
        if rec.endswith("-all"):
            findings.append(finding("ok", "mail.spf", rec))
        elif rec.endswith("~all"):
            findings.append(
                finding(
                    "warn",
                    "mail.spf",
                    f"SPF en softfail: {rec}",
                    "Cambia ~all por -all cuando confirmes que todo el correo legítimo pasa.",
                )
            )
        else:
            findings.append(finding("warn", "mail.spf", rec, "Termina el registro en -all."))
    elif mx:
        findings.append(finding("fail", "mail.spf", "Hay MX y no hay SPF", spf_fix))
    else:
        findings.append(finding("warn", "mail.spf", "Sin SPF", spf_fix))

    dmarc_fix = 'Publica TXT en _dmarc con "v=DMARC1; p=reject; rua=mailto:tu@dominio".'
    if dmarc:
        rec = dmarc[0]
        policy = _dmarc_policy(rec)
        if policy in {"quarantine", "reject"}:
            findings.append(finding("ok", "mail.dmarc", rec))
        else:
            findings.append(
                finding("warn", "mail.dmarc", f"DMARC p={policy}: {rec}", "Sube la política a p=quarantine y después a p=reject.")
            )
    elif mx:
        findings.append(finding("fail", "mail.dmarc", "Hay MX y no hay DMARC", dmarc_fix))
    else:
        findings.append(finding("warn", "mail.dmarc", "Sin DMARC", dmarc_fix))

    if dkim_found:
        findings.append(finding("ok", "mail.dkim", "Selectores: " + ", ".join(sorted(dkim_found))))
    elif mx:
        findings.append(
            finding(
                "warn",
                "mail.dkim",
                "No se vio DKIM en los selectores habituales",
                "Activa la firma DKIM en tu proveedor y publica el selector (Proton: protonmail).",
            )
        )

    if ds:
        findings.append(finding("ok", "dns.dnssec", f"DS publicado ({len(ds)}) y DNSKEY={len(dnskey)}"))
    elif dnskey:
        findings.append(
            finding(
                "warn",
                "dns.dnssec",
                "Hay DNSKEY pero no hay DS en la zona padre: la firma no se valida",
                "Publica el registro DS en tu registrador para cerrar la cadena de confianza.",
            )
        )
    else:
        findings.append(
            finding("warn", "dns.dnssec", "Sin DNSSEC", "Actívalo en tu registrador y publica el DS en la zona padre.")
        )

    if caa:
        findings.append(finding("ok", "dns.caa", "; ".join(caa)))
    else:
        findings.append(
            finding(
                "warn",
                "dns.caa",
                "Sin CAA",
                'Añade CAA: 0 issue "letsencrypt.org" (ajusta a tu CA) para limitar quién puede emitir.',
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
