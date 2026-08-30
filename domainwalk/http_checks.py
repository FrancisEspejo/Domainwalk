from __future__ import annotations

import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from domainwalk.findings import finding

USER_AGENT = "domainwalk/0.2"

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

HEADER_FIXES = {
    "hdr.hsts": "Strict-Transport-Security: max-age=63072000; includeSubDomains",
    "hdr.csp": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none' (tighten from there)",
    "hdr.xcto": "X-Content-Type-Options: nosniff",
    "hdr.frame": "Content-Security-Policy: frame-ancestors 'none' (or X-Frame-Options: DENY)",
    "hdr.referrer": "Referrer-Policy: strict-origin-when-cross-origin",
}

SKIP_MSG = "Not evaluated, the certificate does not validate"

# OIDs mapped to the labels getpeercert() uses.
ATTR_NAMES = {
    "2.5.4.3": "commonName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.6": "countryName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.7": "localityName",
}


class _NoRedirect(HTTPRedirectHandler):
    """Let the redirect surface as an HTTPError instead of following it.

    Without this, urlopen follows the 301 and a TLS failure at the destination
    gets reported as "port 80 did not answer", which is false. Port 80 answered.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch(url: str, timeout: float, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
    req = Request(url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return int(resp.status), headers, resp.read(64_000)
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        body = exc.read(64_000) if exc.fp else b""
        return int(exc.code), headers, body


# cryptography is the preferred path. Without it we fall back to a private
# CPython API that works today but carries no stability guarantee.
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding  # noqa: F401

    HAS_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAS_CRYPTOGRAPHY = False


def _decode_der_cryptography(der: bytes) -> dict:
    """Decode the DER with cryptography and return getpeercert()'s shape."""
    cert = x509.load_der_x509_certificate(der)

    def names(source) -> tuple:
        out = []
        for attr in source:
            label = ATTR_NAMES.get(attr.oid.dotted_string)
            if label:
                out.append(((label, attr.value),))
        return tuple(out)

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = tuple(("DNS", name) for name in sans.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        dns_names = ()

    # Store datetimes instead of OpenSSL's string. _cert_time accepts both.
    return {
        "subject": names(cert.subject),
        "issuer": names(cert.issuer),
        "notBefore": getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before,
        "notAfter": getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after,
        "subjectAltName": dns_names,
    }


def _decode_der_stdlib(der: bytes) -> dict:
    """Dependency free fallback using ssl._ssl._test_decode_cert.

    Private CPython API. Stable on 3.11 to 3.13, no promises for 3.14.
    Install the `crypto` extra to avoid relying on this.
    """
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)
    except (AttributeError, ValueError, OSError):
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _decode_der(der: bytes | None) -> dict:
    if not der:
        return {}
    if HAS_CRYPTOGRAPHY:
        try:
            return _decode_der_cryptography(der)
        except Exception:  # noqa: BLE001, fall back to the stdlib path
            pass
    return _decode_der_stdlib(der)


def _peer_cert(host: str, port: int, timeout: float, verify: bool) -> tuple[dict, str | None, tuple | None]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            if verify:
                cert = ssock.getpeercert() or {}
            else:
                # With CERT_NONE, getpeercert() returns {}, so go to the DER.
                cert = _decode_der(ssock.getpeercert(binary_form=True))
            return cert, ssock.version(), ssock.cipher()


def _cert_time(cert: dict, key: str) -> datetime | None:
    raw = cert.get(key)
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    try:
        # cert_time_to_seconds hardcodes month names, so it ignores the locale.
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), timezone.utc)
    except ValueError:
        return None


def expiry_thresholds(lifetime_days: int | None) -> tuple[int, int]:
    """Return (fail_at, warn_at) in days, scaled to the certificate lifetime.

    A fixed 45 day threshold flags every healthy 90 day ACME certificate, since
    normal renewal passes through that window on every cycle. This scales with
    the duration and caps at the classic values for yearly certificates.
    """
    if not lifetime_days or lifetime_days <= 0:
        return 21, 45
    fail_at = min(21, max(3, round(lifetime_days * 0.07)))
    warn_at = min(45, max(7, round(lifetime_days * 0.15)))
    return fail_at, max(warn_at, fail_at + 1)


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in patterns:
        pat = raw.lower().rstrip(".")
        if pat == host:
            return True
        if pat.startswith("*.") and host.count(".") == pat.count(".") and host.endswith(pat[1:]):
            return True
    return False


def collect_tls(host: str, timeout: float, port: int = 443) -> dict:
    findings: list[dict] = []
    info: dict = {"host": host, "port": port, "verified": None}

    try:
        cert, version, cipher = _peer_cert(host, port, timeout, verify=True)
        info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_error"] = getattr(exc, "verify_message", None) or str(exc)
        findings.append(
            finding(
                "fail",
                "tls.verify",
                f"Invalid chain: {info['verify_error']}",
                "Serve the full chain (leaf plus intermediates) and check the hostname matches.",
            )
        )
        try:
            # Second pass without verification, only to diagnose the reason.
            cert, version, cipher = _peer_cert(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as exc2:
            findings.append(finding("fail", "tls.connect", str(exc2)))
            info["findings"] = findings
            return info
    except (OSError, ssl.SSLError) as exc:
        findings.append(finding("fail", "tls.connect", str(exc), "Check that port 443 is open and serving TLS."))
        info["findings"] = findings
        return info

    info["tls_version"] = version
    info["cipher"] = cipher

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    expires = _cert_time(cert, "notAfter")
    starts = _cert_time(cert, "notBefore")
    days = (expires - datetime.now(timezone.utc)).days if expires else None
    lifetime = (expires - starts).days if expires and starts else None
    fail_at, warn_at = expiry_thresholds(lifetime)
    sans = sorted(ext[1] for ext in cert.get("subjectAltName", ()) if ext[0] == "DNS")

    info.update(
        {
            "subject_cn": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_before": starts.isoformat() if starts else None,
            "not_after": expires.isoformat() if expires else None,
            "days_left": days,
            "lifetime_days": lifetime,
            "san": sans,
        }
    )

    renew = "Check your automatic renewal (certbot or ACME) and renew well before expiry."
    if days is None:
        findings.append(finding("fail", "tls.expiry", "Could not read the expiry date"))
    elif days < 0:
        findings.append(finding("fail", "tls.expiry", f"Expired {-days} days ago ({info['not_after']})", renew))
    elif days < fail_at:
        findings.append(finding("fail", "tls.expiry", f"Expires in {days} days (threshold {fail_at})", renew))
    elif days < warn_at:
        findings.append(finding("warn", "tls.expiry", f"Expires in {days} days (threshold {warn_at})", renew))
    else:
        suffix = f" - {lifetime}d lifetime" if lifetime else ""
        findings.append(finding("ok", "tls.expiry", f"Expires in {days} days ({info['not_after']}){suffix}"))

    if sans:
        covers_host = host_matches(host, sans)
        covers_www = True if host.startswith("www.") else host_matches(f"www.{host}", sans)
        if not covers_host:
            findings.append(
                finding(
                    "fail",
                    "tls.san",
                    f"The certificate does not cover {host}. It covers {', '.join(sans[:6])}",
                    f"Reissue the certificate with {host} in the SAN.",
                )
            )
        elif not covers_www:
            findings.append(
                finding("info", "tls.san", f"Covers {host} but not www.{host}", f"Add www.{host} to the SAN if that host is used.")
            )
        else:
            findings.append(finding("ok", "tls.san", ", ".join(sans[:6])))

    ver = info.get("tls_version") or ""
    if ver in {"TLSv1", "TLSv1.1"}:
        findings.append(finding("fail", "tls.version", ver, "Disable TLS 1.0 and 1.1, keep TLS 1.2 as the minimum."))
    else:
        findings.append(finding("ok", "tls.version", ver or "unknown"))

    info["findings"] = findings
    return info


def _check_plain_http(domain: str, timeout: float) -> tuple[dict, dict]:
    """Check port 80 without following redirects."""
    result: dict = {}
    opener = build_opener(_NoRedirect)
    req = Request(f"http://{domain}/", method="GET", headers={"User-Agent": USER_AGENT})
    redirect_fix = "Return a 301 from http:// to the same path on https://."
    try:
        with opener.open(req, timeout=timeout) as resp:
            result["http_status"] = int(resp.status)
            return result, finding(
                "fail",
                "http.redirect",
                f"HTTP {resp.status} with no redirect to HTTPS",
                redirect_fix,
            )
    except HTTPError as exc:
        loc = exc.headers.get("Location") if exc.headers else None
        result["http_status"] = int(exc.code)
        result["redirected_from_http"] = loc
        if loc and loc.startswith("https://"):
            return result, finding("ok", "http.redirect", f"HTTP {exc.code} -> {loc}")
        if 300 <= exc.code < 400:
            return result, finding("fail", "http.redirect", f"HTTP {exc.code} -> {loc or '?'} (not https)", redirect_fix)
        return result, finding("warn", "http.redirect", f"HTTP {exc.code}")
    except (URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return result, finding("warn", "http.redirect", f"Port 80 did not answer ({reason})")


def collect_http(domain: str, timeout: float, tls_ok: bool = True) -> dict:
    findings: list[dict] = []
    https = f"https://{domain}/"
    result: dict = {"url": https, "redirected_from_http": None, "skipped": False}

    plain, redirect_finding = _check_plain_http(domain, timeout)
    result.update(plain)
    findings.append(redirect_finding)

    if not tls_ok:
        # Without valid TLS every HTTPS request repeats the same error.
        # One problem, one line.
        result["skipped"] = True
        findings.append(finding("info", "https.skipped", SKIP_MSG))
        result["findings"] = findings
        return result

    try:
        status, headers, _ = _fetch(https, timeout)
        result["status"] = status
        result["headers"] = {k: headers[k] for k in SECURITY_HEADERS if k in headers}
    except (URLError, OSError, ssl.SSLError) as exc:
        findings.append(finding("fail", "https.fetch", str(getattr(exc, "reason", exc))))
        result["findings"] = findings
        return result

    if status >= 400:
        findings.append(finding("warn", "https.status", f"HTTPS {status}"))
    else:
        findings.append(finding("ok", "https.status", f"HTTPS {status}"))

    hsts = headers.get("strict-transport-security")
    if hsts:
        findings.append(finding("ok", "hdr.hsts", hsts))
    else:
        findings.append(finding("fail", "hdr.hsts", "No Strict-Transport-Security", HEADER_FIXES["hdr.hsts"]))

    csp = headers.get("content-security-policy", "")
    if csp:
        findings.append(finding("ok", "hdr.csp", csp[:180]))
    else:
        findings.append(finding("warn", "hdr.csp", "No Content-Security-Policy", HEADER_FIXES["hdr.csp"]))

    xcto = headers.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        findings.append(finding("ok", "hdr.xcto", xcto))
    else:
        findings.append(finding("warn", "hdr.xcto", "No X-Content-Type-Options: nosniff", HEADER_FIXES["hdr.xcto"]))

    if headers.get("x-frame-options") or "frame-ancestors" in csp.lower():
        findings.append(finding("ok", "hdr.frame", headers.get("x-frame-options") or "CSP frame-ancestors"))
    else:
        findings.append(finding("warn", "hdr.frame", "No X-Frame-Options and no CSP frame-ancestors", HEADER_FIXES["hdr.frame"]))

    if headers.get("referrer-policy"):
        findings.append(finding("ok", "hdr.referrer", headers["referrer-policy"]))
    else:
        findings.append(finding("warn", "hdr.referrer", "No Referrer-Policy", HEADER_FIXES["hdr.referrer"]))

    result["findings"] = findings
    return result


def collect_well_known(domain: str, timeout: float, tls_ok: bool = True) -> dict:
    findings: list[dict] = []
    out: dict = {"skipped": not tls_ok}

    if not tls_ok:
        findings.append(finding("info", "wk.skipped", SKIP_MSG))
        out["findings"] = findings
        return out

    checks = {
        "security_txt": f"https://{domain}/.well-known/security.txt",
        "robots_txt": f"https://{domain}/robots.txt",
    }
    for key, url in checks.items():
        try:
            status, _, body = _fetch(url, timeout)
            text = body.decode("utf-8", "replace")[:4000]
            out[key] = {"url": url, "status": status, "body": text if status == 200 else ""}
            if key == "security_txt":
                if status == 200 and "Contact:" in text:
                    findings.append(finding("ok", "wk.security_txt", url))
                else:
                    findings.append(
                        finding(
                            "warn",
                            "wk.security_txt",
                            f"{url} -> {status}",
                            "Publish /.well-known/security.txt with Contact: and Expires: lines.",
                        )
                    )
            # A site with no robots.txt does not have a problem. This is informational.
            elif status == 200:
                findings.append(finding("ok", "wk.robots_txt", url))
            else:
                findings.append(finding("info", "wk.robots_txt", f"{url} -> {status}"))
        except (URLError, OSError, ssl.SSLError) as exc:
            reason = str(getattr(exc, "reason", exc))
            out[key] = {"url": url, "status": None, "error": reason}
            findings.append(finding("warn", f"wk.{key}", reason))

    out["findings"] = findings
    return out
