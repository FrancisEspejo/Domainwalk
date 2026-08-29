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
    "hdr.csp": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none' (y ajusta desde ahí)",
    "hdr.xcto": "X-Content-Type-Options: nosniff",
    "hdr.frame": "Content-Security-Policy: frame-ancestors 'none' (o X-Frame-Options: DENY)",
    "hdr.referrer": "Referrer-Policy: strict-origin-when-cross-origin",
}

SKIP_MSG = "No evaluado: el certificado no valida"


class _NoRedirect(HTTPRedirectHandler):
    """Deja que la redirección salga como HTTPError en vez de seguirla.

    Sin esto, urlopen sigue el 301 y un fallo de TLS en el destino se reporta
    como 'HTTP no contestó', que es falso: el puerto 80 contestó perfectamente.
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


def _decode_der(der: bytes | None) -> dict:
    """Decodifica un certificado DER sin pasar por la validación de OpenSSL.

    ssl._ssl._test_decode_cert es API privada de CPython (estable en 3.11-3.13
    pero sin garantías). Si prefieres algo firme, sustituye esta función por
    cryptography.x509.load_der_x509_certificate.
    """
    if not der:
        return {}
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
                # Con CERT_NONE, getpeercert() devuelve {}: hay que ir al DER.
                cert = _decode_der(ssock.getpeercert(binary_form=True))
            return cert, ssock.version(), ssock.cipher()


def _cert_time(cert: dict, key: str) -> datetime | None:
    raw = cert.get(key)
    if not raw:
        return None
    try:
        # cert_time_to_seconds lleva los meses en una tupla: no depende del locale.
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), timezone.utc)
    except ValueError:
        return None


def expiry_thresholds(lifetime_days: int | None) -> tuple[int, int]:
    """Devuelve (fail_at, warn_at) en días, en proporción a la vida del certificado.

    Un umbral fijo de 45 días marca en amarillo cualquier certificado ACME de 90
    días sano, porque su renovación normal pasa por ahí cada ciclo. Se escala con
    la duración y se limita a los valores clásicos para certificados anuales.
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
                f"Cadena no válida: {info['verify_error']}",
                "Sirve la cadena completa (hoja + intermedios) y comprueba que el nombre coincide.",
            )
        )
        try:
            # Segunda pasada sin verificar, solo para poder diagnosticar el porqué.
            cert, version, cipher = _peer_cert(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as exc2:
            findings.append(finding("fail", "tls.connect", str(exc2)))
            info["findings"] = findings
            return info
    except (OSError, ssl.SSLError) as exc:
        findings.append(finding("fail", "tls.connect", str(exc), "Comprueba que el puerto 443 está abierto y sirve TLS."))
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

    renew = "Revisa la renovación automática (certbot/ACME) y renueva antes de 30 días."
    if days is None:
        findings.append(finding("fail", "tls.expiry", "No se leyó la caducidad"))
    elif days < 0:
        findings.append(finding("fail", "tls.expiry", f"Caducado hace {-days} días ({info['not_after']})", renew))
    elif days < fail_at:
        findings.append(finding("fail", "tls.expiry", f"Caduca en {days} días (umbral {fail_at})", renew))
    elif days < warn_at:
        findings.append(finding("warn", "tls.expiry", f"Caduca en {days} días (umbral {warn_at})", renew))
    else:
        suffix = f" · vida {lifetime}d" if lifetime else ""
        findings.append(finding("ok", "tls.expiry", f"Caduca en {days} días ({info['not_after']}){suffix}"))

    if sans:
        covers_host = host_matches(host, sans)
        covers_www = True if host.startswith("www.") else host_matches(f"www.{host}", sans)
        if not covers_host:
            findings.append(
                finding(
                    "fail",
                    "tls.san",
                    f"El certificado no cubre {host}: {', '.join(sans[:6])}",
                    f"Reemite el certificado incluyendo {host} en el SAN.",
                )
            )
        elif not covers_www:
            findings.append(
                finding("info", "tls.san", f"Cubre {host} pero no www.{host}", f"Añade www.{host} al SAN si ese host se usa.")
            )
        else:
            findings.append(finding("ok", "tls.san", ", ".join(sans[:6])))

    ver = info.get("tls_version") or ""
    if ver in {"TLSv1", "TLSv1.1"}:
        findings.append(finding("fail", "tls.version", ver, "Desactiva TLS 1.0/1.1 y deja TLS 1.2 como mínimo."))
    else:
        findings.append(finding("ok", "tls.version", ver or "desconocida"))

    info["findings"] = findings
    return info


def _check_plain_http(domain: str, timeout: float) -> tuple[dict, dict]:
    """Mira el puerto 80 sin seguir redirecciones."""
    result: dict = {}
    opener = build_opener(_NoRedirect)
    req = Request(f"http://{domain}/", method="GET", headers={"User-Agent": USER_AGENT})
    redirect_fix = "Devuelve un 301 desde http:// hacia la misma ruta en https://."
    try:
        with opener.open(req, timeout=timeout) as resp:
            result["http_status"] = int(resp.status)
            return result, finding(
                "fail",
                "http.redirect",
                f"HTTP {resp.status} sin redirigir a HTTPS",
                redirect_fix,
            )
    except HTTPError as exc:
        loc = exc.headers.get("Location") if exc.headers else None
        result["http_status"] = int(exc.code)
        result["redirected_from_http"] = loc
        if loc and loc.startswith("https://"):
            return result, finding("ok", "http.redirect", f"HTTP {exc.code} → {loc}")
        if 300 <= exc.code < 400:
            return result, finding("fail", "http.redirect", f"HTTP {exc.code} → {loc or '?'} (no es https)", redirect_fix)
        return result, finding("warn", "http.redirect", f"HTTP {exc.code}")
    except (URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return result, finding("warn", "http.redirect", f"El puerto 80 no contestó ({reason})")


def collect_http(domain: str, timeout: float, tls_ok: bool = True) -> dict:
    findings: list[dict] = []
    https = f"https://{domain}/"
    result: dict = {"url": https, "redirected_from_http": None, "skipped": False}

    plain, redirect_finding = _check_plain_http(domain, timeout)
    result.update(plain)
    findings.append(redirect_finding)

    if not tls_ok:
        # Sin TLS válido, cada petición HTTPS repetiría el mismo error. Un
        # problema, una línea.
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
        findings.append(finding("fail", "hdr.hsts", "Sin Strict-Transport-Security", HEADER_FIXES["hdr.hsts"]))

    csp = headers.get("content-security-policy", "")
    if csp:
        findings.append(finding("ok", "hdr.csp", csp[:180]))
    else:
        findings.append(finding("warn", "hdr.csp", "Sin Content-Security-Policy", HEADER_FIXES["hdr.csp"]))

    xcto = headers.get("x-content-type-options", "")
    if xcto.lower() == "nosniff":
        findings.append(finding("ok", "hdr.xcto", xcto))
    else:
        findings.append(finding("warn", "hdr.xcto", "Sin X-Content-Type-Options: nosniff", HEADER_FIXES["hdr.xcto"]))

    if headers.get("x-frame-options") or "frame-ancestors" in csp.lower():
        findings.append(finding("ok", "hdr.frame", headers.get("x-frame-options") or "CSP frame-ancestors"))
    else:
        findings.append(finding("warn", "hdr.frame", "Sin X-Frame-Options ni CSP frame-ancestors", HEADER_FIXES["hdr.frame"]))

    if headers.get("referrer-policy"):
        findings.append(finding("ok", "hdr.referrer", headers["referrer-policy"]))
    else:
        findings.append(finding("warn", "hdr.referrer", "Sin Referrer-Policy", HEADER_FIXES["hdr.referrer"]))

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
                            f"{url} → {status}",
                            "Publica /.well-known/security.txt con las líneas Contact: y Expires:.",
                        )
                    )
            # Un sitio sin robots.txt no tiene un problema: es informativo.
            elif status == 200:
                findings.append(finding("ok", "wk.robots_txt", url))
            else:
                findings.append(finding("info", "wk.robots_txt", f"{url} → {status}"))
        except (URLError, OSError, ssl.SSLError) as exc:
            reason = str(getattr(exc, "reason", exc))
            out[key] = {"url": url, "status": None, "error": reason}
            findings.append(finding("warn", f"wk.{key}", reason))

    out["findings"] = findings
    return out
