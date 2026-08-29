"""Integración contra servidores locales. No sale nada a internet."""

from __future__ import annotations

import http.server
import socket
import ssl
import threading
from pathlib import Path

import pytest

from domainwalk.http_checks import _check_plain_http, collect_http, collect_tls, collect_well_known

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def tls_server():
    """Servidor TLS con certificado autofirmado en un puerto libre."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(FIXTURES / "cert.pem", FIXTURES / "key.pem")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                wrapped = ctx.wrap_socket(conn, server_side=True)
                wrapped.recv(1024)
                wrapped.close()
            except (OSError, ssl.SSLError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    yield port
    srv.close()


def test_tls_reads_cert_even_when_verification_fails(tls_server):
    """La regresión importante: un cert que OpenSSL rechaza tiene que poder
    diagnosticarse igual, no quedarse en un error críptico de conexión."""
    result = collect_tls("localhost", timeout=5.0, port=tls_server)
    ids = {f["id"]: f for f in result["findings"]}

    assert result["verified"] is False
    assert "tls.connect" not in ids  # se conectó: el fallo fue de cadena, no de red
    assert ids["tls.verify"]["level"] == "fail"
    assert result["issuer"] == "domainwalk test CA"
    assert result["san"] == ["localhost", "www.localhost"]
    assert result["days_left"] > 0
    assert result["not_after"].endswith("+00:00")
    assert ids["tls.expiry"]["level"] == "ok"
    assert ids["tls.san"]["level"] == "ok"


def test_tls_expiry_parsing_is_locale_independent(tls_server, monkeypatch):
    import locale

    try:
        locale.setlocale(locale.LC_TIME, "es_ES.UTF-8")
    except locale.Error:
        pytest.skip("locale es_ES.UTF-8 no instalado")
    try:
        result = collect_tls("localhost", timeout=5.0, port=tls_server)
        assert result["days_left"] is not None
    finally:
        locale.setlocale(locale.LC_TIME, "C")


def test_tls_connect_failure_on_closed_port():
    result = collect_tls("localhost", timeout=2.0, port=1)
    ids = {f["id"] for f in result["findings"]}
    assert ids == {"tls.connect"}
    assert result["verified"] is None


class _Redirect(http.server.BaseHTTPRequestHandler):
    location = "https://example.com/"

    def do_GET(self):
        self.send_response(301)
        self.send_header("Location", self.location)
        self.end_headers()

    def log_message(self, *args):
        pass


class _NoRedirect(_Redirect):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hola")


def _serve(handler):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_plain_http_reports_the_redirect_not_the_destination():
    """Antes, urlopen seguía el 301 y un TLS roto en destino se reportaba como
    'HTTP no contestó'. El puerto 80 sí contestó."""
    srv = _serve(_Redirect)
    try:
        host = f"127.0.0.1:{srv.server_port}"
        _, item = _check_plain_http(host, timeout=5.0)
        assert item["level"] == "ok"
        assert "301" in item["msg"]
        assert "https://example.com/" in item["msg"]
    finally:
        srv.shutdown()


def test_plain_http_without_redirect_is_a_fail():
    srv = _serve(_NoRedirect)
    try:
        _, item = _check_plain_http(f"127.0.0.1:{srv.server_port}", timeout=5.0)
        assert item["level"] == "fail"
        assert item["fix"]
    finally:
        srv.shutdown()


def test_plain_http_closed_port_is_a_warn():
    _, item = _check_plain_http("127.0.0.1:1", timeout=2.0)
    assert item["level"] == "warn"
    assert "puerto 80" in item["msg"]


def test_https_checks_are_skipped_when_tls_is_broken():
    """Un problema, una línea: sin TLS válido no se repite el error de OpenSSL
    en cada check HTTPS."""
    srv = _serve(_Redirect)
    try:
        result = collect_http(f"127.0.0.1:{srv.server_port}", timeout=5.0, tls_ok=False)
    finally:
        srv.shutdown()
    ids = {f["id"]: f for f in result["findings"]}
    assert result["skipped"] is True
    assert ids["https.skipped"]["level"] == "info"
    assert not any(i.startswith("hdr.") for i in ids)
    assert "https.fetch" not in ids

    wk = collect_well_known("127.0.0.1", timeout=5.0, tls_ok=False)
    assert [f["id"] for f in wk["findings"]] == ["wk.skipped"]
