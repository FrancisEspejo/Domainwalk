Certificado autofirmado de usar y tirar para los tests locales.
No protege nada: la clave privada está aquí a propósito. No lo uses fuera de pytest.

Regenerar:

    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes \
      -subj "/CN=localhost/O=domainwalk test CA" \
      -addext "subjectAltName=DNS:localhost,DNS:www.localhost"
