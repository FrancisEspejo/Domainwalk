# domainwalk

![tests](https://github.com/FrancisRavn/Domainwalker/actions/workflows/tests.yml/badge.svg)

Auditor de superficie pública para **tu** dominio: DNS, DNSSEC, SPF/DMARC/DKIM, TLS, cabeceras HTTP, `security.txt` y `robots.txt`.

Responde a una pregunta concreta: qué ve de ti alguien que no te conoce y solo tiene tu dominio. Todo lo que consulta es público por diseño — los registros DNS, el certificado que sirves, las cabeceras que envías en cada respuesta.

No es un escáner de vulnerabilidades ni un fuzzer. No mira tu código, ni tus dependencias, ni si tu servidor tiene un CVE. Es un chequeo de configuración: cosas que se arreglan publicando un registro DNS o añadiendo una línea al servidor.

Úsalo contra hosts que te pertenezcan.

## Instalar

```bash
git clone https://github.com/FrancisRavn/Domainwalker.git
cd Domainwalker
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

O sin instalar el paquete, desde la raíz del repo:

```bash
pip install -r requirements.txt
python3 -m domainwalk francisravn.com
```

`python3 -m` encuentra el paquete porque el directorio actual entra en `sys.path`;
no hace falta `PYTHONPATH`. La diferencia con lo anterior es que `pip install -e .`
además deja disponible el comando `domainwalk` desde cualquier ruta.

## Uso

```bash
domainwalk francisravn.com
domainwalk francisravn.com --json
domainwalk francisravn.com --json -o informe.json
domainwalk francisravn.com --timeout 8
```

Cada ejecución hace consultas DNS y peticiones HTTP reales contra el dominio que le pases.

Cada hallazgo en rojo o amarillo lleva un `fix`: la línea concreta que hay que publicar o la acción que hay que tomar, no solo qué falta.

### Ejemplo de salida

```
domainwalk  francisravn.com  FAIL
ok=11  warn=8  fail=1  info=0  ·  2026-08-29T17:47:14+00:00

nivel   id               detalle
FAIL    hdr.hsts         Sin Strict-Transport-Security
WARN    dns.caa          Sin CAA
WARN    dns.dnssec       Sin DNSSEC
WARN    hdr.csp          Sin Content-Security-Policy
WARN    mail.spf         SPF en softfail: v=spf1 include:_spf.protonmail.ch ~all
WARN    wk.security_txt  https://francisravn.com/.well-known/security.txt -> 404
OK      dns.address      A=4 AAAA=4
OK      dns.mx           2 MX
OK      dns.www          francisravn.github.io
OK      http.redirect    HTTP 301 -> https://francisravn.com/
OK      mail.dkim        Selectores: protonmail
OK      mail.dmarc       v=DMARC1; p=quarantine
OK      tls.expiry       Caduca en 89 dias (2026-11-27T11:37:46+00:00) - vida 89d
OK      tls.san          francisravn.com, www.francisravn.com
OK      tls.version      TLSv1.3

Como arreglarlo
  - hdr.hsts    Strict-Transport-Security: max-age=63072000; includeSubDomains
  - dns.caa     Anade CAA: 0 issue "letsencrypt.org" (ajusta a tu CA)
  - dns.dnssec  Activalo en tu registrador y publica el DS en la zona padre.
  - mail.spf    Cambia ~all por -all cuando confirmes que todo el correo legitimo pasa.
```

### Comparar con una ejecución anterior

Un informe suelto es una foto. Lo interesante suele ser qué ha cambiado: apareció un TXT nuevo, el DMARC bajó de `quarantine` a `none`, cambiaron los NS.

```bash
domainwalk francisravn.com -o informes/$(date +%F).json
domainwalk francisravn.com --diff informes/2026-08-01.json
domainwalk francisravn.com --diff informes/2026-08-01.json --diff-output cambios.json
```

El diff señala hallazgos nuevos, hallazgos que ya no aparecen, cambios de nivel (marcando si mejoran o empeoran) y altas y bajas de registros DNS. La salida es determinista: las listas van ordenadas y los nombres de host normalizados, así que la rotación del RRset que hace el resolver no aparece como un cambio falso.

`-o` guarda siempre el informe a secas, aunque uses `--diff` a la vez: así el archivo de hoy sirve de línea base para la comparación de mañana. El resultado de la comparación va a `--diff-output`, o a la salida estándar con `--json`.

### Silenciar lo que no puedes arreglar

Si el sitio está en GitHub Pages no controlas las cabeceras de respuesta, y un FAIL que no puedes cerrar acaba siendo ruido que aprendes a ignorar. Crea un `.domainwalk.toml` en la raíz (o `~/.config/domainwalk/config.toml`):

```toml
timeout = 8.0

[mute]
"hdr.*" = "GitHub Pages no permite cabeceras propias"
```

Lo silenciado baja a `INFO`, no cuenta para el grade y sale con su motivo, de forma que dentro de seis meses sabrás por qué está ahí. El diff sigue viendo el nivel real: si algo silenciado empeora, te enteras igual.

Ejecuta con `--no-config` para ignorar cualquier configuración.

## Códigos de salida

- `0` — no hay hallazgos en rojo
- `1` — hay al menos un fallo
- `2` — error de uso, configuración ilegible, o el dominio no resuelve

Sirve como *gate* en CI: un cron semanal con `--diff` te avisa cuando algo cambia sin que tengas que acordarte de mirar.

## Chequeo semanal automático

`.github/workflows/weekly.yml` audita el dominio cada lunes, lo compara con
`baseline.json` y abre un issue si algo cambió.

`baseline.json` es el último estado conocido, no una foto ideal: el workflow lo
actualiza en el mismo commit en que abre el issue. Sin eso, un cambio legítimo
—activar DNSSEC, por ejemplo— reabriría el mismo aviso cada semana hasta
actualizarlo a mano. Lo que ves en el repo es, por tanto, el estado del dominio
la última vez que algo se movió.

Si no hay `baseline.json`, la primera ejecución lo crea sin abrir issue.

Para probarlo sin esperar al lunes: pestaña **Actions** → *chequeo semanal* →
**Run workflow**.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

No sale nada a internet: las pruebas de TLS y de redirección levantan servidores locales en puertos efímeros. El certificado de `tests/fixtures/` es autofirmado y existe solo para eso — su clave privada no protege nada.

## Notas de implementación

- Cuando OpenSSL rechaza el certificado, se reconecta sin verificar **solo** para poder leerlo y decirte por qué falla (caducidad, SAN, emisor). Eso usa `ssl._ssl._test_decode_cert`, API privada de CPython; si prefieres algo con garantías, sustituye `_decode_der` por `cryptography.x509`.
- Si TLS no verifica, los checks HTTPS se marcan como no evaluados en vez de repetir el mismo error de OpenSSL en cada uno. Un problema, una línea.
- El chequeo del puerto 80 no sigue redirecciones, así que distingue "no contestó" de "redirigió bien pero el destino falla".
- El umbral de caducidad se escala con la duración del certificado. Con un umbral fijo, cualquier certificado ACME de 90 días sano sale en amarillo la mitad de su vida, porque su renovación normal pasa por esa ventana cada ciclo.
- La fecha del certificado se parsea con `ssl.cert_time_to_seconds`, que lleva los meses en una tupla y no depende del locale.
- Las consultas DNS y los dos bloques de red van en paralelo.

## Licencia

MIT — ver [LICENSE](LICENSE).
