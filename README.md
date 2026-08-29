# domainwalk

Auditor de superficie pública para **tu** dominio: DNS, DNSSEC, SPF/DMARC/DKIM, TLS, cabeceras HTTP, `security.txt` y `robots.txt`.

Úsalo contra hosts que te pertenezcan. No es un escáner de vulnerabilidades ni un fuzzer.

## Instalar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

O sin instalar el paquete:

```bash
pip install -r requirements.txt
python3 -m domainwalk francisravn.com
```

## Uso

```bash
domainwalk francisravn.com
domainwalk francisravn.com --json
domainwalk francisravn.com --json -o informe.json
domainwalk francisravn.com --timeout 8
```

Cada hallazgo en rojo o amarillo lleva un `fix`: la línea concreta que hay que
publicar o la acción que hay que tomar, no solo qué falta.

### Comparar con una ejecución anterior

Un informe suelto es una foto. Lo interesante suele ser qué ha cambiado:

```bash
domainwalk francisravn.com -o informes/$(date +%F).json
domainwalk francisravn.com --diff informes/2026-08-01.json
domainwalk francisravn.com --diff informes/2026-08-01.json --diff-output cambios.json
```

`-o` guarda siempre el informe a secas, aunque uses `--diff` a la vez: así el
archivo de hoy sirve de línea base para la comparación de mañana. El resultado
de la comparación va a `--diff-output`, o a la salida estándar con `--json`.

El diff señala hallazgos nuevos, hallazgos que ya no aparecen, cambios de nivel
(marcando si mejoran o empeoran) y altas y bajas de registros DNS. La salida es
determinista: las listas van ordenadas, así que la rotación del RRset que hace
el resolver no aparece como un cambio falso.

### Silenciar lo que no puedes arreglar

Si el sitio está en GitHub Pages no controlas las cabeceras de respuesta, y un
FAIL que no puedes cerrar acaba siendo ruido que aprendes a ignorar. Crea un
`.domainwalk.toml` en la raíz (o `~/.config/domainwalk/config.toml`):

```toml
timeout = 8.0

[mute]
"hdr.*" = "GitHub Pages no permite cabeceras propias"
```

Lo silenciado baja a `INFO`, no cuenta para el grade y sale con su motivo, de
forma que dentro de seis meses sabrás por qué está ahí. El diff sigue viendo el
nivel real: si algo silenciado empeora, te enteras igual.

Ejecuta con `--no-config` para ignorar cualquier configuración.

## Códigos de salida

- `0` — no hay hallazgos en rojo
- `1` — hay al menos un fallo
- `2` — error de uso, configuración ilegible, o el dominio no resuelve

## Tests

```bash
pip install -e ".[dev]"
pytest
```

No sale nada a internet: las pruebas de TLS y de redirección levantan servidores
locales en puertos efímeros. El certificado de `tests/fixtures/` es autofirmado y
existe solo para eso — su clave privada no protege nada.

## Notas de implementación

- Cuando OpenSSL rechaza el certificado, se reconecta sin verificar **solo** para
  poder leerlo y decirte por qué falla (caducidad, SAN, emisor). Eso usa
  `ssl._ssl._test_decode_cert`, API privada de CPython; si prefieres algo con
  garantías, sustituye `_decode_der` por `cryptography.x509`.
- Si TLS no verifica, los checks HTTPS se marcan como no evaluados en vez de
  repetir el mismo error de OpenSSL en cada uno. Un problema, una línea.
- El chequeo del puerto 80 no sigue redirecciones, así que distingue "no
  contestó" de "redirigió bien pero el destino falla".
- Las consultas DNS y los dos bloques de red van en paralelo.
- El umbral de caducidad se escala con la duración del certificado. Con un
  umbral fijo, cualquier certificado ACME de 90 días sano sale en amarillo la
  mitad de su vida, porque su renovación normal pasa por esa ventana cada ciclo.
