# Política de seguridad

Si encuentras un fallo de seguridad en domainwalk, escribe a **fran@francisravn.com**
en vez de abrir un issue público. Intento responder en una semana.

Incluye la versión (`domainwalk --version`), el dominio o el escenario con el que
lo reproduces y lo que esperabas que ocurriera.

## Alcance

domainwalk solo lee información pública: consultas DNS, el certificado que el
host presenta y las cabeceras de respuesta HTTP. No autentica, no envía datos a
terceros y no guarda nada fuera de los archivos que le pidas con `-o`.

Los informes JSON contienen los registros DNS completos del dominio auditado.
Son públicos por definición, pero tenlo en cuenta antes de subirlos a un repo
ajeno.
