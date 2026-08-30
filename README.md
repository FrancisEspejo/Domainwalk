# domainwalk

![tests](https://github.com/FrancisRavn/Domainwalk/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A command line tool that audits the public surface of a domain and tells you what
is set up correctly and what is not. DNS records, DNSSEC, SPF, DKIM, DMARC, TLS
certificates, HTTP security headers, `security.txt` and `robots.txt`, in a single
pass and a single report.

Point it at a domain and you get a graded list of findings. Green for what is
fine, yellow and red for what is not, and for every problem the exact line you
need to publish to close it.

Everything domainwalk reads is already public. Anyone can query your DNS. Your TLS
certificate goes to whoever connects. Your response headers ship with every page.
It is a passive audit of visible configuration, which is why you can run it
against your own domain or against one you are just checking out.

## What it checks

Four collectors run against the domain. Each produces findings with a severity
(`fail`, `warn`, `info`, `ok`), a stable id, and the concrete fix when something
is wrong.

### DNS and email authentication

Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`, `DS` and `DNSKEY`, plus `_dmarc`
and twelve common DKIM selectors including `default`, `google`, `selector1` and
`protonmail`.

SPF is parsed properly, so a hard fail (`-all`) and a softfail (`~all`) are not
the same finding. DMARC reports its real policy, because `p=none` monitors
nothing while `p=reject` is the one that actually stops spoofed mail. DKIM lists
which selectors are really published, not just whether a record exists.

DNSSEC has three states and domainwalk separates all three. No signing at all.
Signed with a `DS` record in the parent zone. And the trap in the middle, a
`DNSKEY` published without a `DS`, which means the zone is signed but nobody
validates the signature.

Every query runs in parallel, one resolver per thread.

### TLS certificates

Connects on port 443 and reads issuer, subject, SANs, validity window and
negotiated protocol version.

The interesting part is what happens when OpenSSL rejects the certificate. Most
tools stop there and hand you a cryptic handshake error. domainwalk reconnects
without verification, only to read the certificate anyway and explain what went
wrong. An expired certificate tells you how many days ago it died and who issued
it. A hostname mismatch tells you which names the certificate does cover.

Wildcard matching follows the real rules. `*.example.com` covers `a.example.com`
but not `example.com` and not `a.b.example.com`.

Expiry thresholds scale with the lifetime of the certificate. A fixed 45 day
warning flags every healthy 90 day ACME certificate for half its life, since
normal renewal passes through that window on every cycle. A 90 day certificate
warns under 14 days and fails under 6. A 398 day certificate keeps the classic
45 and 21.

### HTTP and security headers

Checks whether port 80 redirects to HTTPS without following the redirect. That
detail matters. If you follow it, a broken certificate on the HTTPS side gets
reported as "port 80 did not answer", which is false and sends you looking in the
wrong place. Two different problems, two different findings.

Then it fetches over HTTPS and evaluates `Strict-Transport-Security`,
`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options` (a CSP
`frame-ancestors` directive counts as equivalent), `Referrer-Policy` and the
cross-origin family.

### Well-known paths

Looks for `/.well-known/security.txt` and verifies it carries a `Contact:` line
instead of trusting a bare 200. Also checks `/robots.txt`.

When TLS fails to verify, every HTTPS request would fail with the same error, so
those checks come back marked as not evaluated. One problem, one line, instead of
the same OpenSSL message copied across four findings.

## What makes the report usable

**It hands you the fix.** "Missing Referrer-Policy" sends you to a search engine.
`Referrer-Policy: strict-origin-when-cross-origin` is a line you paste into a
config. Every actionable finding carries the literal value or the concrete step.

**It knows a fact from a problem.** A domain with no `MX` is not broken, it just
does not receive mail. A missing `robots.txt` is not a security issue. Those are
`info` and they never drag the grade down, so a well configured domain comes back
clean. That is what makes the red mean something when it shows up.

**It explains the failure instead of reporting it.** The certificate that OpenSSL
rejects is the clearest case. Knowing that a handshake failed is nearly useless.
Knowing it expired 4,157 days ago and was issued by COMODO tells you the whole
story.

**It is honest about scope.** domainwalk is not a vulnerability scanner, a port
scanner or a fuzzer. It does not read code, audit dependencies or hunt CVEs, and
it never sends a single request that a browser would not send. It checks
configuration, meaning things you fix by publishing a DNS record or adding a line
to a server config.

## Install

Python 3.11 or newer. On Debian and Ubuntu, install `python3-venv` first, since
those distros ship it separately and block `pip` outside a virtualenv.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install "domainwalk[crypto] @ git+https://github.com/FrancisRavn/Domainwalk.git"
```

Or from a clone, which is what you want if you plan to change anything.

```bash
git clone https://github.com/FrancisRavn/Domainwalk.git
cd Domainwalk
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[crypto]"
```

Two runtime dependencies, `dnspython` and `rich`. The `crypto` extra pulls in
`cryptography` and is recommended. Without it, reading a certificate that OpenSSL
rejected falls back to a private CPython API that works today but carries no
stability promise.

## Usage

```bash
domainwalk example.com
domainwalk example.com --json
domainwalk example.com --json -o report.json
domainwalk example.com --timeout 8
```

Input is normalized, so all of these end up the same. A bare domain, a full URL
with path and query string, a `host:port` pair, a trailing dot, or an
internationalized name like `dominó.es`, which becomes `xn--domin-4ta.es`.

Every run makes real DNS queries and real HTTP requests against the domain you
pass. Nothing else, and nothing an ordinary browser would not do.

### Sample output

```
domainwalk  cloudflare.com  OK
ok=19  warn=0  fail=0  info=1  |  2026-08-30T08:54:47+00:00

level   id               detail
INFO    tls.san          Covers cloudflare.com but not www.cloudflare.com
OK      dns.address      A=2 AAAA=2
OK      dns.caa          0 iodef "mailto:tls-abuse@cloudflare.com"; 0 issue "comodoca.com"; ...
OK      dns.dnssec       DS published (1), DNSKEY=2
OK      dns.mx           4 MX
OK      hdr.frame        SAMEORIGIN
OK      hdr.hsts         max-age=31536000; includeSubDomains
OK      hdr.referrer     strict-origin-when-cross-origin
OK      hdr.xcto         nosniff
OK      http.redirect    HTTP 301 -> https://www.cloudflare.com/
OK      https.status     HTTPS 200
OK      mail.dkim        Selectors: k1, s1
OK      mail.dmarc       v=DMARC1; p=reject; sp=reject; adkim=r; aspf=r; pct=100; ...
OK      tls.expiry       Expires in 37 days (2026-10-06T22:47:27+00:00) - 90d lifetime
OK      tls.version      TLSv1.3
OK      wk.robots_txt    https://cloudflare.com/robots.txt
OK      wk.security_txt  https://cloudflare.com/.well-known/security.txt
```

And a domain with problems, where the *How to fix* section does the real work.

```
domainwalk  example.com  FAIL
ok=11  warn=6  fail=1  info=1  |  2026-08-30T09:12:04+00:00

level   id               detail
FAIL    hdr.hsts         No Strict-Transport-Security
WARN    dns.caa          No CAA
WARN    dns.dnssec       No DNSSEC
WARN    hdr.csp          No Content-Security-Policy
WARN    mail.spf         SPF softfail: v=spf1 include:_spf.example.net ~all
WARN    wk.security_txt  https://example.com/.well-known/security.txt -> 404
OK      tls.expiry       Expires in 89 days (2026-11-27T11:37:46+00:00) - 90d lifetime
OK      tls.san          example.com, www.example.com

How to fix
  hdr.hsts         Strict-Transport-Security: max-age=63072000; includeSubDomains
  dns.caa          Add CAA: 0 issue "letsencrypt.org" (adjust for your CA) to limit who can issue.
  dns.dnssec       Enable it at your registrar and publish the DS in the parent zone.
  hdr.csp          Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
  mail.spf         Switch ~all to -all once you confirm all legitimate mail passes.
  wk.security_txt  Publish /.well-known/security.txt with Contact: and Expires: lines.
```

Broken TLS is worth seeing too.

```
domainwalk  expired.badssl.com  FAIL

level   id             detail
FAIL    tls.expiry     Expired 4157 days ago (2015-04-12T23:59:59+00:00)
FAIL    tls.verify     Invalid chain: certificate has expired
INFO    https.skipped  Not evaluated, the certificate does not validate
INFO    wk.skipped     Not evaluated, the certificate does not validate
OK      http.redirect  HTTP 301 -> https://expired.badssl.com/
```

### Comparing two runs

Save a report now, compare against it later. Useful when you are fixing a domain
and want to confirm what actually moved, or when you revisit a domain you audited
months ago.

```bash
domainwalk example.com -o audits/example-2026-08.json
domainwalk example.com --diff audits/example-2026-08.json
```

The comparison flags severity changes as regressions or improvements, findings
that appeared or disappeared, and DNS records added or removed.

```
domainwalk diff  example.com
2026-08-01T07:00:11+00:00  ->  2026-09-01T07:00:09+00:00

Severity changes
  ^ dns.caa     warn -> ok    0 issue "letsencrypt.org"
  v mail.dmarc  ok -> warn    DMARC p=none: v=DMARC1; p=none

DNS records
  + caa  0 issue "letsencrypt.org"
  - dmarc  v=DMARC1; p=quarantine
```

Output is deterministic. Record lists are sorted and hostnames normalized, so the
RRset rotation your resolver performs on every query never shows up as a fake
change. `-o` always writes the plain report, even alongside `--diff`, so any
saved report works as a baseline later. The comparison itself goes to
`--diff-output`, or to stdout with `--json`.

### Muting findings you cannot fix

Some findings are real but unfixable in a given setup. You cannot set custom
response headers on GitHub Pages, for example. Drop a `.domainwalk.toml` in the
working directory, or in `~/.config/domainwalk/config.toml`.

```toml
timeout = 8.0

[mute]
"hdr.*" = "GitHub Pages does not allow custom response headers"
```

Muted findings fall to `INFO`, stop counting toward the grade, and print with
their reason attached, so months later you know why they are quiet. Patterns
work, so `hdr.*` covers every header check. Use `--no-config` to ignore
configuration entirely.

## Exit codes

- `0` nothing red
- `1` at least one failure
- `2` usage error, unreadable config, or the domain does not resolve

## JSON output

`--json` prints the full report, including everything the terminal view trims.
Complete header values, all SANs, every TXT record. Finding ids are stable and
language independent, so they are what any script should key off.

```bash
domainwalk example.com --json | jq '.summary'
domainwalk example.com --json | jq '.dns.findings[] | select(.level == "fail")'
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Nothing touches the network. The TLS and redirect tests spin up local servers on
ephemeral ports. The certificate in `tests/fixtures/` is self signed and exists
only for that, and its private key protects nothing.

The suite covers domain normalization, wildcard SAN matching, expiry threshold
scaling, record sorting, mute semantics, diff behavior, and three integration
paths. Reading a certificate OpenSSL rejected, reporting a redirect without
following it, and checking that both certificate decoders agree so results do not
depend on which extras are installed.

## Implementation notes

- Certificates are decoded with `cryptography` when available. The fallback is
  `ssl._ssl._test_decode_cert`, a private CPython API that works on 3.11 to 3.13
  with no promises beyond that. A test asserts both paths return identical fields.
- Certificate dates use `ssl.cert_time_to_seconds`, which hardcodes month names
  and ignores the locale. Parsing with `strptime` and `%b` raises `ValueError`
  under a non English `LC_TIME`, which is a fun one to debug in production.
- DNS queries and the two network phases run in parallel. Finding order is
  computed at print time, so it never depends on which check finishes first.
- Hostnames are lowercased for `MX`, `NS`, `CNAME`, `DS` and `PTR`. `CAA` values
  are left alone since their parameters can be case sensitive.

## Contributing

Issues and pull requests are welcome. New checks should follow the existing
shape, a stable id, a severity that reflects real impact, and a `fix` that tells
the user exactly what to publish. If a finding cannot be acted on, it is probably
`info`.

## License

MIT, see [LICENSE](LICENSE).
