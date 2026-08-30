# domainwalk

![tests](https://github.com/FrancisRavn/domainwalk/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A command line tool that audits the public attack surface of a domain you own. DNS
records, DNSSEC, SPF, DKIM, DMARC, TLS certificates, HTTP security headers,
`security.txt` and `robots.txt`, all in one pass.

It answers a single question. What does someone see when all they have is your
domain name?

Everything domainwalk reads is already public. Anyone can query your DNS. Your TLS
certificate goes to whoever connects. Your response headers ship with every page.
Nothing here is hidden, and domainwalk doesn't try to find hidden things. It
collects what is already visible and tells you which parts are broken, missing, or
about to expire.

## What it checks

Four collectors run against the domain. Each one produces findings with a
severity (`fail`, `warn`, `info`, `ok`), a stable id, and the exact line to
publish when something needs fixing.

### DNS and email authentication

Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`, `DS` and `DNSKEY`, plus `_dmarc`
and twelve common DKIM selectors including `default`, `google`, `selector1` and
`protonmail`.

SPF gets parsed properly, so a hard fail (`-all`) and a softfail (`~all`) are not
the same finding. DMARC reports its actual policy, because `p=none` monitors
nothing and `p=reject` is the one that stops spoofed mail. DKIM lists which
selectors are really published, not just whether the record exists.

DNSSEC has three states and domainwalk separates all three. No signing. Signed
with a `DS` record in the parent zone. And the trap in the middle, a `DNSKEY`
published without a `DS`, which means your zone is signed but nobody validates the
signature.

Every query runs in parallel, one resolver per thread.

### TLS certificates

Connects on port 443 and reads issuer, subject, SANs, validity window and
negotiated protocol version.

The interesting part happens when OpenSSL rejects the certificate. Most tools stop
there and hand you a cryptic handshake error. domainwalk reconnects without
verification, only to read the certificate anyway and explain what went wrong. An
expired certificate tells you how many days ago it died and who issued it. A
hostname mismatch tells you which names the certificate actually covers.

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
reported as "port 80 never answered", which is false and sends you looking in the
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

## Why bother

**It catches what actually breaks.** Not an attacker. A certificate that quietly
expires on a Sunday, or a DNS edit from six months ago that downgraded your DMARC
policy without telling anyone. Nothing alerts you about these until a user does.

**It hands you the fix.** "Missing Referrer-Policy" sends you to a search engine.
`Referrer-Policy: strict-origin-when-cross-origin` is a line you paste into a
config. Every actionable finding carries the literal value or the concrete step.

**It tracks change, not just state.** This is the part most similar tools skip. A
single report is a snapshot. The useful question is what moved since last time.
Save a report, compare against it later, and you get level changes flagged as
regressions or improvements, findings that appeared or vanished, and DNS records
added or removed. Output is deterministic. Record lists are sorted and hostnames
normalized, so the RRset rotation your resolver performs on every query never
shows up as a fake change.

**It knows a fact from a problem.** A domain with no `MX` is not broken, it just
doesn't receive mail. A missing `robots.txt` is not a security issue. Those are
`info` and they don't drag your grade down. When a real finding is genuinely
unfixable in your setup, like custom response headers on GitHub Pages, you can
mute it with a recorded reason so six months later you know why it's quiet. A red
flag you can never clear is noise you learn to ignore.

**It's clear about scope.** domainwalk is not a vulnerability scanner, a port
scanner or a fuzzer. It doesn't read your code, audit dependencies or hunt CVEs.
It checks configuration, meaning things you fix by publishing a DNS record or
adding a line to your server config. Run it against hosts you own.

## Install

Python 3.11 or newer. On Debian and Ubuntu install `python3-venv` first, since
those distros ship it separately and block `pip` outside a virtualenv.

```bash
sudo apt install python3-venv    # Debian and Ubuntu only
git clone https://github.com/FrancisRavn/domainwalk.git
cd domainwalk
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[crypto]"
```

Two runtime dependencies, `dnspython` and `rich`. The `crypto` extra pulls in
`cryptography` and is recommended. Without it, reading a certificate that OpenSSL
rejected falls back to a private CPython API that works today but carries no
stability promise.

To run without installing the package, from the repository root.

```bash
pip install dnspython rich
python3 -m domainwalk example.com
```

`python3 -m` finds the package because the current directory sits on `sys.path`,
so no `PYTHONPATH` needed. The difference is that `pip install -e .` also gives
you the `domainwalk` command from anywhere.

## Usage

```bash
domainwalk example.com
domainwalk example.com --json
domainwalk example.com --json -o report.json
domainwalk example.com --timeout 8
```

Every run makes real DNS queries and real HTTP requests against the domain you
pass.

Input gets normalized, so all of these end up the same. A bare domain, a full URL
with path and query string, a `host:port` pair, a trailing dot, or an
internationalized name like `dominó.es`, which becomes `xn--domin-4ta.es`.

### Sample output

```
domainwalk  francisravn.com  FAIL
ok=11  warn=8  fail=1  info=1  |  2026-08-30T09:12:04+00:00

level   id               detail
FAIL    hdr.hsts         No Strict-Transport-Security
WARN    dns.caa          No CAA
WARN    dns.dnssec       No DNSSEC
WARN    hdr.csp          No Content-Security-Policy
WARN    hdr.frame        No X-Frame-Options and no CSP frame-ancestors
WARN    hdr.referrer     No Referrer-Policy
WARN    hdr.xcto         No X-Content-Type-Options: nosniff
WARN    mail.spf         SPF softfail: v=spf1 include:_spf.protonmail.ch ~all
WARN    wk.security_txt  https://francisravn.com/.well-known/security.txt -> 404
INFO    wk.robots_txt    https://francisravn.com/robots.txt -> 404
OK      dns.address      A=4 AAAA=4
OK      dns.mx           2 MX
OK      dns.www          francisravn.github.io
OK      http.redirect    HTTP 301 -> https://francisravn.com/
OK      https.status     HTTPS 200
OK      mail.dkim        Selectors: protonmail
OK      mail.dmarc       v=DMARC1; p=quarantine
OK      tls.expiry       Expires in 89 days (2026-11-27T11:37:46+00:00) - 90d lifetime
OK      tls.san          francisravn.com, www.francisravn.com
OK      tls.version      TLSv1.3

How to fix
  hdr.hsts         Strict-Transport-Security: max-age=63072000; includeSubDomains
  dns.caa          Add CAA: 0 issue "letsencrypt.org" (adjust for your CA) to limit who can issue.
  dns.dnssec       Enable it at your registrar and publish the DS in the parent zone.
  hdr.csp          Content-Security-Policy: default-src 'self'; frame-ancestors 'none' (tighten from there)
  hdr.frame        Content-Security-Policy: frame-ancestors 'none' (or X-Frame-Options: DENY)
  hdr.referrer     Referrer-Policy: strict-origin-when-cross-origin
  hdr.xcto         X-Content-Type-Options: nosniff
  mail.spf         Switch ~all to -all once you confirm all legitimate mail passes.
  wk.security_txt  Publish /.well-known/security.txt with Contact: and Expires: lines.
```

And what a comparison against a previous run looks like when something moved.

```
domainwalk diff  francisravn.com
2026-08-01T07:00:11+00:00  ->  2026-09-01T07:00:09+00:00

Severity changes
  ^ dns.caa     warn -> ok    0 issue "letsencrypt.org"
  v mail.dmarc  ok -> warn    DMARC p=none: v=DMARC1; p=none

DNS records
  + caa  0 issue "letsencrypt.org"
  + dmarc  v=DMARC1; p=none
  - dmarc  v=DMARC1; p=quarantine
```

### Comparing against a previous run

```bash
domainwalk example.com -o reports/$(date +%F).json
domainwalk example.com --diff reports/2026-08-01.json
domainwalk example.com --diff reports/2026-08-01.json --diff-output changes.json
```

`-o` always writes the plain report, even when you pass `--diff` in the same
command, so today's file works as tomorrow's baseline. The comparison goes to
`--diff-output`, or to stdout with `--json`.

The diff compares severity levels, not text. A certificate renewal that leaves
`tls.expiry` green produces nothing. A DMARC policy dropping from `reject` to
`none` shows up as a regression. Muted findings get compared at their real
severity, so silencing something never hides a regression inside it.

### Muting what you can't fix

Drop a `.domainwalk.toml` in the working directory, or in
`~/.config/domainwalk/config.toml`.

```toml
timeout = 8.0

[mute]
"hdr.*" = "GitHub Pages doesn't allow custom response headers"
```

Muted findings fall to `INFO`, stop counting toward the grade, and print with
their reason attached. Patterns work, so `hdr.*` covers every header check. Use
`--no-config` to ignore configuration entirely.

## Exit codes

- `0` nothing red
- `1` at least one failure
- `2` usage error, unreadable config, or the domain doesn't resolve

Good enough to use as a CI gate.

## Automated weekly check

`.github/workflows/weekly.yml` audits a domain every Monday, compares it against
the previous run, and opens an issue when something changed.

Set the target in **Settings**, **Secrets and variables**, **Actions**,
**Variables**, as a repository variable named `DOMAIN`. You can also override it
per run from the workflow dispatch form.

The baseline lives on its own `baseline` branch, not on `main`. The bot
force pushes a single file there and never touches your working branch, so you
won't come back on Monday to a diverged `main`. It only moves the baseline when
there was something to report, because otherwise a legitimate change like enabling
DNSSEC would reopen the same issue every week until you fixed the file by hand.

First run creates the branch and opens nothing.

To try it without waiting for Monday, go to **Actions**, pick *weekly check*, then
**Run workflow**.

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
following it, and checking that both certificate decoders agree so your results
don't depend on which extras you installed.

## Implementation notes

- Certificates are decoded with `cryptography` when available. The fallback is
  `ssl._ssl._test_decode_cert`, a private CPython API that works on 3.11 to 3.13
  with no promises beyond that. A test asserts both paths return identical fields.
- Certificate dates use `ssl.cert_time_to_seconds`, which hardcodes month names
  and ignores the locale. Parsing with `strptime` and `%b` raises `ValueError`
  under a non English `LC_TIME`, which is a fun one to debug in production.
- DNS queries and the two network phases run in parallel. Finding order gets
  computed at print time, so it never depends on which check finishes first.
- Hostnames are lowercased for `MX`, `NS`, `CNAME`, `DS` and `PTR`. `CAA` values
  are left alone since their parameters can be case sensitive.

## License

MIT, see [LICENSE](LICENSE).
