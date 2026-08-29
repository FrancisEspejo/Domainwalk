# domainwalk

![tests](https://github.com/FrancisRavn/Domainwalker/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

**A public-surface auditor for your own domain.** It answers one question: what does
someone who doesn't know you see when all they have is your domain name?

Everything domainwalk looks at is public by design. DNS records are meant to be
queried by anyone. Your TLS certificate is handed to whoever connects. Your
response headers travel with every page you serve. domainwalk doesn't discover
anything hidden — it collects what is already in plain sight and tells you which
parts are misconfigured, missing, or about to break.

## What it actually checks

Four independent collectors run against the domain, each producing findings with
a severity level (`fail`, `warn`, `info`, `ok`), a stable identifier, and — when
something needs fixing — the exact line to publish.

**DNS and mail authentication.** Resolves `A`, `AAAA`, `MX`, `NS`, `TXT`, `CAA`,
`DS`, and `DNSKEY`, plus `_dmarc` and a dozen common DKIM selectors
(`default`, `google`, `selector1`, `protonmail`, `k1`, and others). It parses SPF
to distinguish a hard fail (`-all`) from a softfail (`~all`), reads the DMARC
policy to tell `p=none` from `p=quarantine` and `p=reject`, and reports which DKIM
selectors are actually published. For DNSSEC it separates three states: no signing
at all, signed with a `DS` in the parent zone, and the trap in between — a `DNSKEY`
published with no `DS`, meaning the zone is signed but nobody validates the
signature. All queries run concurrently in a thread pool, with one resolver per
thread.

**TLS.** Opens a connection on port 443 and inspects the certificate: issuer,
subject, SANs, validity window, negotiated protocol version. When OpenSSL
*rejects* the certificate, domainwalk reconnects without verification — solely to
read the certificate anyway and tell you *why* it failed, rather than surfacing an
opaque handshake error. So an expired certificate reports how many days ago it
expired and who issued it; a hostname mismatch reports which names the certificate
does cover. SAN matching implements wildcard semantics correctly: `*.example.com`
matches `a.example.com` but neither `example.com` nor `a.b.example.com`.

Expiry thresholds scale with the certificate's own lifetime. A fixed 45-day
warning marks every healthy 90-day ACME certificate as a problem for half its
life, because normal renewal passes through that window every cycle. A 90-day
certificate warns under 14 days and fails under 6; a 398-day certificate keeps the
classic 45/21.

**HTTP.** Checks whether port 80 redirects to HTTPS *without following the
redirect*, so it can distinguish "port 80 never answered" from "port 80 redirected
correctly but the HTTPS destination is broken" — two very different problems that
naive tooling reports identically. Then it fetches over HTTPS and evaluates
`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`,
`X-Frame-Options` (accepting a CSP `frame-ancestors` directive as equivalent),
`Referrer-Policy`, and related headers.

**Well-known paths.** Looks for `/.well-known/security.txt` (verifying it actually
carries a `Contact:` line, not just a 200) and `/robots.txt`.

When TLS fails to verify, every HTTPS request would fail with the same error, so
those checks are marked *not evaluated* instead of repeating one OpenSSL message
across four findings. One problem, one line.

## Why it's worth running

**It catches the failure that actually happens to you.** Not an attacker — a
certificate quietly expiring on a Sunday, or a DNS change from six months ago that
silently downgraded your DMARC policy. These break in ways nothing alerts you
about until a user tells you.

**It tells you what to type, not just what's wrong.** "Missing Referrer-Policy"
sends you to a search engine. `Referrer-Policy: strict-origin-when-cross-origin`
is something you paste into a config file. Every actionable finding carries the
literal value or the concrete step.

**It tracks change, not just state.** This is the part most similar tools don't
do. A single report is a snapshot; the interesting question is usually what moved
since last time. Save a report, compare against it later, and you get level
changes marked as improvements or regressions, findings that appeared or
disappeared, and DNS records added or removed. Output is deterministic — record
lists are sorted, hostnames normalized to lowercase — so the RRset rotation your
resolver performs on every query doesn't show up as a phantom change.

**It knows the difference between a problem and a fact.** A domain with no `MX`
isn't broken; it just doesn't receive mail. A missing `robots.txt` isn't a
security finding. These are `info`, and they don't drag your grade down. And when
a real finding is genuinely unfixable in your environment — you can't set response
headers on GitHub Pages — you can mute it *with a recorded reason*, so six months
from now you know why it's silenced. A red flag you can't clear is noise you learn
to ignore.

**It's honest about scope.** domainwalk is not a vulnerability scanner, a port
scanner, or a fuzzer. It doesn't read your code, audit your dependencies, or look
for CVEs. It checks configuration — things you fix by publishing a DNS record or
adding a line to your server config. Run it against hosts you own.

## Install

```bash
git clone https://github.com/FrancisRavn/Domainwalker.git
cd Domainwalker
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or without installing the package, from the repository root:

```bash
pip install -r requirements.txt
python3 -m domainwalk francisravn.com
```

`python3 -m` finds the package because the current directory is on `sys.path`; no
`PYTHONPATH` needed. The difference is that `pip install -e .` also makes the
`domainwalk` command available from anywhere.

Requires Python 3.11 or newer. Two dependencies: `dnspython` and `rich`.

## Usage

```bash
domainwalk francisravn.com
domainwalk francisravn.com --json
domainwalk francisravn.com --json -o report.json
domainwalk francisravn.com --timeout 8
```

Every run performs real DNS queries and HTTP requests against the domain you pass.

Input is normalized, so all of these are equivalent: a bare domain, a full URL
with path and query string, a `host:port` pair, a trailing dot, or an
internationalized name (`dominó.es` becomes `xn--domin-4ta.es`).

### Sample output

```
domainwalk  francisravn.com  FAIL
ok=11  warn=8  fail=1  info=0  ·  2026-08-29T17:47:14+00:00

level   id               detail
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
  - dns.caa     Add CAA: 0 issue "letsencrypt.org" (adjust for your CA)
  - dns.dnssec  Enable it at your registrar and publish the DS in the parent zone.
  - mail.spf    Switch ~all to -all once you confirm all legitimate mail passes.
```

Finding messages are currently in Spanish; the identifiers are stable and
language-independent, which is what tooling should key off.

### Comparing against a previous run

```bash
domainwalk francisravn.com -o reports/$(date +%F).json
domainwalk francisravn.com --diff reports/2026-08-01.json
domainwalk francisravn.com --diff reports/2026-08-01.json --diff-output changes.json
```

`-o` always writes the plain report, even when `--diff` is used in the same
command, so today's file is a valid baseline for tomorrow's comparison. The
comparison result goes to `--diff-output`, or to stdout with `--json`.

The diff is level-based, not text-based: a certificate renewal that leaves
`tls.expiry` green produces no noise, but a DMARC policy dropping from `reject` to
`none` shows up as a regression. Muted findings are compared at their real
severity, so silencing something never hides a regression in it.

### Muting what you can't fix

Create a `.domainwalk.toml` in the repository root (or
`~/.config/domainwalk/config.toml`):

```toml
timeout = 8.0

[mute]
"hdr.*" = "GitHub Pages doesn't allow custom response headers"
```

Muted findings drop to `INFO`, stop counting toward the grade, and are printed
with their reason. Patterns are supported, so `hdr.*` covers every header check.
Run with `--no-config` to ignore configuration entirely.

## Exit codes

- `0` — nothing red
- `1` — at least one failure
- `2` — usage error, unreadable configuration, or the domain doesn't resolve

That makes it usable as a CI gate.

## Automated weekly check

`.github/workflows/weekly.yml` audits the domain every Monday, compares it against
`baseline.json`, and opens an issue if anything changed.

`baseline.json` is the last known state, not an ideal snapshot: the workflow
updates it in the same commit that opens the issue. Without that, a legitimate
change — enabling DNSSEC, say — would reopen the same issue every week until you
updated it by hand. What you see in the repository is therefore the state of the
domain the last time something moved.

If `baseline.json` doesn't exist, the first run creates it without opening an
issue.

To test it without waiting for Monday: **Actions** → *chequeo semanal* → **Run
workflow**.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Nothing touches the network. The TLS and redirect tests spin up local servers on
ephemeral ports; the certificate in `tests/fixtures/` is self-signed and exists
only for that — its private key protects nothing.

The suite covers domain normalization, wildcard SAN matching, expiry threshold
scaling, record sorting, mute semantics, diff behavior, and the two integration
paths that matter most: reading a certificate OpenSSL rejected, and reporting a
redirect without following it.

## Implementation notes

- Reading a rejected certificate uses `ssl._ssl._test_decode_cert`, a private
  CPython API — stable across 3.11–3.13 but not guaranteed. Swap `_decode_der` for
  `cryptography.x509` if you want a supported path.
- Certificate dates are parsed with `ssl.cert_time_to_seconds`, which hardcodes
  month names and is therefore locale-independent. Using `strptime` with `%b`
  raises `ValueError` under a non-English `LC_TIME`.
- DNS queries and the two network phases run in parallel; finding order is
  computed at print time, so it never depends on which check finishes first.
- Hostnames are lowercased for `MX`, `NS`, `CNAME`, `DS`, and `PTR`. `CAA` values
  are left alone because their parameters may be case-sensitive.

## License

MIT — see [LICENSE](LICENSE).
