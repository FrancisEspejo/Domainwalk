# Security policy

If you find a security problem in domainwalk, email **fran@francisravn.com**
instead of opening a public issue. I try to reply within a week.

Include the version (`domainwalk --version`), the domain or scenario that
reproduces it, and what you expected to happen.

## Scope

domainwalk only reads public information. DNS queries, the certificate a host
presents, and HTTP response headers. It does not authenticate, does not send data
anywhere, and stores nothing beyond the files you ask for with `-o`.

JSON reports contain the full DNS records of the audited domain. Those are public
by definition, but keep it in mind before uploading them to someone else's
repository.
