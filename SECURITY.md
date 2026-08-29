# Security policy

If you find a security issue in domainwalk, email **fran@francisravn.com** instead of opening a public issue. I try to reply within a week.

Include the version (`domainwalk --version`), the domain or the scenario you can reproduce it with, and what you expected to happen.

## Scope

domainwalk only reads public information: DNS queries, the certificate the host presents, and HTTP response headers. It does not authenticate, it does not send data to third parties, and it does not store anything beyond the files you ask for with `-o`.

JSON reports include the full DNS records of the domain under audit. Those records are public by definition, but keep that in mind before you push them to someone else’s repo.
