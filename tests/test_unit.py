"""Tests that never touch the network."""

from __future__ import annotations

import pytest

from domainwalk.cli import normalize_domain
from domainwalk.config import Config, apply_mutes, load_config, mute_reason
from domainwalk.diff import diff_reports
from domainwalk.dns_checks import _sorted_records
from domainwalk.findings import finding, score, sort_findings
from domainwalk.http_checks import expiry_thresholds, host_matches


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("francisravn.com", "francisravn.com"),
        ("HTTPS://Francisravn.com/x?y=1", "francisravn.com"),
        ("francisravn.com:8443/", "francisravn.com"),
        ("francisravn.com.", "francisravn.com"),
        ("  francisravn.com  ", "francisravn.com"),
        ("dominó.es", "xn--domin-4ta.es"),
        ("[2001:db8::1]:443", "2001:db8::1"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "http://", "..es"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "host,patterns,expected",
    [
        ("example.com", ["example.com"], True),
        ("a.example.com", ["*.example.com"], True),
        ("example.com", ["*.example.com"], False),  # a wildcard does not cover the apex
        ("a.b.example.com", ["*.example.com"], False),  # nor two levels down
        ("EXAMPLE.com", ["example.com."], True),
        ("wrong.host.badssl.com", ["*.badssl.com", "badssl.com"], False),
    ],
)
def test_host_matches(host, patterns, expected):
    assert host_matches(host, patterns) is expected


def test_sorted_records_is_stable():
    ips = ["185.199.111.153", "185.199.108.153", "185.199.110.153"]
    assert _sorted_records("A", ips) == _sorted_records("A", list(reversed(ips)))
    assert _sorted_records("A", ips)[0] == "185.199.108.153"


def test_mx_sorts_by_priority_not_by_string():
    # Sorted as text, "100 z" would land before "20 a". That would be a bug.
    assert _sorted_records("MX", ["100 z.example", "20 a.example"]) == ["20 a.example", "100 z.example"]


def test_score_ignores_info_for_grade():
    findings = [finding("ok", "a", "x"), finding("info", "b", "y"), finding("warn", "c", "z")]
    result = score(findings)
    assert result == {"ok": 1, "warn": 1, "fail": 0, "info": 1, "grade": "WARN"}
    assert score([finding("ok", "a", "x"), finding("info", "b", "y")])["grade"] == "OK"


def test_sort_findings_order():
    findings = [finding("ok", "z", ""), finding("info", "i", ""), finding("fail", "f", ""), finding("warn", "w", "")]
    assert [f["level"] for f in sort_findings(findings)] == ["fail", "warn", "info", "ok"]


def _report(findings, **dns):
    report = {"domain": "example.com", "dns": {"findings": findings, **dns}}
    report["summary"] = score(findings)
    return report


def test_mute_downgrades_and_keeps_original_level():
    report = _report([finding("fail", "hdr.hsts", "No HSTS"), finding("warn", "dns.caa", "No CAA")])
    apply_mutes(report, {"hdr.*": "Pages does not allow headers"})
    item = report["dns"]["findings"][0]
    assert item["level"] == "info"
    assert item["original_level"] == "fail"
    assert item["mute_reason"] == "Pages does not allow headers"
    assert report["summary"]["grade"] == "WARN"  # the unmuted warn still decides
    assert report["summary"]["muted"] == 1


def test_mute_reason_patterns():
    mute = {"hdr.*": "by pattern", "dns.caa": "exact"}
    assert mute_reason("dns.caa", mute) == "exact"
    assert mute_reason("hdr.csp", mute) == "by pattern"
    assert mute_reason("tls.expiry", mute) is None


def test_load_config(tmp_path):
    (tmp_path / ".domainwalk.toml").write_text('timeout = 3.5\n[mute]\n"hdr.hsts" = "reason"\n', encoding="utf-8")
    config = load_config(cwd=tmp_path)
    assert config.timeout == 3.5
    assert config.mute == {"hdr.hsts": "reason"}


def test_load_config_missing_explicit(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "does-not-exist.toml"))


def test_load_config_absent_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("domainwalk.config.USER_CONFIG", tmp_path / "none.toml")
    assert load_config(cwd=tmp_path) == Config()


def test_diff_detects_regression_and_fix():
    old = _report([finding("ok", "mail.dmarc", "p=reject"), finding("warn", "dns.caa", "No CAA")], a=["1.1.1.1"])
    new = _report([finding("warn", "mail.dmarc", "DMARC p=none"), finding("fail", "tls.expiry", "Expired")], a=["2.2.2.2"])
    old["generated_at"], new["generated_at"] = "2026-01-01T00:00:00+00:00", "2026-02-01T00:00:00+00:00"

    result = diff_reports(old, new)
    assert result["unchanged"] is False
    changed = {c["id"]: c for c in result["findings"]["changed"]}
    assert changed["mail.dmarc"]["direction"] == "worse"
    assert [f["id"] for f in result["findings"]["new"]] == ["tls.expiry"]
    assert [f["id"] for f in result["findings"]["resolved"]] == ["dns.caa"]
    assert result["records"]["a"] == {"added": ["2.2.2.2"], "removed": ["1.1.1.1"]}


def test_diff_unchanged():
    findings = [finding("ok", "dns.address", "A=1 AAAA=0")]
    result = diff_reports(_report(findings), _report(findings))
    assert result["unchanged"] is True


def test_diff_sees_through_mute():
    """A muted regression still shows up in the diff."""
    old = _report([finding("ok", "hdr.hsts", "max-age=...")])
    new = _report([finding("fail", "hdr.hsts", "No HSTS")])
    apply_mutes(new, {"hdr.hsts": "Pages"})
    changed = diff_reports(old, new)["findings"]["changed"]
    assert changed[0]["to"] == "fail"


def test_record_reordering_is_not_a_diff():
    """The resolver rotates the RRset. That is not a real change."""
    old = _report([], a=["185.199.108.153", "185.199.111.153"])
    new = _report([], a=["185.199.111.153", "185.199.108.153"])
    assert diff_reports(old, new)["records"] == {}


@pytest.mark.parametrize(
    "lifetime,days_left,expected",
    [
        # A 90 day ACME certificate with 38 days left is healthy renewal, not a
        # warning. With the old fixed 45 day threshold this was always yellow.
        (90, 38, "ok"),
        (90, 12, "warn"),
        (90, 5, "fail"),
        # Yearly certificate keeps the classic thresholds.
        (398, 60, "ok"),
        (398, 30, "warn"),
        (398, 15, "fail"),
        # Short 47 day certificate.
        (47, 20, "ok"),
        (47, 5, "warn"),
        (47, 2, "fail"),
    ],
)
def test_expiry_thresholds_scale_with_lifetime(lifetime, days_left, expected):
    fail_at, warn_at = expiry_thresholds(lifetime)
    level = "fail" if days_left < fail_at else "warn" if days_left < warn_at else "ok"
    assert level == expected


def test_expiry_thresholds_fallback_without_lifetime():
    assert expiry_thresholds(None) == (21, 45)
    assert expiry_thresholds(0) == (21, 45)


def test_expiry_thresholds_are_ordered():
    for lifetime in (1, 7, 30, 47, 90, 180, 398, 825):
        fail_at, warn_at = expiry_thresholds(lifetime)
        assert 0 < fail_at < warn_at


def test_hostnames_are_lowercased():
    """Example.GitHub.io and example.github.io are the same record."""
    assert _sorted_records("CNAME", ["FrancisRavn.github.io"]) == ["francisravn.github.io"]
    assert _sorted_records("NS", ["NS1.Example.COM"]) == ["ns1.example.com"]


def test_capitalization_change_is_not_a_diff():
    old = _report([], www_cname=["FrancisRavn.github.io"])
    new = _report([], www_cname=["francisravn.github.io"])
    # The value arrives normalized from _sorted_records, so the diff must not see it.
    old["dns"]["www_cname"] = _sorted_records("CNAME", old["dns"]["www_cname"])
    new["dns"]["www_cname"] = _sorted_records("CNAME", new["dns"]["www_cname"])
    assert diff_reports(old, new)["records"] == {}
