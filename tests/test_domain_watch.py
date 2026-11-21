import datetime as dt
import ipaddress
import json
import socket
import ssl
import threading
import urllib.error
import urllib.parse
from datetime import date

import dns.exception
import dns.rdata
import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import domain_watch as dw

TODAY = date(2026, 11, 20)
CFG = {"cert_warn_days": 21, "domain_warn_days": 30, "domains": []}


def rd(rtype, text):
    return dns.rdata.from_text("IN", rtype, text)


class FakeResolver:
    """Answers from a dict of (name, type) -> list of record strings,
    or an exception class to raise."""

    def __init__(self, records):
        self.records = records

    def resolve(self, name, rtype):
        value = self.records.get((name, rtype))
        if value is None:
            raise dns.resolver.NoAnswer()
        if isinstance(value, type) and issubclass(value, Exception):
            raise value()
        return [rd(rtype, v) for v in value]


BASE_DNS = {
    ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "TXT"): ['"v=spf1 -all"'],
    ("example.com", "A"): ["93.184.215.14"],
    ("www.example.com", "CNAME"): ["example.edgesuite.net."],
}

GOOD_TLS = {
    "expires": "2027-03-01", "issuer": "DigiCert Inc", "key": "ECDSA P-256",
    "weak_key": False, "signature": "sha256", "tls_version": "TLSv1.3",
    "fingerprint": "ab12cd34ef567890", "verify_error": "",
}


def issuance(id_, names, issuer="Let's Encrypt", nb="2026-11-19", na="2027-02-17",
             pubkey=None):
    return {"id": id_, "dns_names": names, "issuer": {"friendly_name": issuer},
            "not_before": nb + "T00:00:00Z", "not_after": na + "T00:00:00Z",
            "pubkey": pubkey or {"type": "ecdsa", "curve": "P-256"}}


class FakeNet:
    """Stands in for fetch_json: Cert Spotter pages and RDAP answers."""

    def __init__(self, certs=(), rdap_expiry="2027-08-13", ct_error=None, fail_after=None):
        self.certs = list(certs)
        self.rdap_expiry = rdap_expiry
        self.ct_error = ct_error
        self.fail_after = fail_after  # only fail the request for the page after this id
        self.urls = []

    def __call__(self, url, headers=None, timeout=20):
        self.urls.append(url)
        if url.startswith(dw.CERTSPOTTER_URL):
            query = urllib.parse.parse_qs(url.split("?", 1)[1])
            after = query.get("after", [None])[0]
            if self.ct_error and (self.fail_after is None or after == self.fail_after):
                raise self.ct_error
            ids = [c["id"] for c in self.certs]
            start = ids.index(after) + 1 if after in ids else 0
            return self.certs[start:start + 2]  # two per page
        if url == dw.RDAP_BOOTSTRAP_URL:
            return {"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1/"]]]}
        if url.startswith("https://rdap.verisign.com/com/v1/domain/"):
            events = [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}]
            if self.rdap_expiry:
                events.append({"eventAction": "expiration",
                               "eventDate": self.rdap_expiry + "T04:00:00Z"})
            return {"events": events}
        raise AssertionError(f"unexpected URL {url}")


def domain(name="example.com", hosts=None, ignore=()):
    return {"name": name, "hosts": hosts or [name, "www." + name], "ignore": set(ignore)}


def run(monkeypatch, prev, records=None, net=None, tls=None, d=None):
    monkeypatch.setattr(dw, "fetch_json", net or FakeNet())
    monkeypatch.setattr(dw, "check_tls", lambda host, **kw: dict((tls or {}).get(host, GOOD_TLS)))
    resolver = FakeResolver(records or BASE_DNS)
    servers = dw.load_rdap_bootstrap()
    return dw.check_domain(d or domain(), prev, CFG, resolver, servers, None, TODAY)


# ---------------------------------------------------------------- config

def test_load_config(tmp_path):
    f = tmp_path / "domains.yml"
    f.write_text(
        "domains:\n"
        "  - Example.com.\n"
        "  - name: shop.example.org\n"
        "    hosts: [shop.example.org, api.shop.example.org]\n"
        "    ignore: [a, aaaa]\n"
        "cert_warn_days: 14\n"
    )
    cfg = dw.load_config(f)
    assert cfg["cert_warn_days"] == 14
    assert cfg["domain_warn_days"] == 30
    assert cfg["domains"][0] == {"name": "example.com", "hosts": ["example.com"], "ignore": set()}
    assert cfg["domains"][1]["hosts"] == ["shop.example.org", "api.shop.example.org"]
    assert cfg["domains"][1]["ignore"] == {"A", "AAAA"}


def test_record_text():
    assert dw.record_text("MX", rd("MX", "10 Mail.Example.com.")) == "10 mail.example.com"
    assert dw.record_text("MX", rd("MX", "0 .")) == "0 ."  # null MX
    assert dw.record_text("TXT", rd("TXT", '"v=spf1 " "-all"')) == "v=spf1 -all"
    assert dw.record_text("CAA", rd("CAA", '0 issue "letsencrypt.org"')) == '0 issue "letsencrypt.org"'
    assert dw.record_text("CNAME", rd("CNAME", "Edge.Example.net.")) == "edge.example.net"


# ---------------------------------------------------------------- DNS

def test_first_run_only_saves_a_baseline(monkeypatch):
    report, state = run(monkeypatch, {}, net=FakeNet(certs=[issuance("1", ["example.com"])]))
    assert report.first_run
    assert report.dns_changes == []
    assert report.new_certs == []
    assert not report.needs_issue
    assert "Recorded 1 existing certificate as a baseline" in report.notes
    assert state["dns"]["www.example.com"] == {"CNAME": ["example.edgesuite.net"]}


def test_dns_change_is_reported(monkeypatch):
    _, state = run(monkeypatch, {})
    changed = dict(BASE_DNS)
    changed[("example.com", "MX")] = ["10 mx.attacker.example."]
    report, _ = run(monkeypatch, state, records=changed)
    assert report.dns_changes == [
        "example.com MX: added `10 mx.attacker.example`; removed `10 mail.example.com`"]
    assert report.needs_issue


def test_failed_lookup_keeps_last_values(monkeypatch):
    _, state = run(monkeypatch, {})
    flaky = dict(BASE_DNS)
    flaky[("example.com", "MX")] = dns.exception.Timeout
    report, new_state = run(monkeypatch, state, records=flaky)
    assert report.dns_changes == []
    assert new_state["dns"]["example.com"]["MX"] == ["10 mail.example.com"]
    assert any("DNS lookup failed for example.com MX" in n for n in report.notes)


def test_deleted_record_is_reported(monkeypatch):
    _, state = run(monkeypatch, {})
    gone = dict(BASE_DNS)
    del gone[("example.com", "MX")]
    report, _ = run(monkeypatch, state, records=gone)
    assert report.dns_changes == ["example.com MX: removed `10 mail.example.com`"]


def test_ignored_types_are_skipped(monkeypatch):
    _, state = run(monkeypatch, {}, d=domain(ignore=["A", "AAAA"]))
    assert "A" not in state["dns"]["example.com"]
    assert "NS" in state["dns"]["example.com"]


def test_non_alias_host_tracks_addresses(monkeypatch):
    records = dict(BASE_DNS)
    del records[("www.example.com", "CNAME")]
    records[("www.example.com", "A")] = ["93.184.215.14"]
    _, state = run(monkeypatch, {}, records=records)
    assert state["dns"]["www.example.com"] == {"A": ["93.184.215.14"], "AAAA": []}


# ---------------------------------------------------------------- CT logs

def test_new_certificate_after_baseline(monkeypatch):
    certs = [issuance("1", ["example.com"]), issuance("2", ["www.example.com"]),
             issuance("3", ["example.com"])]
    _, state = run(monkeypatch, {}, net=FakeNet(certs=certs))
    assert state["ct_cursor"] == "3"

    certs.append(issuance("4", ["vpn.example.com", "example.com"], issuer="Sectigo",
                          pubkey={"type": "rsa", "bit_length": 2048}))
    report, state = run(monkeypatch, state, net=FakeNet(certs=certs))
    assert report.new_certs == [
        "vpn.example.com, example.com: issued by Sectigo, valid 2026-11-19 to 2027-02-17, RSA-2048"]
    assert state["ct_cursor"] == "4"


def test_first_certificate_after_an_empty_baseline_is_reported(monkeypatch):
    _, state = run(monkeypatch, {}, net=FakeNet(certs=[]))
    assert state["ct_baselined"] is True
    report, _ = run(monkeypatch, state, net=FakeNet(certs=[issuance("9", ["example.com"])]))
    assert len(report.new_certs) == 1


def test_baseline_can_take_more_than_one_run(monkeypatch):
    monkeypatch.setattr(dw, "CT_MAX_PAGES", 2)
    certs = [issuance(str(i), ["example.com"]) for i in range(1, 6)]
    report, state = run(monkeypatch, {}, net=FakeNet(certs=certs))
    assert (state["ct_cursor"], state["ct_baselined"]) == ("4", False)
    assert any("next run continues" in n for n in report.notes)

    # Cert 5 is still part of the backlog, not a new certificate.
    report, state = run(monkeypatch, state, net=FakeNet(certs=certs))
    assert report.new_certs == []
    assert (state["ct_cursor"], state["ct_baselined"]) == ("5", True)

    certs.append(issuance("6", ["new.example.com"]))
    report, _ = run(monkeypatch, state, net=FakeNet(certs=certs))
    assert [c.split(":")[0] for c in report.new_certs] == ["new.example.com"]


def test_error_partway_keeps_the_pages_already_read(monkeypatch):
    certs = [issuance(str(i), [f"h{i}.example.com"]) for i in range(1, 6)]
    _, state = run(monkeypatch, {}, net=FakeNet(certs=certs[:2]))

    limited = urllib.error.HTTPError(dw.CERTSPOTTER_URL, 429, "Too Many Requests", {}, None)
    report, state = run(monkeypatch, state,
                        net=FakeNet(certs=certs, ct_error=limited, fail_after="4"))
    assert [c.split(":")[0] for c in report.new_certs] == ["h3.example.com", "h4.example.com"]
    assert state["ct_cursor"] == "4"

    report, _ = run(monkeypatch, state, net=FakeNet(certs=certs))
    assert [c.split(":")[0] for c in report.new_certs] == ["h5.example.com"]


def test_rate_limit_keeps_cursor(monkeypatch):
    certs = [issuance("1", ["example.com"])]
    _, state = run(monkeypatch, {}, net=FakeNet(certs=certs))
    limited = urllib.error.HTTPError(dw.CERTSPOTTER_URL, 429, "Too Many Requests", {}, None)
    report, new_state = run(monkeypatch, state, net=FakeNet(certs=certs, ct_error=limited))
    assert new_state["ct_cursor"] == "1"
    assert new_state["ct_baselined"] is True
    assert any("rate limited" in n for n in report.notes)


def test_long_names_list_is_shortened():
    item = issuance("1", [f"h{i}.example.com" for i in range(7)])
    assert "(+3 more)" in dw.describe_issuance(item)


# ---------------------------------------------------------------- registration

def test_registration_expiry_is_recorded(monkeypatch):
    report, state = run(monkeypatch, {})
    assert report.registration == "2027-08-13"
    assert state["registration"] == "2027-08-13"
    assert report.problems == {}


def test_registration_about_to_expire(monkeypatch):
    report, _ = run(monkeypatch, {}, net=FakeNet(rdap_expiry="2026-12-05"))
    assert report.new_problems == ["example.com: registration expires in 15 days (2026-12-05)"]
    assert report.needs_issue


def test_unknown_tld_is_a_note_not_an_error(monkeypatch):
    monkeypatch.setattr(dw, "fetch_json", FakeNet())
    servers = dw.load_rdap_bootstrap()
    assert dw.registration_expiry("example.zz", servers) == (None, "no RDAP service for .zz")


# ---------------------------------------------------------------- problems

def test_tls_problems():
    weak = dict(GOOD_TLS, key="RSA-1024", weak_key=True, signature="sha1", tls_version="TLSv1.1")
    found = dw.tls_problems("old.example.com", weak, 21, TODAY)
    assert set(found) == {"weak-key:old.example.com", "weak-signature:old.example.com",
                          "old-tls:old.example.com"}

    expired = dict(GOOD_TLS, expires="2026-11-01", verify_error="certificate has expired")
    assert set(dw.tls_problems("a.example.com", expired, 21, TODAY)) == {"cert-expired:a.example.com"}

    untrusted = dict(GOOD_TLS, verify_error="self-signed certificate")
    assert set(dw.tls_problems("b.example.com", untrusted, 21, TODAY)) == {"cert-invalid:b.example.com"}

    assert dw.tls_problems("c.example.com", {"error": "Connection refused"}, 21, TODAY) == {
        "tls-error:c.example.com": "c.example.com: TLS connection failed (Connection refused)"}


def test_problem_alerts_once_then_escalates(monkeypatch):
    soon = {"example.com": dict(GOOD_TLS, expires="2026-12-05")}
    report, state = run(monkeypatch, {}, tls=soon)
    assert report.new_problems == ["example.com: certificate expires in 15 days (2026-12-05)"]

    report, state = run(monkeypatch, state, tls=soon)
    assert report.new_problems == []
    assert len(report.problems) == 1

    urgent = {"example.com": dict(GOOD_TLS, expires="2026-11-25")}
    report, state = run(monkeypatch, state, tls=urgent)
    assert report.new_problems == ["example.com: certificate expires in 5 days (2026-11-25)"]

    report, state = run(monkeypatch, state)
    assert report.resolved == ["cert-expiring-urgent:example.com"]
    assert state["problems"] == {}


def test_state_is_stable_between_identical_runs(monkeypatch):
    soon = {"example.com": dict(GOOD_TLS, expires="2026-12-05")}
    _, first = run(monkeypatch, {}, tls=soon)
    _, second = run(monkeypatch, first, tls=soon)
    assert json.dumps(second, sort_keys=True) == json.dumps(first, sort_keys=True)


# ---------------------------------------------------------------- output

def test_render_issue_and_status(monkeypatch):
    _, state = run(monkeypatch, {})
    changed = dict(BASE_DNS)
    changed[("example.com", "TXT")] = ['"v=spf1 include:mail.example.net -all"']
    report, _ = run(monkeypatch, state, records=changed,
                    tls={"www.example.com": dict(GOOD_TLS, expires="2026-11-24")})
    body = dw.render_issue([report])
    assert body.startswith("## example.com")
    assert "**DNS changes**" in body
    assert "www.example.com: certificate expires in 4 days" in body

    status = dw.render_status([report], TODAY)
    assert "_Last refreshed: 2026-11." in status
    assert "| www.example.com | 2026-11-24 | DigiCert Inc | ECDSA P-256 | TLSv1.3 |" in status
    assert "| example.com | 2027-08-13 | 1 |" in status


# ---------------------------------------------------------------- main

def write_config(tmp_path):
    cfg = tmp_path / "domains.yml"
    cfg.write_text("domains:\n  - name: example.com\n    hosts: [example.com]\n")
    return cfg


def days_from_now(n):
    # main() uses the real date, so these tests can't use TODAY.
    return (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=n)).isoformat()


def patch_main(monkeypatch, net):
    monkeypatch.setattr(dw, "fetch_json", net)
    monkeypatch.setattr(dw, "make_resolver", lambda: FakeResolver(BASE_DNS))
    monkeypatch.setattr(dw, "check_tls", lambda host, **kw: dict(GOOD_TLS, expires=days_from_now(4)))


def test_main_opens_issue_and_saves_state(tmp_path, monkeypatch):
    patch_main(monkeypatch, FakeNet())
    opened = []
    monkeypatch.setattr(dw, "open_issue", lambda *a: opened.append(a) or "https://github.com/o/r/issues/1")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

    args = ["-c", str(write_config(tmp_path)), "--state-dir", str(tmp_path / "state"),
            "--status-file", str(tmp_path / "STATUS.md")]
    assert dw.main(args) == 0
    assert len(opened) == 1
    assert "certificate expires in 4 days" in opened[0][3]
    assert (tmp_path / "state" / "example.com.json").exists()
    assert "example.com" in (tmp_path / "STATUS.md").read_text()
    assert "domain-watch run" in summary.read_text()

    # Second run: same problem, nothing new, so no second issue.
    assert dw.main(args) == 0
    assert len(opened) == 1


def test_main_keeps_old_state_when_issue_fails(tmp_path, monkeypatch):
    patch_main(monkeypatch, FakeNet())

    def boom(*a):
        raise urllib.error.URLError("network down")

    monkeypatch.setattr(dw, "open_issue", boom)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    args = ["-c", str(write_config(tmp_path)), "--state-dir", str(tmp_path / "state"),
            "--status-file", str(tmp_path / "STATUS.md")]
    assert dw.main(args) == 1
    assert not (tmp_path / "state" / "example.com.json").exists()


def test_main_with_no_domains(tmp_path, capsys):
    cfg = tmp_path / "domains.yml"
    cfg.write_text("domains: []\n")
    assert dw.main(["-c", str(cfg)]) == 0
    assert "No domains configured" in capsys.readouterr().out


# ---------------------------------------------------------------- real TLS

def make_cert(days_valid, key=None, ca=None, cn="localhost"):
    key = key or ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer_key, issuer_name = (ca[0], ca[1].subject) if ca else (key, name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=10))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if ca is None:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                        critical=True)
    return key, builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def start(key, cert, ca_cert=None):
        (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tmp_path / "key.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        ca_file = tmp_path / "ca.pem"
        ca_file.write_bytes((ca_cert or cert).public_bytes(serialization.Encoding.PEM))

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # so the weak-key test can serve RSA-1024
        ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        sock.settimeout(0.2)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except OSError:
                    continue
                conn.settimeout(5)
                try:
                    with ctx.wrap_socket(conn, server_side=True):
                        pass
                except OSError:
                    pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        servers.append((stop, thread, sock))
        return sock.getsockname()[1], str(ca_file)

    yield start
    for stop, thread, sock in servers:
        stop.set()
        thread.join(timeout=2)
        sock.close()


def test_check_tls_healthy(tls_server):
    ca_key, ca_cert = make_cert(3650, cn="domain-watch test CA")
    key, cert = make_cert(90, ca=(ca_key, ca_cert))
    port, ca_file = tls_server(key, cert, ca_cert)
    info = dw.check_tls("localhost", port=port, cafile=ca_file)
    assert info["verify_error"] == ""
    assert info["key"] == "ECDSA P-256"
    assert info["weak_key"] is False
    assert info["signature"] == "sha256"
    assert info["tls_version"] in ("TLSv1.2", "TLSv1.3")


def test_check_tls_untrusted_still_reads_cert(tls_server):
    key, cert = make_cert(90)
    port, _ = tls_server(key, cert)
    info = dw.check_tls("localhost", port=port)
    assert info["verify_error"]
    assert info["expires"] == cert.not_valid_after_utc.strftime("%Y-%m-%d")


def test_check_tls_weak_key(tls_server):
    key, cert = make_cert(90, key=rsa.generate_private_key(public_exponent=65537, key_size=1024))
    port, ca_file = tls_server(key, cert)
    info = dw.check_tls("localhost", port=port, cafile=ca_file)
    assert info["key"] == "RSA-1024"
    assert info["weak_key"] is True


def test_check_tls_nothing_listening():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert "error" in dw.check_tls("127.0.0.1", port=port, timeout=2)
