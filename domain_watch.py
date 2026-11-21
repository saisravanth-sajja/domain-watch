#!/usr/bin/env python3
"""Watch your domains for DNS changes, new certificates and upcoming expiry.

Meant to run on a schedule in GitHub Actions. Each run compares what it sees
with the snapshot saved by the previous run (under state/), rewrites
STATUS.md, and opens one GitHub issue when something changed or needs
attention.
"""

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

import dns.exception
import dns.resolver
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

USER_AGENT = "domain-watch (https://github.com/saisravanth-sajja/domain-watch)"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

APEX_TYPES = ["NS", "MX", "TXT", "CAA", "A", "AAAA"]
HOST_TYPES = ["A", "AAAA"]
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
OLD_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}
URGENT_DAYS = 7
CT_MAX_PAGES = 20  # per run; a bigger backlog gets picked up over the next runs
NET_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, ValueError, KeyError)


# ---------------------------------------------------------------- config

def load_config(path):
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    domains = []
    for item in raw.get("domains") or []:
        if isinstance(item, str):
            item = {"name": item}
        name = clean_name(item["name"])
        hosts = [clean_name(h) for h in item.get("hosts") or [name]]
        ignore = {str(t).upper() for t in item.get("ignore") or []}
        domains.append({"name": name, "hosts": hosts, "ignore": ignore})

    return {
        "cert_warn_days": int(raw.get("cert_warn_days", 21)),
        "domain_warn_days": int(raw.get("domain_warn_days", 30)),
        "domains": domains,
    }


def clean_name(name):
    return str(name).strip().lower().rstrip(".")


# ---------------------------------------------------------------- DNS

def make_resolver():
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 10
    return resolver


def record_text(rtype, r):
    if rtype in ("A", "AAAA"):
        return r.address
    if rtype in ("CNAME", "NS"):
        return clean_name(r.target.to_text())
    if rtype == "MX":
        return f"{r.preference} {clean_name(r.exchange.to_text())}"
    if rtype == "TXT":
        return b"".join(r.strings).decode("utf-8", "replace")
    if rtype == "CAA":
        return f'{r.flags} {r.tag.decode()} "{r.value.decode()}"'
    return r.to_text()


def lookup(resolver, name, rtype):
    """Sorted record values, [] if there are none, or None if the lookup failed."""
    try:
        answer = resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return sorted(record_text(rtype, r) for r in answer)


def lookup_types(resolver, name, types, ignore, old, failed):
    records = {}
    for rtype in types:
        if rtype in ignore:
            continue
        values = lookup(resolver, name, rtype)
        if values is None:
            # A failed lookup keeps last run's values instead of
            # looking like the records were deleted.
            failed.append(f"{name} {rtype}")
            if rtype in old:
                records[rtype] = old[rtype]
            continue
        records[rtype] = values
    return records


def snapshot_dns(domain, resolver, previous):
    snap, failed = {}, []
    name = domain["name"]
    snap[name] = lookup_types(resolver, name, APEX_TYPES, domain["ignore"],
                              previous.get(name, {}), failed)

    for host in domain["hosts"]:
        if host == name:
            continue
        old = previous.get(host, {})
        cname = lookup(resolver, host, "CNAME")
        if cname is None:
            failed.append(f"{host} CNAME")
            snap[host] = dict(old)
        elif cname and "CNAME" not in domain["ignore"]:
            # An alias: track where it points, not the IPs behind it,
            # since those often rotate.
            snap[host] = {"CNAME": cname}
        else:
            snap[host] = lookup_types(resolver, host, HOST_TYPES, domain["ignore"], old, failed)
    return snap, failed


def diff_dns(old, new):
    changes = []
    for name in sorted(new):
        if name not in old:
            continue  # first time we see this name: baseline only
        for rtype in sorted(set(old[name]) | set(new[name])):
            if rtype not in old[name] or rtype not in new[name]:
                continue  # started or stopped tracking this type
            added = sorted(set(new[name][rtype]) - set(old[name][rtype]))
            removed = sorted(set(old[name][rtype]) - set(new[name][rtype]))
            if not added and not removed:
                continue
            parts = []
            if added:
                parts.append("added " + ", ".join(f"`{v}`" for v in added))
            if removed:
                parts.append("removed " + ", ".join(f"`{v}`" for v in removed))
            changes.append(f"{name} {rtype}: " + "; ".join(parts))
    return changes


# ---------------------------------------------------------------- TLS

def describe_key(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}", key.key_size < 2048
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA-{key.key_size}", True
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {CURVES.get(key.curve.name, key.curve.name)}", key.curve.key_size < 224
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", False
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", False
    return type(key).__name__, False


def short_name(name):
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    return name.rfc4514_string()


def fetch_cert(host, port, timeout, verify=True, cafile=None):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    if not verify:
        # Second attempt after the normal one failed: turn checks off and
        # allow weak keys and old protocols, so we can still report them.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with warnings.catch_warnings():
            # Python warns that TLS 1.0 is deprecated. That's the point:
            # we want to connect anyway and report it.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version()


def error_text(err):
    return getattr(err, "strerror", None) or str(err) or type(err).__name__


def check_tls(host, port=443, timeout=10, cafile=None):
    verify_error = ""
    try:
        der, version = fetch_cert(host, port, timeout, cafile=cafile)
    except ssl.SSLError as e:
        if isinstance(e, ssl.SSLCertVerificationError):
            verify_error = e.verify_message or str(e)
        try:
            der, version = fetch_cert(host, port, timeout, verify=False)
        except OSError as e2:
            return {"error": error_text(e2)}
    except OSError as e:
        return {"error": error_text(e)}

    cert = x509.load_der_x509_certificate(der)
    key, weak_key = describe_key(cert.public_key())
    sig = cert.signature_hash_algorithm
    return {
        "expires": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        "issuer": short_name(cert.issuer),
        "key": key,
        "weak_key": weak_key,
        "signature": sig.name if sig else "none",
        "tls_version": version,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex()[:16],
        "verify_error": verify_error,
    }


def days_until(day, today):
    return (date.fromisoformat(day) - today).days


def tls_problems(host, info, warn_days, today):
    """Things worth an alert, keyed so the same problem alerts only once."""
    if "error" in info:
        return {f"tls-error:{host}": f"{host}: TLS connection failed ({info['error']})"}

    found = {}
    days = days_until(info["expires"], today)
    if days < 0:
        found[f"cert-expired:{host}"] = f"{host}: certificate expired on {info['expires']}"
    elif days <= URGENT_DAYS:
        found[f"cert-expiring-urgent:{host}"] = (
            f"{host}: certificate expires in {days} days ({info['expires']})")
    elif days <= warn_days:
        found[f"cert-expiring:{host}"] = (
            f"{host}: certificate expires in {days} days ({info['expires']})")

    if info["verify_error"] and days >= 0:
        found[f"cert-invalid:{host}"] = (
            f"{host}: certificate failed verification ({info['verify_error']})")
    if info["weak_key"]:
        found[f"weak-key:{host}"] = f"{host}: weak certificate key ({info['key']})"
    if info["signature"] in ("sha1", "md5"):
        found[f"weak-signature:{host}"] = (
            f"{host}: certificate is signed with {info['signature'].upper()}")
    if info["tls_version"] in OLD_TLS:
        found[f"old-tls:{host}"] = f"{host}: server negotiated {info['tls_version']}"
    return found


# ---------------------------------------------------------------- HTTP

def fetch_json(url, headers=None, timeout=20):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json, application/rdap+json",
        **(headers or {}),
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


# ---------------------------------------------------------------- CT logs

def fetch_issuances(domain, after, api_key=None):
    """Unexpired certificates logged for the domain and its subdomains since
    `after`, in the order Cert Spotter found them.

    Returns (issuances, cursor, done). done is False when there may be more
    left; the next run carries on from the cursor.
    """
    found, cursor = [], after
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    for _ in range(CT_MAX_PAGES):
        params = [("domain", domain), ("include_subdomains", "true"),
                  ("expand", "dns_names"), ("expand", "issuer"), ("expand", "pubkey")]
        if cursor:
            params.append(("after", cursor))
        try:
            page = fetch_json(f"{CERTSPOTTER_URL}?{urllib.parse.urlencode(params)}", headers)
        except NET_ERRORS:
            if not found:
                raise
            return found, cursor, False  # keep the pages we already have
        if not page:
            return found, cursor, True
        found.extend(page)
        cursor = page[-1]["id"]
    return found, cursor, False


def describe_issuance(item):
    names = item.get("dns_names") or []
    shown = ", ".join(names[:4]) + (f" (+{len(names) - 4} more)" if len(names) > 4 else "")
    issuer = item.get("issuer") or {}
    issuer = issuer.get("friendly_name") or issuer.get("name") or "unknown CA"
    pubkey = item.get("pubkey") or {}
    key = ""
    if pubkey.get("type") == "rsa" and pubkey.get("bit_length"):
        key = f", RSA-{pubkey['bit_length']}"
    elif pubkey.get("type") == "ecdsa" and pubkey.get("curve"):
        key = f", ECDSA {pubkey['curve']}"
    return (f"{shown or 'no names listed'}: issued by {issuer}, "
            f"valid {item['not_before'][:10]} to {item['not_after'][:10]}{key}")


# ---------------------------------------------------------------- RDAP

def load_rdap_bootstrap():
    data = fetch_json(RDAP_BOOTSTRAP_URL)
    servers = {}
    for tlds, urls in data["services"]:
        https = [u for u in urls if u.startswith("https://")] or urls
        for tld in tlds:
            servers[tld.lower()] = https[0]
    return servers


def registration_expiry(domain, servers):
    """Expiry date from the registry's RDAP record, or (None, reason)."""
    tld = domain.rsplit(".", 1)[-1]
    base = servers.get(tld)
    if not base:
        return None, f"no RDAP service for .{tld}"
    data = fetch_json(f"{base.rstrip('/')}/domain/{urllib.parse.quote(domain)}")
    for event in data.get("events") or []:
        if event.get("eventAction") == "expiration":
            return event["eventDate"][:10], ""
    return None, "registry doesn't publish an expiry date"


# ---------------------------------------------------------------- one domain

@dataclass
class Report:
    domain: str
    dns_changes: list = field(default_factory=list)
    new_certs: list = field(default_factory=list)
    new_problems: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    problems: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    registration: str = ""
    first_run: bool = False

    @property
    def needs_issue(self):
        return bool(self.dns_changes or self.new_certs or self.new_problems)


def check_domain(domain, prev, cfg, resolver, rdap_servers, api_key, today):
    name = domain["name"]
    report = Report(domain=name, first_run=not prev)
    state = {}

    # DNS
    dns_snap, failed = snapshot_dns(domain, resolver, prev.get("dns", {}))
    if failed:
        report.notes.append("DNS lookup failed for " + ", ".join(failed) + "; kept last values")
    report.dns_changes = diff_dns(prev.get("dns", {}), dns_snap)
    state["dns"] = dns_snap

    # TLS on each host
    problems = {}
    state["tls"] = {}
    for host in domain["hosts"]:
        info = check_tls(host)
        report.tls[host] = info
        state["tls"][host] = {k: v for k, v in info.items() if k != "verify_error"}
        problems.update(tls_problems(host, info, cfg["cert_warn_days"], today))

    # Certificate Transparency. Until we've read to the end of what's already
    # logged, we only record it; after that, anything new gets reported.
    cursor = prev.get("ct_cursor")
    baselined = prev.get("ct_baselined", False)
    try:
        issued, new_cursor, done = fetch_issuances(name, cursor, api_key)
    except NET_ERRORS as e:
        hint = " (rate limited; a CERTSPOTTER_API_KEY secret raises the limit)" \
            if isinstance(e, urllib.error.HTTPError) and e.code == 429 else ""
        report.notes.append(f"Certificate Transparency check skipped: {e}{hint}")
        state["ct_cursor"] = cursor
        state["ct_baselined"] = baselined
    else:
        if baselined:
            report.new_certs = [describe_issuance(i) for i in issued]
        elif issued:
            s = "" if len(issued) == 1 else "s"
            report.notes.append(f"Recorded {len(issued)} existing certificate{s} as a baseline")
        if not done:
            report.notes.append("More certificates left in the CT logs; the next run continues from here")
        state["ct_cursor"] = new_cursor
        state["ct_baselined"] = baselined or done

    # Registration
    expires, why = None, "RDAP lookup failed"
    if rdap_servers:
        try:
            expires, why = registration_expiry(name, rdap_servers)
        except NET_ERRORS as e:
            why = f"RDAP lookup failed: {e}"
    if expires:
        report.registration = expires
        days = days_until(expires, today)
        if days < 0:
            problems[f"domain-expired:{name}"] = f"{name}: registration expired on {expires}"
        elif days <= cfg["domain_warn_days"]:
            problems[f"domain-expiring:{name}"] = (
                f"{name}: registration expires in {days} days ({expires})")
        state["registration"] = expires
    else:
        report.notes.append(f"Registration expiry unknown: {why}")
        if prev.get("registration"):
            state["registration"] = prev["registration"]
            report.registration = prev["registration"]

    # Only alert on problems we haven't alerted on before.
    old_problems = prev.get("problems", {})
    report.problems = problems
    report.new_problems = [msg for key, msg in sorted(problems.items()) if key not in old_problems]
    report.resolved = sorted(key for key in old_problems if key not in problems)
    state["problems"] = {key: old_problems.get(key, today.isoformat()) for key in sorted(problems)}

    return report, state


# ---------------------------------------------------------------- output

def render_issue(reports):
    lines = []
    for r in reports:
        if not r.needs_issue:
            continue
        lines.append(f"## {r.domain}\n")
        if r.dns_changes:
            lines.append("**DNS changes**\n")
            lines += [f"- {c}" for c in r.dns_changes]
            lines.append("")
        if r.new_certs:
            lines.append("**New certificates in CT logs** (check that you expected these)\n")
            lines += [f"- {c}" for c in r.new_certs]
            lines.append("")
        if r.new_problems:
            lines.append("**Needs attention**\n")
            lines += [f"- {p}" for p in r.new_problems]
            lines.append("")
    body = "\n".join(lines).strip()
    if len(body) > 60000:
        body = body[:60000] + "\n\n(truncated, see the workflow run for the rest)"
    return body


def render_summary(reports):
    lines = ["# domain-watch run", ""]
    for r in reports:
        lines.append(f"## {r.domain}")
        if r.first_run:
            lines.append("First run: saved a baseline.")
        for c in r.dns_changes:
            lines.append(f"- DNS: {c}")
        for c in r.new_certs:
            lines.append(f"- New certificate: {c}")
        for p in r.problems.values():
            lines.append(f"- Problem: {p}")
        for k in r.resolved:
            lines.append(f"- Resolved: {k}")
        for n in r.notes:
            lines.append(f"- Note: {n}")
        if not (r.dns_changes or r.new_certs or r.problems or r.resolved or r.notes or r.first_run):
            lines.append("No changes.")
        lines.append("")
    return "\n".join(lines)


def render_status(reports, today):
    lines = [
        "# Domain status",
        "",
        f"_Last refreshed: {today:%Y-%m}. The workflow runs daily; this file only "
        "changes when something does, or once a month._",
        "",
        "| Host | Certificate expires | Issuer | Key | TLS |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in reports:
        for host, info in r.tls.items():
            if "error" in info:
                lines.append(f"| {host} | connection failed | | | |")
            else:
                lines.append(f"| {host} | {info['expires']} | {info['issuer']} "
                             f"| {info['key']} | {info['tls_version']} |")
    lines += ["", "| Domain | Registration expires | Open problems |", "| --- | --- | --- |"]
    for r in reports:
        lines.append(f"| {r.domain} | {r.registration or 'unknown'} | {len(r.problems)} |")
    return "\n".join(lines) + "\n"


def open_issue(repo, token, title, body):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues",
        data=json.dumps({"title": title, "body": body}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)["html_url"]


# ---------------------------------------------------------------- main

def load_state(state_dir, domain):
    path = Path(state_dir) / f"{domain}.json"
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(state_dir, domain, state):
    path = Path(state_dir) / f"{domain}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def main(argv=None):
    p = argparse.ArgumentParser(description="Watch domains for DNS changes, new certificates and expiry.")
    p.add_argument("-c", "--config", default="domains.yml",
                   help="config file (default: domains.yml)")
    p.add_argument("--state-dir", default="state",
                   help="where each domain's last snapshot is kept (default: state)")
    p.add_argument("--status-file", default="STATUS.md",
                   help="status table to rewrite on each run (default: STATUS.md)")
    p.add_argument("--no-issue", action="store_true",
                   help="print the report instead of opening a GitHub issue")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    if not cfg["domains"]:
        print("No domains configured yet. Add some to domains.yml.")
        return 0

    today = datetime.now(timezone.utc).date()
    resolver = make_resolver()
    try:
        rdap_servers = load_rdap_bootstrap()
    except NET_ERRORS as e:
        print(f"Couldn't load the RDAP server list, skipping registration checks: {e}")
        rdap_servers = {}
    api_key = os.environ.get("CERTSPOTTER_API_KEY") or None

    reports, states = [], {}
    for domain in cfg["domains"]:
        prev = load_state(args.state_dir, domain["name"])
        report, states[domain["name"]] = check_domain(
            domain, prev, cfg, resolver, rdap_servers, api_key, today)
        reports.append(report)

    summary = render_summary(reports)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(summary + "\n")

    if any(r.needs_issue for r in reports):
        body = render_issue(reports)
        token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
        if args.no_issue or not (token and repo):
            print("Would open an issue with:\n\n" + body)
        else:
            try:
                url = open_issue(repo, token, f"domain-watch: changes on {today.isoformat()}", body)
            except NET_ERRORS as e:
                # Fail before saving state, so the next run alerts again.
                print(f"Couldn't open the issue: {e}", file=sys.stderr)
                return 1
            print(f"Opened {url}")

    for name, state in states.items():
        save_state(args.state_dir, name, state)
    Path(args.status_file).write_text(render_status(reports, today))
    return 0


if __name__ == "__main__":
    sys.exit(main())
