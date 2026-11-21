# domain-watch

Watches your domains from a scheduled GitHub Action and opens an issue when something changes: a DNS record, a new certificate issued for the domain or any subdomain, or a certificate or registration that's close to expiring.

I wanted to know when DNS or certificates change on my domains without paying for a monitoring service or keeping a server running. There's no database here either. Each run saves what it saw under `state/` and commits it, so the next run has something to compare against, and the commit history doubles as a log of what changed and when.

## What it checks

| Check | How | Alerts when |
|-------|-----|-------------|
| DNS | NS, MX, TXT, CAA, A and AAAA on the domain; the CNAME target, or A/AAAA, on each extra host | a record is added, removed or changed |
| New certificates | Certificate Transparency logs, through the [Cert Spotter API](https://sslmate.com/ct_search_api/) | a certificate is issued for the domain or any subdomain |
| TLS | connects to each host on port 443 | the certificate expires within 21 days or fails verification, the key is weak (RSA under 2048 bits), the signature is SHA-1, or the server only supports TLS 1.0/1.1 |
| Registration | the registry's RDAP record | the domain expires within 30 days |

The first run records the DNS records and certificates that already exist without alerting on them. Problems like an expiring certificate are reported straight away.

After that you get at most one issue per run, and only for things it hasn't told you about yet. An expiring certificate alerts once when it enters the warning window and once more at 7 days, not every day.

A certificate you didn't expect in the CT logs is worth a look. Usually it's a forgotten service or another team using a different CA, but it can also be someone else getting a certificate for your name.

## Example

An issue looks like this (names and dates made up):

> ## example.com
>
> **DNS changes**
>
> - example.com MX: added `10 mx1.mailhost.example`; removed `10 mail.example.com`
>
> **New certificates in CT logs** (check that you expected these)
>
> - vpn.example.com: issued by Sectigo, valid 2026-11-19 to 2027-02-17, RSA-2048
>
> **Needs attention**
>
> - www.example.com: certificate expires in 6 days (2026-11-26)

Each run also rewrites [STATUS.md](STATUS.md), a table of every host's certificate and every domain's registration date. The one in this repo is live for example.com.

## Setup

1. Click **Use this template**, then **Create a new repository**. A private repo works too.
2. Delete the `state/` folder. It holds the example.com demo's data.
3. List your domains in `domains.yml`.
4. Open the **Actions** tab, pick **domain-watch** and click **Run workflow**. The first run saves the baseline. After that it runs every day at 11:23 UTC; change the `cron` line in `.github/workflows/domain-watch.yml` for a different time.

Issues are opened by `github-actions[bot]`, so they show up in your normal GitHub notifications.

### Cert Spotter API key (optional)

Without a key, Cert Spotter allows a limited number of queries per hour, for personal or evaluation use. If you watch more than a handful of domains, or the run summary says "rate limited", get an API key from [SSLMate](https://sslmate.com/) and save it as a repository secret named `CERTSPOTTER_API_KEY`.

## domains.yml

```yaml
domains:
  - name: example.com
    hosts: [example.com, www.example.com, api.example.com]
  - example.org          # short form: TLS on the domain itself only
  - name: example.net
    ignore: [TXT]        # don't alert on these record types

cert_warn_days: 21       # default 21
domain_warn_days: 30     # default 30
```

`hosts` is the list of names to check TLS on. Every host other than the domain itself also gets its DNS tracked. If it's a CNAME, only the target is compared, not the IP addresses behind it, because CDNs and load balancers rotate those all the time.

## Running it locally

```
pip install -r requirements.txt
python domain_watch.py --no-issue
```

With `--no-issue`, or without `GITHUB_TOKEN` and `GITHUB_REPOSITORY` set, it prints the issue instead of opening one. It still writes `state/` and `STATUS.md`, so delete those afterwards if you were only trying it out.

```
  -c, --config CONFIG   config file (default: domains.yml)
  --state-dir STATE_DIR
                        where each domain's last snapshot is kept (default:
                        state)
  --status-file STATUS_FILE
                        status table to rewrite on each run (default:
                        STATUS.md)
  --no-issue            print the report instead of opening a GitHub issue
```

## Things to know

- Lookups go through the runner's normal DNS resolver, so a change can take up to the record's TTL to show up.
- Some country-code TLDs don't have an RDAP server, or don't publish an expiry date. For those you get a note in the run summary instead of an expiry check.
- TLS is only checked on port 443.
- If you take a domain out of `domains.yml`, its file in `state/` stays. Delete it by hand.
- GitHub pauses scheduled workflows in public repos after 60 days without activity. If that happens, turn it back on from the Actions tab.
- Commits pushed by the workflow don't trigger other workflows, so the daily state commits don't re-run the tests.

## Tests

```
pip install -r requirements.txt pytest
pytest
```

The tests use a fake DNS resolver, canned API responses and local TLS servers with throwaway certificates, so they run without internet access.

## Ideas for later

- check SPF, DMARC and MTA-STS policies, not just whether the TXT record changed
- send alerts to Slack or a webhook as well as issues
- TLS on ports other than 443

## License

MIT
