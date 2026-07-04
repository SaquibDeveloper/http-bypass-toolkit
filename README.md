# HTTP Access-Control & Rate-Limit Testing Tools

A small collection of Python tools built while doing authorized bug bounty / pentest work.

> ⚠️ **Authorized use only.** These tools are for testing systems you own or have explicit
> written permission to test (e.g. YesWeHack / HackerOne programs in scope). Running them
> against systems without authorization may be illegal in your jurisdiction.

## Tools

### `bypass403.py`
403/401 access-control bypass tester. Tries path manipulation, method switching,
and header-based tricks (`X-Original-URL`, `X-Forwarded-For`, etc.) to see if a
restricted endpoint can be reached despite an access-control check.

- Takes a baseline request first, so results are diffed against the real deny
  response instead of flagging generic error pages as "bypasses."
- Multi-threaded, with an optional delay for rate-limit-friendly scanning.
- Exports results to JSON for reporting.

```bash
python3 bypass403.py -u https://target.com -p /admin --threads 10 --delay 0.3 -o results.json
```

### `ratelimit_bypass.py`
Rate-limit (429) bypass tester. Rotates through proxies (with liveness checks)
and/or spoofs `X-Forwarded-For`-style headers to check whether an endpoint
(password reset, OTP, login) rate-limits per-account or only per-source-IP.

```bash
python3 ratelimit_bypass.py -u https://target.com/api/request-reset -n 20 --proxy-file proxies.txt
python3 ratelimit_bypass.py -u https://target.com/api/request-reset -n 20 --header-spoof-only
```

### `mail_alert.py`
Small SMTP alert utility for pinging yourself when a long recon job finishes
or finds something. Credentials are pulled from environment variables — never
hardcoded.

```bash
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=you@example.com
export SMTP_PASSWORD=your-app-password
export ALERT_TO=you@example.com

python3 mail_alert.py --subject "Recon done" --body "3 live subdomains found"
```

## Setup

```bash
pip install -r requirements.txt
```

## Disclaimer

Provided for educational and authorized security-testing purposes only.
The author is not responsible for misuse.

## License

MIT
