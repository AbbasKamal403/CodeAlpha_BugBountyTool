#!/usr/bin/env python3
"""
bug_bounty_tool.py
Standard Bug Bounty Helper (safe, non-destructive checks)

Usage:
    python bug_bounty_tool.py https://example.com

Outputs:
    - summary printed to terminal
    - report saved as report_<host>_<timestamp>.json and .txt
"""

import sys
import socket
import requests
import concurrent.futures
import json
import time
from urllib.parse import urlparse, urljoin, urlencode
from bs4 import BeautifulSoup

# --- CONFIG ---
COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 3306, 3389, 8080]
DIR_WORDLIST = [
    "admin", "login", "dashboard", "uploads", "upload", "backup", "backup.zip",
    "config", "config.json", ".env", ".git", ".htaccess", "robots.txt", "sitemap.xml",
    "wp-admin", "wp-login.php", "api", "console"
]
HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
TIMEOUT = 5
MAX_WORKERS = 20

# --- UTIL ---
def norm(url):
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/")

def host_from_url(url):
    p = urlparse(url)
    return p.netloc or p.path

def now_ts():
    return time.strftime("%Y%m%d_%H%M%S")

# --- MODULES ---
def scan_security_headers(target):
    result = {"present": {}, "missing": []}
    try:
        r = requests.get(target, timeout=TIMEOUT, allow_redirects=True)
        hdrs = {k: v for k, v in r.headers.items()}
        for h in HEADERS_TO_CHECK:
            if any(k.lower() == h.lower() for k in hdrs):
                result["present"][h] = hdrs.get(h, "")
            else:
                result["missing"].append(h)
        result["status_code"] = r.status_code
    except Exception as e:
        result["error"] = str(e)
    return result

def _check_port(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect((host, port))
        s.close()
        return port, True
    except:
        return port, False

def scan_ports(target):
    parsed = urlparse(target)
    host = parsed.hostname
    res = {"open": [], "closed": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(_check_port, host, p) for p in COMMON_PORTS]
        for f in concurrent.futures.as_completed(futures):
            p, ok = f.result()
            if ok:
                res["open"].append(p)
            else:
                res["closed"].append(p)
    return res

def check_url_get(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return None, ""

def directory_scan(target):
    findings = []
    base = target if target.endswith("/") else target + "/"
    def probe(path):
        url = urljoin(base, path)
        status, _ = check_url_get(url)
        return path, status
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(probe, p) for p in DIR_WORDLIST]
        for f in concurrent.futures.as_completed(futures):
            path, status = f.result()
            findings.append({"path": path, "status": status})
    return findings

def basic_xss_test(target):
    # safe reflection test: append param ?q=<payload> and search response for payload
    payload = '"><script>alert(1)</script>'
    parsed = urlparse(target)
    base = target
    url = base + ('' if parsed.query else '?') + urlencode({'q': payload})
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        found = payload in r.text
        return {"tested_url": url, "reflected": found, "status_code": r.status_code}
    except Exception as e:
        return {"tested_url": url, "error": str(e)}

def basic_sqli_test(target):
    # lightweight check: compare normal request vs payload request length
    parsed = urlparse(target)
    base = target
    benign = base + ('' if parsed.query else '?') + urlencode({'q': 'test'})
    payload = base + ('' if parsed.query else '?') + urlencode({'q': "' OR 1=1--"})
    try:
        r1 = requests.get(benign, timeout=TIMEOUT, allow_redirects=True)
        r2 = requests.get(payload, timeout=TIMEOUT, allow_redirects=True)
        # heuristic: if payload triggers large difference or error, flag
        diff = abs(len(r1.text) - len(r2.text))
        flagged = diff > 100  # heuristic threshold
        return {"benign_len": len(r1.text), "payload_len": len(r2.text), "diff": diff, "possible_sqli": flagged}
    except Exception as e:
        return {"error": str(e)}

def robots_check(target):
    parsed = urlparse(target)
    robots_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", "/robots.txt")
    try:
        r = requests.get(robots_url, timeout=TIMEOUT)
        return {"exists": r.status_code == 200, "status_code": r.status_code, "body": r.text[:1000]}
    except Exception as e:
        return {"error": str(e)}

def extract_links(target):
    try:
        r = requests.get(target, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            links.add(a["href"])
        return list(links)[:50]
    except:
        return []

# --- MAIN RUNNER ---
def run_all(target):
    report = {
        "target": target,
        "timestamp": now_ts(),
        "security_headers": {},
        "ports": {},
        "directories": [],
        "xss_test": {},
        "sqli_test": {},
        "robots": {},
        "links_sample": []
    }
    print(f"[+] Starting scan for {target}")
    print("[*] Scanning security headers...")
    report["security_headers"] = scan_security_headers(target)
    print("[*] Scanning ports (common)...")
    report["ports"] = scan_ports(target)
    print("[*] Directory brute-force (common list)...")
    report["directories"] = directory_scan(target)
    print("[*] Running basic XSS reflection test...")
    report["xss_test"] = basic_xss_test(target)
    print("[*] Running basic SQLi heuristic test...")
    report["sqli_test"] = basic_sqli_test(target)
    print("[*] Checking robots.txt...")
    report["robots"] = robots_check(target)
    print("[*] Extracting sample links from homepage...")
    report["links_sample"] = extract_links(target)

    # Save report
    host = host_from_url(target).replace(":", "_")
    fname = f"report_{host}_{report['timestamp']}"
    with open(fname + ".json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(fname + ".txt", "w", encoding="utf-8") as f:
        f.write("Bug Bounty Tool Report\n")
        f.write(f"Target: {target}\nTimestamp: {report['timestamp']}\n\n")
        f.write("--- Security Headers ---\n")
        sh = report["security_headers"]
        if "error" in sh:
            f.write("Header scan error: " + sh["error"] + "\n")
        else:
            f.write(f"Status code: {sh.get('status_code')}\n")
            f.write("Present:\n")
            for k, v in sh.get("present", {}).items():
                f.write(f"  {k}: {v}\n")
            f.write("Missing:\n")
            for m in sh.get("missing", []):
                f.write(f"  {m}\n")
        f.write("\n--- Ports ---\n")
        f.write("Open: " + ", ".join(map(str, report["ports"].get("open", []))) + "\n")
        f.write("\n--- Directories ---\n")
        for d in report["directories"]:
            f.write(f"{d['path']}: {d['status']}\n")
        f.write("\n--- XSS Test ---\n")
        f.write(json.dumps(report["xss_test"], indent=2))
        f.write("\n\n--- SQLi Test ---\n")
        f.write(json.dumps(report["sqli_test"], indent=2))
        f.write("\n\n--- Robots ---\n")
        f.write(json.dumps(report["robots"], indent=2))
    print(f"[+] Report saved as {fname}.json and {fname}.txt")
    return report

# --- CLI ---
def main():
    if len(sys.argv) != 2:
        print("Usage: python bug_bounty_tool.py https://example.com")
        sys.exit(1)
    target = norm(sys.argv[1])
    report = run_all(target)
    print("\n--- SUMMARY ---")
    print(f"Target: {report['target']}")
    print("Open ports:", report["ports"].get("open", []))
    print("Missing headers:", report["security_headers"].get("missing", []))
    print("Directories found (status != None):")
    for d in report["directories"]:
        if d["status"] is not None:
            print(f"  /{d['path']}: {d['status']}")
    if report["xss_test"].get("reflected"):
        print("[!] Possible XSS reflection detected.")
    else:
        print("XSS: No reflection detected (basic test).")
    if report["sqli_test"].get("possible_sqli"):
        print("[!] SQLi heuristic triggered (investigate manually).")
    else:
        print("SQLi heuristic: No clear indication.")
    print("--- End ---")

if __name__ == "__main__":
    main()
