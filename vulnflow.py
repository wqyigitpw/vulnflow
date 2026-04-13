import subprocess
import os
import sys
import requests
import time
import socket
import random
import string
import tldextract
import re
import threading
import tempfile
import hashlib
import pty
import fcntl
import argparse
import json

from datetime import datetime
from urllib.parse import urlparse, parse_qsl
from collections import defaultdict

# developed by wqyigitpw
version = "1.0.9"

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
DIM    = "\033[2m"
BIG    = "\033[1m"
RESET  = "\033[0m"

# ── UI helpers ──────────────────────────────────────────────
def banner_section(title: str):
    width     = 60
    left      = DIM + "─" * 3 + RESET
    right_len = width - len(title) - 5
    right     = DIM + "─" * max(right_len, 2) + RESET
    print("\n" + left + " " + CYAN + BIG + title + RESET + " " + right + "\n")

def banner_done():
    print(DIM + "─" * 60 + RESET + "\n")

def info(msg):  print("  " + CYAN  + "[i]" + RESET + " " + str(msg))
def ok(msg):    print("  " + GREEN + "[✓]" + RESET + " " + str(msg))
def warn(msg):  print("  " + YELLOW + "[!]" + RESET + " " + str(msg))
def skip(msg):  print("  " + YELLOW + "[~]" + RESET + " " + str(msg))
def err(msg):   print("  " + RED   + "[✗]" + RESET + " " + str(msg))


# =============================
# CONFIG
# =============================
BASE_DIR = None  # Will be set dynamically in main()
DNS_WORDLIST = "Payloads/subdomains.txt"
WORDLISTS = "Payloads/wordlists.txt"

NUCLEI_RATE = "120"
NUCLEI_TIMEOUT = "60"

# WAF Detection Flag
WAF_DETECTED = False

# Scan mode: "auto" | "aggressive" | "human"
SCAN_MODE = "auto"

# Depth: 1-5
SCAN_DEPTH = 3


TEMPLATE_QUEUE = [
    "Payloads/templates/nuclei-templates",       # index 0 — core
    "Payloads/templates/community-templates-1",  # index 1
    "Payloads/templates/community-templates-2",  # index 2
    "Payloads/templates/community-templates-3",  # index 3
    "Payloads/templates/community-templates-4",  # index 4
    "Payloads/templates/community-templates-5",  # index 5
]

# =============================
# DEPTH CONFIG
# =============================
# Nuclei templates per depth:
#   depth 1 → only nuclei-templates (core)
#   depth 2 → core + community-1
#   depth 3 → core + community-1 + community-2
#   depth 4 → core + community-1..3
#   depth 5 → core + community-1..4 (all)
#
# Subdomain tools per depth:
#   depth 1-2 → subfinder only
#   depth 3   → subfinder + assetfinder
#   depth 4-5 → subfinder + assetfinder + gobuster
#
# gobuster threads / timeouts scale with depth.
# httpx / subzy timeouts scale with depth.

def get_depth_config(depth):
    configs = {
        1: {
            "subdomain_tools":  ["subfinder"],
            "gobuster_threads": "20",
            "gobuster_timeout": "30s",
            "nuclei_templates": TEMPLATE_QUEUE[:1],   # core only
            "httpx_timeout":    "10",
            "subzy_timeout":    "15",
        },
        2: {
            "subdomain_tools":  ["subfinder"],
            "gobuster_threads": "30",
            "gobuster_timeout": "45s",
            "nuclei_templates": TEMPLATE_QUEUE[:2],   # core + community-1
            "httpx_timeout":    "20",
            "subzy_timeout":    "20",
        },
        3: {
            "subdomain_tools":  ["subfinder", "assetfinder"],
            "gobuster_threads": "50",
            "gobuster_timeout": "60s",
            "nuclei_templates": TEMPLATE_QUEUE[:3],   # core + community-1..2
            "httpx_timeout":    "30",
            "subzy_timeout":    "30",
        },
        4: {
            "subdomain_tools":  ["subfinder", "assetfinder", "gobuster"],
            "gobuster_threads": "75",
            "gobuster_timeout": "90s",
            "nuclei_templates": TEMPLATE_QUEUE[:4],   # core + community-1..3
            "httpx_timeout":    "45",
            "subzy_timeout":    "45",
        },
        5: {
            "subdomain_tools":  ["subfinder", "assetfinder", "gobuster"],
            "gobuster_threads": "100",
            "gobuster_timeout": "120s",
            "nuclei_templates": TEMPLATE_QUEUE,       # all (core + community-1..5)
            "httpx_timeout":    "60",
            "subzy_timeout":    "60",
        },
    }
    return configs.get(depth, configs[3])


# =============================
# COMMAND RUNNER
# =============================
def run_cmd(cmd, outfile=None):
    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        ) as p:
            for line in p.stdout:
                if "[ERROR]" in line:
                    continue
                print(line, end="")
                if outfile:
                    outfile.write(line)
            p.wait()
    except KeyboardInterrupt:
        print(); warn("Ctrl+C — skipping to next step..."); print()
        try:
            p.terminate()
        except:
            pass
        return


def get_base(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# =============================
# TARGET CHECK
# =============================
def detect_waf(url):
    try:
        result = subprocess.check_output(
            ["wafw00f", url],
            stderr=subprocess.DEVNULL,
            text=True
        )
        match = re.search(r"is behind\s+(.+?)\s+\(", result)
        if match:
            return match.group(1)
        else:
            return None
    except:
        return None


def check_target(domain):
    global WAF_DETECTED

    banner_section("TARGET CHECK")

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(url, timeout=8, allow_redirects=True)

            host = r.url.split("/")[2]
            ip = socket.gethostbyname(host)

            print(); print(f"  {GREEN}{BIG}[+]{RESET} Target is {GREEN}{BIG}ALIVE{RESET}")
            print(f"      {DIM}URL{RESET}  {r.url}")
            print(f"      {DIM}IP{RESET}   {CYAN}{ip}{RESET}")
            print(f"      {DIM}Code{RESET} {GREEN}{r.status_code}{RESET}")

            # ── Mode logic ──────────────────────────────────────────
            if SCAN_MODE == "aggressive":
                WAF_DETECTED = False
                print(f"      {DIM}WAF{RESET}  {YELLOW}skipped (aggressive mode){RESET}")
                print(); info(f"{GREEN}Aggressive mode forced{RESET} — WAF detection skipped")

            elif SCAN_MODE == "human":
                WAF_DETECTED = True
                print(f"      {DIM}WAF{RESET}  {YELLOW}skipped (human mode){RESET}")
                print(); info(f"{YELLOW}Human mode forced{RESET} — stealth settings active")

            else:  # auto
                waf = detect_waf(r.url)
                if waf:
                    WAF_DETECTED = True
                    print(f"      {DIM}WAF{RESET}  {RED}{BIG}{waf}{RESET}")
                    print(); warn(f"WAF detected — enabling human mode")
                    print(f"        {DIM}• Gobuster DNS disabled{RESET}")
                    print(f"        {DIM}• Nuclei rate-limit reduced{RESET}")
                else:
                    WAF_DETECTED = False
                    print(f"      {DIM}WAF{RESET}  {GREEN}Not detected{RESET}")
                    print(); info(f"{GREEN}WAF not detected{RESET} — aggressive mode active")

            info(f"Scan depth  : {BIG}{SCAN_DEPTH}/5{RESET}")
            info(f"Scan mode   : {BIG}{SCAN_MODE}{RESET}")
            info("Continuing in 3 seconds..."); print()
            time.sleep(3)
            return r.url

        except:
            continue

    err("Target unreachable. Aborting.")
    sys.exit(1)


# =============================
# GOBUSTER DNS
# =============================
def is_domain_line(line):
    line = line.strip()
    if not line:
        return False
    if line.startswith("["):
        return False
    if " " in line and not line.split()[0].count(".") >= 1:
        return False
    return "." in line


def run_cmd_domains_only(cmd, outfile):
    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    ) as p:
        for line in p.stdout:
            if is_domain_line(line):
                clean = line.strip().split()[0]
                print(f"  {DIM}{clean}{RESET}")
                outfile.write(clean + "\n")
        p.wait()


def is_subdomain(domain):
    ext = tldextract.extract(domain)
    return ext.subdomain != ""


def run_subdomain_combo(domain):
    """
    Subdomain enumeration.
    - Depth controls which tools are used and at what intensity.
    - WAF / mode controls whether Gobuster DNS runs.
    """
    out_path = f"{BASE_DIR}/subdomains.txt"
    depth_cfg = get_depth_config(SCAN_DEPTH)

    if is_subdomain(domain):
        info(f"'{domain}' is already a subdomain — enumeration skipped.")
        info("Adding target subdomain to list..."); print()
        with open(out_path, "w") as f:
            f.write(domain + "\n")
        ok(f"Target subdomain saved to {out_path}")
        return out_path

    banner_section("SUBDOMAIN ENUMERATION")

    use_gobuster = (
        "gobuster" in depth_cfg["subdomain_tools"] and not WAF_DETECTED
    )

    with open(out_path, "w") as f:
        threads = []

        if "subfinder" in depth_cfg["subdomain_tools"]:
            threads.append(threading.Thread(
                target=run_cmd_domains_only,
                args=(["subfinder", "-d", domain, "-silent"], f)
            ))

        if "assetfinder" in depth_cfg["subdomain_tools"]:
            threads.append(threading.Thread(
                target=run_cmd_domains_only,
                args=(["assetfinder", "--subs-only", domain], f)
            ))

        if use_gobuster:
            threads.append(threading.Thread(
                target=run_cmd_domains_only,
                args=([
                    "gobuster", "dns",
                    "--do", domain,
                    "-w", DNS_WORDLIST,
                    "-t", depth_cfg["gobuster_threads"],
                    "--wildcard",
                    "--timeout", depth_cfg["gobuster_timeout"]
                ], f)
            ))

        for t in threads:
            t.start()

        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print(); warn("Ctrl+C — stopping subdomain enumeration..."); print()
            return

    print(); ok(f"Subdomains saved to {out_path}")
    return out_path


# =============================
# MERGE URLS
# =============================
def merge_urls():
    urls = set()
    urls.add(target.rstrip("/"))

    sub_path = f"{BASE_DIR}/subdomains.txt"
    if os.path.exists(sub_path):
        with open(sub_path) as f:
            for line in f:
                sub = line.strip()
                if sub:
                    urls.add(f"http://{sub}")
                    urls.add(f"https://{sub}")

    out = f"{BASE_DIR}/all_urls.txt"
    with open(out, "w") as f:
        for u in sorted(urls):
            f.write(u + "\n")

    return out, list(urls)


# =============================
# PRUNE URLS
# =============================
def prune_urls(urls, base_domain, target):
    banner_section("FINAL URL PRUNING")

    standardized_urls = set()
    for u in urls:
        clean = u.strip().lower().rstrip("/")
        if clean:
            standardized_urls.add(clean)

    final_unique = set()
    seen_domains = {}

    for url in standardized_urls:
        parsed = urlparse(url)
        domain_path = f"{parsed.netloc}{parsed.path}"

        if domain_path in seen_domains:
            if parsed.scheme == "https":
                final_unique.discard(f"{seen_domains[domain_path]}://{domain_path}")
                final_unique.add(url)
                seen_domains[domain_path] = "https"
        else:
            final_unique.add(url)
            seen_domains[domain_path] = parsed.scheme

    final_urls = sorted(list(final_unique))

    ok(f"URLs before prune : {len(urls)}")
    ok(f"URLs after prune  : {len(final_urls)}")

    output_path = f"{BASE_DIR}/pruned_urls.txt"
    with open(output_path, "w") as f:
        for u in final_urls:
            f.write(u + "\n")

    ok(f"Saved to {output_path}")
    return final_urls


def keep_only_homepages(urls):
    depth_cfg = get_depth_config(SCAN_DEPTH)
    normalized = set()
    homepages = set()

    for url in urls:
        try:
            p = urlparse(url.strip())
            clean = f"{p.scheme.lower()}://{p.netloc.lower()}{p.path}".rstrip("/")
            normalized.add(clean)
        except:
            continue

    for url in normalized:
        try:
            p = urlparse(url)
            if p.path in ("", "/") and not p.query:
                homepages.add(f"{p.scheme}://{p.netloc}")
        except:
            continue

    homepages_all = f"{BASE_DIR}/homepages_all.txt"
    with open(homepages_all, "w") as f:
        for url in homepages:
            f.write(url + "\n")

    homepages_live = f"{BASE_DIR}/homepages_live.txt"
    subprocess.run(
        [
            "httpx", "-silent",
            "-l", homepages_all,
            "-o", homepages_live,
            "-nc",
            "-timeout", depth_cfg["httpx_timeout"]
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    with open(homepages_live) as f:
        live_urls = [line.strip() for line in f if line.strip()]

    ok(f"Total homepages : {len(homepages)}")
    ok(f"Live            : {len(live_urls)}")

    return live_urls


# =============================
# NUCLEI WORKER
# =============================
def run_nuclei_filtered(cmd, outfile):
    levels = ("info", "low", "medium", "high", "critical", "%)")
    seen_lines = set()

    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    ) as p:
        for line in p.stdout:
            clean = line.strip()
            lower = clean.lower()

            if not any(level in lower for level in levels):
                continue
            if clean in seen_lines:
                continue

            seen_lines.add(clean)
            print(clean)
            outfile.write(clean + "\n")

        p.wait()


# =============================
# WAF / CDN IP FILTER — EXPERT SCORING
# =============================
#
# Bir uzmanın bakış açısıyla her nrich bloğunu değerlendirir.
# Tek bir keyword'e değil, birden fazla sinyalin kombinasyonuna bakar.
#
# Sinyal kategorileri:
#   HARD BLOCK  → tek başına yeterli, kesinlikle WAF/CDN proxy IP'si
#   SOFT SIGNAL → tek başına yetmez, diğer sinyallerle birleşince karar verir
#
# Skor ≥ 100 → WAF/CDN olarak işaretle ve atla


# Kesin WAF/CDN ürün imzaları (CPEs veya hostname'de)
_HARD_CPE = [
    "cloudflare", "amazon_cloudfront", "cloudfront",
    "akamai", "fastly", "incapsula", "imperva",
    "sucuri", "stackpath", "ddos-guard", "qrator",
    "f5:big-ip", "barracuda:web_application_firewall",
    "reblaze", "radware:alteon", "azure_front_door",
    "google_cloud_armor", "cdn77", "bunnycdn",
    "limelight", "keycdn", "verizon_media", "edgecast",
    "maxcdn", "section_io", "netlify", "vercel",
]

# Hostname pattern'leri — CDN/WAF sağlayıcılarına ait bilinen hostname kalıpları
_HARD_HOSTNAME = [
    r'\.cloudflare\.net$',
    r'\.cloudflare\.com$',
    r'\.cloudfront\.net$',
    r'r\.cloudfront\.net$',
    r'\.akamaiedge\.net$',
    r'\.akamai\.net$',
    r'\.akamaitechnologies\.com$',
    r'\.fastly\.net$',
    r'\.fastlylb\.net$',
    r'\.incapdns\.net$',
    r'\.sucuri\.net$',
    r'\.stackpathcdn\.com$',
    r'\.azureedge\.net$',
    r'\.msecnd\.net$',       # Azure CDN
    r'\.googleusercontent\.com$',
    r'\.googlevideo\.com$',
    r'\.edgesuite\.net$',    # Akamai
    r'\.edgekey\.net$',      # Akamai
    r'\.srip\.net$',         # Akamai
    r'\.deploy\.static\.akamaitechnologies\.com$',
    r'cdn\d*\.',             # cdn1., cdn2. vb.
    r'\.cdn\.',
    r'edge\d*\.',
    r'\.edgecastcdn\.net$',
    r'\.llnwd\.net$',        # Limelight
    r'\.hwcdn\.net$',        # Highwinds/StackPath
    r'\.r\.worldssl\.net$',  # CDN77
]

# Zayıf sinyaller — tek başına yetmez
_SOFT_TAGS    = ["cdn", "cloud", "proxy", "waf", "firewall", "ddos-protection", "load-balancer"]
_SOFT_CPE     = ["nginx", "apache", "haproxy", "varnish", "squid"]  # reverse proxy olabilir
_SOFT_PORTS   = {80, 443, 8080, 8443}   # sadece web portları → CDN olabilir

# Güçlü ek sinyaller
_STRONG_TAGS  = ["cdn", "waf", "ddos-protection", "proxy"]
_STRONG_PORTS = {2052, 2053, 2086, 2087, 2095, 2096, 8880}  # Cloudflare'e özgü portlar (2082/2083 cPanel ile çakışır, çıkarıldı)


def _parse_block_fields(block: str) -> dict:
    """Bir nrich bloğunu parse ederek alanlarını sözlük olarak döner."""
    fields = {
        "ip":        "",
        "hostnames": [],
        "ports":     set(),
        "tags":      [],
        "cpes":      [],
        "raw":       block,
    }

    ip_re   = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s*(?:\(([^)]*)\))?')
    port_re = re.compile(r'Ports:\s*([\d,\s]+)', re.IGNORECASE)
    tag_re  = re.compile(r'Tags:\s*(.+)',         re.IGNORECASE)
    cpe_re  = re.compile(r'CPEs:\s*(.+)',         re.IGNORECASE)

    for line in block.splitlines():
        stripped = line.strip()

        m = ip_re.match(stripped)
        if m and not fields["ip"]:
            fields["ip"] = m.group(1)
            if m.group(2):
                fields["hostnames"] = [h.strip() for h in m.group(2).split(",")]
            continue

        m = port_re.match(stripped)
        if m:
            fields["ports"] = {int(p.strip()) for p in m.group(1).split(",") if p.strip().isdigit()}
            continue

        m = tag_re.match(stripped)
        if m:
            fields["tags"] = [t.strip().lower() for t in m.group(1).split(",")]
            continue

        m = cpe_re.match(stripped)
        if m:
            fields["cpes"] = [c.strip().lower() for c in m.group(1).split(",")]
            continue

    return fields


def _print_nrich_block(block: str):
    """
    Bir nrich bloğunu renkli olarak terminale yazar.
    Parse edilen alanları renklendirip orijinal formatı korur.
    Nmap komutuna giden veri etkilenmez — bu sadece görsel çıktıdır.
    """
    ip_re   = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})(\s*(?:\([^)]*\))?)$')
    port_re = re.compile(r'(Ports:\s*)(.*)',   re.IGNORECASE)
    tag_re  = re.compile(r'(Tags:\s*)(.*)',    re.IGNORECASE)
    cpe_re  = re.compile(r'(CPEs:\s*)(.*)',          re.IGNORECASE)
    vuln_re = re.compile(r'(Vulnerabilities:\s*)(.*)', re.IGNORECASE)

    lines = block.splitlines()
    out   = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        m = ip_re.match(stripped)
        if m:
            ip_part   = CYAN + BIG + m.group(1) + RESET
            host_part = DIM + (m.group(2) or "") + RESET
            out.append(f"  {ip_part}{host_part}")
            continue

        m = port_re.match(stripped)
        if m:
            ports_colored = ", ".join(
                f"{GREEN}{p.strip()}{RESET}" for p in m.group(2).split(",") if p.strip()
            )
            out.append(f"    {DIM}{m.group(1)}{RESET}{ports_colored}")
            continue

        m = tag_re.match(stripped)
        if m:
            tags_colored = ", ".join(
                f"{YELLOW}{t.strip()}{RESET}" for t in m.group(2).split(",") if t.strip()
            )
            out.append(f"    {DIM}{m.group(1)}{RESET}{tags_colored}")
            continue

        m = cpe_re.match(stripped)
        if m:
            cpes_colored = ", ".join(
                f"{BLUE}{c.strip()}{RESET}" for c in m.group(2).split(",") if c.strip()
            )
            out.append(f"    {DIM}{m.group(1)}{RESET}{cpes_colored}")
            continue

        m = vuln_re.match(stripped)
        if m:
            label = BIG + "Vulnerabilities:" + RESET
            cves_colored = ", ".join(
                f"{RED}{c.strip()}{RESET}" for c in m.group(2).split(",") if c.strip()
            )
            out.append(f"    {label} {cves_colored}")
            continue

        # Diğer satırlar olduğu gibi
        out.append(f"    {DIM}{stripped}{RESET}")

    print("\n".join(out))
    print()  # bloklar arası boşluk


def is_waf_cdn_block(block: str) -> tuple:
    """
    Uzman skorlama sistemi.
    Döner: (bool: waf_mı, str: neden)

    Skor ≥ 100 → WAF/CDN
    """
    f     = _parse_block_fields(block)
    score = 0
    reasons = []

    cpe_str      = " ".join(f["cpes"])
    hostname_str = " ".join(f["hostnames"]).lower()

    # ── HARD: CPE imzası ────────────────────────────────────────
    for sig in _HARD_CPE:
        if sig in cpe_str:
            score += 100
            reasons.append(f"CPE:{sig}")
            break

    # ── HARD: Hostname kalıbı ───────────────────────────────────
    for pattern in _HARD_HOSTNAME:
        for hostname in f["hostnames"]:
            if re.search(pattern, hostname.lower()):
                score += 100
                reasons.append(f"hostname:{hostname}")
                break
        if score >= 100:
            break

    # ── STRONG: WAF/CDN tag'i ───────────────────────────────────
    matched_strong_tags = [t for t in f["tags"] if t in _STRONG_TAGS]
    if matched_strong_tags:
        score += 60
        reasons.append(f"tags:{','.join(matched_strong_tags)}")

    # ── STRONG: Cloudflare'e özgü portlar ──────────────────────
    cf_ports = f["ports"] & _STRONG_PORTS
    if cf_ports:
        score += 50
        reasons.append(f"cf-ports:{sorted(cf_ports)}")

    # ── SOFT: Sadece web portları (80/443/8080/8443) ────────────
    if f["ports"] and f["ports"].issubset(_SOFT_PORTS):
        score += 20
        reasons.append("only-web-ports")

    # ── SOFT: Reverse proxy CPE ─────────────────────────────────
    for sig in _SOFT_CPE:
        if sig in cpe_str:
            score += 10
            reasons.append(f"proxy-cpe:{sig}")
            break

    # ── SOFT: "cloud" tag'i ─────────────────────────────────────
    if "cloud" in f["tags"]:
        score += 15
        reasons.append("tag:cloud")

    is_waf = score >= 100
    reason_str = ", ".join(reasons) if reasons else "clean"
    return is_waf, reason_str


# =============================
# IP EXTRACTION & NRICH
# =============================
def extract_and_scan_ips(urls):
    banner_section("IP EXTRACTION & NRICH SCAN")

    ips = set()
    url_to_ip = {}

    info("Extracting IPs from URLs..."); print()
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            url_to_ip[url] = ip
            print(f"    {DIM}{hostname}{RESET} → {CYAN}{ip}{RESET}")
        except Exception as e:
            print(f"    {DIM}{hostname}{RESET} → {RED}Failed{RESET} {DIM}({str(e)}){RESET}")
            continue

    if not ips:
        print(); warn("No IPs extracted — skipping nrich scan."); print()
        return

    ips_file = f"{BASE_DIR}/ips.txt"
    with open(ips_file, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

    print(); ok(f"Total unique IPs  : {len(ips)}")
    ok(f"IPs saved to {ips_file}"); print()

    info("Running nrich scan..."); print()
    print(DIM + "─" * 60 + RESET)

    nrich_output      = f"{BASE_DIR}/nrich_results.txt"
    nrich_output_full = f"{BASE_DIR}/nrich_results_full.txt"  # WAF IP'leri dahil tam kayıt

    try:
        master_fd, slave_fd = pty.openpty()
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        process = subprocess.Popen(
            ["nrich", ips_file],
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True
        )

        # Tüm çıktıyı önce hafızaya al, sonra bloklara bölerek filtrele
        raw_chunks = []

        while True:
            try:
                data = os.read(master_fd, 4096)
                if data:
                    raw_chunks.append(data.decode(errors="ignore"))
            except BlockingIOError:
                pass

            if process.poll() is not None:
                try:
                    while True:
                        data = os.read(master_fd, 4096)
                        if not data:
                            break
                        raw_chunks.append(data.decode(errors="ignore"))
                except:
                    pass
                break

            time.sleep(0.01)

        full_text = "".join(raw_chunks)

        # Tam çıktıyı kaydet (WAF IP'leri dahil, referans için)
        with open(nrich_output_full, "w") as f:
            f.write(full_text)

        # ── ANSI escape kodlarını temizle ──────────────────────────
        ansi_re  = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        clean_text = ansi_re.sub('', full_text)

        # ── Satır bazlı blok ayırıcı ────────────────────────────────
        # Her IPv4 ile başlayan satır yeni bir blok başlatır.
        # Girintili satırlar (boşluk/tab ile başlayan) mevcut bloğa eklenir.
        ip_start_re = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}')
        blocks      = []
        current     = []

        for line in clean_text.splitlines():
            if ip_start_re.match(line.strip()):
                if current:
                    blocks.append("\n".join(current))
                current = [line]
            elif current and (line.startswith(" ") or line.startswith("\t") or line.strip() == ""):
                if line.strip():   # boş satırları atlat, sadece içerikli girintili satırları ekle
                    current.append(line)
            # else: blok dışı satır (separator vb.) yoksay

        if current:   # son bloğu da ekle
            blocks.append("\n".join(current))

        filtered_parts = []
        skipped_count  = 0

        for block in blocks:
            is_waf, reason = is_waf_cdn_block(block)
            if is_waf:
                skipped_count += 1
                ip_line = block.splitlines()[0].strip()
                skip(f"WAF/CDN IP skipped: {YELLOW}{ip_line}{RESET}  {DIM}({reason}){RESET}")
            else:
                _print_nrich_block(block)
                filtered_parts.append(block)

        # Filtrelenmiş çıktıyı ana dosyaya kaydet
        with open(nrich_output, "w") as f:
            f.write("".join(filtered_parts))

        banner_done()
        if skipped_count:
            warn(f"{skipped_count} WAF/CDN IP(s) skipped — see nrich_results_full.txt")
        print(); ok(f"Nrich results saved to {nrich_output}"); print()

        # nrich sonuçlarını çağırana geri döndür (nmap için kullanılacak)
        return filtered_parts  # WAF/CDN filtrelenmiş bloklar

    except FileNotFoundError:
        err("nrich not found — install: https://gitlab.com/shodan-public/nrich"); print()
    except Exception as e:
        err(f"Nrich error: {str(e)}"); print()

    return []


# =============================
# NMAP CONCURRENT SCAN (depth 3-5)
# =============================
NMAP_MAX_PARALLEL = 5  # Eş zamanlı maksimum nmap süreci

def parse_nrich_blocks(blocks):
    """
    nrich bloklarından {ip: [port, ...]} sözlüğü çıkarır.
    WAF/CDN blokları zaten filtrelenmiş olarak gelir.

    nrich blok formatı:
        217.70.184.56 (webredir.gandi.net)
          Ports: 80, 443
          Tags: hosting
          CPEs: ...
    """
    ip_ports = {}
    ip_re    = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})')   # satır başındaki IP'yi al, parantezli kısmı yoksay
    port_re  = re.compile(r'Ports:\s*([\d,\s]+)', re.IGNORECASE)

    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        # İlk satırdan yalnızca IP adresini çek (hostname parantezi varsa at)
        ip_match = ip_re.match(lines[0].strip())
        if not ip_match:
            continue
        ip = ip_match.group(1)

        ports_match = port_re.search(block)
        if not ports_match:
            continue

        ports = [p.strip() for p in ports_match.group(1).split(",") if p.strip().isdigit()]
        if ports:
            ip_ports[ip] = ports  # ["80", "443", ...] — boşluksuz, join ile birleştirilecek

    return ip_ports


def _colorize_nmap_line(raw: str) -> str:
    """
    Tek bir nmap çıktı satırını parse edip renklendirir.
    Dosyaya yazılacak ham satır etkilenmez — sadece terminale renkli basar.

    Kategoriler:
      - Başlık / meta  (Starting Nmap, Nmap scan report, Host is up, Service detection...)
      - PORT tablosu   (PORT  STATE  SERVICE  VERSION başlığı + port satırları)
      - VULNERABLE     → kırmızı/kalın
      - script çıktısı (|  |_ önekli)  → indent + renk
      - Hata satırları (ERROR, TIMEOUT) → dim
    """
    s = raw.rstrip()

    # ── Boş satır ───────────────────────────────────────────────
    if not s.strip():
        return ""

    sl = s.lower().strip()

    # ── Meta / başlık satırları ──────────────────────────────────
    if s.strip().startswith("Starting Nmap"):
        return f"  {DIM}{s.strip()}{RESET}"

    if s.strip().startswith("Nmap scan report for"):
        host = s.strip().replace("Nmap scan report for ", "")
        return f"\n  {CYAN}{BIG}Nmap scan report{RESET}  {BIG}{host}{RESET}"

    if "host is up" in sl:
        latency = ""
        m = re.search(r"\(([^)]+latency[^)]*)\)", s, re.IGNORECASE)
        if m: latency = f"  {DIM}{m.group(1)}{RESET}"
        return f"  {GREEN}Host is up{RESET}{latency}"

    if s.strip().startswith("Service detection") or s.strip().startswith("Nmap done"):
        return f"  {DIM}{s.strip()}{RESET}"

    if "service unrecognized" in sl or "please report" in sl.lower():
        return f"  {DIM}{s.strip()}{RESET}"

    # ── PORT tablosu başlığı ─────────────────────────────────────
    if re.match(r"^PORT\s+STATE\s+SERVICE", s.strip(), re.IGNORECASE):
        return (f"  {DIM}{'─' * 56}{RESET}\n"
                f"  {DIM}{s.strip()}{RESET}\n"
                f"  {DIM}{'─' * 56}{RESET}")

    # ── PORT satırı: "443/tcp open ssl/http ..." ─────────────────
    m = re.match(r"^(\d+/\w+)\s+(open|closed|filtered)\s+(\S+)(.*)?$", s.strip())
    if m:
        port_proto = m.group(1)
        state      = m.group(2)
        service    = m.group(3)
        version    = (m.group(4) or "").strip()

        state_col = GREEN if state == "open" else (YELLOW if state == "filtered" else DIM)
        ver_col   = CYAN if version else ""

        return (f"  {CYAN}{BIG}{port_proto:<12}{RESET}"
                f"{state_col}{state:<10}{RESET}"
                f"{service:<18}"
                f"{ver_col}{version}{RESET}")

    # ── VULNERABLE / CVE ─────────────────────────────────────────
    if "vulnerable" in sl and "|" in s:
        return f"  {RED}{BIG}{s.strip()}{RESET}"

    if re.search(r"CVE-\d{4}-\d+", s):
        cve = re.search(r"(CVE-\d{4}-\d+)", s)
        colored = s.replace(cve.group(1), f"{RED}{BIG}{cve.group(1)}{RESET}") if cve else s
        return f"  {colored.strip()}"

    # ── Script output satırları (| veya |_) ──────────────────────
    stripped = s.strip()

    if stripped.startswith("|_"):
        body = stripped[2:].strip()
        bl = body.lower()
        # "bulunamadı / hata" satırları her zaman dim — vuln keyword içerse bile
        if any(x in bl for x in ["couldn't find", "no reply", "unable to test",
                "error:", "script execution failed", "timeout"]):
            return f"    {DIM}└─ {body}{RESET}"
        # Gerçek bulgular
        if any(x in bl for x in ["authentication was not required", "authentication bypass",
                "sql injection", "rce", "remote code", "directory traversal",
                "local file inclusion", "open redirect", "ssrf"]):
            return f"    {DIM}└─{RESET} {RED}{BIG}{body}{RESET}"
        return f"    {DIM}└─{RESET} {body}"

    if stripped.startswith("|"):
        body = stripped[1:].strip()
        if not body:
            return ""
        bl = body.lower()
        # State satırı
        if bl.startswith("state:"):
            state_val = body.split(":", 1)[1].strip().lower()
            col = RED if "vuln" in state_val else (YELLOW if "unknown" in state_val else GREEN)
            return f"    {DIM}│  State:{RESET} {col}{state_val.upper()}{RESET}"
        # IDs / CVE referansı
        if bl.startswith("ids:") or re.search(r"CVE-\d{4}-\d+", body):
            cve = re.search(r"(CVE-\d{4}-\d+)", body)
            cb = body.replace(cve.group(1), f"{RED}{BIG}{cve.group(1)}{RESET}{YELLOW}") if cve else body
            return f"    {DIM}│{RESET}  {YELLOW}{cb}{RESET}"
        # "bulunamadı / hata" satırları — vuln keyword içerse bile dim
        if any(x in bl for x in ["couldn't find", "no reply", "unable to test",
                "error:", "script execution failed", "timeout"]):
            return f"    {DIM}│  {body}{RESET}"
        # Gerçek bulgular
        if any(x in bl for x in ["authentication was not required", "authentication bypass",
                "sql injection", "rce", "remote code", "directory traversal",
                "local file inclusion", "open redirect", "ssrf"]):
            return f"    {DIM}│{RESET}  {RED}{BIG}{body}{RESET}"
        if any(x in bl for x in ["possible admin", "possible code", "possible backup",
                "possible config", "possible documentation"]):
            return f"    {DIM}│{RESET}  {YELLOW}{body}{RESET}"
        if len(body) > 120:
            return f"    {DIM}│  {body[:117]}...{RESET}"
        return f"    {DIM}│{RESET}  {body}"

    # ── SF-Port fingerprint (çok uzun, kısalt) ───────────────────
    if s.strip().startswith("SF-"):
        return f"  {DIM}[fingerprint data — see file]{RESET}"

    # ── Service Info ─────────────────────────────────────────────
    if s.strip().lower().startswith("service info:"):
        return f"  {GREEN}{BIG}{s.strip()}{RESET}"

    # ── Diğer ────────────────────────────────────────────────────
    return f"  {DIM}{s.strip()}{RESET}"


def _run_nmap_single(ip, ports, out_dir):
    """Tek bir IP için nmap çalıştırır, çıktıyı terminale renkli, dosyaya ham yazar."""
    port_str = ",".join(ports)
    out_file  = os.path.join(out_dir, f"nmap_{ip.replace('.', '_')}.txt")

    cmd = ["nmap", "-sV", "-p", port_str, "--script", "vuln", ip]

    sep    = DIM + "─" * 60 + RESET
    header = f"\n{sep}\n  {CYAN}[nmap]{RESET} {BIG}{ip}{RESET}  {DIM}→{RESET}  ports: {CYAN}{port_str}{RESET}\n{sep}\n"
    print(header)

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        ) as p:
            with open(out_file, "w") as f:
                f.write(f"[nmap] {ip}  →  ports: {port_str}\n")
                for raw_line in p.stdout:
                    f.write(raw_line)              # dosyaya ham
                    colored = _colorize_nmap_line(raw_line)
                    if colored:
                        print(colored)
            p.wait()
        print()
    except FileNotFoundError:
        err(f"nmap not found — skipping {ip}")
    except Exception as e:
        err(f"nmap error for {ip}: {e}")


def run_nmap_concurrent(nrich_blocks):
    """
    nrich bloklarını parse eder, her IP için kendi portlarıyla nmap başlatır.
    Eş zamanlı maksimum NMAP_MAX_PARALLEL (5) süreç çalışır;
    biri bitince kuyruktaki bir sonrakine geçilir.
    Yalnızca depth 3-5 için çağrılır.
    """
    if SCAN_DEPTH < 3:
        return

    banner_section("NMAP VULNERABILITY SCAN")

    ip_ports = parse_nrich_blocks(nrich_blocks)

    if not ip_ports:
        warn("No IP/port data from nrich — skipping nmap."); print()
        return

    nmap_out_dir = os.path.join(BASE_DIR, "nmap")
    os.makedirs(nmap_out_dir, exist_ok=True)

    info(f"Targets   : {len(ip_ports)} IP(s)")
    info(f"Parallel  : max {NMAP_MAX_PARALLEL} concurrent scans"); print()

    # Thread pool ile eş zamanlı tarama
    semaphore = threading.Semaphore(NMAP_MAX_PARALLEL)

    def worker(ip, ports):
        with semaphore:
            _run_nmap_single(ip, ports, nmap_out_dir)

    threads = []
    for ip, ports in ip_ports.items():
        t = threading.Thread(target=worker, args=(ip, ports), daemon=True)
        threads.append(t)
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(); warn("Ctrl+C — skipping nmap..."); print()
        return

    print(); ok(f"Nmap results saved to {nmap_out_dir}/"); print()


# =============================
# SUBZY
# =============================
def run_subzy_passive(input_file, urls):
    depth_cfg = get_depth_config(SCAN_DEPTH)
    banner_section("SUBZY TAKEOVER SCAN")

    ansi_escape = re.compile(rb'\x1B\[[0-?]*[ -/]*[@-~]')

    process = subprocess.Popen(
        [
            "subzy", "run",
            "--targets", input_file,
            "--timeout", depth_cfg["subzy_timeout"]
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    start_printing = False

    for raw_line in iter(process.stdout.readline, b""):
        clean = ansi_escape.sub(b"", raw_line)

        if b"[ No ] Show only potentially vulnerable subdomains (--hide_fails)" in clean:
            start_printing = True
            continue

        if start_printing and b"[ NOT VULNERABLE ]" not in clean and b"[ HTTP ERROR ]" not in clean:
            print(raw_line.decode(errors="ignore"), end="")

    process.wait()


# =============================
# NUCLEI SEQUENTIAL
# =============================
def run_nuclei_sequential(urls):
    depth_cfg = get_depth_config(SCAN_DEPTH)

    url_file = f"{BASE_DIR}/nuclei_urls.txt"
    with open(url_file, "w") as f:
        for u in urls:
            f.write(u + "\n")

    if WAF_DETECTED:  # human mode (forced or auto-detected)
        rate_limit = "20"
        timeout = "90"
        bulk_size = "10"
        concurrency = "5"
    else:             # aggressive mode (forced or auto-detected)
        rate_limit = NUCLEI_RATE
        timeout = NUCLEI_TIMEOUT
        bulk_size = "25"
        concurrency = "25"

    templates = depth_cfg["nuclei_templates"]

    for template in templates:
        out = f"{BASE_DIR}/nuclei_{template.split('/')[-1]}.txt"
        print(); info(f"Nuclei started → {CYAN}{template}{RESET}"); print()

        nuclei_cmd = [
            "nuclei",
            "-l", url_file,
            "-t", template,
            "-severity", "critical,high,medium",
            "-rate-limit", rate_limit,
            "-timeout", timeout,
            "-bulk-size", bulk_size,
            "-c", concurrency,
            "-max-host-error", "999999",
            "-stats"
        ]

        if WAF_DETECTED:
            nuclei_cmd.extend(["-retries", "2", "-no-stdin"])

        with open(out, "w") as f:
            run_nuclei_filtered(nuclei_cmd, f)


# =============================
# OSINT & LEAK CHECK (DEPTH 5)
# =============================
def check_leak(email):
    """Leaknix üzerinden e-posta sızıntı kontrolü yapar."""
    url = f"https://leaknix.com/email-check.data?email={email}"

    try:
        response = requests.get(url, timeout=15)
        content = response.text

        if '"limitReached",true' in content.replace(" ", ""):
            print(f"\n  {YELLOW}[!]{RESET} {email} → Limit reached.")
            return

        if '"found",0' in content.replace(" ", ""):
            print(f"\n  {CYAN}[i]{RESET} {email} → No data found.")
            return

        raw = json.loads(content)

        # result indexlerini bul
        result_indexes = []
        for i in range(len(raw)):
            if raw[i] == "result":
                result_indexes = raw[i + 1]
                break

        # string liste
        data = re.findall(r'"([^"]+)"', content)

        def is_site(val):
            return "." in val and not val.replace(".", "").isdigit()

        def is_date(val):
            return re.match(r"\d{4}-\d{2}", val)

        records = []

        for idx_i in range(len(result_indexes)):
            start = result_indexes[idx_i]

            if idx_i + 1 < len(result_indexes):
                end = result_indexes[idx_i + 1]
            else:
                end = len(raw)

            chunk = data[start:start + 30]

            record = {
                "email": email,
                "password": "-",
                "username": "-",
                "site": "-",
                "breach_date": "-"
            }

            for i, val in enumerate(chunk):
                if val == "password" and i + 1 < len(chunk):
                    record["password"] = chunk[i + 1]

                if val == "name" and i + 1 < len(chunk):
                    next_val = chunk[i + 1]
                    if not is_site(next_val):
                        record["username"] = next_val

                if is_site(val):
                    record["site"] = val

                if is_date(val):
                    record["breach_date"] = val

            records.append(record)

        # TABLO
        print("\n" + "  " + "=" * 110)
        print(f"  {RED}[!]{RESET} {email} Leaks Detected:\n")
        print(f"  {'E-MAIL':<30} | {'PASSWORD':<20} | {'BREACH NAME':<20} | {'BREACH DATE':<12} | {'BREACHED':<25}")
        print("  " + "-" * 110)

        for r in records:
            print(f"  {r['email']:<30} | "
                  f"{r['password']:<20} | "
                  f"{r['username']:<20} | "
                  f"{r['breach_date']:<12} | "
                  f"{r['site']:<25}")

        print("  " + "=" * 110)

    except Exception as e:
        print(f"  {RED}[!]{RESET} Error: {e}")


def fetch_proxynova(domain):
    """Proxynova API üzerinden domain için sızıntıları getirir."""
    url = f"https://api.proxynova.com/comb?query=@{domain}&start=0&limit=100"

    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            lines = response.text.splitlines()

            # Sadece hedef domaini içerenleri al ve temizle
            found = [
                line.replace('"', '').replace(',', '').strip()
                for line in lines if f"@{domain}" in line
            ]

            if found:
                # 👉 BURAYA TAŞINDI
                print(f"\n  {RED}[!]{RESET} Leaked {domain} Mail(s) Found...")

                unique_found = list(set(found))

                print("\n  " + "="*70)
                print(f"  {'E-MAIL':<40} | {'PASSWORD'}")
                print("  " + "-" * 70)

                for entry in unique_found:
                    if ":" in entry:
                        email, password = entry.split(":", 1)
                        print(f"  {email:<40} | {password}")

                print("  " + "="*70)
            else:
                print(f"  {YELLOW}[!]{RESET} No data found for {domain}.")
        else:
            print(f"  {RED}[!]{RESET} API Error: {response.status_code}")

    except Exception as e:
        print(f"  {RED}[!]{RESET} Connection error: {e}")


def run_osint_scan(domain):
    """
    OSINT taraması yapar (depth 5'te aktif).
    Subdomain girilirse otomatik olarak root domain'e düşürür.
    """

    # ── ROOT DOMAIN FIX ───────────────────────────────────────
    try:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
    except:
        pass

    if SCAN_DEPTH < 0:
        return

    banner_section("LEAKED DATA SCAN")

    info(f"Running OSINT scan for {CYAN}{domain}{RESET}..."); print()

    cmd = [
        "spiderfoot",
        "-m", "sfp_email,sfp_phone,sfp_haveibeenpwned,sfp_username,sfp_leaks,sfp_whois,sfp_geoips,sfp_dns,sfp_pgp,sfp_social",
        "-s", domain,
        "-q"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        
        keywords = ["Domain Registrar", "Affiliate - Email Address", "Phone Number"]
        found_lines = []
        emails = set()

        for line in result.stdout.splitlines():
            if any(keyword in line for keyword in keywords):
                found_lines.append(line)
            found_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', line)
            emails.update(found_emails)
        
        if not found_lines:
            print(f"  {YELLOW}[!]{RESET} No SpiderFoot data found.\n")
        else:
            print("\n  " + "="*80)
            print(f"  {'MODULE':<30} {'TYPE':<40} {'DATA'}")
            print("  " + "-" * 80)
            for line in found_lines:
                print(f"  {line}")
            print("  " + "="*80)
        
        # E-posta sızıntı kontrolleri
        if emails:
            print(f"\n  {CYAN}[i]{RESET} Checking {len(emails)} email(s) for leaks...\n")
            for email in emails:
                check_leak(email)
        
        # Proxynova sorgusu
        fetch_proxynova(domain)

        # Sonuçları dosyaya kaydet
        osint_output = f"{BASE_DIR}/osint_results.txt"
        with open(osint_output, "w") as f:
            f.write(f"OSINT Scan Results for {domain}\n")
            f.write("=" * 80 + "\n\n")
            f.write("SpiderFoot Output:\n")
            f.write(result.stdout)
            f.write("\n\nEmails Found:\n")
            for email in emails:
                f.write(f"  {email}\n")
        
        print(); ok(f"OSINT results saved to {osint_output}"); print()

    except subprocess.TimeoutExpired:
        warn("SpiderFoot scan timeout — skipping..."); print()
    except subprocess.CalledProcessError as e:
        err(f"SpiderFoot error: {e}"); print()
    except FileNotFoundError:
        warn("SpiderFoot not found — skipping OSINT scan..."); print()
    except Exception as e:
        err(f"OSINT scan error: {e}"); print()


# =============================
# ARG PARSER
# =============================
def parse_args():
    parser = argparse.ArgumentParser(
        prog="vulnflow",
        description="Vulnflow — automated vulnerability scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL (e.g. https://example.com)\nLeave empty to be prompted interactively."
    )

    parser.add_argument(
        "--depth",
        type=int,
        choices=range(1, 6),
        metavar="[1-5]",
        default=None,
        help=(
            "Scan depth (1-5):\n"
            "  1 — minimal/fast  (subfinder only, 1 template set)\n"
            "  2 — light         (subfinder + assetfinder, 2 template sets)\n"
            "  3 — default       (subfinder + assetfinder, 3 template sets)\n"
            "  4 — deep          (+ gobuster DNS, 5 template sets)\n"
            "  5 — maximum       (all tools, all template sets, OSINT scan)"
        )
    )

    parser.add_argument(
        "--mode",
        choices=["aggressive", "human", "auto"],
        default=None,
        help=(
            "Scan mode:\n"
            "  aggressive — ignore WAF, full speed\n"
            "  human      — always use slow/stealth settings\n"
            "  auto       — detect WAF and decide automatically (default)"
        )
    )

    return parser.parse_args()


# =============================
# MAIN
# =============================
def main():
    global target, BASE_DIR, SCAN_MODE, SCAN_DEPTH

    print(f"""
 __   ___   _ _    _  _ ___ _    _____      __
 \\ \\ / / | | | |  | \\| | __| |  / _ \\ \\    / /
  \\ V /| |_| | |__| .` | _|| |_| (_) \\ \\/\\/ / 
   \\_/  \\___/|____|_|\\_|_| |____\\___/ \\_/\\_/  v{version}
    """)

    print(
        f"  {RED}{BIG}[!]{RESET} {YELLOW}{BIG}Legal Disclaimer:{RESET} "
        f"Vulnflow is for {BIG}authorized{RESET} security testing only. "
        f"{RED}Any unauthorized use is illegal.{RESET} "
        f"{DIM}The user is solely responsible for complying with all applicable laws. "
        f"The developers assume no liability for misuse or damages.{RESET}\n"
    )

    args = parse_args()

    # ── Target ──────────────────────────────────────────────────
    if args.target:
        target = args.target.strip()
    else:
        target = input(f"  {CYAN}▶{RESET} Target URL (https://example.com): ").strip()

    # ── Depth ───────────────────────────────────────────────────
    if args.depth is not None:
        SCAN_DEPTH = args.depth
    else:
        depth_input = input(f"  {CYAN}▶{RESET} Scan depth [1-5] (default 3): ").strip()
        if depth_input:
            if depth_input.isdigit() and 1 <= int(depth_input) <= 5:
                SCAN_DEPTH = int(depth_input)
            else:
                warn("Invalid depth — using default: 3")
                SCAN_DEPTH = 3
        else:
            SCAN_DEPTH = 3

    # ── Mode ────────────────────────────────────────────────────
    if args.mode is not None:
        SCAN_MODE = args.mode
    else:
        SCAN_MODE = "auto"  # mode is auto by default, no need to ask

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    # ── Output dir ──────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    BASE_DIR = f"scan_output/{domain}_{timestamp}"
    os.makedirs(BASE_DIR, exist_ok=True)

    print(); info(f"Scan output directory : {BIG}{BASE_DIR}{RESET}")
    info(f"Depth                 : {BIG}{SCAN_DEPTH}/5{RESET}")
    info(f"Mode                  : {BIG}{SCAN_MODE}{RESET}"); print()

    start = datetime.now()

    check_target(domain)
    run_subdomain_combo(domain)

    _, urls = merge_urls()

    urls = prune_urls(urls, domain, target)
    nucleiurls = keep_only_homepages(urls)

    nuclei_url_file = f"{BASE_DIR}/nuclei_urls.txt"
    print(); info(f"Writing {len(nucleiurls)} live URLs to {nuclei_url_file}..."); print()
    with open(nuclei_url_file, "w") as f:
        for u in nucleiurls:
            f.write(u + "\n")

    nrich_blocks = extract_and_scan_ips(nucleiurls)

    if SCAN_DEPTH >= 3 and nrich_blocks:
        run_nmap_concurrent(nrich_blocks)

    run_subzy_passive(nuclei_url_file, nucleiurls)
    run_nuclei_sequential(nucleiurls)

    # ── OSINT taraması (depth 5) ────────────────────────────────
    run_osint_scan(domain)

    banner_section("DONE")
    ok(f"Duration : {(datetime.now() - start).seconds}s")
    ok(f"Output   : {BIG}{BASE_DIR}/{RESET}")


if __name__ == "__main__":
    main()
