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

from datetime import datetime
from urllib.parse import urlparse, parse_qsl
from collections import defaultdict

# developed by wqyigitpw
version = "1.0.8"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BIG = "\033[1m"
RESET = "\033[0m"


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
        print("\n[!] Ctrl+C detected → skipping to next step...\n")
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

    print("\n========== TARGET CHECK ==========\n")

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(url, timeout=8, allow_redirects=True)

            host = r.url.split("/")[2]
            ip = socket.gethostbyname(host)

            print(f"[+] Target is {GREEN}ALIVE{RESET}")
            print(f"    URL : {BIG}{r.url}{RESET}")
            print(f"    IP  : {ip}")
            print(f"    Code: {GREEN}{r.status_code}{RESET}")

            # ── Mode logic ──────────────────────────────────────────
            if SCAN_MODE == "aggressive":
                WAF_DETECTED = False
                print(f"    WAF : {YELLOW}(skipped — aggressive mode){RESET}")
                print(f"\n{GREEN}[i] Aggressive mode forced — skipping WAF detection{RESET}")

            elif SCAN_MODE == "human":
                WAF_DETECTED = True
                print(f"    WAF : {YELLOW}(skipped — human mode){RESET}")
                print(f"\n{YELLOW}[i] Human mode forced — WAF detection skipped{RESET}")

            else:  # auto
                waf = detect_waf(r.url)
                if waf:
                    WAF_DETECTED = True
                    print(f"    WAF : {RED}{BIG}{waf}{RESET}")
                    print(f"\n{YELLOW}[!] WAF DETECTED - Enabling Human Mode:{RESET}")
                    print(f"    • Gobuster DNS will be disabled")
                    print(f"    • Nuclei rate-limit reduced to appear human-like")
                else:
                    WAF_DETECTED = False
                    print(f"    WAF : {GREEN}Not Detected!{RESET}")
                    print(f"\n{GREEN}[i] WAF not detected - Enabling Aggressive Mode{RESET}")

            print(f"\n[i] Scan depth : {BIG}{SCAN_DEPTH}/5{RESET}")
            print(f"[i] Scan mode  : {BIG}{SCAN_MODE}{RESET}")
            print("\n[i] Continuing in 3 seconds...\n")
            time.sleep(3)
            return r.url

        except:
            continue

    print("[-] Target unreachable. Aborting.")
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
                print(clean)
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
        print(f"[i] '{domain}' is already a subdomain; active enumeration is being skipped.")
        print(f"[i] Adding target subdomain to list...\n")
        with open(out_path, "w") as f:
            f.write(domain + "\n")
        print(f"[✓] Target subdomain saved to {out_path}")
        return out_path

    print("\n========== SUBDOMAIN ENUMERATION ==========\n")

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
            print("\n[!] Ctrl+C detected → stopping subdomain enumeration, moving on...\n")
            return

    print(f"\n[✓] Subdomains saved to {out_path}")
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
    print("\n========== FINAL URL PRUNING ==========\n")

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

    print(f"[✓] URLs before prune : {len(urls)}")
    print(f"[✓] URLs after prune  : {len(final_urls)}")

    output_path = f"{BASE_DIR}/pruned_urls.txt"
    with open(output_path, "w") as f:
        for u in final_urls:
            f.write(u + "\n")

    print(f"[✓] Saved to {output_path}")
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

    print(f"[✓] Total homepages : {len(homepages)}")
    print(f"[✓] Live            : {len(live_urls)}")

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
# WAF / CDN IP FILTER
# =============================
# nrich çıktısında bu keyword'lerden biri geçen IP blokları terminalde gösterilmez.
# WAF tespit edilmese bile Cloudflare/Akamai gibi CDN'lere ait IP'leri
# hedef IP olarak işlemek anlamsız olduğundan her zaman filtrelenir.
WAF_CDN_KEYWORDS = [
    "cloudflare",
    "akamai",
    "fastly",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "aws shield",
    "azure front door",
    "google cloud armor",
    "f5",
    "barracuda",
    "reblaze",
    "radware",
    "cdn77",
    "limelight",
    "keycdn",
    "bunnycdn",
    "ddos-guard",
    "qrator",
]

def is_waf_cdn_block(block: str) -> bool:
    """Bir nrich IP bloğu WAF/CDN'e aitse True döner."""
    lower = block.lower()
    return any(kw in lower for kw in WAF_CDN_KEYWORDS)


# =============================
# IP EXTRACTION & NRICH
# =============================
def extract_and_scan_ips(urls):
    print("\n========== IP EXTRACTION & NRICH SCAN ==========\n")

    ips = set()
    url_to_ip = {}

    print("[i] Extracting IPs from URLs...\n")
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            url_to_ip[url] = ip
            print(f"  {hostname} → {ip}")
        except Exception as e:
            print(f"  {hostname} → Failed ({str(e)})")
            continue

    if not ips:
        print("\n[!] No IPs extracted. Skipping nrich scan.\n")
        return

    ips_file = f"{BASE_DIR}/ips.txt"
    with open(ips_file, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

    print(f"\n[✓] Total unique IPs: {len(ips)}")
    print(f"[✓] IPs saved to {ips_file}\n")

    print("[i] Running nrich scan...\n")
    print("=" * 60)

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

        # IP bloklarına böl: her blok bir IPv4 adresiyle başlar
        # Örnek blok:
        #   172.67.179.135
        #     Ports: 80, 443
        #     Tags: cdn
        #     CPEs: cpe:/a:cloudflare:cloudflare
        ip_block_re = re.compile(
            r'(\d{1,3}(?:\.\d{1,3}){3}[^\n]*\n(?:[ \t]+[^\n]*\n)*)',
            re.MULTILINE
        )
        blocks = ip_block_re.findall(full_text)

        filtered_parts = []
        skipped_count  = 0

        for block in blocks:
            if is_waf_cdn_block(block):
                skipped_count += 1
                ip_line = block.splitlines()[0].strip()
                print(f"  {YELLOW}[~] Skipping WAF/CDN IP: {ip_line}{RESET}")
            else:
                print(block, end="")
                filtered_parts.append(block)

        # Filtrelenmiş çıktıyı ana dosyaya kaydet
        with open(nrich_output, "w") as f:
            f.write("".join(filtered_parts))

        print("=" * 60)
        if skipped_count:
            print(
                f"\n{YELLOW}[i] {skipped_count} WAF/CDN IP(s) skipped "
                f"(full output → nrich_results_full.txt){RESET}"
            )
        print(f"\n[✓] Nrich results saved to {nrich_output}\n")

    except FileNotFoundError:
        print("[!] nrich not found. Please install it: https://gitlab.com/shodan-public/nrich\n")
    except Exception as e:
        print(f"[!] Nrich error: {str(e)}\n")


# =============================
# SUBZY
# =============================
def run_subzy_passive(input_file, urls):
    depth_cfg = get_depth_config(SCAN_DEPTH)
    print("\n========== SUBZY TAKEOVER SCAN ==========\n")

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
        print(f"\n[i] Nuclei started → {template}\n")

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
            "  5 — maximum       (all tools, all template sets)"
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
        f"{RED}{BIG}[!]{RESET} {YELLOW}{BIG}Legal Disclaimer:{RESET} "
        f"Vulnflow is for authorized security testing only. "
        f"{BIG}Any unauthorized use is illegal.{RESET} "
        f"The user is solely responsible for complying with all applicable laws. "
        f"The developers assume no liability for misuse or damages.\n"
    )

    args = parse_args()

    # ── Target ──────────────────────────────────────────────────
    if args.target:
        target = args.target.strip()
    else:
        target = input(f"{BIG}Target URL (https://example.com): {RESET}").strip()

    # ── Depth ───────────────────────────────────────────────────
    if args.depth is not None:
        SCAN_DEPTH = args.depth
    else:
        depth_input = input(
            f"{BIG}Scan depth [1-5] (default 3): {RESET}"
        ).strip()
        if depth_input:
            if depth_input.isdigit() and 1 <= int(depth_input) <= 5:
                SCAN_DEPTH = int(depth_input)
            else:
                print(f"{YELLOW}[!] Invalid depth, using default: 3{RESET}")
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

    print(f"\n[i] Scan output directory : {BIG}{BASE_DIR}{RESET}")
    print(f"[i] Depth                 : {BIG}{SCAN_DEPTH}/5{RESET}")
    print(f"[i] Mode                  : {BIG}{SCAN_MODE}{RESET}\n")

    start = datetime.now()

    check_target(domain)
    run_subdomain_combo(domain)

    _, urls = merge_urls()

    urls = prune_urls(urls, domain, target)
    nucleiurls = keep_only_homepages(urls)

    nuclei_url_file = f"{BASE_DIR}/nuclei_urls.txt"
    print(f"\n[i] Writing {len(nucleiurls)} live URLs to {nuclei_url_file}...\n")
    with open(nuclei_url_file, "w") as f:
        for u in nucleiurls:
            f.write(u + "\n")

    extract_and_scan_ips(nucleiurls)
    run_subzy_passive(nuclei_url_file, nucleiurls)
    run_nuclei_sequential(nucleiurls)

    print("\n========== DONE ==========")
    print(f"Duration : {(datetime.now() - start).seconds}s")
    print(f"Output   : {BIG}{BASE_DIR}/{RESET}")


if __name__ == "__main__":
    main()
