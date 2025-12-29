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
from datetime import datetime
from multiprocessing import Process
from urllib.parse import urlparse

# developed by wqyigitpw
version = "1.0.1"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BIG = "\033[1m"
RESET = "\033[0m"


# =============================
# CONFIG
# =============================
BASE_DIR = "scan_output"
DNS_WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

NUCLEI_WORKERS = 1          # 🔥 AYNI ANDA KAÇ LINK GRUBU
NUCLEI_RATE = "10000"
NUCLEI_TIMEOUT = "21"
NUCLEI_CCC = "25"

os.makedirs(BASE_DIR, exist_ok=True)

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

        # WAF tespit satırı
        match = re.search(r"is behind\s+(.+?)\s+\(", result)
        if match:
            return match.group(1)
        else:
            return "Not Detected!"
    except:
        return "Not Detected!"


def check_target(domain):
    print("\n========== TARGET CHECK ==========\n")

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(url, timeout=8, allow_redirects=True)

            host = r.url.split("/")[2]
            ip = socket.gethostbyname(host)

            waf = detect_waf(r.url)

            print(f"[+] Target is {GREEN}ALIVE{RESET}")
            print(f"    URL : {BIG}{r.url}{RESET}")
            print(f"    IP  : {ip}")
            print(f"    Code: {GREEN}{r.status_code}{RESET}")
            print(f"    WAF : {waf}{RESET}")

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
    # ext.subdomain boş değilse → subdomain
    return ext.subdomain != ""
    
def run_gobuster(domain):

    print("\n========== GOBUSTER DNS ==========\n")
    with open(f"{BASE_DIR}/gobuster_dns.txt", "w") as f:
        run_cmd([
            "gobuster", "dns",
            "--do", domain,
            "-w", DNS_WORDLIST,
            "-t", "50",
            "--wildcard",
            "--timeout", "60s"
        ], f)
        
def run_subfinder(domain):

    print("\n========== SUBFINDER ==========\n")
    with open(f"{BASE_DIR}/subfinder.txt", "w") as f:
        run_cmd([
            "subfinder",
            "-d", domain,
            "-silent"
        ], f)
        
def run_assetfinder(domain):

    print("\n========== ASSETFINDER ==========\n")
    with open(f"{BASE_DIR}/assetfinder.txt", "w") as f:
        run_cmd([
            "assetfinder",
            "--subs-only",
            domain
        ], f)
        
def run_subdomain_combo(domain):
    if is_subdomain(domain):
        print(f"[i] '{domain}' is already a subdomain; subdomain scan is being skipped.")
        return

    print("\n========== SUBDOMAIN ENUMERATION ==========\n")

    out_path = f"{BASE_DIR}/subdomains.txt"

    with open(out_path, "w") as f:
        threads = []

        t1 = threading.Thread(
            target=run_cmd_domains_only,
            args=(["subfinder", "-d", domain, "-silent"], f)
        )

        t2 = threading.Thread(
            target=run_cmd_domains_only,
            args=(["assetfinder", "--subs-only", domain], f)
        )

        t3 = threading.Thread(
            target=run_cmd_domains_only,
            args=([
                "gobuster", "dns",
                "--do", domain,
                "-w", DNS_WORDLIST,
                "-t", "50",
                "--wildcard",
                "--timeout", "60s"
            ], f)
        )

        for t in (t1, t2, t3):
            t.start()
            threads.append(t)

        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected → stopping subdomain enumeration, moving on...\n")
            return

    print(f"\n[✓] Subdomains saved to {out_path}")
    return out_path


# =============================
# GOBUSTER DIR (SMART)
# =============================
def run_gobuster_dir(url):
    base = get_base(url)
    print("\n========== GOBUSTER DIR ==========\n")
    
    cmd = [
        "gobuster", "dir",
        "-u", base,
        "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "-t", "60",
        "--status-codes-blacklist", "301,302,404,429,503",
        "--timeout", "60s"
    ]

    out_path = f"{BASE_DIR}/gobuster_dir.txt"

    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    ) as p, open(out_path, "w") as f:

        base = url.rstrip("/")

        try:
            for line in p.stdout:
                line = line.strip()

                # sadece gerçek sonuç satırları
                if line.startswith("/") and "(Status:" in line:
                    path = line.split()[0]
                    full_url = base + path
                    print(full_url)
                    f.write(full_url + "\n")

            p.wait()

        except KeyboardInterrupt:
            print("\n[!] Ctrl+C detected → stopping path brute-force, moving on...\n")
            try:
                p.terminate()
            except:
                pass
            return

    print(f"[✓] Clean URLs saved to {out_path}")


# =============================
# KATANA
# =============================
def run_katana(url):
    print("\n========== SPİDER ==========\n")
    with open(f"{BASE_DIR}/katana.txt", "w") as f:
        run_cmd([
            "katana",
            "-u", url,
            "-d", "3",
            "-timeout", "40",
            "-silent"
        ], f)

# =============================
# MERGE URLS
# =============================
def merge_urls():
    urls = set()
    
    urls.add(target.rstrip("/"))

    # 1️⃣ Subdomain’ler → URL’e çevrilir
    sub_path = f"{BASE_DIR}/subdomains.txt"
    if os.path.exists(sub_path):
        with open(sub_path) as f:
            for line in f:
                sub = line.strip()
                if sub:
                    urls.add(f"http://{sub}")
                    urls.add(f"https://{sub}")

    # 2️⃣ Katana çıktıları (tam URL)
    katana_path = f"{BASE_DIR}/katana.txt"
    if os.path.exists(katana_path):
        with open(katana_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("http"):
                    urls.add(line)

    # 3️⃣ Gobuster DIR → path + BASE_URL
    dir_path = f"{BASE_DIR}/gobuster_dir.txt"
    if os.path.exists(dir_path):
        with open(dir_path) as f:
            for line in f:
                line = line.strip()
                if "(Status:" in line:
                    p = line.split()[0]
                    if p.startswith("/"):
                        urls.add(BASE_URL.rstrip("/") + p)

    out = f"{BASE_DIR}/all_urls.txt"
    with open(out, "w") as f:
        for u in sorted(urls):
            f.write(u + "\n")

    return out, list(urls)


# =============================
# PRUNE URLS
# =============================
def prune_urls(urls, base_domain):
    print("\n========== FINAL URL PRUNING ==========\n")

    import subprocess
    import tempfile
    import hashlib
    from urllib.parse import urlparse, parse_qsl
    from collections import defaultdict

    # -----------------------------
    # 1️⃣ Normalize + domain filter
    # -----------------------------
    cleaned = set()

    for url in urls:
        try:
            url = url.strip().rstrip("/")
            parsed = urlparse(url)

            if base_domain not in parsed.netloc:
                continue

            cleaned.add(url)
        except:
            continue

    # ----------------------------------------
    # 2️⃣ Parametre çeşitliliğini maksimize et
    # ----------------------------------------
    path_groups = defaultdict(list)

    for url in cleaned:
        parsed = urlparse(url)
        params = set(k for k, _ in parse_qsl(parsed.query))
        path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        path_groups[path_key].append((url, params))

    param_pruned_urls = []

    for path, url_list in path_groups.items():
        all_params = set().union(*(p for _, p in url_list))
        covered = set()

        url_list.sort(key=lambda x: len(x[1]), reverse=True)

        for url, params in url_list:
            if not params:
                continue

            if not params.issubset(covered):
                param_pruned_urls.append(url)
                covered.update(params)

            if covered == all_params:
                break

        if not all_params and url_list:
            param_pruned_urls.append(url_list[0][0])

    # -----------------------------
    # 3️⃣ httpx ile ölüleri sil
    # -----------------------------
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        for u in param_pruned_urls:
            tmp.write(u + "\n")
        tmp_path = tmp.name

    try:
        alive = subprocess.check_output(
            [
                "httpx",
                "-l", tmp_path,
                "-silent",
                "-mc", "200,201,202,204,301,302,307,308"
            ],
            text=True
        ).splitlines()
    except:
        alive = param_pruned_urls

    # ----------------------------------
    # 4️⃣ HTML hash ile aynı içerikleri sil
    # ----------------------------------
    html_hashes = {}
    final_urls = []

    for url in alive:
        try:
            body = subprocess.check_output(
                ["curl", "-sL", "--max-time", "10", url],
                text=True,
                stderr=subprocess.DEVNULL
            )
            h = hashlib.sha256(body.encode(errors="ignore")).hexdigest()

            if h not in html_hashes:
                html_hashes[h] = url
                final_urls.append(url)
        except:
            continue

    print(f"[✓] URLs before prune : {len(urls)}")
    print(f"[✓] URLs after prune  : {len(final_urls)}")

    return final_urls



# =============================
# SPLIT URLS
# =============================
def split_urls(urls, parts):
    size = len(urls) // parts + 1
    return [urls[i:i + size] for i in range(0, len(urls), size)]

# =============================
# NUCLEI WORKER
# =============================
def run_nuclei_filtered(cmd, outfile):
    levels = ("info", "low", "medium", "high", "critical", "%)")
    seen_lines = set()  # ← BURASI ÖNEMLİ

    print("\n[i] Running general vulnerability scan on all active links")

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

            # severity filtresi
            if not any(level in lower for level in levels):
                continue

            # duplicate engelleme
            if clean in seen_lines:
                continue

            seen_lines.add(clean)

            print(clean)
            outfile.write(clean + "\n")

        p.wait()


def nuclei_worker(urls, index):
    file = f"{BASE_DIR}/urls_part_{index}.txt"
    out = f"{BASE_DIR}/nuclei_part_{index}.txt"

    with open(file, "w") as f:
        for u in urls:
            f.write(u + "\n")

    with open(out, "w") as f:
        run_nuclei_filtered([
            "nuclei",
            "-l", file,
            "-t", "/root/.local/nuclei-templates/http/exposures,/root/.local/nuclei-templates/http/cves,/root/.local/nuclei-templates/http/misconfiguration",
            "-severity", "critical,high,medium",
            "-rate-limit", str(NUCLEI_RATE),
            "-timeout", str(NUCLEI_TIMEOUT),
            "-concurrency", str(NUCLEI_CCC),
            "-stats"
        ], f)

# =============================
# GENERAL VULNERABILITY SCANNING
# =============================
def run_nuclei_parallel(urls):
    print("\n========== GENERAL VULNERABILITY SCANNING ==========\n")

    chunks = split_urls(urls, NUCLEI_WORKERS)
    processes = []

    for i, chunk in enumerate(chunks):
        p = Process(target=nuclei_worker, args=(chunk, i))
        p.start()
        processes.append(p)

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected → stopping scan, moving on...\n")
        for p in processes:
            try:
                p.terminate()
            except:
                pass
        return


# =============================
# MAIN
# =============================
def main():
    global target

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

    target = input(f"{BIG}Target URL (https://example.com): {RESET}").strip()
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    start = datetime.now()

    url = check_target(domain)
    run_subdomain_combo(domain)
    run_gobuster_dir(url)
    run_katana(url)

    _, urls = merge_urls()

    base_domain = domain  # example.com
    urls = prune_urls(urls, base_domain)

    run_nuclei_parallel(urls)

    print("\n========== DONE ==========")
    print(f"Duration: {(datetime.now() - start).seconds}s")
    print(f"Output: {BASE_DIR}/")

if __name__ == "__main__":
    main()
