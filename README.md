# Vulnflow v1.0.9

Vulnflow is an advanced open-source **web vulnerability scanning framework** built for **authorized penetration testing and bug bounty workflows**.

It combines reconnaissance, intelligent filtering, infrastructure analysis, and vulnerability scanning into a **single automated pipeline**.

---

## 🚀 What's New in v1.0.9

- 🔥 **Depth-based scanning system (1–5)**
- 🧠 **Smart WAF detection & adaptive scan mode**
- 🌐 **Advanced subdomain enumeration (subfinder, assetfinder, gobuster)**
- 🧹 **Intelligent URL pruning & normalization**
- ⚡ **Live endpoint filtering (httpx)**
- 🛰️ **nrich integration (IP intelligence)**
- 🛡️ **WAF/CDN filtering (expert scoring system)**
- 🎯 **Concurrent Nmap vulnerability scanning**
- 💥 **Advanced Nuclei scanning (multi-template queue)**
- 📡 **Subdomain takeover detection (Subzy)**
- 🔥 **All HTTP(S) scan (Nuclei)**
- 🕵️ **OSINT & leak detection**

---

## ⚙️ Features

- Automated URL collection & expansion  
- Active endpoint detection  
- Smart parameter pruning  
- Depth-based modular scanning  
- Adaptive scan modes (auto / aggressive / human)  
- Infrastructure intelligence (IP → ports → services)  
- Vulnerability scanning (Nuclei + Nmap)  
- Clean and structured output  

---

## 📸 Screenshots

![Vulnflow Scan](https://i.ibb.co/xKcXJJLw/Screenshot-2.png)  
![Vulnflow Output](https://i.ibb.co/G4MpHtxB/Screenshot-3.png)
![Vulnflow Output](https://i.ibb.co/0RKRHc8q/Screenshot-5.png)

---

## 📦 Installation

Clone the repository:

git clone https://github.com/wqyigitpw/vulnflow
cd vulnflow  

Run the installer:

chmod +x install.sh  
./install.sh  

And install requirements:

pip install -r requirements.txt  

---

## 🔧 Required External Tools

Automatically installed by installer:

- httpx  
- nuclei  
- gobuster  
- wafw00f  
- subfinder  
- assetfinder  
- subzy  
- nmap  
- nrich  
- spiderfoot  

---

## 🧪 Usage

Run:

python vulnflow.py  

Or:

python vulnflow.py https://example.com --depth 4 --mode auto  

---

## 🎚️ Scan Depth Levels

| Depth | Description |
|------|------------|
| 1 | Minimal / fast |
| 2 | Light |
| 3 | Default |
| 4 | Deep |
| 5 | Maximum (includes OSINT) |

---

## ⚡ Scan Modes

| Mode | Description |
|------|------------|
| auto | WAF detection + adaptive |
| aggressive | Full speed |
| human | Stealth |

---

## 🔄 Workflow

1. Target check + WAF detection  
2. Subdomain enumeration  
3. URL normalization  
4. Live filtering  
5. IP extraction + nrich  
6. WAF/CDN filtering  
7. Nmap scan  
8. Subdomain takeover scan  
9. Nuclei scan  
10. (Depth 5) OSINT scan  

---

## 📂 Output

scan_output/<target>_<timestamp>/

---

## ⚠️ Legal Disclaimer

**For authorized testing only. Unauthorized use is illegal.**  
The user is responsible for all actions. Developers assume no liability.

---

## 👨‍💻 Author

**wqyigitpw**  
https://github.com/wqyigitpw
