# Vulnflow v1.0.1

Vulnflow is an open-source **web vulnerability scanning framework** designed for **authorized penetration testing**.
It automates URL discovery, filters active endpoints, prunes redundant parameters, and performs efficient general vulnerability scans.

---

## Features

- Automated URL collection from multiple sources  
- Active endpoint detection (dead URLs removed)  
- Smart parameter pruning to avoid duplicate testing  
- General vulnerability scanning workflow  
- Clean and organized scan output  
- Bug bounty & pentest focused design  

---

## Screenshots

![Vulnflow Scan](https://ibb.co/CKJcTvWC)
![Vulnflow Output](https://ibb.co/XxWh71yH)

---

Clone the repository:

    git clone https://github.com/wqyigitpw/vulnflow.git
    cd vulnflow

Run the installer:

    chmod +x install.sh
    ./install.sh

Alternatively, install Python dependencies manually:

    pip install -r requirements.txt

### Required external tools

The installer will automatically install and configure:

- katana  
- httpx  
- nuclei  
- gobuster  
- curl
- wafw00f

---

## Usage

Run Vulnflow:

    python vulnflow.py

Enter the target URL when prompted:

    Target URL (https://example.com):

Vulnflow will automatically:

- Discover URLs  
- Filter alive endpoints  
- Prune redundant parameters  
- Start general vulnerability scanning  

---

## Output

All scan results are saved under:

    scan_output/

---

## Legal Disclaimer

**Vulnflow is for authorized security testing only.**  
Any unauthorized use is illegal. The user is solely responsible for complying with all applicable laws.  
The developers assume **no liability** for misuse or damages.

---

## Author

**wqyigitpw**  
https://github.com/wqyigitpw
