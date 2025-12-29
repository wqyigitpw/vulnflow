#!/bin/bash

echo "[*] VULNFLOW dependency installer"

TOOLS=(
  nuclei
  katana
  gobuster
  subfinder
  assetfinder
  httpx
  wafw00f
)

echo "[*] Updating system..."
apt update -y

echo "[*] Installing base packages..."
apt install -y git curl wget python3 python3-pip unzip

# =============================
# GO INSTALL
# =============================
if ! command -v go &> /dev/null; then
  echo "[*] Installing Golang..."
  apt install -y golang
fi

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# =============================
# TOOL INSTALL
# =============================
install_if_missing () {
  if ! command -v $1 &> /dev/null; then
    echo "[+] Installing $1"
    eval "$2"
  else
    echo "[✓] $1 already installed"
  fi
}

install_if_missing nuclei "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_if_missing katana "go install github.com/projectdiscovery/katana/cmd/katana@latest"
install_if_missing subfinder "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_if_missing httpx "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_if_missing assetfinder "go install github.com/tomnomnom/assetfinder@latest"

install_if_missing gobuster "apt install -y gobuster"
install_if_missing wafw00f "apt install -y wafw00f"

# =============================
# SECLISTS
# =============================
if [ ! -d "/usr/share/seclists" ]; then
  echo "[*] Installing SecLists..."
  apt install -y seclists
fi

# =============================
# PYTHON DEPS
# =============================
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# =============================
# NUCLEI TEMPLATES
# =============================
echo "[*] Updating nuclei templates..."
nuclei -update-templates

echo "[✓] Installation completed."
