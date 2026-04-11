#!/bin/bash
echo "[*] VULNFLOW dependency installer"

TOOLS=(
  nuclei
  gobuster
  subfinder
  assetfinder
  httpx
  wafw00f
  subzy
  nrich
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

install_if_missing nuclei      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_if_missing subfinder   "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_if_missing httpx       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_if_missing assetfinder "go install github.com/tomnomnom/assetfinder@latest"
install_if_missing subzy       "go install -v github.com/LukaSikic/subzy@latest"
install_if_missing gobuster    "apt install -y gobuster"
install_if_missing wafw00f     "apt install -y wafw00f"

# =============================
# NRICH (Shodan)
# =============================
if ! command -v nrich &> /dev/null; then
  echo "[+] Installing nrich..."
  ARCH=$(dpkg --print-architecture)
  case "$ARCH" in
    amd64)  NRICH_URL="https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/current/nrich_latest_amd64.deb" ;;
    arm64)  NRICH_URL="https://gitlab.com/api/v4/projects/33695681/packages/generic/nrich/current/nrich_latest_arm64.deb" ;;
    *)
      echo "[!] Unsupported arch: $ARCH — skipping nrich"
      NRICH_URL=""
      ;;
  esac

  if [ -n "$NRICH_URL" ]; then
    wget -q "$NRICH_URL" -O /tmp/nrich.deb && dpkg -i /tmp/nrich.deb && rm /tmp/nrich.deb
    if command -v nrich &> /dev/null; then
      echo "[✓] nrich installed"
    else
      echo "[!] nrich install failed — install manually: https://gitlab.com/shodan-public/nrich"
    fi
  fi
else
  echo "[✓] nrich already installed"
fi

# =============================
# SECLISTS
# =============================
if [ ! -d "/usr/share/seclists" ]; then
  echo "[*] Installing SecLists..."
  apt install -y seclists
else
  echo "[✓] SecLists already installed"
fi

# =============================
# PYTHON DEPS
# =============================
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages

# =============================
# NUCLEI TEMPLATES
# =============================
echo "[*] Updating nuclei templates..."
nuclei -update-templates

echo ""
echo "[✓] Installation completed."
echo ""
echo "[i] Make sure GOPATH is in your PATH:"
echo "    export GOPATH=\$HOME/go"
echo "    export PATH=\$PATH:\$GOPATH/bin"
echo "    (Add these lines to ~/.bashrc or ~/.zshrc)"
