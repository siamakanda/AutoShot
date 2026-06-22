#!/data/data/com.termux/files/usr/bin/bash

# ---------------------------------------------------------------------
# AutoShot / OneShot – One‑click Termux setup
# ---------------------------------------------------------------------

set -e  # stop on any error

echo "[*] Starting AutoShot automated setup..."

# 1. Force non‑interactive mode for apt
export DEBIAN_FRONTEND=noninteractive

# 2. Update & upgrade all packages, accepting new config files automatically
apt update -y
apt upgrade -y -o Dpkg::Options::="--force-confnew"

# 3. Install root repository (needed for iw, wpa‑supplicant, etc.)
pkg install -y root-repo

# 4. Install core dependencies
pkg install -y git python wpa-supplicant pixiewps iw openssl


# 5. Install sudo (replaces tsu if present)
pkg install -y sudo

# 5b. Install Termux Wi‑Fi connection helper (for auto‑connect)
pkg install -y termux-wifi-connection


# 6. Verify critical binaries are installed
echo "[*] Verifying system binaries..."
for bin in iw wpa_supplicant pixiewps; do
    if ! command -v "$bin" &> /dev/null; then
        echo "[!] ERROR: $bin not found in PATH after installation"
        exit 1
    fi
    echo "    ✓ $bin found"
done

# 7. Clone / update the AutoShot repository
ASH_HOME="$HOME/AutoShot"
if [ -d "$ASH_HOME" ]; then
    echo "[*] AutoShot directory already exists. Pulling latest changes..."
    cd "$ASH_HOME" || exit 1
    if ! git pull; then
        echo "[!] WARNING: git pull failed. Continuing with existing version..."
    fi
    cd - > /dev/null || exit 1
else
    echo "[*] Cloning AutoShot from GitHub..."
    if ! git clone https://github.com/siamakanda/AutoShot.git "$ASH_HOME"; then
        echo "[!] ERROR: Failed to clone AutoShot repository"
        exit 1
    fi
fi

# 8. Check for pip3 availability
if ! command -v pip3 &> /dev/null; then
    echo "[!] ERROR: pip3 not found. Installing python-pip..."
    pkg install -y python-pip
fi

# 9. Install Python modules from requirements.txt
echo "[*] Installing Python dependencies..."
if [ -f "$ASH_HOME/requirements.txt" ]; then
    if pip3 install -r "$ASH_HOME/requirements.txt"; then
        echo "    ✓ Python dependencies installed"
    else
        echo "[!] WARNING: Some Python packages failed to install"
    fi
else
    echo "[!] WARNING: requirements.txt not found, installing wcwidth directly..."
    pip3 install wcwidth
fi

# 10. Make Python scripts executable
chmod +x "$ASH_HOME/oneshot.py"
chmod +x "$ASH_HOME/auto_cracker.py"
echo "    ✓ Scripts made executable"

# 11. Verify setup completion
echo ""
echo "✅ Setup complete!"
echo ""
echo "📍 Installation location: $ASH_HOME"
echo ""
echo "🚀 Usage:"
echo "   OneShot (single target):     sudo python $ASH_HOME/oneshot.py -i wlan0 --iface-down -K"
echo "   AutoCracker (loop + crack):  sudo python $ASH_HOME/auto_cracker.py -i wlan0"
echo ""
echo "💡 Tips:"
echo "   • Replace 'wlan0' with your actual Wi-Fi interface (use 'iw dev' to list)"
echo "   • OneShot options: sudo python $ASH_HOME/oneshot.py -h"
echo "   • AutoCracker options: sudo python $ASH_HOME/auto_cracker.py -h"
echo "   • Test scan (no attacks): python $ASH_HOME/oneshot.py -i wlan0 --scan-only"