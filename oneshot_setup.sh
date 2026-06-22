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

# 6. Clone / update the AutoShot repository
cd ~
if [ -d "AutoShot" ]; then
    echo "[*] AutoShot directory already exists. Pulling latest changes..."
    cd AutoShot
    git pull
    cd ..
else
    echo "[*] Cloning AutoShot from GitHub..."
    git clone https://github.com/siamakanda/AutoShot.git
fi

# 7. Install Python module required by the script
pip3 install wcwidth

# 8. Make the Python script executable (optional)
chmod +x ~/AutoShot/oneshot.py

echo ""
echo "✅ Setup complete!"
echo "👉 You can now run AutoShot with:"
echo "   sudo python ~/AutoShot/oneshot.py -i wlan0 --iface-down -K"
echo ""
echo "💡 Tip: Replace wlan0 with your actual Wi‑Fi interface (use 'iw dev' to list)."
echo "   For more options: sudo python ~/AutoShot/oneshot.py -h"