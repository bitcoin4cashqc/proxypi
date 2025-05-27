#!/bin/bash

# ProxyPi Installation Script
# This script installs and configures ProxyPi on Raspberry Pi OS

set -e

echo "=== ProxyPi Installation Script ==="
echo "This script will install ProxyPi and its dependencies on your Raspberry Pi"
echo

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Please do not run this script as root. Run as a regular user with sudo access."
   exit 1
fi

# Check if running on Raspberry Pi OS
if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null && ! grep -q "raspbian\|Raspberry Pi OS" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is designed for Raspberry Pi OS. Continue anyway? (y/N)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Updating package lists..."
sudo apt update

echo "Installing required packages..."
sudo apt install -y \
    hostapd \
    dnsmasq \
    iptables \
    iw \
    curl \
    net-tools \
    python3 \
    python3-pip \
    git \
    unzip \
    wget

echo "Checking Python version..."
python3_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "Python version: $python3_version"

if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 6) else 1)'; then
    echo "Python version is compatible"
else
    echo "Error: Python 3.6 or higher is required"
    exit 1
fi

echo "Making main.py executable..."
chmod +x main.py

echo "Creating systemd service file..."
sudo tee /etc/systemd/system/proxypi.service > /dev/null << 'EOF'
[Unit]
Description=ProxyPi WiFi Hotspot with SOCKS5 Proxy
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxypi
ExecStart=/opt/proxypi/main.py --proxy socks5://127.0.0.1:1080
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

echo "Creating installation directory..."
sudo mkdir -p /opt/proxypi
sudo cp main.py /opt/proxypi/
sudo cp README.md /opt/proxypi/
sudo chmod +x /opt/proxypi/main.py

echo "Creating configuration directory..."
sudo mkdir -p /etc/proxypi

echo "Creating example configuration..."
sudo tee /etc/proxypi/config.example > /dev/null << 'EOF'
# ProxyPi Configuration Example
# Copy this file to config and modify as needed

# SOCKS5 Proxy Settings
PROXY_URL="socks5://username:password@proxy.example.com:1080"

# WiFi Hotspot Settings
SSID="ProxyPi"
PASSWORD="changeme123"

# Network Interface (leave empty for auto-detection)
INTERFACE=""

# Logging
VERBOSE=false
EOF

echo "Setting up log rotation..."
sudo tee /etc/logrotate.d/proxypi > /dev/null << 'EOF'
/var/log/proxypi.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

echo "Disabling default hostapd and dnsmasq services..."
sudo systemctl disable hostapd 2>/dev/null || true
sudo systemctl disable dnsmasq 2>/dev/null || true

echo "Creating wrapper script for easier usage..."
sudo tee /usr/local/bin/proxypi > /dev/null << 'EOF'
#!/bin/bash
# ProxyPi wrapper script

PROXYPI_DIR="/opt/proxypi"
CONFIG_FILE="/etc/proxypi/config"

if [[ $EUID -ne 0 ]]; then
   echo "ProxyPi must be run as root. Use: sudo proxypi [options]"
   exit 1
fi

# Source config file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# Build command line arguments
ARGS=()

if [[ -n "$PROXY_URL" ]]; then
    ARGS+=(--proxy "$PROXY_URL")
fi

if [[ -n "$SSID" ]]; then
    ARGS+=(--ssid "$SSID")
fi

if [[ -n "$PASSWORD" ]]; then
    ARGS+=(--password "$PASSWORD")
fi

if [[ -n "$INTERFACE" ]]; then
    ARGS+=(--interface "$INTERFACE")
fi

if [[ "$VERBOSE" == "true" ]]; then
    ARGS+=(--verbose)
fi

# Add any command line arguments passed to this script
ARGS+=("$@")

# Run ProxyPi
exec "$PROXYPI_DIR/main.py" "${ARGS[@]}"
EOF

sudo chmod +x /usr/local/bin/proxypi

echo "Creating uninstall script..."
sudo tee /opt/proxypi/uninstall.sh > /dev/null << 'EOF'
#!/bin/bash
# ProxyPi Uninstall Script

echo "Uninstalling ProxyPi..."

# Stop and disable service
sudo systemctl stop proxypi 2>/dev/null || true
sudo systemctl disable proxypi 2>/dev/null || true

# Remove service file
sudo rm -f /etc/systemd/system/proxypi.service

# Remove installation directory
sudo rm -rf /opt/proxypi

# Remove configuration
sudo rm -rf /etc/proxypi

# Remove wrapper script
sudo rm -f /usr/local/bin/proxypi

# Remove log rotation
sudo rm -f /etc/logrotate.d/proxypi

# Remove tun2socks binary
sudo rm -f /usr/local/bin/tun2socks

# Reload systemd
sudo systemctl daemon-reload

echo "ProxyPi has been uninstalled."
echo "Note: Installed packages (hostapd, dnsmasq, etc.) were not removed."
EOF

sudo chmod +x /opt/proxypi/uninstall.sh

echo
echo "=== Installation Complete ==="
echo
echo "ProxyPi has been installed successfully!"
echo
echo "Quick Start:"
echo "1. Configure your proxy settings:"
echo "   sudo cp /etc/proxypi/config.example /etc/proxypi/config"
echo "   sudo nano /etc/proxypi/config"
echo
echo "2. Run ProxyPi:"
echo "   sudo proxypi"
echo
echo "   Or run directly with arguments:"
echo "   sudo proxypi --proxy socks5://user:pass@proxy.com:1080 --ssid MyHotspot"
echo
echo "3. To run as a service:"
echo "   sudo systemctl enable proxypi"
echo "   sudo systemctl start proxypi"
echo
echo "4. To uninstall:"
echo "   sudo /opt/proxypi/uninstall.sh"
echo
echo "For more information, see: /opt/proxypi/README.md"
echo
echo "Note: Make sure you have a working SOCKS5 proxy before starting ProxyPi."
EOF 