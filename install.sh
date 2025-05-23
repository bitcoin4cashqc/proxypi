#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print with color
print_green() {
    echo -e "${GREEN}$1${NC}"
}

print_yellow() {
    echo -e "${YELLOW}$1${NC}"
}

print_red() {
    echo -e "${RED}$1${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_red "Please run as root (sudo)"
    exit 1
fi

# Check for DNS port conflict
print_yellow "Checking for DNS port conflicts..."
if lsof -i :53 >/dev/null 2>&1; then
    print_yellow "Port 53 is in use. Attempting to resolve..."
    
    # Try to stop systemd-resolved if it's running
    if systemctl is-active --quiet systemd-resolved; then
        print_yellow "Stopping systemd-resolved..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
    fi
    
    # Try to stop any other dnsmasq instances
    if pgrep dnsmasq >/dev/null; then
        print_yellow "Stopping existing dnsmasq instances..."
        systemctl stop dnsmasq
        pkill dnsmasq
    fi
    
    # Wait a moment for ports to be released
    sleep 2
    
    # Check if port is still in use
    if lsof -i :53 >/dev/null 2>&1; then
        print_red "Port 53 is still in use. Please manually stop the service using port 53 and try again."
        print_yellow "You can check what's using port 53 with: sudo lsof -i :53"
        exit 1
    fi
fi

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    print_yellow "Warning: This script is designed for Raspberry Pi OS"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_green "Starting ProxyPi installation..."

# Update system
print_yellow "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install required packages
print_yellow "Installing required packages..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    hostapd \
    dnsmasq \
    iptables \
    iproute2 \
    wireless-tools \
    git

# Enable hostapd
print_yellow "Enabling hostapd service..."
systemctl unmask hostapd
systemctl enable hostapd

# Create virtual environment
print_yellow "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
print_yellow "Installing Python dependencies..."
pip install --upgrade pip
pip install requests

# Make main script executable
print_yellow "Setting up main script..."
chmod +x main.py

# Create a wrapper script for easy execution
print_yellow "Creating wrapper script..."
cat > proxypi << 'EOF'
#!/bin/bash
source "$(dirname "$0")/venv/bin/activate"
sudo python3 "$(dirname "$0")/main.py" "$@"
EOF

chmod +x proxypi

# Create systemd service for auto-start
print_yellow "Creating systemd service..."
cat > /etc/systemd/system/proxypi.service << 'EOF'
[Unit]
Description=ProxyPi WiFi Hotspot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxypi
ExecStart=/opt/proxypi/proxypi --proxy socks5://127.0.0.1:1080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create installation directory
print_yellow "Setting up installation directory..."
mkdir -p /opt/proxypi
cp main.py /opt/proxypi/
cp -r venv /opt/proxypi/
cp proxypi /opt/proxypi/

print_green "Installation complete!"
print_yellow "To start ProxyPi, you can:"
print_yellow "1. Run directly: sudo ./proxypi --proxy socks5://your-proxy:port"
print_yellow "2. Enable and start the service:"
print_yellow "   sudo systemctl enable proxypi"
print_yellow "   sudo systemctl start proxypi"
print_yellow "3. Check service status: sudo systemctl status proxypi"

# Cleanup
print_yellow "Cleaning up..."
rm proxypi

print_green "Done! ProxyPi is ready to use." 