#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
TUN2SOCKS_VERSION="2.5.2"
ARCHITECTURE=$(uname -m)

echo -e "${GREEN}=== ProxyPi Installation Script ===${NC}"
echo "Installing dependencies for Wi-Fi hotspot with SOCKS5 proxy..."

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Detect architecture and set tun2socks binary name
case $ARCHITECTURE in
    "x86_64")
        TUN2SOCKS_BINARY="tun2socks-linux-amd64"
        ;;
    "aarch64"|"arm64")
        TUN2SOCKS_BINARY="tun2socks-linux-arm64"
        ;;
    "armv7l")
        TUN2SOCKS_BINARY="tun2socks-linux-armv7"
        ;;
    *)
        print_warning "Unknown architecture: $ARCHITECTURE"
        print_warning "Defaulting to arm64 binary. You may need to change this manually."
        TUN2SOCKS_BINARY="tun2socks-linux-arm64"
        ;;
esac

print_status "Detected architecture: $ARCHITECTURE"
print_status "Will install tun2socks binary: $TUN2SOCKS_BINARY"

# Update package list
print_status "Updating package list..."
apt update

# Install basic dependencies
print_status "Installing basic system dependencies..."
apt install -y \
    hostapd \
    dnsmasq \
    openssh-client \
    iptables \
    iproute2 \
    wget \
    curl \
    build-essential \
    git \
    netstat-nat \
    net-tools

# Install tun2socks
print_status "Installing tun2socks..."
TUN2SOCKS_URL="https://github.com/xjasonlyu/tun2socks/releases/download/v${TUN2SOCKS_VERSION}/${TUN2SOCKS_BINARY}"

# Download to /usr/local/bin
if wget -q "$TUN2SOCKS_URL" -O "/usr/local/bin/$TUN2SOCKS_BINARY"; then
    chmod +x "/usr/local/bin/$TUN2SOCKS_BINARY"
    print_status "tun2socks installed successfully at /usr/local/bin/$TUN2SOCKS_BINARY"
else
    print_error "Failed to download tun2socks from $TUN2SOCKS_URL"
    print_warning "You may need to download it manually or check the version/architecture"
fi

# Create symlink for easier access
ln -sf "/usr/local/bin/$TUN2SOCKS_BINARY" "/usr/local/bin/tun2socks"
print_status "Created symlink: /usr/local/bin/tun2socks -> /usr/local/bin/$TUN2SOCKS_BINARY"

# Install dns2socks
print_status "Installing dns2socks..."

# First try to install from package manager
if apt install -y dns2socks 2>/dev/null; then
    print_status "dns2socks installed from package manager"
    DNS2SOCKS_INSTALLED_PATH=$(which dns2socks)
    print_status "dns2socks available at: $DNS2SOCKS_INSTALLED_PATH"
else
    print_warning "dns2socks not available in package manager, compiling from source..."
    
    # Create temporary directory for compilation
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone and compile dns2socks
    if git clone https://github.com/ghostunnel/dns2socks.git; then
        cd dns2socks
        if make; then
            cp dns2socks /usr/local/bin/
            chmod +x /usr/local/bin/dns2socks
            print_status "dns2socks compiled and installed to /usr/local/bin/dns2socks"
        else
            print_error "Failed to compile dns2socks"
            print_warning "DNS leak protection may not work properly"
        fi
    else
        print_error "Failed to clone dns2socks repository"
        print_warning "DNS leak protection may not work properly"
    fi
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
fi

# Configure systemd services to not conflict
print_status "Configuring system services..."

# Stop and disable hostapd and dnsmasq services (we'll run them manually)
systemctl stop hostapd 2>/dev/null || true
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable hostapd 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true

print_status "Disabled hostapd and dnsmasq services (will be run manually by script)"

# Create configuration directory
mkdir -p /etc/proxypi
print_status "Created configuration directory: /etc/proxypi"

# # Create a sample configuration file
# cat > /etc/proxypi/config.conf <<EOF
# # ProxyPi Configuration File
# # This file contains default values that can be overridden by command line arguments

# # Network Interfaces
# WLAN_IF=wlan1
# INET_IF=wlan0

# # Hotspot Configuration
# HOTSPOT_SSID=MyProxyAP
# HOTSPOT_PSK=password123

# # TUN Interface
# TUN_IF=tun0
# LOCAL_SOCKS_PORT=1080

# # Binary Paths
# TUN2SOCKS_BINARY=/usr/local/bin/$TUN2SOCKS_BINARY
# DNS2SOCKS_BINARY=/usr/local/bin/dns2socks

# # Features
# DISABLE_UDP=false
# USE_DNS2SOCKS=true
# DNS2SOCKS_PORT=5454

# # Required (must be provided via command line or environment):
# # PROXY_IP
# # PROXY_PORT
# # PROXY_USER (optional)
# # PROXY_PASS (optional)
# EOF

# print_status "Created sample configuration file: /etc/proxypi/config.conf"

# Make main.sh executable
if [[ -f "main.sh" ]]; then
    chmod +x main.sh
    print_status "Made main.sh executable"
fi

# Check if NetworkManager is installed and provide instructions
if command -v nmcli &> /dev/null; then
    print_warning "NetworkManager is installed and may interfere with the hotspot."
    print_warning "The script will automatically handle this, but you may need to:"
    print_warning "1. Ensure your Wi-Fi interfaces are not managed by NetworkManager during hotspot operation"
    print_warning "2. Or consider disabling NetworkManager: sudo systemctl disable NetworkManager"
fi

echo
print_status "Installation completed successfully!"
echo
echo -e "${GREEN}=== Usage Instructions ===${NC}"
echo "- Run the main script with required proxy settings:"
echo "   sudo ./main.sh --proxy-ip <IP> --proxy-port <PORT> [options]"
echo
echo "Example:"
echo "   sudo ./main.sh --proxy-ip 83.97.79.222 --proxy-port 1080 --proxy-user myuser --proxy-pass mypass"
echo
echo "For help and all available options:"
echo "   ./main.sh --help"
echo
print_status "Your ProxyPi hotspot system is ready to use!" 