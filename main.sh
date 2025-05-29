#!/bin/bash

set -e

# === CONFIGURATION ===
WLAN_IF=wlan1
INET_IF=wlan0
HOTSPOT_SSID="MyProxyAP"
HOTSPOT_PSK="password123"

# SOCKS5 proxy details — change here or export as env vars before running
PROXY_IP="83.97.79.222"
PROXY_PORT="1080"
PROXY_USER="1grj9lcxh4x"
PROXY_PASS="115c06dfl8r"
TUN_IF=tun0
LOCAL_SOCKS_PORT=1080

# DNS servers to use (will be served through the proxy)
DNS_SERVERS="8.8.8.8,1.1.1.1"

# UDP Configuration - set to true to disable UDP completely
DISABLE_UDP=true

# DNS leak protection using dns2socks
USE_DNS2SOCKS=true
DNS2SOCKS_PORT=5454
DNS2SOCKS_PATH="$HOME/dns2socks"

# Process tracking
HOSTAPD_PID=""
DNSMASQ_PID=""
TUN2SOCKS_PID=""
SSH_TUNNEL_PID=""
DNS2SOCKS_PID=""

# Check for required tools
if ! command -v tun2socks-linux-arm64 &> /dev/null; then
  echo "tun2socks-linux-arm64 not found! Please install tun2socks-linux-arm64."
  exit 1
fi

if ! command -v ssh &> /dev/null; then
  echo "ssh not found! Please install openssh-client."
  exit 1
fi

if [[ "$USE_DNS2SOCKS" == "true" ]] && [[ ! -x "$DNS2SOCKS_PATH" ]]; then
  echo "dns2socks not found at $DNS2SOCKS_PATH!"
  echo "Please ensure dns2socks is compiled and available at: $DNS2SOCKS_PATH"
  echo "Or install system version with: sudo apt install dns2socks"
  exit 1
fi

function cleanup {
    echo -e "\nCleaning up..."

    # Kill processes in reverse order
    [[ -n "$TUN2SOCKS_PID" ]] && kill $TUN2SOCKS_PID 2>/dev/null && wait $TUN2SOCKS_PID 2>/dev/null || true
    [[ -n "$SSH_TUNNEL_PID" ]] && kill $SSH_TUNNEL_PID 2>/dev/null && wait $SSH_TUNNEL_PID 2>/dev/null || true
    [[ -n "$DNS2SOCKS_PID" ]] && kill $DNS2SOCKS_PID 2>/dev/null && wait $DNS2SOCKS_PID 2>/dev/null || true
    [[ -n "$HOSTAPD_PID" ]] && kill $HOSTAPD_PID 2>/dev/null && wait $HOSTAPD_PID 2>/dev/null || true
    [[ -n "$DNSMASQ_PID" ]] && kill $DNSMASQ_PID 2>/dev/null && wait $DNSMASQ_PID 2>/dev/null || true

    # Clean up any leftover processes that might be using our ports
    echo "Cleaning up leftover processes..."
    pkill -f "socat.*$DNS2SOCKS_PORT" 2>/dev/null || true
    pkill -f "dns2socks.*$DNS2SOCKS_PORT" 2>/dev/null || true
    
    # Kill any dns2socks processes by name
    pkill dns2socks 2>/dev/null || true

    # Cleanup iptables rules
    iptables -t nat -D POSTROUTING -o $INET_IF -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -o $TUN_IF -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $WLAN_IF -o $TUN_IF -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $TUN_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $WLAN_IF -o $INET_IF -j DROP 2>/dev/null || true

    # Remove routing rules
    ip rule del from 192.168.50.0/24 table 100 2>/dev/null || true
    ip route flush table 100 2>/dev/null || true
    ORIGINAL_GW=$(ip route | grep "^default" | head -1 | awk '{print $3}' 2>/dev/null) || true
    [[ -n "$ORIGINAL_GW" ]] && ip route del $PROXY_IP via $ORIGINAL_GW dev $INET_IF 2>/dev/null || true

    # Remove tun interface
    ip link set $TUN_IF down 2>/dev/null || true
    ip tuntap del dev $TUN_IF mode tun 2>/dev/null || true

    # Restore original DNS settings
    if [[ "$USE_DNS2SOCKS" == "true" ]]; then
        echo "Restoring original DNS configuration..."
        
        # Remove immutable flag from resolv.conf
        chattr -i /etc/resolv.conf 2>/dev/null || true
        
        # Restore original resolv.conf
        if [[ -f /tmp/resolv.conf.backup ]]; then
            cp /tmp/resolv.conf.backup /etc/resolv.conf
            rm -f /tmp/resolv.conf.backup
        fi
        
        # Restore NetworkManager DNS management
        if command -v nmcli &> /dev/null; then
            echo "Restoring NetworkManager DNS management..."
            nmcli device set $WLAN_IF managed yes 2>/dev/null || true
            nmcli device set $INET_IF ipv4.ignore-auto-dns no 2>/dev/null || true
        fi
        
        # Restore systemd-resolved settings
        if systemctl is-active --quiet systemd-resolved; then
            echo "Restoring systemd-resolved settings..."
            resolvectl revert $INET_IF 2>/dev/null || true
            # Restart systemd-resolved to restore original settings
            systemctl restart systemd-resolved 2>/dev/null || true
        fi
        
        echo "DNS settings restored"
    fi

    # Remove temp files
    rm -f /tmp/hostapd.conf /tmp/dnsmasq.conf

    echo "Cleanup done."
}

trap cleanup EXIT

# Initial cleanup in case of previous failed runs
echo "Performing initial cleanup..."
# Kill any leftover processes first
pkill -f "socat.*5454" 2>/dev/null || true
pkill dns2socks 2>/dev/null || true
cleanup 2>/dev/null || true

echo "Starting Wi-Fi hotspot..."

# 1) Create hostapd config with more compatible settings
cat > /tmp/hostapd.conf <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$HOTSPOT_SSID
hw_mode=g
channel=6
country_code=US
ieee80211n=1
ieee80211d=1
ieee80211h=1
wmm_enabled=1
ht_capab=[HT40][SHORT-GI-20][SHORT-GI-40]
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$HOTSPOT_PSK
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
beacon_int=100
dtim_period=2
max_num_sta=10
EOF

# 2) Create dnsmasq config
if [[ "$USE_DNS2SOCKS" == "true" ]]; then
cat > /tmp/dnsmasq.conf <<EOF
interface=$WLAN_IF
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
dhcp-option=3,192.168.50.1
dhcp-option=6,192.168.50.1
server=127.0.0.1#$DNS2SOCKS_PORT
no-resolv
EOF
else
cat > /tmp/dnsmasq.conf <<EOF
interface=$WLAN_IF
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
dhcp-option=3,192.168.50.1
dhcp-option=6,192.168.50.1
server=8.8.8.8
server=1.1.1.1
EOF
fi

# Setup wlan interface
ip link set $WLAN_IF down
ip addr flush dev $WLAN_IF

# Prevent NetworkManager from interfering with our hotspot interface
if command -v nmcli &> /dev/null; then
    echo "Configuring NetworkManager to release control of $WLAN_IF..."
    
    # First disconnect any existing connections
    nmcli device disconnect $WLAN_IF 2>/dev/null || true
    
    # Set to unmanaged
    nmcli device set $WLAN_IF managed no 2>/dev/null || true
    
    # Give NetworkManager time to release the interface
    echo "Waiting for NetworkManager to release interface..."
    sleep 2
    
    # Verify the interface is unmanaged
    if nmcli device show $WLAN_IF | grep -q "GENERAL.STATE.*unmanaged"; then
        echo "$WLAN_IF is now unmanaged by NetworkManager"
    else
        echo "Warning: $WLAN_IF may still be managed by NetworkManager"
    fi
fi

# Ensure interface is completely reset
ip link set $WLAN_IF down
sleep 1
ip addr flush dev $WLAN_IF
ip addr add 192.168.50.1/24 dev $WLAN_IF
ip link set $WLAN_IF up

# Start dnsmasq
echo "Starting dnsmasq..."
dnsmasq --conf-file=/tmp/dnsmasq.conf --pid-file=/tmp/dnsmasq.pid
DNSMASQ_PID=$(cat /tmp/dnsmasq.pid)

# Start hostapd
echo "Starting hostapd..."
hostapd /tmp/hostapd.conf &
HOSTAPD_PID=$!

sleep 3

echo "Creating tun device $TUN_IF..."
ip tuntap add dev $TUN_IF mode tun 2>/dev/null || true
ip addr add 10.0.0.1/24 dev $TUN_IF 2>/dev/null || true
ip link set $TUN_IF up

echo "Setting up local SOCKS5 tunnel..."

# Create SSH tunnel to forward local port to remote SOCKS5 proxy
if [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]]; then
    # For authenticated SOCKS5, we'll use a simple approach with expect or similar
    # For now, let's use a direct connection approach
    echo "Setting up authenticated SOCKS5 connection..."
    
    # Use direct connection with authentication in tun2socks
    echo "Using direct SOCKS5 connection with authentication."
    SSH_TUNNEL_PID=""
else
    # For non-authenticated SOCKS5, create a simple port forward
    ssh -f -N -D $LOCAL_SOCKS_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost &
    SSH_TUNNEL_PID=$!
fi

sleep 2

echo "Starting tun2socks-linux-arm64..."

# Build UDP timeout parameter based on configuration
UDP_TIMEOUT_PARAM=""
if [[ "$DISABLE_UDP" == "true" ]]; then
    UDP_TIMEOUT_PARAM="--udp-timeout 0"
    echo "UDP is disabled (timeout set to 0)"
else
    echo "UDP is enabled"
fi

if [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]]; then
    tun2socks-linux-arm64 -device tun://$TUN_IF -proxy socks5://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT -interface $INET_IF $UDP_TIMEOUT_PARAM &
else
    tun2socks-linux-arm64 -device tun://$TUN_IF -proxy socks5://$PROXY_IP:$PROXY_PORT -interface $INET_IF $UDP_TIMEOUT_PARAM &
fi
TUN2SOCKS_PID=$!

sleep 3

echo "Enabling IP forwarding and setting up routing..."
sysctl -w net.ipv4.ip_forward=1

# Set up dns2socks for DNS leak protection
if [[ "$USE_DNS2SOCKS" == "true" ]]; then
    echo "Starting dns2socks for DNS leak protection..."
    
    # Check if port is available
    if netstat -tulpn 2>/dev/null | grep -q ":$DNS2SOCKS_PORT "; then
        echo "Port $DNS2SOCKS_PORT is already in use. Attempting to free it..."
        pkill -f "socat.*$DNS2SOCKS_PORT" 2>/dev/null || true
        pkill -f "dns2socks.*$DNS2SOCKS_PORT" 2>/dev/null || true
        sleep 1
        
        # Check again
        if netstat -tulpn 2>/dev/null | grep -q ":$DNS2SOCKS_PORT "; then
            echo "Error: Port $DNS2SOCKS_PORT is still in use. Please check what's using it:"
            netstat -tulpn | grep ":$DNS2SOCKS_PORT "
            exit 1
        fi
    fi
    
    # Backup original DNS settings before making changes
    echo "Backing up original DNS configuration..."
    cp /etc/resolv.conf /tmp/resolv.conf.backup 2>/dev/null || true
    
    # Prevent NetworkManager from managing DNS on our interfaces
    if command -v nmcli &> /dev/null; then
        echo "Configuring NetworkManager to not override DNS..."
        # Set our interfaces to unmanaged for DNS
        nmcli device set $INET_IF ipv4.ignore-auto-dns yes 2>/dev/null || true
    fi
    
    # Start dns2socks to forward DNS through SOCKS proxy
    if [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]]; then
        $DNS2SOCKS_PATH /u:$PROXY_USER /p:$PROXY_PASS $PROXY_IP:$PROXY_PORT 8.8.8.8:53 127.0.0.1:$DNS2SOCKS_PORT &
        DNS2SOCKS_PID=$!
        echo "dns2socks started with authentication for $PROXY_IP:$PROXY_PORT"
    else
        $DNS2SOCKS_PATH $PROXY_IP:$PROXY_PORT 8.8.8.8:53 127.0.0.1:$DNS2SOCKS_PORT &
        DNS2SOCKS_PID=$!
        echo "dns2socks started for $PROXY_IP:$PROXY_PORT"
    fi
    
    sleep 2
    
    # Configure system DNS to use local dns2socks
    echo "Configuring system DNS to prevent leaks..."
    
    # Method 1: Use systemd-resolved if available
    if systemctl is-active --quiet systemd-resolved; then
        echo "Configuring systemd-resolved to use dns2socks..."
        resolvectl dns $INET_IF 127.0.0.1:$DNS2SOCKS_PORT 2>/dev/null || true
        resolvectl domain $INET_IF "~." 2>/dev/null || true
        # Also set global DNS as fallback
        resolvectl dns 127.0.0.1:$DNS2SOCKS_PORT 2>/dev/null || true
        echo "systemd-resolved configured to use SOCKS proxy"
    fi
    
    # Method 2: Set /etc/resolv.conf as backup
    echo "Setting /etc/resolv.conf to use local DNS proxy..."
    cat > /etc/resolv.conf <<EOF
# DNS through SOCKS proxy via dns2socks
nameserver 127.0.0.1
# Fallback to our hotspot DNS
nameserver 192.168.50.1
EOF
    
    # Protect resolv.conf from being overwritten
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    echo "Pi DNS configured to use SOCKS proxy - no DNS leaks!"
fi

# Add route to proxy server through original interface (prevent routing loop)
ORIGINAL_GW=$(ip route | grep "^default" | head -1 | awk '{print $3}')
ip route add $PROXY_IP via $ORIGINAL_GW dev $INET_IF 2>/dev/null || true

# Clear any existing iptables rules for our interfaces
iptables -t nat -F 2>/dev/null || true
iptables -F FORWARD 2>/dev/null || true

# Set up NAT for internet access
iptables -t nat -A POSTROUTING -o $TUN_IF -j MASQUERADE
iptables -t nat -A POSTROUTING -o $INET_IF -j MASQUERADE

# Set up forwarding rules
iptables -A FORWARD -i $WLAN_IF -o $TUN_IF -j ACCEPT
iptables -A FORWARD -i $TUN_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

# Block direct internet access from hotspot (force through TUN)
iptables -A FORWARD -i $WLAN_IF -o $INET_IF -j DROP

# Set up routing table for hotspot clients
ip route flush table 100 2>/dev/null || true
ip route add default dev $TUN_IF table 100
ip rule del from 192.168.50.0/24 table 100 2>/dev/null || true
ip rule add from 192.168.50.0/24 table 100 priority 100

# Add route for local network communication
ip route add 192.168.50.0/24 dev $WLAN_IF table 100

echo
echo "Hotspot '$HOTSPOT_SSID' is running!"
echo "Internet traffic is routed through SOCKS5 proxy $PROXY_IP:$PROXY_PORT"
if [[ -n "$PROXY_USER" ]]; then
  echo "Using SOCKS5 auth user: $PROXY_USER"
fi
if [[ "$USE_DNS2SOCKS" == "true" ]]; then
  echo "DNS leak protection: ENABLED (custom dns2socks at $DNS2SOCKS_PATH) - All DNS queries go through proxy"
else
  echo "DNS leak protection: DISABLED - DNS queries may leak"
fi
echo "Connect your device to the Wi-Fi and enjoy."
echo "Press Ctrl+C to stop and clean up."

# Wait for any of the critical processes to exit
wait $TUN2SOCKS_PID
