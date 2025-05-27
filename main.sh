#!/bin/bash

set -e

# === CONFIGURATION ===
WLAN_IF=wlan1
INET_IF=wlan0
HOTSPOT_SSID="MyProxyAP"
HOTSPOT_PSK="password123"

# SOCKS5 proxy details — change here or export as env vars before running
PROXY_IP="217.182.194.105"
PROXY_PORT="10113"
PROXY_USER="VUdmv"
PROXY_PASS="3yxDF"
TUN_IF=tun0
LOCAL_SOCKS_PORT=1080

# Process tracking
HOSTAPD_PID=""
DNSMASQ_PID=""
TUN2SOCKS_PID=""
SSH_TUNNEL_PID=""

# Check for required tools
if ! command -v tun2socks-linux-arm64 &> /dev/null; then
  echo "tun2socks-linux-arm64 not found! Please install tun2socks-linux-arm64."
  exit 1
fi

if ! command -v ssh &> /dev/null; then
  echo "ssh not found! Please install openssh-client."
  exit 1
fi

function cleanup {
    echo -e "\nCleaning up..."

    # Kill processes in reverse order
    [[ -n "$TUN2SOCKS_PID" ]] && kill $TUN2SOCKS_PID 2>/dev/null && wait $TUN2SOCKS_PID 2>/dev/null || true
    [[ -n "$SSH_TUNNEL_PID" ]] && kill $SSH_TUNNEL_PID 2>/dev/null && wait $SSH_TUNNEL_PID 2>/dev/null || true
    [[ -n "$HOSTAPD_PID" ]] && kill $HOSTAPD_PID 2>/dev/null && wait $HOSTAPD_PID 2>/dev/null || true
    [[ -n "$DNSMASQ_PID" ]] && kill $DNSMASQ_PID 2>/dev/null && wait $DNSMASQ_PID 2>/dev/null || true

    # Cleanup iptables rules
    iptables -t nat -D POSTROUTING -o $INET_IF -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $WLAN_IF -o $TUN_IF -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $TUN_IF -o $WLAN_IF -j ACCEPT 2>/dev/null || true

    # Remove tun interface
    ip link set $TUN_IF down 2>/dev/null || true
    ip tuntap del dev $TUN_IF mode tun 2>/dev/null || true

    # Remove temp files
    rm -f /tmp/hostapd.conf /tmp/dnsmasq.conf

    echo "Cleanup done."
}

trap cleanup EXIT

echo "Starting Wi-Fi hotspot..."

# 1) Create hostapd config
cat > /tmp/hostapd.conf <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$HOTSPOT_SSID
hw_mode=g
channel=6
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$HOTSPOT_PSK
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# 2) Create dnsmasq config
cat > /tmp/dnsmasq.conf <<EOF
interface=$WLAN_IF
dhcp-range=192.168.50.10,192.168.50.100,255.255.255.0,24h
EOF

# Setup wlan interface
ip link set $WLAN_IF down
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
ip tuntap add dev $TUN_IF mode tun
ip addr add 10.0.0.1/24 dev $TUN_IF
ip link set $TUN_IF up

echo "Setting up local SOCKS5 tunnel..."

# Create SSH tunnel to forward local port to remote SOCKS5 proxy
if [[ -n "$PROXY_USER" && -n "$PROXY_PASS" ]]; then
    # For authenticated SOCKS5, we'll use a simple approach with expect or similar
    # For now, let's use a direct connection approach
    echo "Setting up authenticated SOCKS5 connection..."
    
    # Create a simple SOCKS5 forwarder using socat if available
    if command -v socat &> /dev/null; then
        socat TCP-LISTEN:$LOCAL_SOCKS_PORT,reuseaddr,fork SOCKS5:$PROXY_IP:0.0.0.0:0,socksport=$PROXY_PORT,socksuser=$PROXY_USER,sockspass=$PROXY_PASS &
        SSH_TUNNEL_PID=$!
    else
        echo "Warning: socat not found. Using direct connection without local forwarding."
        LOCAL_SOCKS_PORT=$PROXY_PORT
    fi
else
    # For non-authenticated SOCKS5, create a simple port forward
    ssh -f -N -D $LOCAL_SOCKS_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost &
    SSH_TUNNEL_PID=$!
fi

sleep 2

echo "Starting tun2socks-linux-arm64..."
if [[ -n "$SSH_TUNNEL_PID" ]]; then
    tun2socks-linux-arm64 -interface $TUN_IF -proxy socks5://127.0.0.1:$LOCAL_SOCKS_PORT &
else
    tun2socks-linux-arm64 -interface $TUN_IF -proxy socks5://$PROXY_USER:$PROXY_PASS@$PROXY_IP:$PROXY_PORT &
fi
TUN2SOCKS_PID=$!

sleep 3

echo "Enabling IP forwarding and setting up routing..."
sysctl -w net.ipv4.ip_forward=1

# Simplified iptables setup - route hotspot traffic through tun interface
iptables -t nat -A POSTROUTING -o $INET_IF -j MASQUERADE
iptables -A FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $WLAN_IF -o $TUN_IF -j ACCEPT
iptables -A FORWARD -i $TUN_IF -o $WLAN_IF -j ACCEPT

# Add route to send hotspot traffic through tun interface
ip route add 192.168.50.0/24 dev $TUN_IF

echo
echo "Hotspot '$HOTSPOT_SSID' is running!"
echo "Internet traffic is routed through SOCKS5 proxy $PROXY_IP:$PROXY_PORT"
if [[ -n "$PROXY_USER" ]]; then
  echo "Using SOCKS5 auth user: $PROXY_USER"
fi
echo "Connect your device to the Wi-Fi and enjoy."
echo "Press Ctrl+C to stop and clean up."

# Wait for any of the critical processes to exit
wait $TUN2SOCKS_PID
