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

# Check for proxychains4
if ! command -v proxychains4 &> /dev/null; then
  echo "proxychains4 not found! Please install proxychains-ng."
  exit 1
fi

# Check for tun2socks
if ! command -v tun2socks &> /dev/null; then
  echo "tun2socks not found! Please install badvpn tun2socks."
  exit 1
fi

function cleanup {
    echo -e "\nCleaning up..."

    iptables -t nat -D POSTROUTING -o $INET_IF -j MASQUERADE || true
    iptables -D FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT || true
    iptables -D FORWARD -i $WLAN_IF -o $INET_IF -j ACCEPT || true

    iptables -F PROXY || true
    iptables -X PROXY || true

    ip link set $TUN_IF down || true
    ip tuntap del dev $TUN_IF mode tun || true

    # Kill tun2socks process if running
    if [[ ! -z "$TUN2SOCKS_PID" ]]; then
      kill $TUN2SOCKS_PID 2>/dev/null || true
      wait $TUN2SOCKS_PID 2>/dev/null || true
    fi

    # Stop services
    killall hostapd dnsmasq 2>/dev/null || true

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
dnsmasq --conf-file=/tmp/dnsmasq.conf

# Start hostapd
hostapd /tmp/hostapd.conf &

sleep 3

echo "Enabling IP forwarding and NAT..."

sysctl -w net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o $INET_IF -j MASQUERADE
iptables -A FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $WLAN_IF -o $INET_IF -j ACCEPT

echo "Creating tun device $TUN_IF..."

ip tuntap add dev $TUN_IF mode tun
ip link set $TUN_IF up

echo "Generating proxychains config with SOCKS5 auth..."

cat > /tmp/proxychains.conf <<EOF
strict_chain
proxy_dns
[ProxyList]
EOF

if [[ -z "$PROXY_USER" || -z "$PROXY_PASS" ]]; then
  echo "socks5 $PROXY_IP $PROXY_PORT" >> /tmp/proxychains.conf
else
  echo "socks5 $PROXY_IP $PROXY_PORT $PROXY_USER $PROXY_PASS" >> /tmp/proxychains.conf
fi

echo "Starting tun2socks wrapped in proxychains4..."

proxychains4 -f /tmp/proxychains.conf tun2socks --tundev $TUN_IF --socks-server-addr 127.0.0.1:$PROXY_PORT &

TUN2SOCKS_PID=$!

sleep 3

echo "Setting up iptables PROXY chain with killswitch..."

iptables -N PROXY || iptables -F PROXY

iptables -F PROXY

# Allow traffic from tun device itself
iptables -A PROXY -i $TUN_IF -j ACCEPT

# Drop anything else (killswitch)
iptables -A PROXY -j DROP

# Redirect traffic from WLAN_IF to PROXY chain for filtering
iptables -I FORWARD -i $WLAN_IF -j PROXY

echo
echo "Hotspot '$HOTSPOT_SSID' is running!"
echo "Internet from $INET_IF is routed through SOCKS5 proxy $PROXY_IP:$PROXY_PORT"
if [[ -n "$PROXY_USER" ]]; then
  echo "Using SOCKS5 auth user: $PROXY_USER"
fi
echo "Connect your device to the Wi-Fi and enjoy."
echo "Press Ctrl+C to stop and clean up."

wait $TUN2SOCKS_PID
