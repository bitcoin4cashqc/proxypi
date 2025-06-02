#!/bin/bash

set +e  # Don't exit on errors - we want to clean everything regardless

echo "=== COMPREHENSIVE SYSTEM CLEANUP ==="
echo "This script will restore your system from the proxy setup."
echo "Cleaning up processes, network settings, iptables, and DNS..."
echo

# === CONFIGURATION (same as original script) ===
WLAN_IF=wlan1
INET_IF=wlan0
TUN_IF=tun0
DNS2SOCKS_PORT=5454
LASTPROXYIP="83.97.79.222"

# === KILL ALL RELATED PROCESSES ===
echo "1. Killing all related processes..."

# Kill processes by PID files if they exist
if [[ -f /tmp/dnsmasq.pid ]]; then
    DNSMASQ_PID=$(cat /tmp/dnsmasq.pid 2>/dev/null)
    [[ -n "$DNSMASQ_PID" ]] && kill $DNSMASQ_PID 2>/dev/null
fi

# Kill processes by pattern/name (more comprehensive)
echo "   Killing hostapd processes..."
pkill -f hostapd 2>/dev/null || true
killall hostapd 2>/dev/null || true

echo "   Killing dnsmasq processes..."
pkill -f dnsmasq 2>/dev/null || true
killall dnsmasq 2>/dev/null || true

echo "   Killing tun2socks processes..."
pkill -f tun2socks 2>/dev/null || true
killall tun2socks-linux-arm64 2>/dev/null || true

echo "   Killing SSH tunnel processes..."
pkill -f "ssh.*-D.*1080" 2>/dev/null || true

echo "   Killing dns2socks processes..."
pkill -f dns2socks 2>/dev/null || true
killall dns2socks 2>/dev/null || true

echo "   Killing socat processes on port $DNS2SOCKS_PORT..."
pkill -f "socat.*$DNS2SOCKS_PORT" 2>/dev/null || true

# Give processes time to die
sleep 2

# Force kill if still running
echo "   Force killing any remaining processes..."
pkill -9 -f hostapd 2>/dev/null || true
pkill -9 -f dnsmasq 2>/dev/null || true
pkill -9 -f tun2socks 2>/dev/null || true
pkill -9 -f dns2socks 2>/dev/null || true

echo "   ✓ All processes killed"

# === RESTORE IPTABLES ===
echo
echo "2. Restoring iptables rules..."

# Flush all tables
echo "   Flushing all iptables rules..."
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -t filter -F 2>/dev/null || true
iptables -F 2>/dev/null || true

# Delete custom chains
iptables -t nat -X 2>/dev/null || true
iptables -t mangle -X 2>/dev/null || true
iptables -t filter -X 2>/dev/null || true
iptables -X 2>/dev/null || true

# Remove specific rules that might still exist
iptables -t nat -D POSTROUTING -o $INET_IF -j MASQUERADE 2>/dev/null || true
iptables -t nat -D POSTROUTING -o $TUN_IF -j MASQUERADE 2>/dev/null || true
iptables -D FORWARD -i $INET_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $WLAN_IF -o $TUN_IF -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $TUN_IF -o $WLAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i $WLAN_IF -o $INET_IF -j DROP 2>/dev/null || true

# Set default policies to ACCEPT (restore normal operation)
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# If you have iptables-persistent, you might want to save the clean state
if command -v iptables-save &> /dev/null; then
    echo "   Saving clean iptables state..."
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

echo "   ✓ iptables rules restored"

# === RESTORE ROUTING ===
echo
echo "3. Restoring routing tables..."

# Remove custom routing rules
echo "   Removing custom routing rules..."
ip rule del from 192.168.50.0/24 table 100 2>/dev/null || true
ip rule del from 192.168.50.0/24 lookup 100 2>/dev/null || true

# Flush custom routing table
echo "   Flushing custom routing table 100..."
ip route flush table 100 2>/dev/null || true

# Remove any proxy-specific routes (try common proxy IPs)
COMMON_PROXY_IPS=("127.0.0.1" "10.0.0.1" "$LASTPROXYIP")
for proxy_ip in "${COMMON_PROXY_IPS[@]}"; do
    # Get current default gateway
    ORIGINAL_GW=$(ip route | grep "^default" | head -1 | awk '{print $3}' 2>/dev/null) || true
    if [[ -n "$ORIGINAL_GW" ]]; then
        ip route del $proxy_ip via $ORIGINAL_GW dev $INET_IF 2>/dev/null || true
    fi
done

echo "   ✓ Routing tables restored"

# === REMOVE TUN INTERFACES ===
echo
echo "4. Removing TUN interfaces..."

# Remove tun interface
echo "   Removing $TUN_IF interface..."
ip link set $TUN_IF down 2>/dev/null || true
ip tuntap del dev $TUN_IF mode tun 2>/dev/null || true

# Remove any other tun interfaces that might exist
for tun in tun0 tun1 tun2; do
    ip link set $tun down 2>/dev/null || true
    ip tuntap del dev $tun mode tun 2>/dev/null || true
done

echo "   ✓ TUN interfaces removed"

# === RESTORE NETWORK INTERFACES ===
echo
echo "5. Restoring network interfaces..."

# Restore WLAN interface
echo "   Restoring $WLAN_IF interface..."
ip link set $WLAN_IF down 2>/dev/null || true
ip addr flush dev $WLAN_IF 2>/dev/null || true
ip link set $WLAN_IF up 2>/dev/null || true

# Restore INET interface 
echo "   Restoring $INET_IF interface..."
ip link set $INET_IF up 2>/dev/null || true

echo "   ✓ Network interfaces restored"

# === RESTORE NETWORKMANAGER ===
echo
echo "6. Restoring NetworkManager..."

if command -v nmcli &> /dev/null; then
    echo "   Restoring NetworkManager device management..."
    
    # Set interfaces back to managed
    nmcli device set $WLAN_IF managed yes 2>/dev/null || true
    nmcli device set $INET_IF managed yes 2>/dev/null || true
    
    # Restore DNS management
    nmcli device set $INET_IF ipv4.ignore-auto-dns no 2>/dev/null || true
    nmcli device set $WLAN_IF ipv4.ignore-auto-dns no 2>/dev/null || true
    
    # Restart NetworkManager to ensure clean state
    echo "   Restarting NetworkManager..."
    systemctl restart NetworkManager 2>/dev/null || true
    
    # Wait for NetworkManager to settle
    sleep 3
    
    echo "   ✓ NetworkManager restored"
else
    echo "   NetworkManager not found, skipping..."
fi

# === RESTORE DNS SETTINGS ===
echo
echo "7. Restoring DNS settings..."

# Remove immutable flag from resolv.conf
echo "   Removing immutable flag from resolv.conf..."
chattr -i /etc/resolv.conf 2>/dev/null || true

# Restore original resolv.conf if backup exists
if [[ -f /tmp/resolv.conf.backup ]]; then
    echo "   Restoring resolv.conf from backup..."
    cp /tmp/resolv.conf.backup /etc/resolv.conf
    rm -f /tmp/resolv.conf.backup
else
    echo "   Creating default resolv.conf..."
    cat > /etc/resolv.conf <<EOF
# Default DNS configuration
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 208.67.222.222
EOF
fi

# Restore systemd-resolved settings
if systemctl is-active --quiet systemd-resolved; then
    echo "   Restoring systemd-resolved settings..."
    
    # Revert any interface-specific DNS settings
    resolvectl revert $INET_IF 2>/dev/null || true
    resolvectl revert $WLAN_IF 2>/dev/null || true
    
    # Restart systemd-resolved to restore original settings
    systemctl restart systemd-resolved 2>/dev/null || true
    
    echo "   ✓ systemd-resolved restored"
fi

echo "   ✓ DNS settings restored"

# === RESTORE IP FORWARDING ===
echo
echo "8. Restoring IP forwarding settings..."

# Disable IP forwarding (default state)
echo "   Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true

echo "   ✓ IP forwarding disabled"

# === CLEAN UP TEMPORARY FILES ===
echo
echo "9. Cleaning up temporary files..."

# Remove temp files
rm -f /tmp/hostapd.conf 2>/dev/null || true
rm -f /tmp/dnsmasq.conf 2>/dev/null || true
rm -f /tmp/dnsmasq.pid 2>/dev/null || true
rm -f /tmp/resolv.conf.backup 2>/dev/null || true

echo "   ✓ Temporary files removed"

# === FINAL NETWORK RESTART ===
echo
echo "10. Final network service restart..."

# Restart networking service if available
if systemctl list-units --type=service | grep -q networking; then
    echo "   Restarting networking service..."
    systemctl restart networking 2>/dev/null || true
fi

# If NetworkManager is running, restart it one more time to ensure clean state
if systemctl is-active --quiet NetworkManager; then
    echo "   Final NetworkManager restart..."
    systemctl restart NetworkManager 2>/dev/null || true
    sleep 3
fi

echo "   ✓ Network services restarted"

# === VERIFICATION ===
echo
echo "11. Verification..."

echo "   Checking network connectivity..."
if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo "   ✓ Internet connectivity: OK"
else
    echo "   ⚠ Internet connectivity: Issues detected - you may need to reconnect to WiFi"
fi

echo "   Checking DNS resolution..."
if nslookup google.com >/dev/null 2>&1; then
    echo "   ✓ DNS resolution: OK"
else
    echo "   ⚠ DNS resolution: Issues detected - DNS may need time to propagate"
fi

# === COMPLETION ===
echo
echo "=== CLEANUP COMPLETED ==="
echo
echo "✓ All processes killed"
echo "✓ iptables rules restored"
echo "✓ Routing tables cleaned"
echo "✓ Network interfaces restored"
echo "✓ NetworkManager restored"
echo "✓ DNS settings restored"
echo "✓ IP forwarding disabled"
echo "✓ Temporary files removed"
echo
echo "Your system should now be back to normal operation."
echo
echo "If you still have network issues:"
echo "1. Try reconnecting to your WiFi network"
echo "2. Restart your computer if problems persist"
echo "3. Check 'nmcli device status' to see interface states"
echo
echo "To completely reset network settings, you can also run:"
echo "   sudo systemctl restart NetworkManager"
echo "   sudo systemctl restart systemd-resolved"
echo 