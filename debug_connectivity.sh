#!/bin/bash

echo "=== ProxyAP Debug Information ==="
echo

echo "1. Network Interfaces:"
ip addr show | grep -E "(wlan|tun)" -A 5
echo

echo "2. Routing Tables:"
echo "Main routing table:"
ip route
echo
echo "Table 100 (proxy routing):"
ip route show table 100
echo

echo "3. Routing Rules:"
ip rule show
echo

echo "4. iptables NAT rules:"
iptables -t nat -L -n -v
echo

echo "5. iptables FORWARD rules:"
iptables -L FORWARD -n -v
echo

echo "6. Active processes:"
echo "tun2socks processes:"
ps aux | grep tun2socks | grep -v grep
echo "dnsmasq processes:"
ps aux | grep dnsmasq | grep -v grep
echo "hostapd processes:"
ps aux | grep hostapd | grep -v grep
echo

echo "7. Test connectivity from host:"
echo "Ping to 8.8.8.8:"
ping -c 3 8.8.8.8 | tail -4
echo
echo "DNS resolution test:"
nslookup google.com | tail -4
echo

echo "8. TUN interface status:"
if ip link show tun0 &>/dev/null; then
    echo "TUN interface exists"
    ip addr show tun0
else
    echo "TUN interface does not exist"
fi
echo

echo "9. DHCP leases (if any):"
if [ -f /var/lib/dhcp/dhcpd.leases ]; then
    tail -10 /var/lib/dhcp/dhcpd.leases
elif [ -f /tmp/dnsmasq.leases ]; then
    cat /tmp/dnsmasq.leases
else
    echo "No DHCP lease file found"
fi
echo

echo "=== End Debug Information ===" 