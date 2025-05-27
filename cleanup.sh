#!/bin/bash
sudo ip link del dummy0 2>/dev/null
sudo iptables -F
sudo iptables -t nat -F
sudo pkill tun2socks
