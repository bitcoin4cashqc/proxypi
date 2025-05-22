# ProxyPi - WiFi Hotspot with SOCKS5 Proxy Forwarding

ProxyPi is a Python script that turns your Raspberry Pi into a WiFi hotspot that forwards all traffic through a SOCKS5 proxy. This is useful for:
- Creating a portable proxy hotspot
- Sharing a proxy connection with multiple devices
- Bypassing network restrictions
- Testing network applications

## Features

- Creates a WiFi hotspot with WPA2 encryption
- Forwards all traffic through a SOCKS5 proxy
- Automatic interface detection for dual-band WiFi
- Killswitch to prevent traffic leaks
- Automatic dependency installation
- Proper cleanup on exit

## Requirements

- Raspberry Pi (or any Linux system with wireless capabilities)
- Root/sudo access
- Wireless adapter that supports AP mode
- Python 3.6 or higher

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/proxypi.git
cd proxypi
```

2. Make the script executable:
```bash
chmod +x main.py
```

## Usage

Basic usage:
```bash
sudo python3 main.py --proxy socks5://proxy_address:port
```

Full options:
```bash
sudo python3 main.py \
    --proxy socks5://proxy_address:port \
    --ssid "MyHotspot" \
    --password "mypassword" \
    --dns "8.8.8.8" \
    --interface wlan0
```

### Arguments

- `--proxy`: (Required) SOCKS5 proxy URL (e.g., `socks5://1.2.3.4:1080`)
- `--ssid`: (Optional) Hotspot SSID name (default: "ProxyPi")
- `--password`: (Optional) Hotspot password (default: "changeme123")
- `--dns`: (Optional) DNS server to use (default: "8.8.8.8")
- `--interface`: (Optional) Specific wireless interface to use (e.g., "wlan0")

## How It Works

1. The script creates a TUN interface for handling the proxy traffic
2. Sets up a WiFi hotspot using hostapd
3. Configures dnsmasq for DHCP
4. Sets up iptables rules for traffic forwarding
5. Uses tun2socks to forward all traffic through the SOCKS5 proxy

## Network Configuration

- Hotspot IP: 192.168.45.1
- DHCP Range: 192.168.45.10 - 192.168.45.100
- TUN Interface: tun0
- TUN Network: 10.0.0.0/24

## Troubleshooting

### No Wireless Interfaces Found
- Make sure your wireless adapter is properly connected
- Check if your adapter supports AP mode
- Try specifying the interface manually with `--interface`

### Interface Already in Use
- The script will detect if an interface is already connected to WiFi
- Use `--interface` to specify a different interface
- Disconnect from WiFi on the interface you want to use

### Permission Issues
- Make sure you're running the script with sudo
- Check if all required dependencies are installed

## Security Notes

- Change the default password
- Use a strong password for the hotspot
- Consider using a secure DNS server
- The killswitch prevents traffic leaks when the proxy is down



- [tun2socks](https://github.com/xjasonlyu/tun2socks) for the SOCKS5 forwarding
- hostapd and dnsmasq for the WiFi hotspot functionality 