# ProxyPi - Raspberry Pi WiFi Hotspot with SOCKS5 Proxy

ProxyPi transforms your Raspberry Pi into a WiFi hotspot that routes all traffic through a SOCKS5 proxy using tun2socks. This creates a portable proxy solution that any device can connect to wirelessly.

## Features

- **Automatic Setup**: Downloads and configures tun2socks binary for your architecture
- **SOCKS5 Authentication**: Supports username/password authentication
- **Conflict Resolution**: Automatically handles port 53 and service conflicts
- **Interface Detection**: Auto-detects wireless interfaces or allows manual selection
- **Comprehensive Logging**: Debug logging with separate log files
- **Clean Shutdown**: Proper resource cleanup and service restoration
- **Proxy Validation**: Tests proxy connectivity before starting
- **Architecture Support**: Works on ARM64, ARMv7, x86_64, and i386

## Requirements

- Raspberry Pi (any model with WiFi)
- At least one WiFi adapter (built-in or USB)
- Python 3.6 or higher
- Root access (sudo)
- Working SOCKS5 proxy

## Quick Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/proxypi.git
cd proxypi
```

2. Run the installation script:
```bash
chmod +x install.sh
./install.sh
```

3. Configure your proxy:
```bash
sudo cp /etc/proxypi/config.example /etc/proxypi/config
sudo nano /etc/proxypi/config
```

4. Start ProxyPi:
```bash
sudo proxypi
```

## Manual Installation

If you prefer manual installation:

```bash
# Install dependencies
sudo apt update
sudo apt install -y hostapd dnsmasq iptables iw curl net-tools python3

# Make script executable
chmod +x main.py

# Run directly
sudo ./main.py --proxy socks5://user:pass@proxy.com:1080
```

## Usage

### Command Line Arguments

```bash
sudo ./main.py --proxy PROXY_URL [OPTIONS]
```

**Required:**
- `--proxy`: SOCKS5 proxy URL in format `socks5://[username:password@]host:port`

**Optional:**
- `--interface`: WiFi interface for hotspot (auto-detected if not specified)
- `--ssid`: WiFi hotspot SSID (default: ProxyPi)
- `--password`: WiFi hotspot password (default: changeme123)
- `--verbose`, `-v`: Enable verbose logging

### Examples

**Basic usage:**
```bash
sudo ./main.py --proxy socks5://proxy.example.com:1080
```

**With authentication:**
```bash
sudo ./main.py --proxy socks5://username:password@proxy.example.com:1080
```

**Custom WiFi settings:**
```bash
sudo ./main.py --proxy socks5://proxy.com:1080 --ssid "MyHotspot" --password "mypassword123"
```

**Specify interface:**
```bash
sudo ./main.py --proxy socks5://proxy.com:1080 --interface wlan1
```

**With verbose logging:**
```bash
sudo ./main.py --proxy socks5://proxy.com:1080 --verbose
```

### Using the Wrapper Script (after installation)

```bash
# Configure once
sudo nano /etc/proxypi/config

# Run with config
sudo proxypi

# Override config
sudo proxypi --proxy socks5://different.proxy.com:1080
```

### Running as a Service

```bash
# Enable and start service
sudo systemctl enable proxypi
sudo systemctl start proxypi

# Check status
sudo systemctl status proxypi

# View logs
sudo journalctl -u proxypi -f
```

## Network Configuration

- **Hotspot IP**: 192.168.45.1
- **DHCP Range**: 192.168.45.2 - 192.168.45.50
- **Subnet**: 192.168.45.0/24
- **DNS Servers**: 8.8.8.8, 8.8.4.4
- **TUN Interface**: 198.18.0.1/15

## How It Works

1. **Validation**: Checks root access, proxy connectivity, and available interfaces
2. **Conflict Resolution**: Stops conflicting services (systemd-resolved, existing dnsmasq/hostapd)
3. **Package Installation**: Installs required packages if missing
4. **Binary Download**: Downloads correct tun2socks binary for your architecture
5. **Hotspot Setup**: Configures hostapd for WiFi access point
6. **DHCP/DNS**: Sets up dnsmasq for client IP assignment and DNS resolution
7. **Tunnel Setup**: Creates TUN interface and starts tun2socks with SOCKS5 proxy
8. **Routing**: Configures iptables rules to route traffic through the tunnel
9. **Monitoring**: Continuously monitors all processes and handles cleanup

## Troubleshooting

### Common Issues

**1. "No wireless interfaces found"**
```bash
# Check available interfaces
ip link show
iw dev

# Specify interface manually
sudo ./main.py --proxy socks5://proxy.com:1080 --interface wlan0
```

**2. "Cannot connect to SOCKS5 proxy"**
```bash
# Test proxy manually
curl --proxy socks5://username:password@proxy.com:1080 https://www.google.com

# Check proxy credentials and connectivity
```

**3. "hostapd failed to start"**
```bash
# Check if interface supports AP mode
iw list | grep -A 10 "Supported interface modes"

# Try different interface
sudo ./main.py --proxy socks5://proxy.com:1080 --interface wlan1
```

**4. "Port 53 conflicts"**
```bash
# Check what's using port 53
sudo netstat -tulpn | grep :53

# The script should handle this automatically, but you can manually stop:
sudo systemctl stop systemd-resolved
```

**5. "tun2socks process died"**
```bash
# Check tun2socks logs
cat /tmp/tun2socks.log

# Check proxy connectivity
curl --proxy socks5://proxy.com:1080 https://httpbin.org/ip
```

### Debug Information

**Enable verbose logging:**
```bash
sudo ./main.py --proxy socks5://proxy.com:1080 --verbose
```

**Check log files:**
```bash
# Main debug log
tail -f proxypi_debug.log

# tun2socks log
tail -f /tmp/tun2socks.log

# System logs
sudo journalctl -f
```

**Network diagnostics:**
```bash
# Check interfaces
ip addr show

# Check routing
ip route show

# Check iptables rules
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# Test connectivity from client
# (run on connected device)
curl https://httpbin.org/ip
nslookup google.com
```

### Architecture Issues

If you get "Exec format error":
```bash
# Check your architecture
uname -m

# The script should auto-detect, but you can verify the binary:
file /usr/local/bin/tun2socks
```

## Security Considerations

- **Strong Passwords**: Use strong WiFi passwords (minimum 8 characters)
- **Proxy Security**: Ensure your SOCKS5 proxy is trustworthy
- **Network Isolation**: Consider the security implications of sharing your proxy
- **Monitoring**: Monitor connected devices and traffic patterns
- **Updates**: Keep your system and ProxyPi updated

## Performance Tips

- **USB WiFi Adapters**: Use quality USB WiFi adapters for better performance
- **Proxy Location**: Choose geographically close proxy servers
- **Channel Selection**: Use less congested WiFi channels (1, 6, 11 for 2.4GHz)
- **Bandwidth**: Consider your proxy's bandwidth limitations

## Uninstallation

```bash
# If installed via install.sh
sudo /opt/proxypi/uninstall.sh

# Manual cleanup
sudo systemctl stop proxypi
sudo systemctl disable proxypi
sudo rm -f /etc/systemd/system/proxypi.service
sudo rm -f /usr/local/bin/proxypi
sudo rm -rf /opt/proxypi /etc/proxypi
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/yourusername/proxypi.git
cd proxypi

# Test your changes
sudo ./main.py --proxy socks5://test.proxy.com:1080 --verbose
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### v2.0.0 (Latest)
- Complete rewrite with comprehensive error handling
- Automatic architecture detection and tun2socks download
- SOCKS5 authentication support
- Conflict resolution for port 53 and services
- Interface auto-detection
- Comprehensive logging and debugging
- Proper resource cleanup
- Installation script and systemd service

### v1.0.0
- Basic WiFi hotspot with SOCKS5 proxy functionality 