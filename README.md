# ProxyPi - Raspberry Pi WiFi Hotspot with SOCKS5 Proxy

This project turns your Raspberry Pi into a WiFi hotspot that forwards all traffic through a SOCKS5 proxy. It's perfect for scenarios where you need to route multiple devices through a proxy connection.

## Features

- Creates a WiFi hotspot on your Raspberry Pi
- Forwards all traffic through a SOCKS5 proxy
- Supports SOCKS5 authentication (username/password)
- Configurable SSID and password
- Custom DNS server support
- Automatic interface detection for dual-band WiFi
- Systemd service for easy management

## Requirements

- Raspberry Pi (any model with WiFi capability)
- Raspberry Pi OS (or any Debian-based Linux distribution)
- Root access
- Internet connection (via Ethernet or WiFi)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/proxypi.git
cd proxypi
```

2. Run the installation script:
```bash
sudo ./install.sh
```

The installation script will:
- Install required packages (hostapd, dnsmasq, python3)
- Configure the WiFi hotspot
- Set up the proxy forwarding
- Create a systemd service

## Usage

### Basic Usage

Start the hotspot with default settings:
```bash
sudo proxypi --proxy socks5://1.2.3.4:1080
```

### Advanced Usage

Start the hotspot with custom settings:
```bash
sudo proxypi --proxy socks5://1.2.3.4:1080 --ssid "MyHotspot" --password "mypassword" --dns "1.1.1.1" --interface "wlan0"
```

### SOCKS5 Authentication

If your SOCKS5 proxy requires authentication, use this format:
```bash
sudo proxypi --proxy socks5://username:password@1.2.3.4:1080
```

### Command Line Arguments

- `--proxy`: SOCKS5 proxy URL (required)
  - Format: `socks5://host:port` or `socks5://username:password@host:port`
- `--ssid`: WiFi network name (default: "ProxyPi")
- `--password`: WiFi password (default: "changeme123")
- `--dns`: DNS server to use (default: "8.8.8.8")
- `--interface`: Specific wireless interface to use (e.g., "wlan0")

## Service Management

The installation creates a systemd service for easy management:

```bash
# Start the service
sudo systemctl start proxypi

# Stop the service
sudo systemctl stop proxypi

# Check status
sudo systemctl status proxypi

# View logs
sudo journalctl -u proxypi
```

## Troubleshooting

### Common Issues

1. **No Wireless Interface Found**
   - Make sure your Raspberry Pi has WiFi capability
   - Check if the wireless interface is enabled
   - Try specifying the interface manually with `--interface`

2. **Cannot Connect to Hotspot**
   - Verify the SSID and password
   - Check if hostapd is running: `sudo systemctl status hostapd`
   - Ensure the wireless interface is properly configured

3. **No Internet Access**
   - Verify the proxy server is accessible
   - Check if IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward`
   - Verify NAT rules: `sudo iptables -t nat -L`

4. **Proxy Connection Issues**
   - Verify the proxy URL format
   - Check if the proxy server is running and accessible
   - If using authentication, verify username and password

### Logs

Check the logs for detailed information:
```bash
sudo journalctl -u proxypi
```

## Security Considerations

- Change the default WiFi password
- Use a strong password for the SOCKS5 proxy if authentication is enabled
- Keep your system updated
- Consider using a firewall to restrict access

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 