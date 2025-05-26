# ProxyPi - Raspberry Pi WiFi Hotspot with SOCKS5 Proxy

ProxyPi is a tool that transforms your Raspberry Pi into a WiFi hotspot that routes all traffic through a SOCKS5 proxy. This allows you to create a portable proxy solution that any device can connect to.

## Features

- Creates a WiFi hotspot on your Raspberry Pi
- Routes all TCP traffic through a SOCKS5 proxy
- Supports proxy authentication
- Dual interface support (hotspot and internet)
- Automatic package installation
- Comprehensive logging and error handling
- Clean shutdown and cleanup
- Temporary file management
- Service state tracking

## Requirements

- Raspberry Pi (any model)
- Two WiFi adapters (one for hotspot, one for internet)
- Python 3.6 or higher
- Root access (sudo)

## Dependencies

The script will automatically install these dependencies:
- hostapd
- dnsmasq
- redsocks

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

Run the script with sudo privileges:

```bash
sudo ./main.py [options]
```

### Command Line Arguments

- `--hotspot-interface`: WiFi interface for hotspot (default: wlan1)
- `--internet-interface`: WiFi interface for internet (default: wlan0)
- `--socks5-host`: SOCKS5 proxy host (default: 127.0.0.1)
- `--socks5-port`: SOCKS5 proxy port (default: 1080)
- `--socks5-username`: SOCKS5 proxy username (optional)
- `--socks5-password`: SOCKS5 proxy password (optional)
- `--ssid`: Hotspot SSID (default: RaspberryPi-Proxy)
- `--password`: Hotspot password (default: raspberry123)
- `--verbose`, `-v`: Enable verbose logging

### Examples

Basic usage with default settings:
```bash
sudo ./main.py --socks5-host 1.2.3.4 --socks5-port 1080
```

Custom interface and WiFi settings:
```bash
sudo ./main.py --hotspot-interface wlan1 --internet-interface wlan0 --ssid "MyProxy" --password "mypassword123"
```

With proxy authentication:
```bash
sudo ./main.py --socks5-host 1.2.3.4 --socks5-port 1080 --socks5-username user --socks5-password pass
```

## How It Works

1. The script checks for root access and required interfaces
2. Verifies SOCKS5 proxy accessibility
3. Installs required packages if missing
4. Creates a WiFi hotspot using hostapd
5. Sets up dnsmasq for DHCP and DNS services
6. Configures iptables rules for routing
7. Sets up redsocks for SOCKS5 proxy forwarding
8. Manages all services and temporary files
9. Provides clean shutdown and cleanup on exit

## Network Configuration

- Hotspot IP: 192.168.4.1
- DHCP Range: 192.168.4.2 - 192.168.4.20
- Subnet: 192.168.4.0/24
- DNS Servers: 8.8.8.8, 8.8.4.4

## Troubleshooting

### Common Issues

1. **Interface not found**
   - List available wireless interfaces:
     ```bash
     ip link show
     ```
   - Specify the correct interfaces using `--hotspot-interface` and `--internet-interface`

2. **Proxy connection issues**
   - Verify your proxy is working:
     ```bash
     curl --proxy socks5://your-proxy:port https://www.google.com
     ```
   - Check the logs at `/tmp/redsocks.log`

3. **Service conflicts**
   - The script will automatically stop conflicting services
   - If issues persist, manually stop services:
     ```bash
     sudo systemctl stop hostapd
     sudo systemctl stop dnsmasq
     ```

### Logs

- Main log: Console output with timestamps
- Debug log: Available when using `--verbose` flag
- redsocks log: `/tmp/redsocks.log`

## Security Notes

- Always use strong passwords for your WiFi network
- Keep your proxy credentials secure
- The script requires root access to configure network interfaces
- Consider using a VPN in addition to the SOCKS5 proxy for enhanced security

## Cleanup

The script automatically handles cleanup on exit:
- Stops all started services
- Resets iptables rules
- Resets network interfaces
- Removes temporary files
- Restarts original services

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 