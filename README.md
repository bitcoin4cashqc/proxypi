# ProxyPi - Wi-Fi Hotspot with SOCKS5 Proxy

A comprehensive solution to create a Wi-Fi hotspot that routes all traffic through a SOCKS5 proxy, with built-in DNS leak protection.

## Features

- **Wi-Fi Hotspot**: Creates a secure Wi-Fi access point
- **SOCKS5 Proxy Integration**: Routes all traffic through your SOCKS5 proxy server
- **DNS Leak Protection**: Prevents DNS queries from leaking outside the proxy tunnel
- **UDP Support**: Configurable UDP traffic handling
- **Authentication Support**: Works with authenticated and non-authenticated SOCKS5 proxies
- **Flexible Configuration**: Command-line arguments and configuration file support
- **Multi-Architecture**: Automatic detection and installation for ARM64, AMD64, and ARMv7

## Requirements

- Linux system with root access
- Two network interfaces:
  - One for internet connection (e.g., `wlan0`, `eth0`)
  - One for the hotspot (e.g., `wlan1`, USB Wi-Fi adapter)
- SOCKS5 proxy server details (IP and port required)

## Installation

1. **Clone or download the scripts**:
   ```bash
   # If you have the files locally, just make sure you're in the right directory
   cd /path/to/proxypi
   ```

2. **Run the installation script**:
   ```bash
   sudo ./install.sh
   ```

   This will:
   - Install all required dependencies (hostapd, dnsmasq, tun2socks, dns2socks, etc.)
   - Download the appropriate tun2socks binary for your architecture
   - Configure system services
   - Create configuration files

## Configuration

### Method 1: Command Line Arguments (Recommended)

Run the script with required parameters:

```bash
sudo ./main.sh --proxy-ip <PROXY_IP> --proxy-port <PROXY_PORT> [OPTIONS]
```

**Required Parameters:**
- `--proxy-ip <IP>`: Your SOCKS5 proxy server IP address
- `--proxy-port <PORT>`: Your SOCKS5 proxy server port

### Method 2: Configuration File

Edit the configuration file:
```bash
sudo nano /etc/proxypi/config.conf
```

Then run with just the required parameters:
```bash
sudo ./main.sh --proxy-ip <PROXY_IP> --proxy-port <PROXY_PORT>
```

### Method 3: Environment Variables

```bash
export PROXY_IP="your.proxy.ip"
export PROXY_PORT="1080"
export PROXY_USER="username"  # if authentication needed
export PROXY_PASS="password"  # if authentication needed
sudo ./main.sh --proxy-ip $PROXY_IP --proxy-port $PROXY_PORT
```

## Usage Examples

### Basic Usage (No Authentication)
```bash
sudo ./main.sh --proxy-ip 192.168.1.100 --proxy-port 1080
```

### With SOCKS5 Authentication
```bash
sudo ./main.sh --proxy-ip 83.97.79.222 --proxy-port 1080 --proxy-user myuser --proxy-pass mypass
```

### Custom Hotspot Settings
```bash
sudo ./main.sh --proxy-ip 192.168.1.100 --proxy-port 1080 \
  --ssid "MyCustomHotspot" \
  --password "SecurePassword123" \
  --wlan-if wlan0
```

### Disable DNS Leak Protection
```bash
sudo ./main.sh --proxy-ip 192.168.1.100 --proxy-port 1080 --disable-dns-proxy
```

### Disable UDP Traffic
```bash
sudo ./main.sh --proxy-ip 192.168.1.100 --proxy-port 1080 --disable-udp
```

### Custom Binary Paths
```bash
sudo ./main.sh --proxy-ip 192.168.1.100 --proxy-port 1080 \
  --tun2socks /custom/path/tun2socks \
  --dns2socks /custom/path/dns2socks
```

## Available Options

### Required Parameters
- `--proxy-ip <IP>`: SOCKS5 proxy server IP address
- `--proxy-port <PORT>`: SOCKS5 proxy server port

### Optional Parameters
- `--proxy-user <USER>`: SOCKS5 proxy username (if authentication required)
- `--proxy-pass <PASS>`: SOCKS5 proxy password (if authentication required)

### Network Configuration
- `--wlan-if <INTERFACE>`: Wi-Fi interface for hotspot (default: wlan1)
- `--inet-if <INTERFACE>`: Internet interface (default: wlan0)
- `--tun-if <INTERFACE>`: TUN interface name (default: tun0)

### Hotspot Configuration
- `--ssid <SSID>`: Hotspot SSID (default: MyProxyAP)
- `--password <PASSWORD>`: Hotspot password (default: password123)
- `--local-port <PORT>`: Local SOCKS port (default: 1080)

### Feature Configuration
- `--disable-udp`: Disable UDP traffic through proxy
- `--enable-udp`: Enable UDP traffic through proxy (default)
- `--disable-dns-proxy`: Disable DNS leak protection
- `--enable-dns-proxy`: Enable DNS leak protection (default)
- `--dns-port <PORT>`: DNS2SOCKS local port (default: 5454)

### Binary Paths
- `--tun2socks <PATH>`: Path to tun2socks binary
- `--dns2socks <PATH>`: Path to dns2socks binary

### Other Options
- `--config <FILE>`: Use custom configuration file
- `--help`: Show help message

## How It Works

1. **Hotspot Creation**: Creates a Wi-Fi access point using `hostapd`
2. **DHCP Server**: Provides IP addresses to connected devices using `dnsmasq`
3. **TUN Interface**: Creates a virtual network interface for proxy traffic
4. **SOCKS5 Tunneling**: Routes all traffic through the SOCKS5 proxy using `tun2socks`
5. **DNS Protection**: Prevents DNS leaks by routing DNS queries through the proxy using `dns2socks`
6. **Traffic Routing**: Uses iptables and routing rules to ensure all traffic goes through the proxy

## Network Layout

```
[Connected Device] 
        ↓ (Wi-Fi)
[Raspberry Pi - wlan1] (192.168.50.x/24)
        ↓ (Routing Rules)
[TUN Interface] (10.0.0.x/24)
        ↓ (tun2socks)
[SOCKS5 Proxy] → [Internet]
```

## Troubleshooting

### Common Issues

1. **"Interface busy" or "Device already in use"**:
   ```bash
   # Stop NetworkManager from managing the hotspot interface
   sudo nmcli device set wlan1 managed no
   ```

2. **DNS not working**:
   - Ensure DNS leak protection is enabled: `--enable-dns-proxy`
   - Check if dns2socks is running: `ps aux | grep dns2socks`

3. **UDP not working**:
   - Enable UDP explicitly: `--enable-udp`
   - Some SOCKS5 proxies don't support UDP

4. **Can't connect to hotspot**:
   - Check if the Wi-Fi interface supports AP mode
   - Try a different channel: edit the hostapd configuration

### Checking Status

```bash
# Check running processes
ps aux | grep -E "(hostapd|dnsmasq|tun2socks|dns2socks)"

# Check network interfaces
ip addr show

# Check routing rules
ip route show table 100

# Check iptables rules
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v
```

### Stopping the Hotspot

Press `Ctrl+C` in the terminal where the script is running. The cleanup function will automatically:
- Stop all processes
- Remove iptables rules
- Restore DNS settings
- Clean up network interfaces

## Security Considerations

- Change the default hotspot password
- Use strong SOCKS5 proxy authentication
- Consider using a VPN in addition to the SOCKS5 proxy for extra security
- Regularly update the system and dependencies

## Files and Directories

- `main.sh`: Main hotspot script
- `install.sh`: Installation script for dependencies
- `/etc/proxypi/config.conf`: Default configuration file
- `/usr/local/bin/tun2socks*`: tun2socks binaries
- `/usr/local/bin/dns2socks`: dns2socks binary
- `/tmp/hostapd.conf`: Temporary hostapd configuration
- `/tmp/dnsmasq.conf`: Temporary dnsmasq configuration

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is provided as-is for educational and legitimate use purposes. 