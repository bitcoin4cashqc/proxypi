#!/usr/bin/env python3
"""
ProxyPi - Raspberry Pi WiFi Hotspot with SOCKS5 Proxy

This script transforms a Raspberry Pi into a WiFi hotspot that routes all traffic
through a SOCKS5 proxy using tun2socks.
"""

import argparse
import json
import logging
import os
import platform
import re
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Global variables for cleanup
processes: List[subprocess.Popen] = []
temp_files: List[str] = []
original_services: Dict[str, bool] = {}
cleanup_done = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxypi_debug.log')
    ]
)
logger = logging.getLogger(__name__)


class ProxyPiError(Exception):
    """Custom exception for ProxyPi errors"""
    pass


def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        raise ProxyPiError("This script must be run as root (use sudo)")


def detect_architecture() -> str:
    """Detect system architecture for tun2socks binary"""
    machine = platform.machine().lower()
    arch_map = {
        'aarch64': 'linux-arm64',
        'armv7l': 'linux-armv7',
        'x86_64': 'linux-amd64',
        'i686': 'linux-386',
        'i386': 'linux-386'
    }
    
    if machine in arch_map:
        return arch_map[machine]
    else:
        raise ProxyPiError(f"Unsupported architecture: {machine}")


def download_tun2socks() -> str:
    """Download and install tun2socks binary"""
    arch = detect_architecture()
    version = "v2.5.2"
    url = f"https://github.com/xjasonlyu/tun2socks/releases/download/{version}/tun2socks-{arch}.zip"
    
    tun2socks_path = "/usr/local/bin/tun2socks"
    
    if os.path.exists(tun2socks_path):
        logger.info("tun2socks already installed")
        return tun2socks_path
    
    logger.info(f"Downloading tun2socks for {arch}...")
    
    try:
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            urllib.request.urlretrieve(url, tmp_file.name)
            temp_files.append(tmp_file.name)
            
            with zipfile.ZipFile(tmp_file.name, 'r') as zip_ref:
                zip_ref.extractall('/tmp')
            
            # Find the extracted binary
            extracted_binary = f"/tmp/tun2socks-{arch}"
            if not os.path.exists(extracted_binary):
                raise ProxyPiError(f"Extracted binary not found: {extracted_binary}")
            
            # Move to final location and make executable
            subprocess.run(['mv', extracted_binary, tun2socks_path], check=True)
            subprocess.run(['chmod', '+x', tun2socks_path], check=True)
            
            logger.info(f"tun2socks installed to {tun2socks_path}")
            return tun2socks_path
            
    except Exception as e:
        raise ProxyPiError(f"Failed to download tun2socks: {e}")


def parse_proxy_url(proxy_url: str) -> Tuple[str, int, Optional[str], Optional[str]]:
    """Parse SOCKS5 proxy URL with optional authentication"""
    if not proxy_url.startswith('socks5://'):
        proxy_url = f'socks5://{proxy_url}'
    
    parsed = urllib.parse.urlparse(proxy_url)
    
    if not parsed.hostname or not parsed.port:
        raise ProxyPiError("Invalid proxy URL format. Use: socks5://[username:password@]host:port")
    
    return parsed.hostname, parsed.port, parsed.username, parsed.password


def validate_proxy_connection(host: str, port: int, username: Optional[str] = None, password: Optional[str] = None) -> bool:
    """Validate SOCKS5 proxy connection using curl"""
    try:
        proxy_url = f"socks5://{host}:{port}"
        if username and password:
            proxy_url = f"socks5://{username}:{password}@{host}:{port}"
        
        result = subprocess.run([
            'curl', '--proxy', proxy_url, '--connect-timeout', '10',
            '--silent', '--output', '/dev/null', '--write-out', '%{http_code}',
            'https://www.google.com'
        ], capture_output=True, text=True, timeout=15)
        
        return result.returncode == 0 and result.stdout.strip() == '200'
    except Exception as e:
        logger.error(f"Proxy validation failed: {e}")
        return False


def get_wireless_interfaces() -> List[str]:
    """Get list of wireless interfaces"""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                interface = line.split()[-1]
                interfaces.append(interface)
        return interfaces
    except subprocess.CalledProcessError:
        return []


def detect_interface_conflicts() -> Dict[str, List[str]]:
    """Detect services that might conflict with our setup"""
    conflicts = {'port_53': [], 'hostapd': [], 'dnsmasq': []}
    
    # Check for port 53 conflicts
    try:
        result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if ':53 ' in line and 'LISTEN' in line:
                if 'systemd-resolved' in line:
                    conflicts['port_53'].append('systemd-resolved')
                elif 'dnsmasq' in line:
                    conflicts['port_53'].append('dnsmasq')
    except subprocess.CalledProcessError:
        pass
    
    # Check for running services
    for service in ['hostapd', 'dnsmasq']:
        try:
            result = subprocess.run(['systemctl', 'is-active', service], 
                                  capture_output=True, text=True)
            if result.stdout.strip() == 'active':
                conflicts[service].append(service)
        except subprocess.CalledProcessError:
            pass
    
    return conflicts


def resolve_conflicts(conflicts: Dict[str, List[str]]):
    """Resolve detected conflicts"""
    global original_services
    
    # Stop systemd-resolved if it's using port 53
    if 'systemd-resolved' in conflicts['port_53']:
        logger.info("Stopping systemd-resolved to free port 53")
        try:
            subprocess.run(['systemctl', 'stop', 'systemd-resolved'], check=True)
            original_services['systemd-resolved'] = True
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to stop systemd-resolved: {e}")
    
    # Stop conflicting services
    for service in ['hostapd', 'dnsmasq']:
        if conflicts[service]:
            logger.info(f"Stopping {service}")
            try:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True)
                if result.stdout.strip() == 'active':
                    original_services[service] = True
                    subprocess.run(['systemctl', 'stop', service], check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to stop {service}: {e}")


def install_packages():
    """Install required packages"""
    packages = ['hostapd', 'dnsmasq', 'iptables', 'iw', 'curl', 'netstat-nat']
    
    logger.info("Installing required packages...")
    try:
        subprocess.run(['apt', 'update'], check=True, capture_output=True)
        subprocess.run(['apt', 'install', '-y'] + packages, check=True, capture_output=True)
        logger.info("Packages installed successfully")
    except subprocess.CalledProcessError as e:
        raise ProxyPiError(f"Failed to install packages: {e}")


def create_temp_file(content: str, suffix: str = '') -> str:
    """Create a temporary file with given content"""
    fd, path = tempfile.mkstemp(suffix=suffix, text=True)
    temp_files.append(path)
    
    with os.fdopen(fd, 'w') as f:
        f.write(content)
    
    return path


def setup_hostapd(interface: str, ssid: str, password: str) -> subprocess.Popen:
    """Setup hostapd for WiFi hotspot"""
    hostapd_conf = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    
    conf_file = create_temp_file(hostapd_conf, '.conf')
    
    # Configure interface
    subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True)
    subprocess.run(['ip', 'addr', 'flush', 'dev', interface], check=True)
    subprocess.run(['ip', 'addr', 'add', '192.168.45.1/24', 'dev', interface], check=True)
    subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True)
    
    logger.info(f"Starting hostapd on {interface}")
    process = subprocess.Popen(['hostapd', conf_file], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.STDOUT)
    processes.append(process)
    
    # Wait for hostapd to start
    time.sleep(3)
    if process.poll() is not None:
        output, _ = process.communicate()
        raise ProxyPiError(f"hostapd failed to start: {output.decode()}")
    
    return process


def setup_dnsmasq(interface: str) -> subprocess.Popen:
    """Setup dnsmasq for DHCP and DNS"""
    dnsmasq_conf = f"""interface={interface}
bind-interfaces
dhcp-range=192.168.45.2,192.168.45.50,255.255.255.0,12h
dhcp-option=3,192.168.45.1
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
"""
    
    conf_file = create_temp_file(dnsmasq_conf, '.conf')
    
    logger.info(f"Starting dnsmasq on {interface}")
    process = subprocess.Popen(['dnsmasq', '-C', conf_file, '--no-daemon'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.STDOUT)
    processes.append(process)
    
    # Wait for dnsmasq to start
    time.sleep(2)
    if process.poll() is not None:
        output, _ = process.communicate()
        raise ProxyPiError(f"dnsmasq failed to start: {output.decode()}")
    
    return process


def setup_tun2socks(tun2socks_path: str, proxy_host: str, proxy_port: int, 
                   username: Optional[str] = None, password: Optional[str] = None) -> subprocess.Popen:
    """Setup tun2socks for SOCKS5 proxy"""
    
    # Create TUN interface
    subprocess.run(['ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'], check=True)
    subprocess.run(['ip', 'addr', 'add', '198.18.0.1/15', 'dev', 'tun0'], check=True)
    subprocess.run(['ip', 'link', 'set', 'tun0', 'up'], check=True)
    
    # Create tun2socks config
    config = {
        'interface': 'tun0',
        'proxy': f'socks5://{proxy_host}:{proxy_port}',
        'loglevel': 'info'
    }
    
    if username and password:
        config['proxy'] = f'socks5://{username}:{password}@{proxy_host}:{proxy_port}'
    
    config_file = create_temp_file(json.dumps(config, indent=2), '.json')
    
    logger.info(f"Starting tun2socks with proxy {proxy_host}:{proxy_port}")
    
    # Start tun2socks with config file
    cmd = [tun2socks_path, '-config', config_file]
    
    with open('/tmp/tun2socks.log', 'w') as log_file:
        process = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
    
    processes.append(process)
    
    # Wait for TUN interface to be ready
    for i in range(10):
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                                  capture_output=True, text=True, timeout=5)
            if 'tun0' in result.stdout:
                logger.info("tun2socks is ready")
                break
        except subprocess.TimeoutExpired:
            pass
        
        if process.poll() is not None:
            raise ProxyPiError("tun2socks process died")
        
        time.sleep(1)
    else:
        logger.warning("tun2socks may not be fully ready")
    
    return process


def setup_routing(hotspot_interface: str):
    """Setup routing and iptables rules"""
    logger.info("Setting up routing and iptables rules")
    
    # Enable IP forwarding
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
    
    # Clear existing rules
    subprocess.run(['iptables', '-F'], check=True)
    subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
    
    # Set up NAT and forwarding rules
    subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', 'tun0', '-j', 'MASQUERADE'], check=True)
    subprocess.run(['iptables', '-A', 'FORWARD', '-i', hotspot_interface, '-o', 'tun0', '-j', 'ACCEPT'], check=True)
    subprocess.run(['iptables', '-A', 'FORWARD', '-i', 'tun0', '-o', hotspot_interface, '-j', 'ACCEPT'], check=True)
    
    # Route traffic through TUN interface
    subprocess.run(['ip', 'route', 'add', '0.0.0.0/1', 'dev', 'tun0'], check=True)
    subprocess.run(['ip', 'route', 'add', '128.0.0.0/1', 'dev', 'tun0'], check=True)


def cleanup():
    """Clean up all resources"""
    global cleanup_done
    if cleanup_done:
        return
    
    cleanup_done = True
    logger.info("Cleaning up...")
    
    # Stop all processes
    for process in processes:
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as e:
            logger.warning(f"Error stopping process: {e}")
    
    # Clean up network configuration
    try:
        subprocess.run(['iptables', '-F'], check=False)
        subprocess.run(['iptables', '-t', 'nat', '-F'], check=False)
        subprocess.run(['ip', 'route', 'del', '0.0.0.0/1', 'dev', 'tun0'], check=False)
        subprocess.run(['ip', 'route', 'del', '128.0.0.0/1', 'dev', 'tun0'], check=False)
        subprocess.run(['ip', 'link', 'set', 'tun0', 'down'], check=False)
        subprocess.run(['ip', 'tuntap', 'del', 'dev', 'tun0', 'mode', 'tun'], check=False)
    except Exception as e:
        logger.warning(f"Error cleaning up network: {e}")
    
    # Remove temporary files
    for temp_file in temp_files:
        try:
            os.unlink(temp_file)
        except Exception as e:
            logger.warning(f"Error removing temp file {temp_file}: {e}")
    
    # Restart original services
    for service, was_active in original_services.items():
        if was_active:
            try:
                subprocess.run(['systemctl', 'start', service], check=True)
                logger.info(f"Restarted {service}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to restart {service}: {e}")


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    cleanup()
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='ProxyPi - WiFi Hotspot with SOCKS5 Proxy')
    parser.add_argument('--interface', help='WiFi interface for hotspot')
    parser.add_argument('--proxy', required=True, help='SOCKS5 proxy URL (socks5://[user:pass@]host:port)')
    parser.add_argument('--ssid', default='ProxyPi', help='WiFi hotspot SSID')
    parser.add_argument('--password', default='changeme123', help='WiFi hotspot password')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Check prerequisites
        check_root()
        
        # Parse proxy URL
        proxy_host, proxy_port, proxy_username, proxy_password = parse_proxy_url(args.proxy)
        logger.info(f"Using proxy: {proxy_host}:{proxy_port}")
        
        # Validate proxy connection
        if not validate_proxy_connection(proxy_host, proxy_port, proxy_username, proxy_password):
            raise ProxyPiError("Cannot connect to SOCKS5 proxy")
        
        # Detect and resolve conflicts
        conflicts = detect_interface_conflicts()
        resolve_conflicts(conflicts)
        
        # Install packages
        install_packages()
        
        # Download tun2socks
        tun2socks_path = download_tun2socks()
        
        # Get wireless interfaces
        interfaces = get_wireless_interfaces()
        if not interfaces:
            raise ProxyPiError("No wireless interfaces found")
        
        # Select interface
        if args.interface:
            if args.interface not in interfaces:
                raise ProxyPiError(f"Interface {args.interface} not found")
            hotspot_interface = args.interface
        else:
            hotspot_interface = interfaces[0]
            logger.info(f"Using interface: {hotspot_interface}")
        
        # Setup components
        logger.info("Setting up WiFi hotspot...")
        hostapd_process = setup_hostapd(hotspot_interface, args.ssid, args.password)
        
        logger.info("Setting up DHCP and DNS...")
        dnsmasq_process = setup_dnsmasq(hotspot_interface)
        
        logger.info("Setting up SOCKS5 tunnel...")
        tun2socks_process = setup_tun2socks(tun2socks_path, proxy_host, proxy_port, 
                                          proxy_username, proxy_password)
        
        logger.info("Setting up routing...")
        setup_routing(hotspot_interface)
        
        logger.info(f"ProxyPi is running!")
        logger.info(f"WiFi SSID: {args.ssid}")
        logger.info(f"WiFi Password: {args.password}")
        logger.info(f"Proxy: {proxy_host}:{proxy_port}")
        logger.info("Press Ctrl+C to stop")
        
        # Keep running until interrupted
        while True:
            time.sleep(1)
            
            # Check if any critical process died
            if hostapd_process.poll() is not None:
                raise ProxyPiError("hostapd process died")
            if dnsmasq_process.poll() is not None:
                raise ProxyPiError("dnsmasq process died")
            if tun2socks_process.poll() is not None:
                raise ProxyPiError("tun2socks process died")
    
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except ProxyPiError as e:
        logger.error(f"ProxyPi error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        cleanup()


if __name__ == '__main__':
    main()
