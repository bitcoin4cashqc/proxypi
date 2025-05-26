#!/usr/bin/env python3
"""
WiFi Hotspot with SOCKS5 Proxy Router
Raspberry Pi 4 tool to create hotspot and route traffic through SOCKS5 proxy
"""

import os
import sys
import signal
import subprocess
import tempfile
import time
import logging
import argparse
import socket
from pathlib import Path

class WiFiSOCKS5Router:
    def __init__(self, hotspot_interface="wlan1", internet_interface="wlan0", 
                 socks5_host="127.0.0.1", socks5_port=1080,
                 socks5_username=None, socks5_password=None,
                 hotspot_ssid="RaspberryPi-Proxy", hotspot_password="raspberry123"):
        self.hotspot_interface = hotspot_interface
        self.internet_interface = internet_interface
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port
        self.socks5_username = socks5_username
        self.socks5_password = socks5_password
        self.hotspot_ssid = hotspot_ssid
        self.hotspot_password = hotspot_password
        
        # Network configuration
        self.hotspot_ip = "192.168.4.1"
        self.dhcp_range_start = "192.168.4.2"
        self.dhcp_range_end = "192.168.4.20"
        self.subnet = "192.168.4.0/24"
        
        # Temporary files
        self.temp_files = []
        self.services_started = []
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Register cleanup on exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle cleanup on signal"""
        self.logger.info(f"Received signal {signum}, cleaning up...")
        self.cleanup()
        sys.exit(0)
    
    def _run_command(self, cmd, check=True, capture_output=True):
        """Run shell command with error handling"""
        self.logger.debug(f"Running: {cmd}")
        try:
            if isinstance(cmd, str):
                result = subprocess.run(cmd, shell=True, check=check, 
                                      capture_output=capture_output, text=True)
            else:
                result = subprocess.run(cmd, check=check, 
                                      capture_output=capture_output, text=True)
            return result
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd}")
            self.logger.error(f"Error: {e.stderr if hasattr(e, 'stderr') else str(e)}")
            raise
    
    def _check_root(self):
        """Check if running as root"""
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root (use sudo)")
            sys.exit(1)
    
    def _check_interfaces(self):
        """Check if network interfaces exist"""
        interfaces = os.listdir('/sys/class/net/')
        if self.hotspot_interface not in interfaces:
            self.logger.error(f"Hotspot interface {self.hotspot_interface} not found")
            sys.exit(1)
        if self.internet_interface not in interfaces:
            self.logger.error(f"Internet interface {self.internet_interface} not found")
            sys.exit(1)
        self.logger.info(f"Using {self.hotspot_interface} for hotspot, {self.internet_interface} for internet")
    
    def _check_socks5(self):
        """Check if SOCKS5 proxy is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.socks5_host, self.socks5_port))
            sock.close()
            if result != 0:
                self.logger.warning(f"SOCKS5 proxy at {self.socks5_host}:{self.socks5_port} is not accessible")
                self.logger.warning("Make sure your SOCKS5 proxy is running before starting the hotspot")
            else:
                self.logger.info(f"SOCKS5 proxy at {self.socks5_host}:{self.socks5_port} is accessible")
        except Exception as e:
            self.logger.warning(f"Could not check SOCKS5 proxy: {e}")
    
    def _create_hostapd_config(self):
        """Create hostapd configuration file"""
        config_content = f"""
interface={self.hotspot_interface}
driver=nl80211
ssid={self.hotspot_ssid}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={self.hotspot_password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
        
        fd, path = tempfile.mkstemp(suffix='.conf', prefix='hostapd_')
        self.temp_files.append(path)
        
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        self.logger.info(f"Created hostapd config: {path}")
        return path
    
    def _create_dnsmasq_config(self):
        """Create dnsmasq configuration file"""
        config_content = f"""
interface={self.hotspot_interface}
dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},255.255.255.0,24h
dhcp-option=3,{self.hotspot_ip}
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
listen-address={self.hotspot_ip}
"""
        
        fd, path = tempfile.mkstemp(suffix='.conf', prefix='dnsmasq_')
        self.temp_files.append(path)
        
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        self.logger.info(f"Created dnsmasq config: {path}")
        return path
    
    def _setup_interface(self):
        """Configure hotspot interface"""
        self.logger.info("Setting up hotspot interface...")
        
        # Bring interface down
        self._run_command(f"ip link set {self.hotspot_interface} down")
        
        # Set IP address
        self._run_command(f"ip addr flush dev {self.hotspot_interface}")
        self._run_command(f"ip addr add {self.hotspot_ip}/24 dev {self.hotspot_interface}")
        
        # Bring interface up
        self._run_command(f"ip link set {self.hotspot_interface} up")
        
        self.logger.info(f"Interface {self.hotspot_interface} configured with IP {self.hotspot_ip}")
    
    def _setup_iptables(self):
        """Setup iptables rules for SOCKS5 routing"""
        self.logger.info("Setting up iptables rules...")
        
        # Enable IP forwarding
        self._run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Clear existing rules
        self._run_command("iptables -t nat -F")
        self._run_command("iptables -t mangle -F")
        self._run_command("iptables -F")
        
        # Allow traffic on loopback
        self._run_command("iptables -A INPUT -i lo -j ACCEPT")
        self._run_command("iptables -A OUTPUT -o lo -j ACCEPT")
        
        # Allow established connections
        self._run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
        self._run_command("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
        
        # Allow traffic from hotspot interface
        self._run_command(f"iptables -A INPUT -i {self.hotspot_interface} -j ACCEPT")
        self._run_command(f"iptables -A FORWARD -i {self.hotspot_interface} -j ACCEPT")
        
        # NAT for internet access (fallback)
        self._run_command(f"iptables -t nat -A POSTROUTING -o {self.internet_interface} -j MASQUERADE")
        
        # Mark packets from hotspot subnet for SOCKS5 routing
        self._run_command(f"iptables -t mangle -A OUTPUT -s {self.subnet} -j MARK --set-mark 1")
        
        self.logger.info("iptables rules configured")
    
    def _install_packages(self):
        """Install required packages"""
        packages = ["hostapd", "dnsmasq", "redsocks"]
        
        self.logger.info("Checking required packages...")
        for package in packages:
            try:
                self._run_command(f"dpkg -l {package}")
            except subprocess.CalledProcessError:
                self.logger.info(f"Installing {package}...")
                self._run_command(f"apt-get update && apt-get install -y {package}")
    
    def _setup_redsocks(self):
        """Setup redsocks for SOCKS5 routing"""
        config_content = f"""
base {{
    log_debug = on;
    log_info = on;
    log = "file:/tmp/redsocks.log";
    daemon = on;
    redirector = iptables;
}}

redsocks {{
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = {self.socks5_host};
    port = {self.socks5_port};
    type = socks5;"""

        # Add authentication if provided
        if self.socks5_username and self.socks5_password:
            config_content += f"""
    login = "{self.socks5_username}";
    password = "{self.socks5_password}";"""
        
        config_content += """
}
"""
        
        fd, path = tempfile.mkstemp(suffix='.conf', prefix='redsocks_')
        self.temp_files.append(path)
        
        with os.fdopen(fd, 'w') as f:
            f.write(config_content)
        
        # Start redsocks
        self._run_command(f"redsocks -c {path}")
        self.services_started.append("redsocks")
        
        # Add iptables rules for redsocks
        self._run_command(f"iptables -t nat -A OUTPUT -p tcp --dport 80 -s {self.subnet} -j REDIRECT --to-ports 12345")
        self._run_command(f"iptables -t nat -A OUTPUT -p tcp --dport 443 -s {self.subnet} -j REDIRECT --to-ports 12345")
        
        self.logger.info(f"Redsocks configured with config: {path}")
        return path
    
    def start_services(self):
        """Start hotspot and routing services"""
        self._check_root()
        self._check_interfaces()
        self._check_socks5()
        self._install_packages()
        
        self.logger.info("Starting WiFi hotspot with SOCKS5 routing...")
        
        # Stop conflicting services
        self._run_command("systemctl stop hostapd", check=False)
        self._run_command("systemctl stop dnsmasq", check=False)
        
        # Setup network interface
        self._setup_interface()
        
        # Create configuration files
        hostapd_config = self._create_hostapd_config()
        dnsmasq_config = self._create_dnsmasq_config()
        
        # Setup iptables
        self._setup_iptables()
        
        # Setup redsocks for SOCKS5
        self._setup_redsocks()
        
        # Start dnsmasq
        self.logger.info("Starting dnsmasq...")
        self._run_command(f"dnsmasq -C {dnsmasq_config} -d &", check=False)
        self.services_started.append("dnsmasq")
        time.sleep(2)
        
        # Start hostapd
        self.logger.info("Starting hostapd...")
        self._run_command(f"hostapd {hostapd_config} &", check=False)
        self.services_started.append("hostapd")
        time.sleep(5)
        
        self.logger.info("="*50)
        self.logger.info(f"WiFi Hotspot Started!")
        self.logger.info(f"SSID: {self.hotspot_ssid}")
        self.logger.info(f"Password: {self.hotspot_password}")
        self.logger.info(f"Hotspot IP: {self.hotspot_ip}")
        self.logger.info(f"SOCKS5 Proxy: {self.socks5_host}:{self.socks5_port}")
        if self.socks5_username:
            self.logger.info(f"SOCKS5 Auth: {self.socks5_username}:***")
        self.logger.info("All connected devices will route through the SOCKS5 proxy")
        self.logger.info("Press Ctrl+C to stop")
        self.logger.info("="*50)
    
    def cleanup(self):
        """Clean up all configurations and services"""
        self.logger.info("Cleaning up...")
        
        # Stop services
        if "hostapd" in self.services_started:
            self._run_command("pkill hostapd", check=False)
        
        if "dnsmasq" in self.services_started:
            self._run_command("pkill dnsmasq", check=False)
        
        if "redsocks" in self.services_started:
            self._run_command("pkill redsocks", check=False)
        
        # Reset iptables
        self._run_command("iptables -F", check=False)
        self._run_command("iptables -t nat -F", check=False)
        self._run_command("iptables -t mangle -F", check=False)
        
        # Reset interface
        self._run_command(f"ip addr flush dev {self.hotspot_interface}", check=False)
        self._run_command(f"ip link set {self.hotspot_interface} down", check=False)
        
        # Disable IP forwarding
        self._run_command("echo 0 > /proc/sys/net/ipv4/ip_forward", check=False)
        
        # Remove temporary files
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
        
        # Restart original services
        self._run_command("systemctl start hostapd", check=False)
        self._run_command("systemctl start dnsmasq", check=False)
        
        self.logger.info("Cleanup completed")
    
    def run(self):
        """Main run loop"""
        try:
            self.start_services()
            
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
        except Exception as e:
            self.logger.error(f"Error: {e}")
        finally:
            self.cleanup()

def main():
    parser = argparse.ArgumentParser(description="WiFi Hotspot with SOCKS5 Proxy Router")
    parser.add_argument("--hotspot-interface", default="wlan1", 
                       help="WiFi interface for hotspot (default: wlan1)")
    parser.add_argument("--internet-interface", default="wlan0", 
                       help="WiFi interface for internet (default: wlan0)")
    parser.add_argument("--socks5-host", default="127.0.0.1", 
                       help="SOCKS5 proxy host (default: 127.0.0.1)")
    parser.add_argument("--socks5-port", type=int, default=1080, 
                       help="SOCKS5 proxy port (default: 1080)")
    parser.add_argument("--socks5-username", 
                       help="SOCKS5 proxy username (optional)")
    parser.add_argument("--socks5-password", 
                       help="SOCKS5 proxy password (optional)")
    parser.add_argument("--ssid", default="RaspberryPi-Proxy", 
                       help="Hotspot SSID (default: RaspberryPi-Proxy)")
    parser.add_argument("--password", default="raspberry123", 
                       help="Hotspot password (default: raspberry123)")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    router = WiFiSOCKS5Router(
        hotspot_interface=args.hotspot_interface,
        internet_interface=args.internet_interface,
        socks5_host=args.socks5_host,
        socks5_port=args.socks5_port,
        socks5_username=args.socks5_username,
        socks5_password=args.socks5_password,
        hotspot_ssid=args.ssid,
        hotspot_password=args.password
    )
    
    router.run()

if __name__ == "__main__":
    main()