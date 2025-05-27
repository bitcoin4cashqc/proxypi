#!/usr/bin/env python3
"""
Optimized WiFi Hotspot with SOCKS5 Proxy Router
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
import threading
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
        
        # Process management
        self.temp_files = []
        self.processes = {}
        self.running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Register cleanup on exit
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle cleanup on signal"""
        self.logger.info(f"Received signal {signum}, cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def _run_command(self, cmd, check=True, capture_output=True, timeout=30):
        """Run shell command with error handling and timeout"""
        self.logger.debug(f"Running: {cmd}")
        try:
            if isinstance(cmd, str):
                result = subprocess.run(cmd, shell=True, check=check, 
                                      capture_output=capture_output, text=True,
                                      timeout=timeout)
            else:
                result = subprocess.run(cmd, check=check, 
                                      capture_output=capture_output, text=True,
                                      timeout=timeout)
            
            if result.stdout and capture_output:
                self.logger.debug(f"Command output: {result.stdout.strip()}")
            if result.stderr and capture_output:
                self.logger.warning(f"Command stderr: {result.stderr.strip()}")
                
            return result
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {cmd}")
            raise
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {cmd}")
            if hasattr(e, 'stderr') and e.stderr:
                self.logger.error(f"Error output: {e.stderr}")
            if not check:
                return e
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
            self.logger.info("Available interfaces: " + ", ".join(interfaces))
            sys.exit(1)
        
        if self.internet_interface not in interfaces:
            self.logger.error(f"Internet interface {self.internet_interface} not found")
            self.logger.info("Available interfaces: " + ", ".join(interfaces))
            sys.exit(1)
        
        # Check interface capabilities
        try:
            result = self._run_command(f"iw {self.hotspot_interface} info")
            self.logger.debug(f"Interface {self.hotspot_interface} info: {result.stdout}")
        except:
            self.logger.warning(f"Could not get info for {self.hotspot_interface}")
        
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
                return False
            else:
                self.logger.info(f"SOCKS5 proxy at {self.socks5_host}:{self.socks5_port} is accessible")
                return True
        except Exception as e:
            self.logger.warning(f"Could not check SOCKS5 proxy: {e}")
            return False
    
    def _install_packages(self):
        """Install required packages"""
        packages = ["hostapd", "dnsmasq", "redsocks", "iptables-persistent"]
        
        self.logger.info("Checking required packages...")
        missing_packages = []
        
        for package in packages:
            try:
                self._run_command(f"dpkg -l {package} | grep -q '^ii'")
            except subprocess.CalledProcessError:
                missing_packages.append(package)
        
        if missing_packages:
            self.logger.info(f"Installing missing packages: {', '.join(missing_packages)}")
            self._run_command("apt-get update")
            for package in missing_packages:
                self._run_command(f"apt-get install -y {package}")
    
    def _stop_conflicting_services(self):
        """Stop services that might conflict"""
        services_to_stop = ["hostapd", "dnsmasq", "systemd-resolved"]
        
        for service in services_to_stop:
            try:
                self._run_command(f"systemctl stop {service}", check=False)
                self._run_command(f"systemctl disable {service}", check=False)
            except:
                pass
        
        # Kill any processes using port 53
        self._run_command("fuser -k 53/udp", check=False)
        self._run_command("fuser -k 53/tcp", check=False)
        
        # Kill existing hostapd and dnsmasq processes
        self._run_command("pkill -f hostapd", check=False)
        self._run_command("pkill -f dnsmasq", check=False)
        self._run_command("pkill -f redsocks", check=False)
        
        time.sleep(2)
    
    def _setup_interface(self):
        """Configure hotspot interface"""
        self.logger.info("Setting up hotspot interface...")
        
        # Reset interface
        self._run_command(f"ip link set {self.hotspot_interface} down", check=False)
        self._run_command(f"ip addr flush dev {self.hotspot_interface}", check=False)
        
        # Configure interface
        self._run_command(f"ip addr add {self.hotspot_ip}/24 dev {self.hotspot_interface}")
        self._run_command(f"ip link set {self.hotspot_interface} up")
        
        self.logger.info(f"Interface {self.hotspot_interface} configured with IP {self.hotspot_ip}")
    
    def _setup_iptables(self):
        """Setup iptables rules for routing and SOCKS5"""
        self.logger.info("Setting up iptables rules...")
        
        # Enable IP forwarding
        self._run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Clear existing rules
        self._run_command("iptables -F", check=False)
        self._run_command("iptables -t nat -F", check=False)
        self._run_command("iptables -t mangle -F", check=False)
        
        # Set default policies
        self._run_command("iptables -P INPUT ACCEPT")
        self._run_command("iptables -P FORWARD ACCEPT")
        self._run_command("iptables -P OUTPUT ACCEPT")
        
        # Allow loopback
        self._run_command("iptables -A INPUT -i lo -j ACCEPT")
        self._run_command("iptables -A OUTPUT -o lo -j ACCEPT")
        
        # Allow established connections
        self._run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
        self._run_command("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
        
        # Allow traffic from hotspot interface
        self._run_command(f"iptables -A INPUT -i {self.hotspot_interface} -j ACCEPT")
        self._run_command(f"iptables -A FORWARD -i {self.hotspot_interface} -j ACCEPT")
        
        # NAT for internet access
        self._run_command(f"iptables -t nat -A POSTROUTING -o {self.internet_interface} -j MASQUERADE")
        
        # Redirect HTTP/HTTPS traffic to redsocks
        self._run_command(f"iptables -t nat -A PREROUTING -i {self.hotspot_interface} -p tcp --dport 80 -j REDIRECT --to-ports 12345")
        self._run_command(f"iptables -t nat -A PREROUTING -i {self.hotspot_interface} -p tcp --dport 443 -j REDIRECT --to-ports 12345")
        
        # Redirect all other TCP traffic to redsocks (optional - for full proxy)
        self._run_command(f"iptables -t nat -A PREROUTING -i {self.hotspot_interface} -p tcp -j REDIRECT --to-ports 12345")
        
        self.logger.info("iptables rules configured")
    
    def _create_redsocks_config(self):
        """Create redsocks configuration"""
        timestamp = int(time.time())
        config_path = f"/tmp/redsocks_{timestamp}.conf"
        log_path = f"/tmp/redsocks_{timestamp}.log"
        
        config_content = f"""base {{
    log_debug = on;
    log_info = on;
    log = "file:{log_path}";
    daemon = on;
    redirector = iptables;
}}

redsocks {{
    local_ip = 127.0.0.1;
    local_port = 12345;
    ip = {self.socks5_host};
    port = {self.socks5_port};
    type = socks5;"""

        if self.socks5_username and self.socks5_password:
            config_content += f"""
    login = "{self.socks5_username}";
    password = "{self.socks5_password}";"""
        
        config_content += "\n}\n"
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        # Create log file
        Path(log_path).touch()
        os.chmod(log_path, 0o666)
        
        self.temp_files.extend([config_path, log_path])
        self.logger.info(f"Created redsocks config: {config_path}")
        
        return config_path
    
    def _create_hostapd_config(self):
        """Create hostapd configuration"""
        timestamp = int(time.time())
        config_path = f"/tmp/hostapd_{timestamp}.conf"
        
        config_content = f"""interface={self.hotspot_interface}
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
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        os.chmod(config_path, 0o644)
        self.temp_files.append(config_path)
        self.logger.info(f"Created hostapd config: {config_path}")
        
        return config_path
    
    def _create_dnsmasq_config(self):
        """Create dnsmasq configuration"""
        timestamp = int(time.time())
        config_path = f"/tmp/dnsmasq_{timestamp}.conf"
        
        config_content = f"""interface={self.hotspot_interface}
bind-interfaces
listen-address={self.hotspot_ip}
dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},255.255.255.0,24h
dhcp-option=3,{self.hotspot_ip}
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
no-resolv
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        self.temp_files.append(config_path)
        self.logger.info(f"Created dnsmasq config: {config_path}")
        
        return config_path
    
    def _start_process(self, name, cmd, config_file=None):
        """Start a process and monitor it"""
        self.logger.info(f"Starting {name}...")
        
        try:
            # Test configuration if provided
            if config_file:
                if name == "hostapd":
                    test_cmd = f"hostapd -t {config_file}"
                elif name == "redsocks":
                    test_cmd = f"redsocks -t -c {config_file}"
                elif name == "dnsmasq":
                    test_cmd = f"dnsmasq --test -C {config_file}"
                
                print(f"Testing {name} config with: {test_cmd}", flush=True)
                result = self._run_command(test_cmd, timeout=10)
                if result.returncode != 0:
                    raise Exception(f"{name} configuration test failed: {result.stderr}")
                print(f"{name} configuration test passed", flush=True)
            
            # Start the process with full output capture
            print(f"Starting {name} with command: {cmd}", flush=True)
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Give it time to start
            time.sleep(3)
            
            # Check if process is running
            if process.poll() is not None:
                output, _ = process.communicate()
                print(f"{name} failed to start. Output:", flush=True)
                print(output, flush=True)
                raise Exception(f"{name} failed to start. See output above.")
            
            self.processes[name] = process
            print(f"{name} started successfully (PID: {process.pid})", flush=True)
            
            # Start output monitoring thread
            def monitor_output():
                while self.running and process.poll() is None:
                    try:
                        line = process.stdout.readline()
                        if line:
                            print(f"{name}: {line.strip()}", flush=True)
                            self.logger.debug(f"{name}: {line.strip()}")
                    except:
                        break
            
            thread = threading.Thread(target=monitor_output, daemon=True)
            thread.start()
            
            return process
            
        except Exception as e:
            print(f"Failed to start {name}: {e}", flush=True)
            self.logger.error(f"Failed to start {name}: {e}")
            raise
    
    def start_services(self):
        """Start all services"""
        self._check_root()
        self._check_interfaces()
        self._install_packages()
        self._stop_conflicting_services()
        
        print("Starting WiFi hotspot with SOCKS5 routing...", flush=True)
        self.logger.info("Starting WiFi hotspot with SOCKS5 routing...")
        self.running = True
        
        # Check SOCKS5 proxy
        if not self._check_socks5():
            print("WARNING: SOCKS5 proxy is not accessible. Traffic may not be proxied properly.", flush=True)
            self.logger.warning("SOCKS5 proxy is not accessible. Traffic may not be proxied properly.")
        
        # Setup network
        self._setup_interface()
        self._setup_iptables()
        
        # Create configuration files
        redsocks_config = self._create_redsocks_config()
        hostapd_config = self._create_hostapd_config()
        dnsmasq_config = self._create_dnsmasq_config()
        
        # Start services in order
        try:
            # Start redsocks first
            print("\nStarting redsocks...", flush=True)
            self._start_process("redsocks", f"redsocks -c {redsocks_config}", redsocks_config)
            time.sleep(2)
            
            # Start dnsmasq
            print("\nStarting dnsmasq...", flush=True)
            self._start_process("dnsmasq", f"dnsmasq -C {dnsmasq_config} -d", dnsmasq_config)
            time.sleep(2)
            
            # Start hostapd last
            print("\nStarting hostapd...", flush=True)
            self._start_process("hostapd", f"hostapd {hostapd_config}", hostapd_config)
            time.sleep(5)
            
            print("\nAll services started successfully", flush=True)
            self.logger.info("All services started successfully")
            
            print("=" * 60)
            print("WiFi Hotspot with SOCKS5 Proxy Started Successfully!")
            print("=" * 60)
            print(f"SSID: {self.hotspot_ssid}")
            print(f"Password: {self.hotspot_password}")
            print(f"Hotspot IP: {self.hotspot_ip}")
            print(f"SOCKS5 Proxy: {self.socks5_host}:{self.socks5_port}")
            if self.socks5_username:
                print(f"SOCKS5 Auth: {self.socks5_username}:***")
            print(f"Internet Interface: {self.internet_interface}")
            print(f"Hotspot Interface: {self.hotspot_interface}")
            print("\nAll connected devices will route through the SOCKS5 proxy")
            print("Press Ctrl+C to stop")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\nFailed to start services: {e}", flush=True)
            self.logger.error(f"Failed to start services: {e}")
            self.cleanup()
            return False
    
    def monitor_services(self):
        """Monitor running services"""
        while self.running:
            try:
                # Check if all processes are still running
                dead_processes = []
                for name, process in self.processes.items():
                    if process.poll() is not None:
                        dead_processes.append(name)
                
                if dead_processes:
                    self.logger.error(f"Services died: {', '.join(dead_processes)}")
                    break
                
                time.sleep(5)
                
            except KeyboardInterrupt:
                self.logger.info("Interrupted by user")
                break
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                break
    
    def cleanup(self):
        """Clean up all configurations and services"""
        self.logger.info("Cleaning up...")
        self.running = False
        
        # Terminate processes
        for name, process in self.processes.items():
            try:
                if process.poll() is None:
                    self.logger.info(f"Terminating {name}...")
                    process.terminate()
                    time.sleep(2)
                    if process.poll() is None:
                        process.kill()
            except:
                pass
        
        # Kill any remaining processes
        self._run_command("pkill -f hostapd", check=False)
        self._run_command("pkill -f dnsmasq", check=False)
        self._run_command("pkill -f redsocks", check=False)
        
        # Reset network configuration
        self._run_command(f"ip addr flush dev {self.hotspot_interface}", check=False)
        self._run_command(f"ip link set {self.hotspot_interface} down", check=False)
        
        # Reset iptables
        self._run_command("iptables -F", check=False)
        self._run_command("iptables -t nat -F", check=False)
        self._run_command("iptables -t mangle -F", check=False)
        self._run_command("iptables -P INPUT ACCEPT", check=False)
        self._run_command("iptables -P FORWARD ACCEPT", check=False)
        self._run_command("iptables -P OUTPUT ACCEPT", check=False)
        
        # Disable IP forwarding
        self._run_command("echo 0 > /proc/sys/net/ipv4/ip_forward", check=False)
        
        # Remove temporary files
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except:
                pass
        
        self.logger.info("Cleanup completed")
    
    def run(self):
        """Main run method"""
        try:
            if self.start_services():
                self.monitor_services()
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