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
                                      capture_output=capture_output, text=True,
                                      bufsize=1, universal_newlines=True)
            else:
                result = subprocess.run(cmd, check=check, 
                                      capture_output=capture_output, text=True,
                                      bufsize=1, universal_newlines=True)
            
            # Log command output immediately
            if result.stdout:
                print(f"Command output: {result.stdout}", flush=True)
                self.logger.debug(f"Command output: {result.stdout}")
            if result.stderr:
                print(f"Command errors: {result.stderr}", flush=True)
                self.logger.error(f"Command errors: {result.stderr}")
                
            return result
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {cmd}", flush=True)
            print(f"Error output: {e.stderr if hasattr(e, 'stderr') else str(e)}", flush=True)
            self.logger.error(f"Command failed: {cmd}")
            self.logger.error(f"Error output: {e.stderr if hasattr(e, 'stderr') else str(e)}")
            raise
    
    def _check_root(self):
        """Check if running as root"""
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root (use sudo)")
            sys.exit(1)
    
    def _check_interfaces(self):
        """Check if network interfaces exist"""
        print("Checking network interfaces...", flush=True)
        interfaces = os.listdir('/sys/class/net/')
        
        # Check and initialize hotspot interface
        if self.hotspot_interface not in interfaces:
            print(f"Hotspot interface {self.hotspot_interface} not found, attempting to initialize...", flush=True)
            try:
                # Try to bring up the interface
                self._run_command(f"ip link set {self.hotspot_interface} up", check=False)
                time.sleep(2)  # Give it time to initialize
                
                # Check if it's up now
                interfaces = os.listdir('/sys/class/net/')
                if self.hotspot_interface not in interfaces:
                    print(f"Failed to initialize {self.hotspot_interface}", flush=True)
                    print("Please check if your WiFi adapter is properly connected", flush=True)
                    print("You can check available interfaces with: ip link show", flush=True)
                    sys.exit(1)
            except Exception as e:
                print(f"Error initializing {self.hotspot_interface}: {e}", flush=True)
                sys.exit(1)
        
        # Check internet interface
        if self.internet_interface not in interfaces:
            print(f"Internet interface {self.internet_interface} not found", flush=True)
            print("Please check if your WiFi adapter is properly connected", flush=True)
            print("You can check available interfaces with: ip link show", flush=True)
            sys.exit(1)
        
        # Verify interfaces are up
        try:
            # Check hotspot interface
            result = self._run_command(f"ip link show {self.hotspot_interface}", check=False)
            if "state DOWN" in result.stdout:
                print(f"Bringing up {self.hotspot_interface}...", flush=True)
                self._run_command(f"ip link set {self.hotspot_interface} up")
                time.sleep(2)  # Give it time to initialize
            
            # Check internet interface
            result = self._run_command(f"ip link show {self.internet_interface}", check=False)
            if "state DOWN" in result.stdout:
                print(f"Bringing up {self.internet_interface}...", flush=True)
                self._run_command(f"ip link set {self.internet_interface} up")
                time.sleep(2)  # Give it time to initialize
                
        except Exception as e:
            print(f"Error checking interface status: {e}", flush=True)
            sys.exit(1)
        
        print(f"Using {self.hotspot_interface} for hotspot, {self.internet_interface} for internet", flush=True)
        
        # Print interface details for debugging
        self._run_command(f"ip link show {self.hotspot_interface}")
        self._run_command(f"ip link show {self.internet_interface}")
    
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
logger_syslog=1
logger_syslog_level=2
logger_stdout=1
logger_stdout_level=2
"""
        
        # Create a unique temporary file with a specific name
        timestamp = int(time.time())
        path = f"/tmp/hostapd_{timestamp}.conf"
        
        try:
            # Create the file with proper permissions
            with open(path, 'w') as f:
                f.write(config_content)
            
            # Set permissions to 644 (read/write for owner, read for others)
            os.chmod(path, 0o644)
            
            # Verify the file exists and has correct permissions
            if not os.path.exists(path):
                raise Exception(f"Failed to create hostapd config file at {path}")
            
            # Verify file contents
            with open(path, 'r') as f:
                content = f.read()
                if not content.strip():
                    raise Exception("Created hostapd config file is empty")
            
            print(f"Created hostapd config file: {path}", flush=True)
            print(f"File permissions: {oct(os.stat(path).st_mode)[-3:]}", flush=True)
            print(f"File contents:\n{config_content}", flush=True)
            
            self.temp_files.append(path)
            return path
            
        except Exception as e:
            print(f"Error creating hostapd config file: {e}", flush=True)
            # Try fallback to a different location
            try:
                fallback_path = f"/tmp/hostapd_fallback_{timestamp}.conf"
                with open(fallback_path, 'w') as f:
                    f.write(config_content)
                os.chmod(fallback_path, 0o644)
                print(f"Created fallback hostapd config file: {fallback_path}", flush=True)
                self.temp_files.append(fallback_path)
                return fallback_path
            except Exception as e2:
                print(f"Fallback also failed: {e2}", flush=True)
                raise Exception(f"Could not create hostapd config file: {e}")
    
    def _create_dnsmasq_config(self):
        """Create dnsmasq configuration file"""
        # Create a unique log file name
        timestamp = int(time.time())
        log_file = f"/tmp/dnsmasq_{timestamp}.log"
        try:
            # Create or truncate the log file
            with open(log_file, 'w') as f:
                pass
            # Set permissions to 666 (read/write for all)
            os.chmod(log_file, 0o666)
            self.logger.info(f"Created dnsmasq log file: {log_file}")
        except Exception as e:
            self.logger.error(f"Failed to create dnsmasq log file: {e}")
            # Fallback to a temporary file
            fd, log_file = tempfile.mkstemp(suffix='.log', prefix='dnsmasq_')
            os.close(fd)
            self.temp_files.append(log_file)
            self.logger.info(f"Using temporary log file: {log_file}")

        config_content = f"""
# Basic configuration
interface={self.hotspot_interface}
bind-interfaces
listen-address={self.hotspot_ip}
no-resolv
no-poll
strict-order

# DHCP configuration
dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},255.255.255.0,24h
dhcp-option=3,{self.hotspot_ip}
dhcp-option=6,8.8.8.8,8.8.4.4

# DNS configuration
server=8.8.8.8
server=8.8.4.4

# Logging
log-queries
log-dhcp
log-facility={log_file}
"""
        
        # Create a unique config file name
        config_path = f"/tmp/dnsmasq_{timestamp}.conf"
        self.temp_files.append(config_path)
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        self.logger.info(f"Created dnsmasq config: {config_path}")
        return config_path
    
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
        # Create a unique log file name
        timestamp = int(time.time())
        log_file = f"/tmp/redsocks_{timestamp}.log"
        try:
            # Create or truncate the log file
            with open(log_file, 'w') as f:
                pass
            # Set permissions to 666 (read/write for all)
            os.chmod(log_file, 0o666)
            self.logger.info(f"Created redsocks log file: {log_file}")
        except Exception as e:
            self.logger.error(f"Failed to create redsocks log file: {e}")
            # Fallback to a temporary file
            fd, log_file = tempfile.mkstemp(suffix='.log', prefix='redsocks_')
            os.close(fd)
            self.temp_files.append(log_file)
            self.logger.info(f"Using temporary log file: {log_file}")

        config_content = f"""
base {{
    log_debug = on;
    log_info = on;
    log = "file:{log_file}";
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
        
        # Create a unique config file name
        config_path = f"/tmp/redsocks_{timestamp}.conf"
        self.temp_files.append(config_path)
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        self.logger.info(f"Created redsocks config: {config_path}")
        
        # Start redsocks with debug output
        try:
            self.logger.info("Starting redsocks...")
            redsocks_cmd = f"redsocks -c {config_path}"
            self.logger.info(f"Running redsocks command: {redsocks_cmd}")
            
            # Run redsocks in a way that we can see its output
            process = subprocess.Popen(
                redsocks_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Give it a moment to start
            time.sleep(2)
            
            # Check if it's running
            result = self._run_command("pgrep redsocks", check=False)
            if not result.stdout:
                # Get any output from the process
                stdout, stderr = process.communicate()
                if stdout:
                    print(f"redsocks stdout: {stdout}", flush=True)
                    self.logger.error(f"redsocks stdout: {stdout}")
                if stderr:
                    print(f"redsocks stderr: {stderr}", flush=True)
                    self.logger.error(f"redsocks stderr: {stderr}")
                raise Exception("redsocks failed to start")
            
            self.services_started.append("redsocks")
            print("redsocks started successfully", flush=True)
            self.logger.info("redsocks started successfully")
            
            # Check redsocks log file
            try:
                if os.path.exists(log_file):
                    with open(log_file, "r") as f:
                        log_content = f.read()
                        print(f"redsocks log content: {log_content}", flush=True)
                        self.logger.debug(f"redsocks log content: {log_content}")
            except Exception as e:
                self.logger.warning(f"Could not read redsocks log file: {e}")
            
            # Add iptables rules for redsocks
            self._run_command(f"iptables -t nat -A OUTPUT -p tcp --dport 80 -s {self.subnet} -j REDIRECT --to-ports 12345")
            self._run_command(f"iptables -t nat -A OUTPUT -p tcp --dport 443 -s {self.subnet} -j REDIRECT --to-ports 12345")
            
        except Exception as e:
            print(f"Failed to start redsocks: {e}", flush=True)
            self.logger.error(f"Failed to start redsocks: {e}")
            self.cleanup()
            sys.exit(1)
        
        return config_path
    
    def _check_port_53(self):
        """Check if port 53 is in use and free it"""
        self.logger.info("Checking port 53...")
        try:
            # Check if port 53 is in use
            result = self._run_command("lsof -i :53", check=False)
            if result.stdout:
                self.logger.warning("Port 53 is in use. Attempting to free it...")
                # Stop systemd-resolved
                self._run_command("systemctl stop systemd-resolved", check=False)
                self._run_command("systemctl disable systemd-resolved", check=False)
                # Stop dnsmasq if running
                self._run_command("systemctl stop dnsmasq", check=False)
                # Kill any remaining processes on port 53
                self._run_command("fuser -k 53/udp", check=False)
                self._run_command("fuser -k 53/tcp", check=False)
                time.sleep(2)  # Give it time to free up
        except Exception as e:
            self.logger.error(f"Error checking port 53: {e}")
    
    def start_services(self):
        """Start hotspot and routing services"""
        self._check_root()
        self._check_interfaces()
        self._check_socks5()
        self._install_packages()
        
        print("Starting WiFi hotspot with SOCKS5 routing...", flush=True)
        self.logger.info("Starting WiFi hotspot with SOCKS5 routing...")
        
        # Stop conflicting services and free port 53
        self._check_port_53()
        
        # Setup network interface
        self._setup_interface()
        
        # Create configuration files
        hostapd_config = self._create_hostapd_config()
        dnsmasq_config = self._create_dnsmasq_config()
        
        # Setup iptables
        self._setup_iptables()
        
        # Setup redsocks for SOCKS5
        self._setup_redsocks()
        
        # Start dnsmasq with debug output
        print("Starting dnsmasq...", flush=True)
        self.logger.info("Starting dnsmasq...")
        try:
            # First, verify the config file
            self._run_command(f"dnsmasq --test -C {dnsmasq_config}")
            print("dnsmasq config test passed", flush=True)
            self.logger.info("dnsmasq config test passed")
            
            # Start dnsmasq in foreground with debug output
            dnsmasq_cmd = f"dnsmasq -C {dnsmasq_config} -d --log-debug --log-queries --no-daemon"
            print(f"Running dnsmasq command: {dnsmasq_cmd}", flush=True)
            self.logger.info(f"Running dnsmasq command: {dnsmasq_cmd}")
            
            # Run dnsmasq in a way that we can see its output
            dnsmasq_process = subprocess.Popen(
                dnsmasq_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Give it a moment to start
            time.sleep(2)
            
            # Check if it's running
            result = self._run_command("pgrep dnsmasq", check=False)
            if not result.stdout:
                # Get any output from the process
                stdout, stderr = dnsmasq_process.communicate()
                if stdout:
                    print(f"dnsmasq stdout: {stdout}", flush=True)
                    self.logger.error(f"dnsmasq stdout: {stdout}")
                if stderr:
                    print(f"dnsmasq stderr: {stderr}", flush=True)
                    self.logger.error(f"dnsmasq stderr: {stderr}")
                raise Exception("dnsmasq failed to start")
            
            self.services_started.append("dnsmasq")
            print("dnsmasq started successfully", flush=True)
            self.logger.info("dnsmasq started successfully")
            
        except Exception as e:
            print(f"Failed to start dnsmasq: {e}", flush=True)
            self.logger.error(f"Failed to start dnsmasq: {e}")
            self.cleanup()
            sys.exit(1)
        
        # Start hostapd
        print("Starting hostapd...", flush=True)
        self.logger.info("Starting hostapd...")
        try:
            # First, verify the config file
            print(f"Testing hostapd config: {hostapd_config}", flush=True)
            self._run_command(f"hostapd -dd {hostapd_config}")
            print("hostapd config test passed", flush=True)
            self.logger.info("hostapd config test passed")
            
            # Start hostapd in foreground with maximum debug output
            hostapd_cmd = f"hostapd -dd -K {hostapd_config}"
            print(f"Running hostapd command: {hostapd_cmd}", flush=True)
            self.logger.info(f"Running hostapd command: {hostapd_cmd}")
            
            # Run hostapd in a way that we can see its output
            hostapd_process = subprocess.Popen(
                hostapd_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Give it a moment to start
            time.sleep(5)
            
            # Check if it's running
            result = self._run_command("pgrep hostapd", check=False)
            if not result.stdout:
                # Get any output from the process
                stdout, stderr = hostapd_process.communicate()
                if stdout:
                    print(f"hostapd stdout: {stdout}", flush=True)
                    self.logger.error(f"hostapd stdout: {stdout}")
                if stderr:
                    print(f"hostapd stderr: {stderr}", flush=True)
                    self.logger.error(f"hostapd stderr: {stderr}")
                raise Exception("hostapd failed to start")
            
            self.services_started.append("hostapd")
            print("hostapd started successfully", flush=True)
            self.logger.info("hostapd started successfully")
            
        except Exception as e:
            print(f"Failed to start hostapd: {e}", flush=True)
            self.logger.error(f"Failed to start hostapd: {e}")
            self.cleanup()
            sys.exit(1)
        
        print("="*50, flush=True)
        print(f"WiFi Hotspot Started!", flush=True)
        print(f"SSID: {self.hotspot_ssid}", flush=True)
        print(f"Password: {self.hotspot_password}", flush=True)
        print(f"Hotspot IP: {self.hotspot_ip}", flush=True)
        print(f"SOCKS5 Proxy: {self.socks5_host}:{self.socks5_port}", flush=True)
        if self.socks5_username:
            print(f"SOCKS5 Auth: {self.socks5_username}:***", flush=True)
        print("All connected devices will route through the SOCKS5 proxy", flush=True)
        print("Press Ctrl+C to stop", flush=True)
        print("="*50, flush=True)
        
        # Keep processes running and monitor their output
        try:
            while True:
                # Check if all services are still running
                for service in self.services_started:
                    result = self._run_command(f"pgrep {service}", check=False)
                    if not result.stdout:
                        print(f"{service} has stopped unexpectedly", flush=True)
                        self.logger.error(f"{service} has stopped unexpectedly")
                        raise Exception(f"{service} process died")
                
                # Read and log any new output from processes
                if dnsmasq_process.poll() is None:  # if process is still running
                    stdout = dnsmasq_process.stdout.readline()
                    if stdout:
                        print(f"dnsmasq: {stdout.strip()}", flush=True)
                        self.logger.debug(f"dnsmasq: {stdout.strip()}")
                
                if hostapd_process.poll() is None:
                    stdout = hostapd_process.stdout.readline()
                    if stdout:
                        print(f"hostapd: {stdout.strip()}", flush=True)
                        self.logger.debug(f"hostapd: {stdout.strip()}")
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("Interrupted by user", flush=True)
            self.logger.info("Interrupted by user")
        except Exception as e:
            print(f"Error: {e}", flush=True)
            self.logger.error(f"Error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up all configurations and services"""
        self.logger.info("Cleaning up...")
        
        # Stop services
        if "hostapd" in self.services_started:
            self._run_command("pkill hostapd", check=False)
            self._run_command("systemctl stop hostapd", check=False)
        
        if "dnsmasq" in self.services_started:
            self._run_command("pkill dnsmasq", check=False)
            self._run_command("systemctl stop dnsmasq", check=False)
            # Free port 53
            self._run_command("fuser -k 53/udp", check=False)
            self._run_command("fuser -k 53/tcp", check=False)
        
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