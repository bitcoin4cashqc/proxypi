#!/usr/bin/env python3
import os
import subprocess
import argparse
import signal
import sys
import urllib.request
import stat
import tempfile
import logging
import hashlib
import shutil
from contextlib import contextmanager
from typing import Optional, List
import time
import zipfile

# ========== CONFIG ==========
TUN_INTERFACE = "tun0"
TUN_ADDR = "10.0.0.1"
TUN_GATEWAY = "10.0.0.2"
TUN_MASK = "255.255.255.0"
DEFAULT_HOTSPOT_IFACE = "wlan0"  # Will be overridden by detected interface
HOTSPOT_IP = "192.168.45.1"
DNS_RANGE = "192.168.45.10,192.168.45.100,12h"

# Tun2socks URLs for different architectures
TUN2SOCKS_URLS = {
    'aarch64': "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-arm64.zip",
    'armv7l': "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-arm.zip",
    'x86_64': "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-amd64.zip",
    'i686': "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-386.zip"
}

TUN2SOCKS_PATH = "/usr/local/bin/tun2socks"
DEFAULT_DNS = "8.8.8.8"

DEPENDENCIES = ["hostapd", "dnsmasq", "iptables", "iproute2", "curl", "wireless-tools"]

# ========== LOGGING ==========
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxypi.log')
    ]
)
logger = logging.getLogger(__name__)

# Add file handler for debug logs
debug_handler = logging.FileHandler('proxypi_debug.log')
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s\nFile: %(filename)s\nFunction: %(funcName)s\nLine: %(lineno)d\n')
debug_handler.setFormatter(debug_formatter)
logger.addHandler(debug_handler)

tun2socks_process = None
hostapd_conf_path = ""
dnsmasq_conf_path = ""

# ========== UTILS ==========
def get_wireless_interfaces() -> List[str]:
    """Get list of available wireless interfaces."""
    try:
        # First check if iwconfig is available
        try:
            run("which iwconfig", check=True)
        except subprocess.CalledProcessError:
            logger.error("iwconfig command not found. Installing wireless-tools...")
            run("apt-get update && apt-get install -y wireless-tools")
        
        # Get all wireless interfaces and their status
        interfaces = []
        result = run("iwconfig 2>/dev/null", check=False)
        if result.returncode == 0:
            current_iface = None
            for line in result.stdout.splitlines():
                if line and not line.startswith(' '):
                    current_iface = line.split()[0]
                    # Check if interface is not connected to any network
                    if "ESSID:off/any" in line or "ESSID:off" in line:
                        interfaces.append(current_iface)
        
        # If iwconfig fails or returns no interfaces, try ip command
        if not interfaces:
            logger.info("Falling back to ip command for interface detection...")
            result = run("ip link show | grep -E '^[0-9]+: wl' | cut -d: -f2 | tr -d ' '", check=False)
            if result.returncode == 0 and result.stdout.strip():
                # Check each interface's status
                for iface in result.stdout.splitlines():
                    if iface:
                        # Check if interface is down or not connected
                        status = run(f"ip link show {iface}", check=False)
                        if "state DOWN" in status.stdout or "NO-CARRIER" in status.stdout:
                            interfaces.append(iface)
        
        return interfaces
    except Exception as e:
        logger.error(f"Failed to get wireless interfaces: {e}")
        return []

def validate_proxy_url(url: str) -> bool:
    """Validate proxy URL format."""
    if not url.startswith("socks5://"):
        logger.error("Proxy URL must start with 'socks5://'")
        return False
    try:
        # Remove the protocol part
        url = url[9:]
        
        # Check for authentication
        if '@' in url:
            auth, rest = url.split('@', 1)
            if ':' not in auth:
                logger.error("Invalid authentication format. Use: socks5://username:password@host:port")
                return False
            username, password = auth.split(':', 1)
            if not username or not password:
                logger.error("Username and password cannot be empty")
                return False
            url = rest
        
        # Check host and port
        if ':' not in url:
            logger.error("Port is required. Use: socks5://host:port")
            return False
        
        host, port = url.split(':', 1)
        if not host:
            logger.error("Host cannot be empty")
            return False
        
        port = int(port)
        if not (1 <= port <= 65535):
            logger.error("Port must be between 1 and 65535")
            return False
        
        return True
    except Exception as e:
        logger.error(f"Invalid proxy URL format: {e}")
        return False

@contextmanager
def temp_file(content: str, filename: str):
    """Context manager for temporary file creation and cleanup."""
    path = os.path.join(tempfile.gettempdir(), filename)
    try:
        with open(path, "w") as f:
            f.write(content)
        yield path
    finally:
        if os.path.exists(path):
            os.remove(path)

def run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command with proper logging and error handling."""
    logger.debug(f"Running command: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            logger.debug(f"Command stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"Command stderr: {result.stderr}")
        logger.debug(f"Command return code: {result.returncode}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}")
        logger.error(f"Command stderr: {e.stderr}")
        raise

def verify_download(file_path: str, expected_hash: Optional[str] = None) -> bool:
    """Verify downloaded file integrity."""
    if not expected_hash:
        return True
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash

def get_system_architecture() -> str:
    """Get system architecture."""
    try:
        logger.debug("Detecting system architecture...")
        arch = subprocess.check_output(['uname', '-m']).decode().strip()
        logger.debug(f"Raw architecture from uname -m: {arch}")
        
        # Map common architecture names to our supported ones
        arch_map = {
            'aarch64': 'aarch64',
            'arm64': 'aarch64',
            'armv7l': 'armv7l',
            'armv6l': 'armv7l',  # Use armv7l binary for armv6l
            'x86_64': 'x86_64',
            'amd64': 'x86_64',
            'i686': 'i686',
            'i386': 'i686'
        }
        mapped_arch = arch_map.get(arch, arch)
        logger.debug(f"Mapped architecture: {mapped_arch}")
        return mapped_arch
    except Exception as e:
        logger.error(f"Failed to detect system architecture: {e}")
        raise

def download_tun2socks():
    """Download and verify tun2socks binary."""
    if os.path.exists(TUN2SOCKS_PATH) and os.access(TUN2SOCKS_PATH, os.X_OK):
        logger.info("tun2socks already installed.")
        # Check if the binary is executable
        try:
            result = run(f"file {TUN2SOCKS_PATH}", check=False)
            logger.debug(f"Current tun2socks binary info: {result.stdout}")
        except Exception as e:
            logger.error(f"Error checking existing tun2socks binary: {e}")
        return

    logger.info("Detecting system architecture...")
    arch = get_system_architecture()
    if arch not in TUN2SOCKS_URLS:
        logger.error(f"Unsupported architecture: {arch}")
        logger.error(f"Supported architectures: {list(TUN2SOCKS_URLS.keys())}")
        raise RuntimeError(f"Unsupported architecture: {arch}")

    logger.info(f"Downloading tun2socks binary for {arch}...")
    logger.debug(f"Download URL: {TUN2SOCKS_URLS[arch]}")
    temp_path = os.path.join(tempfile.gettempdir(), "tun2socks.zip")
    
    try:
        # Download the file
        logger.debug(f"Downloading to temporary path: {temp_path}")
        urllib.request.urlretrieve(TUN2SOCKS_URLS[arch], temp_path)
        
        # Verify the downloaded file
        logger.debug(f"Downloaded file size: {os.path.getsize(temp_path)} bytes")
        
        # Extract the zip file
        logger.debug("Extracting zip file...")
        with zipfile.ZipFile(temp_path, 'r') as zip_ref:
            # List contents of zip file
            logger.debug("Zip file contents:")
            for file_info in zip_ref.filelist:
                logger.debug(f"  {file_info.filename} ({file_info.file_size} bytes)")
            
            # Extract to a temporary directory
            temp_dir = tempfile.mkdtemp()
            logger.debug(f"Extracting to temporary directory: {temp_dir}")
            zip_ref.extractall(temp_dir)
            
            # Find the tun2socks binary in the extracted files
            tun2socks_binary = None
            logger.debug("Searching for tun2socks binary...")
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.startswith('tun2socks'):
                        tun2socks_binary = os.path.join(root, file)
                        logger.debug(f"Found tun2socks binary: {tun2socks_binary}")
                        break
                if tun2socks_binary:
                    break
            
            if not tun2socks_binary:
                logger.error("Could not find tun2socks binary in the downloaded package")
                raise RuntimeError("Could not find tun2socks binary in the downloaded package")
            
            # Check binary before moving
            logger.debug("Checking binary before installation...")
            result = run(f"file {tun2socks_binary}", check=False)
            logger.debug(f"Binary file info: {result.stdout}")
            
            # Move the binary to the final location
            logger.debug(f"Moving binary to {TUN2SOCKS_PATH}")
            shutil.move(tun2socks_binary, TUN2SOCKS_PATH)
            
            # Set permissions
            logger.debug("Setting binary permissions...")
            os.chmod(TUN2SOCKS_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            
            # Verify final installation
            logger.debug("Verifying installation...")
            result = run(f"file {TUN2SOCKS_PATH}", check=False)
            logger.debug(f"Installed binary info: {result.stdout}")
            
            logger.info(f"tun2socks downloaded and installed to {TUN2SOCKS_PATH}")
            
            # Clean up
            logger.debug("Cleaning up temporary files...")
            shutil.rmtree(temp_dir)
            
    except Exception as e:
        logger.error(f"Failed to download tun2socks: {e}")
        logger.exception("Detailed error information:")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def check_and_install_dependencies():
    """Check and install required dependencies."""
    missing = []
    for pkg in DEPENDENCIES:
        try:
            run(f"dpkg-query -W -f='${{Status}}' {pkg}", check=True)
        except subprocess.CalledProcessError:
            missing.append(pkg)
    
    if missing:
        logger.info(f"Installing missing dependencies: {' '.join(missing)}")
        run(f"apt-get update && apt-get install -y {' '.join(missing)}")

def cleanup(hotspot_iface: str):
    """Cleanup function with proper error handling and logging."""
    logger.info("Cleaning up...")
    
    # Stop tun2socks if running
    if tun2socks_process and tun2socks_process.poll() is None:
        logger.info("Stopping tun2socks...")
        try:
            # Get any remaining output
            stdout, stderr = tun2socks_process.communicate(timeout=1)
            if stdout:
                logger.debug(f"Final tun2socks stdout: {stdout}")
            if stderr:
                logger.debug(f"Final tun2socks stderr: {stderr}")
            
            tun2socks_process.terminate()
            tun2socks_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("tun2socks did not terminate gracefully, forcing...")
            tun2socks_process.kill()
        except Exception as e:
            logger.error(f"Error stopping tun2socks: {e}")

    # Remove default route through TUN
    try:
        run(f"ip route del default via {TUN_GATEWAY} dev {TUN_INTERFACE}", check=False)
    except Exception as e:
        logger.error(f"Error removing default route: {e}")

    # Flush iptables rules
    try:
        run("iptables -F", check=False)
        run("iptables -t nat -F", check=False)
    except Exception as e:
        logger.error(f"Error flushing iptables: {e}")

    # Remove TUN interface
    try:
        run(f"ip link set {TUN_INTERFACE} down", check=False)
        run(f"ip tuntap del dev {TUN_INTERFACE} mode tun", check=False)
    except Exception as e:
        logger.error(f"Error removing TUN interface: {e}")

    # Stop services
    try:
        run("pkill hostapd", check=False)
        run("pkill dnsmasq", check=False)
    except Exception as e:
        logger.error(f"Error stopping services: {e}")

    # Bring down hotspot interface
    try:
        run(f"ip link set {hotspot_iface} down", check=False)
        run(f"ip addr flush dev {hotspot_iface}", check=False)
    except Exception as e:
        logger.error(f"Error bringing down hotspot interface: {e}")

    logger.info("Cleanup complete.")

def validate_proxy_connection(proxy_url: str) -> bool:
    """Validate that the proxy is actually working."""
    try:
        # Parse proxy URL
        proxy_parts = proxy_url.split('://', 1)
        if len(proxy_parts) != 2:
            return False
        
        protocol, rest = proxy_parts
        if protocol != 'socks5':
            return False
        
        # Handle authentication if present
        if '@' in rest:
            auth, address = rest.split('@', 1)
            username, password = auth.split(':', 1)
            host, port = address.split(':', 1)
            proxy_arg = f"--proxy socks5://{username}:{password}@{host}:{port}"
        else:
            host, port = rest.split(':', 1)
            proxy_arg = f"--proxy socks5://{host}:{port}"
        
        # Try to connect to a known host
        cmd = f"curl -s --connect-timeout 10 {proxy_arg} https://www.google.com"
        logger.debug(f"Testing proxy with command: {cmd}")
        result = run(cmd, check=False)
        
        if result.returncode == 0:
            logger.info("Proxy connection test successful")
            return True
        else:
            logger.error(f"Proxy connection test failed: {result.stderr}")
            return False
            
    except Exception as e:
        logger.error(f"Proxy validation failed: {e}")
        return False

# ========== SETUP FUNCTIONS ==========
def setup_hotspot(hotspot_iface: str, ssid: str, password: str):
    """Setup hotspot with proper error handling."""
    logger.info("Setting up hotspot interface and services...")
    logger.debug(f"Setting up hotspot with interface: {hotspot_iface}, SSID: {ssid}")

    try:
        # Check for DNS port conflict
        try:
            run("lsof -i :53", check=False)
            logger.warning("Port 53 is in use. Attempting to resolve...")
            
            # Try to stop systemd-resolved
            if run("systemctl is-active systemd-resolved", check=False).returncode == 0:
                logger.info("Stopping systemd-resolved...")
                run("systemctl stop systemd-resolved", check=False)
                run("systemctl disable systemd-resolved", check=False)
            
            # Try to stop any other dnsmasq instances
            if run("pgrep dnsmasq", check=False).returncode == 0:
                logger.info("Stopping existing dnsmasq instances...")
                run("systemctl stop dnsmasq", check=False)
                run("pkill dnsmasq", check=False)
            
            # Wait for ports to be released
            time.sleep(2)
            
            # Check if port is still in use
            if run("lsof -i :53", check=False).returncode == 0:
                logger.error("Port 53 is still in use. Please manually stop the service using port 53 and try again.")
                logger.error("You can check what's using port 53 with: sudo lsof -i :53")
                raise RuntimeError("DNS port 53 is in use")
        except Exception as e:
            logger.error(f"Failed to resolve DNS port conflict: {e}")
            raise

        run(f"ip link set {hotspot_iface} down || true")
        run(f"ip addr flush dev {hotspot_iface} || true")
        run(f"ip link set {hotspot_iface} up")
        run(f"ip addr add {HOTSPOT_IP}/24 dev {hotspot_iface}")

        hostapd_conf = f"""
interface={hotspot_iface}
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
rsn_pairwise=CCMP
"""
        logger.debug(f"Generated hostapd configuration:\n{hostapd_conf}")
        with temp_file(hostapd_conf.strip(), "hostapd.conf") as hostapd_conf_path:
            logger.debug(f"Starting hostapd with config file: {hostapd_conf_path}")
            run(f"hostapd {hostapd_conf_path} -B")
            logger.debug("hostapd started successfully")

        dnsmasq_conf = f"""
interface={hotspot_iface}
dhcp-range={DNS_RANGE}
no-resolv
no-poll
server=8.8.8.8
server=8.8.4.4
bind-interfaces
listen-address={HOTSPOT_IP}
cache-size=1000
dns-forward-max=500
log-queries
log-dhcp
log-facility=/tmp/dnsmasq.log
"""
        with temp_file(dnsmasq_conf.strip(), "dnsmasq.conf") as dnsmasq_conf_path:
            run(f"dnsmasq -C {dnsmasq_conf_path}")

        run("sysctl -w net.ipv4.ip_forward=1")
    except Exception as e:
        logger.error(f"Failed to setup hotspot: {e}")
        raise

def setup_tun_interface():
    """Setup TUN interface with proper error handling."""
    logger.info("Creating TUN interface...")
    try:
        run(f"ip tuntap add dev {TUN_INTERFACE} mode tun")
        run(f"ip addr add {TUN_ADDR}/{TUN_MASK} dev {TUN_INTERFACE}")
        run(f"ip link set {TUN_INTERFACE} up")
    except Exception as e:
        logger.error(f"Failed to setup TUN interface: {e}")
        raise

def setup_routing(hotspot_iface: str):
    """Setup routing rules with proper error handling."""
    logger.info("Setting up iptables rules...")
    try:
        # Flush existing rules
        run("iptables -F", check=False)
        run("iptables -t nat -F", check=False)
        
        # Enable IP forwarding
        run("sysctl -w net.ipv4.ip_forward=1")
        
        # Set up NAT
        run(f"iptables -t nat -A POSTROUTING -o {TUN_INTERFACE} -j MASQUERADE")
        
        # Allow forwarding between interfaces
        run(f"iptables -A FORWARD -i {hotspot_iface} -o {TUN_INTERFACE} -j ACCEPT")
        run(f"iptables -A FORWARD -i {TUN_INTERFACE} -o {hotspot_iface} -j ACCEPT")
        
        # Drop traffic that doesn't go through TUN
        run(f"iptables -A FORWARD -i {hotspot_iface} ! -o {TUN_INTERFACE} -j DROP")
        
        # Add default route through TUN interface
        run(f"ip route add default via {TUN_GATEWAY} dev {TUN_INTERFACE} metric 100", check=False)
        
        # Log the rules
        logger.debug("Current iptables rules:")
        run("iptables -L -v -n", check=False)
        run("iptables -t nat -L -v -n", check=False)
        
        # Log routing table
        logger.debug("Current routing table:")
        run("ip route show", check=False)
    except Exception as e:
        logger.error(f"Failed to setup routing: {e}")
        raise

def start_tun2socks(proxy_url: str, dns: str = DEFAULT_DNS):
    """Start tun2socks with proper error handling."""
    global tun2socks_process
    logger.info("Starting tun2socks...")
    try:
        # Verify tun2socks binary before starting
        logger.debug("Verifying tun2socks binary...")
        result = run(f"file {TUN2SOCKS_PATH}", check=False)
        logger.debug(f"tun2socks binary info: {result.stdout}")
        
        # Check if binary is executable
        if not os.access(TUN2SOCKS_PATH, os.X_OK):
            logger.error(f"tun2socks binary is not executable: {TUN2SOCKS_PATH}")
            raise RuntimeError("tun2socks binary is not executable")
        
        # Test binary execution
        logger.debug("Testing binary execution...")
        test_result = run(f"{TUN2SOCKS_PATH} -version", check=False)
        logger.debug(f"Version test output: {test_result.stdout}")
        if test_result.stderr:
            logger.debug(f"Version test error: {test_result.stderr}")
        
        # Parse proxy URL to ensure proper formatting
        proxy_parts = proxy_url.split('://', 1)
        if len(proxy_parts) != 2:
            raise ValueError("Invalid proxy URL format")
        
        protocol, rest = proxy_parts
        if protocol != 'socks5':
            raise ValueError("Only SOCKS5 protocol is supported")
        
        # Handle authentication if present
        if '@' in rest:
            auth, address = rest.split('@', 1)
            username, password = auth.split(':', 1)
            proxy_url = f"socks5://{username}:{password}@{address}"
        
        # Create a temporary config file
        config_content = f"""
device: tun://{TUN_INTERFACE}
interface: {TUN_INTERFACE}
proxy: {proxy_url}
mtu: 1500
tcp-auto-tuning: true
loglevel: debug
log-file: /tmp/tun2socks.log
"""
        logger.debug(f"Generated tun2socks configuration:\n{config_content}")
        with temp_file(config_content.strip(), "tun2socks.yaml") as config_path:
            cmd = f"{TUN2SOCKS_PATH} -config {config_path}"
            logger.debug(f"Starting tun2socks with command: {cmd}")
            
            # Start process with output capture
            tun2socks_process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Check if process started successfully
            if tun2socks_process.poll() is not None:
                stdout, stderr = tun2socks_process.communicate()
                logger.error(f"tun2socks failed to start. Return code: {tun2socks_process.returncode}")
                if stdout:
                    logger.error(f"stdout: {stdout}")
                if stderr:
                    logger.error(f"stderr: {stderr}")
                raise RuntimeError("tun2socks failed to start")
            
            # Start output monitoring thread
            def monitor_output(process, pipe, log_func):
                for line in pipe:
                    log_func(line.strip())
            
            import threading
            stdout_thread = threading.Thread(
                target=monitor_output,
                args=(tun2socks_process, tun2socks_process.stdout, logger.info),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=monitor_output,
                args=(tun2socks_process, tun2socks_process.stderr, logger.error),
                daemon=True
            )
            stdout_thread.start()
            stderr_thread.start()
            
            logger.debug("tun2socks process started successfully")
            
            # Wait a moment to check if process is still running
            time.sleep(2)
            if tun2socks_process.poll() is not None:
                stdout, stderr = tun2socks_process.communicate()
                logger.error("tun2socks process terminated unexpectedly")
                if stdout:
                    logger.error(f"stdout: {stdout}")
                if stderr:
                    logger.error(f"stderr: {stderr}")
                raise RuntimeError("tun2socks process terminated unexpectedly")
                
    except Exception as e:
        logger.error(f"Failed to start tun2socks: {e}")
        logger.exception("Detailed error information:")
        raise

# ========== MAIN ==========
if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("Please run as root (sudo). Exiting.")
        sys.exit(1)
    
    check_and_install_dependencies()
    download_tun2socks()

    parser = argparse.ArgumentParser(description="Raspberry Pi Wi-Fi Hotspot SOCKS5 Proxy Forwarder")
    parser.add_argument("--proxy", required=True, 
                      help="SOCKS5 proxy URL (e.g., socks5://1.2.3.4:1080 or socks5://user:pass@1.2.3.4:1080)")
    parser.add_argument("--ssid", default="ProxyPi", help="Hotspot SSID (default ProxyPi)")
    parser.add_argument("--password", default="changeme123", help="Hotspot password (default changeme123)")
    parser.add_argument("--dns", default=DEFAULT_DNS, help=f"DNS server to use (default {DEFAULT_DNS})")
    parser.add_argument("--interface", help="Specific wireless interface to use (e.g., wlan0)")
    args = parser.parse_args()

    # Validate proxy URL
    if not validate_proxy_url(args.proxy):
        sys.exit(1)

    # Validate proxy connection
    logger.info("Validating proxy connection...")
    if not validate_proxy_connection(args.proxy):
        logger.error("Failed to connect to proxy. Please check if the proxy is working.")
        sys.exit(1)
    logger.info("Proxy connection validated successfully.")

    # Detect wireless interface
    wireless_interfaces = get_wireless_interfaces()
    
    # Select interface
    if args.interface:
        if args.interface in wireless_interfaces:
            hotspot_iface = args.interface
            logger.info(f"Using specified interface: {hotspot_iface}")
        else:
            logger.error(f"Specified interface {args.interface} not available. Available interfaces: {', '.join(wireless_interfaces) if wireless_interfaces else 'none'}")
            sys.exit(1)
    elif wireless_interfaces:
        hotspot_iface = wireless_interfaces[0]
        logger.info(f"Using first available interface: {hotspot_iface}")
    else:
        hotspot_iface = DEFAULT_HOTSPOT_IFACE
        logger.warning(f"No available wireless interfaces found. Using default interface: {hotspot_iface}")
        logger.warning("Note: This interface might be in use by your WiFi connection.")

    # Set up signal handler with the correct interface
    signal.signal(signal.SIGINT, lambda sig, frame: cleanup(hotspot_iface) or sys.exit(0))
    signal.signal(signal.SIGTERM, lambda sig, frame: cleanup(hotspot_iface) or sys.exit(0))

    try:
        setup_hotspot(hotspot_iface, args.ssid, args.password)
        setup_tun_interface()
        setup_routing(hotspot_iface)
        start_tun2socks(args.proxy, args.dns)

        logger.info("Hotspot with proxy forwarding running.")
        logger.info(f"Connect your devices to Wi-Fi SSID: {args.ssid}")
        logger.info(f"Traffic will be routed via SOCKS5 proxy: {args.proxy}")
        logger.info("Press Ctrl+C to stop and cleanup.")

        tun2socks_process.wait()

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        cleanup(hotspot_iface)
        sys.exit(1)
    finally:
        cleanup(hotspot_iface)
