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

# ========== CONFIG ==========
TUN_INTERFACE = "tun0"
TUN_ADDR = "10.0.0.1"
TUN_GATEWAY = "10.0.0.2"
TUN_MASK = "255.255.255.0"
DEFAULT_HOTSPOT_IFACE = "wlan0"  # Will be overridden by detected interface
HOTSPOT_IP = "192.168.45.1"
DNS_RANGE = "192.168.45.10,192.168.45.100,12h"
TUN2SOCKS_URL_LINUX_ARM = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-arm64.zip"
#TUN2SOCKS_URL_LINUX_ARM = "https://github.com/xjasonlyu/tun2socks/releases/download/v2.5.2/tun2socks-linux-amd64.zip"
TUN2SOCKS_PATH = "/usr/local/bin/tun2socks"
DEFAULT_DNS = "8.8.8.8"

DEPENDENCIES = ["hostapd", "dnsmasq", "iptables", "iproute2", "curl", "wireless-tools"]

# ========== LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('proxypi.log')
    ]
)
logger = logging.getLogger(__name__)

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
        # Basic format validation
        parts = url[9:].split(":")
        if len(parts) != 2:
            logger.error("Proxy URL must be in format: socks5://host:port")
            return False
        port = int(parts[1])
        if not (1 <= port <= 65535):
            logger.error("Port must be between 1 and 65535")
            return False
        return True
    except Exception:
        logger.error("Invalid proxy URL format")
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
    logger.info(f"Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            logger.debug(f"Command output: {result.stdout}")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {e.stderr}")
        raise

def verify_download(file_path: str, expected_hash: Optional[str] = None) -> bool:
    """Verify downloaded file integrity."""
    if not expected_hash:
        return True
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash == expected_hash

def download_tun2socks():
    """Download and verify tun2socks binary."""
    if os.path.exists(TUN2SOCKS_PATH) and os.access(TUN2SOCKS_PATH, os.X_OK):
        logger.info("tun2socks already installed.")
        return

    logger.info("Downloading tun2socks binary...")
    temp_path = os.path.join(tempfile.gettempdir(), "tun2socks.zip")
    
    try:
        urllib.request.urlretrieve(TUN2SOCKS_URL_LINUX_ARM, temp_path)
        # TODO: Add actual hash verification once we have the correct hash
        # if not verify_download(temp_path, EXPECTED_HASH):
        #     raise ValueError("Downloaded file hash mismatch")
        
        shutil.move(temp_path, TUN2SOCKS_PATH)
        os.chmod(TUN2SOCKS_PATH, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        logger.info(f"tun2socks downloaded and installed to {TUN2SOCKS_PATH}")
    except Exception as e:
        logger.error(f"Failed to download tun2socks: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

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
            tun2socks_process.terminate()
            tun2socks_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("tun2socks did not terminate gracefully, forcing...")
            tun2socks_process.kill()
        except Exception as e:
            logger.error(f"Error stopping tun2socks: {e}")

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

# ========== SETUP FUNCTIONS ==========
def setup_hotspot(hotspot_iface: str, ssid: str, password: str):
    """Setup hotspot with proper error handling."""
    logger.info("Setting up hotspot interface and services...")

    try:
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
        with temp_file(hostapd_conf.strip(), "hostapd.conf") as hostapd_conf_path:
            run(f"hostapd {hostapd_conf_path} -B")

        dnsmasq_conf = f"""
interface={hotspot_iface}
dhcp-range={DNS_RANGE}
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
        run(f"iptables -t nat -A POSTROUTING -o {TUN_INTERFACE} -j MASQUERADE")
        run(f"iptables -A FORWARD -i {hotspot_iface} -o {TUN_INTERFACE} -j ACCEPT")
        run(f"iptables -A FORWARD -i {TUN_INTERFACE} -o {hotspot_iface} -j ACCEPT")
        run(f"iptables -A FORWARD -i {hotspot_iface} ! -o {TUN_INTERFACE} -j DROP")
    except Exception as e:
        logger.error(f"Failed to setup routing: {e}")
        raise

def start_tun2socks(proxy_url: str, dns: str = DEFAULT_DNS):
    """Start tun2socks with proper error handling."""
    global tun2socks_process
    logger.info("Starting tun2socks...")
    try:
        cmd = (
            f"{TUN2SOCKS_PATH} "
            f"-proxy {proxy_url} "
            f"-interface {TUN_INTERFACE} "
            f"-tunAddr {TUN_ADDR} "
            f"-tunGw {TUN_GATEWAY} "
            f"-tunMask {TUN_MASK} "
            f"-dns {dns}"
        )
        tun2socks_process = subprocess.Popen(cmd, shell=True)
    except Exception as e:
        logger.error(f"Failed to start tun2socks: {e}")
        raise

# ========== MAIN ==========
if __name__ == "__main__":
    if os.geteuid() != 0:
        logger.error("Please run as root (sudo). Exiting.")
        sys.exit(1)
    
    check_and_install_dependencies()
    download_tun2socks()

    parser = argparse.ArgumentParser(description="Raspberry Pi Wi-Fi Hotspot SOCKS5 Proxy Forwarder")
    parser.add_argument("--proxy", required=True, help="SOCKS5 proxy URL (e.g., socks5://1.2.3.4:1080)")
    parser.add_argument("--ssid", default="ProxyPi", help="Hotspot SSID (default ProxyPi)")
    parser.add_argument("--password", default="changeme123", help="Hotspot password (default changeme123)")
    parser.add_argument("--dns", default=DEFAULT_DNS, help=f"DNS server to use (default {DEFAULT_DNS})")
    parser.add_argument("--interface", help="Specific wireless interface to use (e.g., wlan0)")
    args = parser.parse_args()

    # Validate proxy URL
    if not validate_proxy_url(args.proxy):
        sys.exit(1)

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
