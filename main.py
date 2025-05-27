import os
import signal
import subprocess
import tempfile
import sys

# ==== CONFIG ====
AP_IFACE = "wlan1"
INTERNET_IFACE = "wlan0"
SSID = "ProxyHotspot"
PASSWORD = "changeme123"

PROXY_HOST = "217.182.193.32"
PROXY_PORT = 10040
PROXY_USERNAME = "1RzgE"
PROXY_PASSWORD = "RyMxP"

TUN2SOCKS_PATH = "/usr/local/bin/tun2socks"  # or wherever you installed xjasonlyu/tun2socks
# ===============


# Temp files
temp_files = []

def write_temp(content, suffix=""):
    tmp = tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=suffix)
    tmp.write(content)
    tmp.close()
    temp_files.append(tmp.name)
    return tmp.name

def run(cmd, **kwargs):
    return subprocess.Popen(cmd, shell=True, **kwargs)

def setup_hotspot():
    hostapd_conf = f"""
interface={AP_IFACE}
driver=nl80211
ssid={SSID}
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
    """.strip()
    dnsmasq_conf = f"""
interface={AP_IFACE}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8
bind-interfaces
    """.strip()
    os.system(f"ip link set {AP_IFACE} down")
    os.system(f"ip addr flush dev {AP_IFACE}")
    os.system(f"ip addr add 10.0.0.1/24 dev {AP_IFACE}")
    os.system(f"ip link set {AP_IFACE} up")

    hostapd_file = write_temp(hostapd_conf, ".conf")
    dnsmasq_file = write_temp(dnsmasq_conf, ".conf")

    dnsmasq = run(f"dnsmasq -C {dnsmasq_file}")
    hostapd = run(f"hostapd {hostapd_file}")

    return hostapd, dnsmasq

def setup_routing():
    # Enable IP forwarding
    os.system("sysctl -w net.ipv4.ip_forward=1")

    # Set up TUN interface
    os.system("ip tuntap add dev tun0 mode tun")
    os.system("ip addr add 10.0.0.2/24 dev tun0")
    os.system("ip link set tun0 up")

    # Redirect traffic from wlan1 (AP) to tun0
    os.system(f"iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE")
    os.system(f"iptables -A FORWARD -i {AP_IFACE} -o tun0 -j ACCEPT")
    os.system(f"iptables -A FORWARD -i tun0 -o {AP_IFACE} -j ACCEPT")

    # Start tun2socks to tunnel traffic from tun0 through SOCKS5
    tun2socks = run(
    f"{TUN2SOCKS_PATH} --netif tun0 --socks5 {PROXY_HOST}:{PROXY_PORT} "
    f"--username {PROXY_USERNAME} --password {PROXY_PASSWORD}",
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL
)
    print(tun2socks.stdout.read().decode())
    return tun2socks

def cleanup():
    print("\nCleaning up...")
    os.system("killall hostapd dnsmasq tun2socks >/dev/null 2>&1")
    os.system("iptables -F")
    os.system("iptables -t nat -F")
    os.system("ip link set tun0 down")
    os.system("ip tuntap del dev tun0 mode tun")
    for f in temp_files:
        os.unlink(f)

def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Starting hotspot on {AP_IFACE} using internet from {INTERNET_IFACE}")
    hostapd, dnsmasq = setup_hotspot()
    tun2socks = setup_routing()

    print("Hotspot running. Press Ctrl+C to stop.")
    signal.pause()
