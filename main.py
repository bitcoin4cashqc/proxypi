import os
import platform
import psutil
import subprocess
import time
import argparse

# CONFIGURATION
SSID = "ProxyHotspot"
PASSWORD = "securepass"
WIFI_INTERFACE_IN = "wlan0"
WIFI_INTERFACE_OUT = "wlan1"
TUN_DEVICE = "tun0"
SOCKS5_PROXY = "217.182.193.32:10040"
SOCKS5_USER = "1RzgE"
SOCKS5_PASS = "RyMxP"

def run(cmd, check=True):
    print(f"💻 {cmd}")
    return subprocess.run(cmd, shell=True, check=check)

def is_raspberry_pi():
    return platform.machine().startswith("arm") and 'raspberrypi' in platform.uname().nodename

def create_ap_config():
    print("📄 Creating hostapd config...")
    with open("/etc/hostapd/hostapd.conf", "w") as f:
        f.write(f"""
interface={WIFI_INTERFACE_OUT}
driver=nl80211
ssid={SSID}
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
        """)
    run("sed -i 's|#DAEMON_CONF=\"\"|DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"|' /etc/default/hostapd")

def configure_dhcp_dns():
    print("📄 Configuring dnsmasq...")
    with open("/etc/dnsmasq.conf", "a") as f:
        f.write(f"""
interface={WIFI_INTERFACE_OUT}
dhcp-range=10.10.0.10,10.10.0.50,255.255.255.0,24h
        """)
    run(f"ifconfig {WIFI_INTERFACE_OUT} 10.10.0.1 netmask 255.255.255.0 up")

def enable_ip_forwarding():
    run("sysctl -w net.ipv4.ip_forward=1")

def setup_iptables(in_iface, out_iface):
    print(f"🔀 Setting up iptables: {out_iface} -> {in_iface}")
    run("iptables -F")
    run("iptables -t nat -F")
    run(f"iptables -t nat -A POSTROUTING -o {in_iface} -j MASQUERADE")
    run(f"iptables -A FORWARD -i {in_iface} -o {out_iface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run(f"iptables -A FORWARD -i {out_iface} -o {in_iface} -j ACCEPT")

def start_services():
    run("systemctl unmask hostapd")
    run("systemctl enable hostapd")
    run("systemctl start hostapd")
    run("systemctl restart dnsmasq")

def start_tun2socks(interface):
    print("🚀 Starting tun2socks...")
    cmd = (
        f"tun2socks -device {TUN_DEVICE} "
        f"-proxy socks5://{SOCKS5_USER}:{SOCKS5_PASS}@{SOCKS5_PROXY} "
        f"-interface {interface} &"
    )
    run(cmd, check=False)

def simulate_in_wsl():
    print("🧪 Simulating setup with dummy interfaces on Linux/WSL")

    # Create dummy interface
    run("ip link add dummy0 type dummy", check=False)
    run("ip addr add 10.10.0.1/24 dev dummy0")
    run("ip link set dummy0 up")

    # Enable forwarding
    enable_ip_forwarding()

    # Find a real outbound interface
    real_iface = next((iface.name for iface in psutil.net_if_addrs() if iface != "lo" and "dummy" not in iface), "eth0")
    print(f"🌐 Using {real_iface} as outbound interface")

    setup_iptables(real_iface, "dummy0")
    start_tun2socks("dummy0")

    print("\n✅ Simulation running.")
    print("💡 Test with: curl --interface dummy0 http://ipinfo.io")
    print("\n🧹 To clean up:")
    print("    sudo ip link del dummy0")
    print("    sudo iptables -F; sudo iptables -t nat -F")
    print("    sudo pkill tun2socks")

def run_real_pi_setup():
    if not is_raspberry_pi():
        print("❌ Not a Raspberry Pi. Use --simulate for WSL/Linux.")
        return

    print("📶 Setting up real Pi hotspot with SOCKS5 proxy routing...")
    create_ap_config()
    configure_dhcp_dns()
    enable_ip_forwarding()
    setup_iptables(WIFI_INTERFACE_IN, WIFI_INTERFACE_OUT)
    start_services()
    start_tun2socks(WIFI_INTERFACE_OUT)
    print("✅ Hotspot is up. Clients will be proxy routed via SOCKS5.")

def main():
    parser = argparse.ArgumentParser(description="SOCKS5 Proxy Hotspot Setup")
    parser.add_argument("--simulate", action="store_true", help="Simulate using dummy interfaces in WSL/Linux")
    args = parser.parse_args()

    if args.simulate:
        simulate_in_wsl()
    else:
        run_real_pi_setup()

if __name__ == "__main__":
    main()
