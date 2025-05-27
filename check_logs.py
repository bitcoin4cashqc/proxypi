#!/usr/bin/env python3
"""
Simple script to check tun2socks logs and provide diagnostics
"""

import os
import subprocess

def check_logs():
    """Check various log files and system status"""
    
    print("=== ProxyPi Log Checker ===")
    print()
    
    # Check tun2socks log
    log_file = '/tmp/tun2socks.log'
    print(f"=== tun2socks log ({log_file}) ===")
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                content = f.read()
            if content.strip():
                print(content)
            else:
                print("(Log file is empty)")
        except Exception as e:
            print(f"Error reading log file: {e}")
    else:
        print("(Log file not found)")
    
    print("\n" + "="*50)
    
    # Check if tun2socks binary exists
    tun2socks_path = "/usr/local/bin/tun2socks"
    print(f"\n=== tun2socks binary check ===")
    if os.path.exists(tun2socks_path):
        print(f"✅ Binary exists: {tun2socks_path}")
        
        # Check permissions
        if os.access(tun2socks_path, os.X_OK):
            print("✅ Binary is executable")
        else:
            print("❌ Binary is not executable")
        
        # Check file info
        try:
            result = subprocess.run(['file', tun2socks_path], capture_output=True, text=True)
            print(f"File info: {result.stdout.strip()}")
        except:
            pass
        
        # Try version check
        try:
            result = subprocess.run([tun2socks_path, '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"Version: {result.stdout.strip()}")
            else:
                print(f"Version check failed: {result.stderr}")
        except Exception as e:
            print(f"Version check error: {e}")
    else:
        print(f"❌ Binary not found: {tun2socks_path}")
    
    # Check system architecture
    print(f"\n=== System info ===")
    try:
        result = subprocess.run(['uname', '-m'], capture_output=True, text=True)
        print(f"Architecture: {result.stdout.strip()}")
    except:
        pass
    
    # Check if TUN interface exists
    print(f"\n=== Network interfaces ===")
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if 'tun0' in result.stdout:
            print("✅ tun0 interface exists")
        else:
            print("❌ tun0 interface not found")
    except:
        print("Could not check network interfaces")
    
    # Check running processes
    print(f"\n=== Running processes ===")
    try:
        result = subprocess.run(['pgrep', '-f', 'tun2socks'], capture_output=True, text=True)
        if result.stdout.strip():
            print(f"✅ tun2socks processes: {result.stdout.strip()}")
        else:
            print("❌ No tun2socks processes running")
    except:
        print("Could not check processes")
    
    # Check proxy connectivity
    print(f"\n=== Proxy connectivity test ===")
    try:
        result = subprocess.run([
            'curl', '--proxy', 'socks5://1RzgE:RyMxP@217.182.193.32:10040',
            '--connect-timeout', '10', '--silent', '--output', '/dev/null',
            '--write-out', '%{http_code}', 'https://www.google.com'
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout.strip() == '200':
            print("✅ Proxy connection successful")
        else:
            print(f"❌ Proxy connection failed. Return code: {result.returncode}, HTTP code: {result.stdout.strip()}")
            if result.stderr:
                print(f"Error: {result.stderr}")
    except Exception as e:
        print(f"❌ Proxy test error: {e}")

if __name__ == '__main__':
    check_logs() 