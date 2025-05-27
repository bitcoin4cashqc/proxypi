#!/usr/bin/env python3
"""
Debug script for tun2socks issues
"""

import json
import os
import subprocess
import tempfile
import time

def test_tun2socks():
    """Test tun2socks binary and configuration"""
    
    tun2socks_path = "/usr/local/bin/tun2socks"
    
    print("=== tun2socks Debug Script ===")
    print()
    
    # Check if binary exists
    if not os.path.exists(tun2socks_path):
        print(f"❌ tun2socks binary not found at {tun2socks_path}")
        return
    
    print(f"✅ tun2socks binary found at {tun2socks_path}")
    
    # Check if executable
    if not os.access(tun2socks_path, os.X_OK):
        print(f"❌ tun2socks binary is not executable")
        return
    
    print("✅ tun2socks binary is executable")
    
    # Test version
    try:
        result = subprocess.run([tun2socks_path, '-version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ tun2socks version: {result.stdout.strip()}")
        else:
            print(f"❌ tun2socks version check failed: {result.stderr}")
            return
    except Exception as e:
        print(f"❌ tun2socks version check error: {e}")
        return
    
    # Test with sample config
    print("\n=== Testing with sample configuration ===")
    
    config = {
        'interface': 'tun0',
        'proxy': 'socks5://1RzgE:RyMxP@217.182.193.32:10040',
        'loglevel': 'debug'
    }
    
    # Create temp config file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_file = f.name
    
    print(f"Config file: {config_file}")
    print(f"Config content:\n{json.dumps(config, indent=2)}")
    
    # Create TUN interface
    print("\n=== Creating TUN interface ===")
    try:
        subprocess.run(['ip', 'tuntap', 'add', 'dev', 'tun0', 'mode', 'tun'], check=True)
        subprocess.run(['ip', 'addr', 'add', '198.18.0.1/15', 'dev', 'tun0'], check=True)
        subprocess.run(['ip', 'link', 'set', 'tun0', 'up'], check=True)
        print("✅ TUN interface created successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create TUN interface: {e}")
        cleanup_tun()
        os.unlink(config_file)
        return
    
    # Test tun2socks
    print("\n=== Testing tun2socks ===")
    log_file = '/tmp/tun2socks_debug.log'
    
    try:
        with open(log_file, 'w') as f:
            process = subprocess.Popen([tun2socks_path, '-config', config_file], 
                                     stdout=f, stderr=subprocess.STDOUT)
        
        print(f"Started tun2socks process (PID: {process.pid})")
        print("Waiting 5 seconds...")
        time.sleep(5)
        
        if process.poll() is not None:
            print(f"❌ tun2socks process died (exit code: {process.returncode})")
        else:
            print("✅ tun2socks process is still running")
            process.terminate()
            process.wait()
        
        # Read log file
        print(f"\n=== tun2socks log ({log_file}) ===")
        try:
            with open(log_file, 'r') as f:
                log_content = f.read()
            if log_content.strip():
                print(log_content)
            else:
                print("(Log file is empty)")
        except FileNotFoundError:
            print("(Log file not found)")
    
    except Exception as e:
        print(f"❌ Error testing tun2socks: {e}")
    
    finally:
        # Cleanup
        print("\n=== Cleanup ===")
        cleanup_tun()
        try:
            os.unlink(config_file)
            print("✅ Cleaned up temp files")
        except:
            pass

def cleanup_tun():
    """Clean up TUN interface"""
    try:
        subprocess.run(['ip', 'link', 'set', 'tun0', 'down'], check=False)
        subprocess.run(['ip', 'tuntap', 'del', 'dev', 'tun0', 'mode', 'tun'], check=False)
        print("✅ TUN interface cleaned up")
    except:
        print("⚠️  TUN interface cleanup may have failed")

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo)")
        exit(1)
    
    test_tun2socks() 