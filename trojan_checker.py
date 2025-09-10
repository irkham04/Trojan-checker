import subprocess
import requests
import re
import json
from datetime import datetime
import os

# Fungsi untuk memeriksa status server dengan ping dan mendapatkan latensi
def check_server_status(ip_or_host):
    try:
        result = subprocess.run(
            ['ping', '-c', '1', ip_or_host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            text=True
        )
        if result.returncode == 0:
            latency_match = re.search(r'time=(\d+\.\d+) ms', result.stdout)
            latency = latency_match.group(1) if latency_match else "Unknown"
            return True, latency
        return False, None
    except subprocess.TimeoutExpired:
        return False, None
    except Exception as e:
        print(f"Error checking {ip_or_host}: {str(e)}")
        return False, None

# Fungsi untuk memparsing URL Trojan dari file atau teks
def parse_trojan_urls(data):
    pattern = r'trojan://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:[0-9]+(?:\?[^#\s]*)?(?:#[^\s]*)?'
    return re.findall(pattern, data)

# Fungsi untuk mengambil IP/hostname dari URL Trojan
def extract_host_from_url(url):
    try:
        return url.split('@')[1].split(':')[0]
    except IndexError:
        return None

# Fungsi untuk mengambil daftar server dari file di repositori
def fetch_server_list(file_path):
    try:
        with open(file_path, 'r') as f:
            return parse_trojan_urls(f.read())
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return []

# Fungsi utama
def main():
    # Path ke file daftar server di repositori
    server_file = "servers.txt"
    output_file = f"active_trojan_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # Ambil daftar URL Trojan
    trojan_urls = fetch_server_list(server_file)
    
    if not trojan_urls:
        print("No Trojan URLs found in servers.txt.")
        return

    # Simpan URL yang aktif
    active_urls = []
    print("Checking servers...")
    for url in trojan_urls:
        host = extract_host_from_url(url)
        if not host:
            print(f"Invalid URL format: {url}")
            continue
        is_active, latency = check_server_status(host)
        if is_active:
            active_urls.append(url)
            print(f"Active: {url} (Ping: {latency} ms)")
        else:
            print(f"Inactive: {url}")

    # Simpan URL aktif ke file
    if active_urls:
        with open(output_file, 'w') as f:
            f.write("\n".join(active_urls))
        print(f"\nActive Trojan URLs saved to {output_file}")
    else:
        print("\nNo active Trojan URLs found.")

if __name__ == "__main__":
    main()
