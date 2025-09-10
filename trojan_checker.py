import subprocess
import requests
import re
import json
import base64
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

# Fungsi untuk memparsing URL Trojan dari teks
def parse_trojan_urls(data):
    pattern = r'trojan://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:[0-9]+(?:\?[^#\s]*)?(?:#[^\s]*)?'
    return re.findall(pattern, data)

# Fungsi untuk mengambil IP/hostname dari URL Trojan
def extract_host_from_url(url):
    try:
        return url.split('@')[1].split(':')[0]
    except IndexError:
        return None

# Fungsi untuk mendekode sub URL (base64 atau teks biasa)
def fetch_from_sub_url(sub_url):
    try:
        response = requests.get(sub_url, timeout=10)
        response.raise_for_status()
        content = response.text.strip()
        # Coba dekode base64 jika kontennya adalah base64
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            return parse_trojan_urls(decoded_content)
        except Exception:
            # Jika bukan base64, anggap sebagai teks biasa
            return parse_trojan_urls(content)
    except requests.RequestException as e:
        print(f"Error fetching sub URL {sub_url}: {str(e)}")
        return []

# Fungsi untuk membaca servers.txt dan memproses URL Trojan serta sub URL
def fetch_server_list(file_path):
    trojan_urls = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Cek apakah ini URL Trojan atau sub URL
            if line.startswith('trojan://'):
                trojan_urls.append(line)
            elif line.startswith('http://') or line.startswith('https://'):
                # Anggap sebagai sub URL dan ambil daftar Trojan URLs
                trojan_urls.extend(fetch_from_sub_url(line))
            else:
                print(f"Invalid line in servers.txt: {line}")
        return trojan_urls
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return []

# Fungsi utama
def main():
    server_file = "servers.txt"
    output_file = f"active_trojan_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # Ambil daftar URL Trojan
    trojan_urls = fetch_server_list(server_file)
    
    if not trojan_urls:
        print("No Trojan URLs found in servers.txt or sub URLs.")
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
