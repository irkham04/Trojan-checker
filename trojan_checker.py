import requests
import re
import base64
from datetime import datetime
import os
import ssl
import socket
import subprocess

# Bug operator (ganti dengan bug operator yang kamu gunakan)
BUG_OPERATOR = "cdn.provider.com"  # Contoh, ubah sesuai kebutuhan

# Fungsi untuk memeriksa status server dengan TLS handshake
def check_server_status(ip_or_host, port):
    print(f"Memeriksa TLS handshake untuk {ip_or_host}:{port}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip_or_host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip_or_host) as ssock:
                ssock.settimeout(5)
                print(f"Sukses: TLS handshake berhasil untuk {ip_or_host}:{port}")
                # Jika TLS berhasil, coba ping bug operator untuk latensi
                try:
                    ping_result = subprocess.run(
                        ['ping', '-c', '1', BUG_OPERATOR],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        text=True
                    )
                    if ping_result.returncode == 0:
                        latency_match = re.search(r'time=(\d+\.\d+) ms', ping_result.stdout)
                        latency = latency_match.group(1) if latency_match else "Unknown"
                        print(f"Ping sukses ke {BUG_OPERATOR} (Latensi: {latency} ms)")
                        return True, latency
                    else:
                        print(f"Ping gagal ke {BUG_OPERATOR}, tetapi TLS aktif")
                        return True, None
                except Exception as e:
                    print(f"Error ping ke {BUG_OPERATOR}: {str(e)}")
                    return True, None
    except Exception as e:
        print(f"Error TLS handshake untuk {ip_or_host}:{port}: {str(e)}")
        return False, None

# Fungsi untuk memparsing URL Trojan dari teks
def parse_trojan_urls(data):
    pattern = r'trojan://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:[0-9]+(?:\?[^#\s]*)?(?:#[^\s]*)?'
    urls = re.findall(pattern, data)
    print(f"Ditemukan {len(urls)} URL Trojan: {urls[:5]}...")
    return urls

# Fungsi untuk mengambil IP/hostname dan port dari URL Trojan
def extract_host_and_port_from_url(url):
    try:
        host_port = url.split('@')[1].split('#')[0]
        host = host_port.split(':')[0]
        port = int(host_port.split(':')[1].split('?')[0])
        print(f"Host: {host}, Port: {port} diekstrak dari {url}")
        return host, port
    except (IndexError, ValueError) as e:
        print(f"Format URL tidak valid: {url} - Error: {str(e)}")
        return None, None

# Fungsi untuk mendekode sub URL (base64 atau teks biasa)
def fetch_from_sub_url(sub_url):
    print(f"Mengambil sub URL: {sub_url}")
    try:
        response = requests.get(sub_url, timeout=15)
        response.raise_for_status()
        content = response.text.strip()
        print(f"Isi sub URL (100 karakter pertama): {content[:100]}")
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            print(f"Dekode base64 (100 karakter pertama): {decoded_content[:100]}")
            return parse_trojan_urls(decoded_content)
        except Exception:
            print("Bukan base64, memproses sebagai teks biasa")
            return parse_trojan_urls(content)
    except requests.RequestException as e:
        print(f"Error saat mengambil sub URL {sub_url}: {str(e)}")
        return []

# Fungsi untuk membaca servers.txt dan memproses URL Trojan serta sub URL
def fetch_server_list(file_path):
    trojan_urls = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        print(f"Membaca {file_path} dengan {len(lines)} baris")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            print(f"Memproses baris: {line}")
            if line.startswith('trojan://'):
                trojan_urls.append(line)
            elif line.startswith('http://') or line.startswith('https://'):
                trojan_urls.extend(fetch_from_sub_url(line))
            else:
                print(f"Baris tidak valid di servers.txt: {line}")
        print(f"Total URL Trojan terkumpul: {len(trojan_urls)}")
        return trojan_urls
    except Exception as e:
        print(f"Error saat membaca file {file_path}: {str(e)}")
        return []

# Fungsi utama
def main():
    server_file = "servers.txt"
    output_file = f"active_trojan_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    trojan_urls = fetch_server_list(server_file)
    
    active_urls = []
    print("Memeriksa server...")
    for url in trojan_urls:
        host, port = extract_host_and_port_from_url(url)
        if not host or not port:
            print(f"Melewati URL tidak valid: {url}")
            continue
        is_active, latency = check_server_status(host, port)
        if is_active:
            active_urls.append(url)
            print(f"Aktif: {url} (Latensi ke {BUG_OPERATOR}: {latency if latency else 'TLS only'} ms)")
        else:
            print(f"Tidak aktif: {url}")

    with open(output_file, 'w') as f:
        if active_urls:
            f.write("\n".join(active_urls))
            print(f"\nURL Trojan aktif disimpan ke {output_file}")
        else:
            f.write("Tidak ada URL Trojan aktif yang ditemukan.")
            print(f"\nTidak ada URL Trojan aktif, disimpan ke {output_file}")

if __name__ == "__main__":
    main()
