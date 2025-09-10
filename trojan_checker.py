import subprocess
import requests
import re
import base64
from datetime import datetime
import os
import socket

# Fungsi untuk memeriksa status server dengan koneksi TCP
def check_server_status(ip_or_host, port):
    print(f"Checking {ip_or_host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Timeout 3 detik
        result = sock.connect_ex((ip_or_host, port))
        sock.close()
        if result == 0:
            print(f"Success: {ip_or_host}:{port} is reachable")
            return True, None
        else:
            print(f"Failed: {ip_or_host}:{port} returned error code {result}")
            return False, None
    except Exception as e:
        print(f"Error checking {ip_or_host}:{port}: {str(e)}")
        return False, None

# Fungsi untuk memparsing URL Trojan dari teks
def parse_trojan_urls(data):
    pattern = r'trojan://[a-zA-Z0-9\-]+@[a-zA-Z0-9\.\-]+:[0-9]+(?:\?[^#\s]*)?(?:#[^\s]*)?'
    urls = re.findall(pattern, data)
    print(f"Found {len(urls)} Trojan URLs: {urls}")
    return urls

# Fungsi untuk mengambil IP/hostname dan port dari URL Trojan
def extract_host_and_port_from_url(url):
    try:
        host_port = url.split('@')[1].split('#')[0]
        host = host_port.split(':')[0]
        port = int(host_port.split(':')[1].split('?')[0])
        print(f"Extracted host: {host}, port: {port} from {url}")
        return host, port
    except (IndexError, ValueError) as e:
        print(f"Invalid URL format: {url} - Error: {str(e)}")
        return None, None

# Fungsi untuk mendekode sub URL (base64 atau teks biasa)
def fetch_from_sub_url(sub_url):
    print(f"Fetching sub URL: {sub_url}")
    try:
        response = requests.get(sub_url, timeout=10)
        response.raise_for_status()
        content = response.text.strip()
        print(f"Sub URL content (first 100 chars): {content[:100]}")
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            print(f"Decoded base64 (first 100 chars): {decoded_content[:100]}")
            return parse_trojan_urls(decoded_content)
        except Exception:
            print("Not base64, processing as plain text")
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
        print(f"Reading {file_path} with {len(lines)} lines")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            print(f"Processing line: {line}")
            if line.startswith('trojan://'):
                trojan_urls.append
