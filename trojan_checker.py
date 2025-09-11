import requests
import re
import base64
import ssl
import socket
import subprocess
import platform
from urllib.parse import urlparse
import sys
import subprocess as sp

# Coba import speedtest, kalau tidak ada install dulu
try:
    import speedtest
except ImportError:
    print("Module 'speedtest-cli' tidak ditemukan. Sedang menginstall...")
    sp.check_call([sys.executable, "-m", "pip", "install", "speedtest-cli"])
    import speedtest
    print("Instalasi speedtest-cli berhasil.\n")

# Host bug operator
BUG_OPERATOR = "quiz.vidio.com"

# Fungsi untuk memeriksa status server dengan TLS handshake
def check_server_status(ip_or_host, port):
    print(f"Memeriksa TLS handshake untuk {ip_or_host}:{port}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip_or_host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip_or_host) as ssock:
                ssock.settimeout(5)
                print(f"Sukses: TLS handshake berhasil untuk {ip_or_host}:{port}")

                # Ping ke bug operator (sesuai OS)
                try:
                    system = platform.system().lower()
                    if "windows" in system:
                        ping_cmd = ['ping', '-n', '1', BUG_OPERATOR]
                    else:
                        ping_cmd = ['ping', '-c', '1', BUG_OPERATOR]

                    ping_result = subprocess.run(
                        ping_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                        text=True
                    )
                    if ping_result.returncode == 0:
                        latency_match = re.search(r'time[=<](\d+\.?\d*) ?ms', ping_result.stdout)
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

# Fungsi parsing URL Trojan
def parse_trojan_urls(data):
    pattern = r'trojan://[^\s]+'
    return re.findall(pattern, data)

# Fungsi ambil host:port dari URL
def extract_host_and_port_from_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
        return host, port
    except:
        return None, None

# Fungsi decode sub URL
def fetch_from_sub_url(sub_url):
    try:
        response = requests.get(sub_url, timeout=15)
        response.raise_for_status()
        content = response.text.strip()
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            return parse_trojan_urls(decoded_content)
        except Exception:
            return parse_trojan_urls(content)
    except:
        return []

# Fungsi baca servers.txt
def fetch_server_list(file_path):
    trojan_urls = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('trojan://'):
                trojan_urls.append(line)
            elif line.startswith('http://') or line.startswith('https://'):
                trojan_urls.extend(fetch_from_sub_url(line))
        return trojan_urls
    except:
        return []

# Silent Speedtest check, return True/False
def silent_speedtest_check():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        return True
    except:
        return False

# Fungsi utama
def main():
    server_file = "servers.txt"
    output_file = "active_trojan_urls.txt"
    
    trojan_urls = fetch_server_list(server_file)
    active_urls = []
    
    print(f"Total akun Trojan ditemukan: {len(trojan_urls)}")
    print("Memeriksa server...\n")
    
    for url in trojan_urls:
        # Paksa ganti host dengan BUG_OPERATOR
        try:
            user_pass, rest = url.split("@", 1)
            if ":" in rest:
                port_part = rest.split(":", 1)[1]
                url = f"{user_pass}@{BUG_OPERATOR}:{port_part}"
        except Exception as e:
            print(f"Gagal ganti host di URL {url}: {e}")
            continue

        host, port = extract_host_and_port_from_url(url)
        if not host or not port:
            continue

        is_active, latency = check_server_status(host, port)
        if is_active:
            # Silent Speedtest check
            speedtest_ok = silent_speedtest_check()
            if speedtest_ok:
                active_urls.append(url)
                print(f"Aktif: {url} (Latensi: {latency if latency else 'TLS only'} ms)\n")
            else:
                print(f"Akun lolos TLS/ping tapi gagal tes Speedtest, tidak dimasukkan: {url}\n")
        else:
            print(f"Tidak aktif: {url}\n")

    # Simpan hasil
    with open(output_file, 'w') as f:
        if active_urls:
            f.write("\n".join(active_urls))
        else:
            f.write("Tidak ada URL Trojan aktif yang ditemukan.")

    # Ringkasan hasil
    print("\n=== RINGKASAN ===")
    print(f"Akun aktif: {len(active_urls)} dari {len(trojan_urls)} total akun")
    if len(trojan_urls) > 0:
        persen = (len(active_urls) / len(trojan_urls)) * 100
        print(f"Persentase aktif: {persen:.2f}%")
    print(f"Hasil disimpan ke {output_file}")

if __name__ == "__main__":
    main()
