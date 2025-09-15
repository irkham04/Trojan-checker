#!/usr/bin/env python3
# vpn_checker.py
import requests
import re
import base64
import ssl
import socket
import subprocess
import platform
import sys
import json
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Coba import speedtest, kalau tidak ada install dulu
try:
    import speedtest
except ImportError:
    print("Module 'speedtest-cli' tidak ditemukan. Sedang menginstall...")
    import subprocess as sp
    sp.check_call([sys.executable, "-m", "pip", "install", "speedtest-cli"])
    import speedtest
    print("Instalasi speedtest-cli berhasil.\n")

BUG_OPERATOR = "quiz.vidio.com"
SERVER_FILE = "servers.txt"

# ---------------------
# Helper parse functions
# ---------------------
def find_trojan_in_text(text):
    return re.findall(r'trojan://[^\s]+', text)

def find_vless_in_text(text):
    return re.findall(r'vless://[^\s]+', text)

def find_vmess_in_text(text):
    # vmess links often like vmess://<base64>
    return re.findall(r'vmess://[A-Za-z0-9+/=]+', text)

def decode_base64_str(s):
    # add padding if necessary
    s = s.strip()
    padding = len(s) % 4
    if padding:
        s += "=" * (4 - padding)
    try:
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return None

def encode_base64_str(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

# Replace host in trojan/vless preserving params
def replace_host_in_generic_url(url, new_host):
    # url like trojan://password@host:port?params#...
    parsed = urlparse(url)
    scheme = parsed.scheme
    username = parsed.username  # may be None
    password = None
    # For trojan and vless the "username" is the password field; urlparse places it in username
    # We reconstruct authority manually
    # parsed.netloc may be like 'password@host:port'
    # get port
    port = parsed.port
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        # username is actually the credential; urlparse can't show % encoded easily; keep as-is
    # reconstruct
    netloc = f"{userinfo}@{new_host}"
    if port:
        netloc += f":{port}"
    new_url = f"{scheme}://{netloc}{query}{fragment}"
    return new_url, new_host, port

# For vmess: decode JSON, change 'add', keep 'port', re-encode
def replace_host_in_vmess_link(vmess_url, new_host):
    # vmess://<base64json>
    b64 = vmess_url.replace("vmess://", "", 1)
    decoded = decode_base64_str(b64)
    if not decoded:
        return None
    try:
        j = json.loads(decoded)
    except Exception:
        return None
    # vmess json often has fields: v, ps, add, port, id, aid, net, type, host, path, tls
    if 'add' in j:
        j['add'] = new_host
    else:
        # fallback: check if "host" field exists
        if 'host' in j:
            j['host'] = new_host
    new_json = json.dumps(j, separators=(',', ':'))
    new_b64 = encode_base64_str(new_json)
    return "vmess://" + new_b64

# ---------------------
# Network checks
# ---------------------
def check_server_status(host, port, timeout_conn=6):
    """Return (is_tls_ok: bool, ping_latency_ms: str or None)"""
    if not host or not port:
        return False, None
    try:
        # TLS handshake
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=timeout_conn) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.settimeout(5)
                # If we reach here, TLS handshake OK
                # Ping to BUG_OPERATOR
                try:
                    system = platform.system().lower()
                    if "windows" in system:
                        ping_cmd = ['ping', '-n', '1', BUG_OPERATOR]
                    else:
                        ping_cmd = ['ping', '-c', '1', BUG_OPERATOR']

                    ping_result = subprocess.run(
                        ping_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=6,
                        text=True
                    )
                    if ping_result.returncode == 0:
                        latency_match = re.search(r'time[=<](\d+\.?\d*) ?ms', ping_result.stdout)
                        latency = latency_match.group(1) if latency_match else "Unknown"
                        return True, latency
                    else:
                        return True, None
                except Exception:
                    return True, None
    except Exception:
        return False, None

def silent_speedtest_check():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        return True
    except Exception:
        return False

# ---------------------
# Fetch subs / reading file
# ---------------------
def fetch_from_sub_url(sub_url):
    try:
        resp = requests.get(sub_url, timeout=15)
        resp.raise_for_status()
        content = resp.text.strip()
        # The content may be base64 of the whole list, or plain lines
        decoded = decode_base64_str(content)
        if decoded:
            text_to_parse = decoded
        else:
            text_to_parse = content

        trojans = find_trojan_in_text(text_to_parse)
        vlesses = find_vless_in_text(text_to_parse)
        vmesses = find_vmess_in_text(text_to_parse)
        # Also allow plain lines starting with vmess:// (not base64)
        vmesses += re.findall(r'vmess://[^\s]+', text_to_parse)
        return trojans, vlesses, vmesses
    except Exception:
        return [], [], []

def fetch_server_list(file_path):
    trojan_urls = []
    vless_urls = []
    vmess_urls = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception:
        return trojan_urls, vless_urls, vmess_urls

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('http://') or line.startswith('https://'):
            t, v, m = fetch_from_sub_url(line)
            trojan_urls.extend(t)
            vless_urls.extend(v)
            vmess_urls.extend(m)
        else:
            # try direct matches
            trojan_urls.extend(find_trojan_in_text(line))
            vless_urls.extend(find_vless_in_text(line))
            vmess_urls.extend(find_vmess_in_text(line))
            # also allow vmess raw with base64 that may have = padding or url-safe variants
            vmess_urls.extend(re.findall(r'vmess://[A-Za-z0-9_\-+/=]+', line))
    # dedupe while preserving order
    def dedupe(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return dedupe(trojan_urls), dedupe(vless_urls), dedupe(vmess_urls)

# ---------------------
# Main runner
# ---------------------
def main():
    trojan_urls, vless_urls, vmess_urls = fetch_server_list(SERVER_FILE)
    total = len(trojan_urls) + len(vless_urls) + len(vmess_urls)
    print(f"Total accounts found: trojan={len(trojan_urls)}, vless={len(vless_urls)}, vmess={len(vmess_urls)} (total {total})\n")

    active_trojan = []
    active_vless = []
    active_vmess = []

    def process_generic_list(urls, kind):
        active_list = []
        for url in urls:
            try:
                new_url, host, port = replace_host_in_generic_url(url, BUG_OPERATOR)
                if not host or not port:
                    print(f"[{kind}] Skip (no host/port parsed): {url}")
                    continue
            except Exception as e:
                print(f"[{kind}] Replace host failed for {url}: {e}")
                continue

            is_ok, latency = check_server_status(host, port)
            if is_ok:
                if silent_speedtest_check():
                    active_list.append(new_url)
                    print(f"[{kind}] ACTIVE: {new_url} (latency: {latency if latency else 'TLS only'})")
                else:
                    print(f"[{kind}] TLS/ping ok but speedtest failed: {new_url}")
            else:
                print(f"[{kind}] NOT active: {new_url}")
        return active_list

    # Process trojan & vless (they share similar URL structure)
    active_trojan = process_generic_list(trojan_urls, "TROJAN")
    active_vless = process_generic_list(vless_urls, "VLESS")

    # Process vmess: decode JSON, replace 'add', encode
    for vm in vmess_urls:
        new_vm = replace_host_in_vmess_link(vm, BUG_OPERATOR)
        if not new_vm:
            print(f"[VMESS] Failed to decode/replace: {vm}")
            continue
        # parse host/port from JSON
        decoded_json = decode_base64_str(new_vm.replace("vmess://", "", 1))
        try:
            j = json.loads(decoded_json)
            host = j.get('add') or j.get('host')
            port = j.get('port')
        except Exception:
            print(f"[VMESS] Failed JSON parse after replace: {new_vm}")
            continue

        is_ok, latency = check_server_status(host, port)
        if is_ok:
            if silent_speedtest_check():
                active_vmess.append(new_vm)
                print(f"[VMESS] ACTIVE: {new_vm} (latency: {latency if latency else 'TLS only'})")
            else:
                print(f"[VMESS] TLS/ping ok but speedtest failed: {new_vm}")
        else:
            print(f"[VMESS] NOT active: {new_vm}")

    # Save results
    with open("active_trojan_urls.txt", "w", encoding='utf-8') as f:
        if active_trojan:
            f.write("\n".join(active_trojan))
        else:
            f.write("")

    with open("active_vless_urls.txt", "w", encoding='utf-8') as f:
        if active_vless:
            f.write("\n".join(active_vless))
        else:
            f.write("")

    with open("active_vmess_urls.txt", "w", encoding='utf-8') as f:
        if active_vmess:
            f.write("\n".join(active_vmess))
        else:
            f.write("")

    # Combined
    all_active = active_trojan + active_vless + active_vmess
    with open("active_all_urls.txt", "w", encoding='utf-8') as f:
        if all_active:
            f.write("\n".join(all_active))
        else:
            f.write("")

    # Summary
    print("\n=== SUMMARY ===")
    print(f"Trojan active: {len(active_trojan)} / {len(trojan_urls)}")
    print(f"VLESS active: {len(active_vless)} / {len(vless_urls)}")
    print(f"VMESS active: {len(active_vmess)} / {len(vmess_urls)}")
    total_found = len(trojan_urls) + len(vless_urls) + len(vmess_urls)
    total_active = len(all_active)
    print(f"Total active: {total_active} / {total_found}")
    if total_found:
        print(f"Active percent: {total_active/total_found*100:.2f}%")

if __name__ == "__main__":
    main()
