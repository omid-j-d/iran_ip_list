#!/usr/bin/env python3
import requests
import ipaddress
import json
import csv
from io import StringIO
from bs4 import BeautifulSoup
import sys
import os
from datetime import datetime

# ==================== تنظیمات ====================
HEADERS = {'User-Agent': 'IranIPCollector/2.0 (+https://github.com/yourname/iran-ip-collector)'}
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==================== منابع ====================
SOURCES = {
    "ripe": {
        "url": "https://stat.ripe.net/data/country-resource-list/data.json?resource=IR",
        "parser": "ripe"
    },
    "apnic": {
        "url": "https://raw.githubusercontent.com/APNIC-Labs/allocated-blocks/master/allocated-blocks.txt",
        "parser": "apnic"
    },
    "ipdeny": {
        "url": "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
        "parser": "ipdeny"
    },
    "nirsoft": {
        "url": "https://www.nirsoft.net/countryip/ir.html",
        "parser": "nirsoft"
    },
    "ip2location": {
        "url": "https://lite.ip2location.com/iran-ip-address-ranges",
        "parser": "ip2location"
    },
    "maxmind": {
        "url": "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=000000000000&suffix=zip",
        "parser": "maxmind",
        "requires_download": True
    },
    "dbip": {
        "url": "https://download.db-ip.com/free/dbip-country-lite-latest.csv.gz",
        "parser": "dbip",
        "requires_download": True
    }
}

# ==================== پارس‌کننده‌ها ====================
def parse_ripe(data):
    nets = []
    try:
        for ip in data['data']['resources'].get('ipv4', []):
            nets.append(ipaddress.ip_network(ip.strip(), strict=False))
        for ip in data['data']['resources'].get('ipv6', []):
            nets.append(ipaddress.ip_network(ip.strip(), strict=False))
    except:
        pass
    return [(net, "RIPE") for net in nets]

def parse_apnic(text):
    nets = []
    for line in text.splitlines():
        if line.startswith("apnic|IR|ipv"):
            parts = line.split('|')
            if len(parts) >= 5 and parts[2] in ['ipv4', 'ipv6']:
                nets.append(ipaddress.ip_network(f"{parts[3]}/{parts[4]}", strict=False))
    return [(net, "APNIC") for net in nets]

def parse_ipdeny(text):
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.version == 4:
                    nets.append(net)
            except:
                pass
    return [(net, "IPDeny") for net in nets]

def parse_nirsoft(html):
    nets = []
    soup = BeautifulSoup(html, 'html.parser')
    for line in soup.get_text().splitlines():
        if ' - ' in line and line.count('.') == 7:
            try:
                start, end = line.split(' - ')
                start_ip = ipaddress.IPv4Address(start.strip())
                end_ip = ipaddress.IPv4Address(end.strip())
                summarized = list(ipaddress.summarize_address_range(start_ip, end_ip))
                nets.extend(summarized)
            except:
                pass
    return [(net, "Nirsoft") for net in nets]

def parse_ip2location(html):
    nets = []
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')
    if table:
        for row in table.find_all('tr')[1:]:
            cols = row.find_all('td')
            if len(cols) >= 3:
                cidr = cols[2].get_text(strip=True)
                if '/' in cidr:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        nets.append(net)
                    except:
                        pass
    return [(net, "IP2Location") for net in nets]

def parse_maxmind():
    # نیاز به دانلود دستی (به دلیل license key)
    print("MaxMind: لطفاً فایل GeoLite2-Country-CSV را دانلود و در output/ قرار دهید.")
    return []

def parse_dbip():
    # نیاز به دانلود دستی
    print("DB-IP: لطفاً فایل dbip-country-lite-latest.csv.gz را دانلود و در output/ قرار دهید.")
    return []

# ==================== دانلود و پارس ====================
all_ranges = []

for name, config in SOURCES.items():
    url = config['url']
    parser = config['parser']
    print(f"[{name.upper()}] در حال پردازش...")

    try:
        if config.get("requires_download"):
            # فعلاً غیرفعال — نیاز به دانلود دستی
            continue

        resp = requests.get(url, headers=HEADERS, timeout=20)
        resp.raise_for_status()

        if parser == "ripe":
            data = resp.json()
            ranges = parse_ripe(data)
        elif parser == "apnic":
            ranges = parse_apnic(resp.text)
        elif parser == "ipdeny":
            ranges = parse_ipdeny(resp.text)
        elif parser == "nirsoft":
            ranges = parse_nirsoft(resp.text)
        elif parser == "ip2location":
            ranges = parse_ip2location(resp.text)
        else:
            continue

        all_ranges.extend(ranges)
        print(f"  → {len(ranges)} رنج")

    except Exception as e:
        print(f"  خطا: {e}")

if not all_ranges:
    print("هیچ رنجی جمع‌آوری نشد!")
    sys.exit(1)

# ==================== ادغام و تمیز کردن ====================
print(f"\nقبل از ادغام: {len(all_ranges)} رنج")
unique_nets = {}
for net, source in all_ranges:
    key = (net.network_address, net.broadcast_address if net.version == 4 else net.network_address)
    if key not in unique_nets:
        unique_nets[key] = (net, source)

merged_list = [(net, source) for net, source in unique_nets.values()]
merged_list.sort(key=lambda x: x[0].network_address)

# ادغام هم‌پوشانی
ipv4_nets = [n for n, s in merged_list if n.version == 4]
ipv6_nets = [n for n, s in merged_list if n.version == 6]

merged_ipv4 = ipaddress.collapse_addresses(ipv4_nets)
merged_ipv6 = ipaddress.collapse_addresses(ipv6_nets)

print(f"بعد از ادغام: {len(merged_ipv4)} IPv4 + {len(merged_ipv6)} IPv6")

# ==================== خروجی‌ها ====================
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

# 1. iran_ips.txt
with open(f"{OUTPUT_DIR}/iran_ips.txt", "w", encoding="utf-8") as f:
    f.write(f"# IP Ranges for Iran - Generated on {timestamp}\n")
    f.write(f"# Total IPv4 ranges: {len(merged_ipv4)}\n\n")
    for net in merged_ipv4:
        f.write(f"{net.network_address} - {net.broadcast_address}\n")

# 2. iran_cidr.txt
with open(f"{OUTPUT_DIR}/iran_cidr.txt", "w", encoding="utf-8") as f:
    f.write(f"# CIDR for Iran - {timestamp}\n\n")
    for net in merged_ipv4:
        f.write(f"{net}\n")

# 3. iran_ipv6.txt
with open(f"{OUTPUT_DIR}/iran_ipv6.txt", "w", encoding="utf-8") as f:
    f.write(f"# IPv6 Ranges for Iran - {timestamp}\n\n")
    for net in merged_ipv6:
        f.write(f"{net}\n")

# 4. iran_full.json
full_data = {
    "generated_at": timestamp,
    "total_ipv4": len(merged_ipv4),
    "total_ipv6": len(merged_ipv6),
    "ipv4": [
        {
            "start": str(net.network_address),
            "end": str(net.broadcast_address),
            "cidr": str(net),
            "prefix": net.prefixlen
        } for net in merged_ipv4
    ],
    "ipv6": [str(net) for net in merged_ipv6]
}

with open(f"{OUTPUT_DIR}/iran_full.json", "w", encoding="utf-8") as f:
    json.dump(full_data, f, indent=2, ensure_ascii=False)

print(f"\nتمام فایل‌ها در فولدر '{OUTPUT_DIR}/' ذخیره شدند!")
print("   iran_ips.txt")
print("   iran_cidr.txt")
print("   iran_ipv6.txt")
print("   iran_full.json")
