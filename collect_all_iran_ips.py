#!/usr/bin/env python3
import requests
import ipaddress
import json
import os
from datetime import datetime

# ==================== تنظیمات ====================
HEADERS = {
    'User-Agent': 'IranIPCollector/2.0 (GitHub Actions)'
}
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==================== منابع فعال (بدون نیاز به دانلود دستی) ====================
SOURCES = [
    {
        "name": "RIPE NCC",
        "url": "https://stat.ripe.net/data/country-resource-list/data.json?resource=IR",
        "parser": "ripe"
    },
    {
        "name": "IPDeny",
        "url": "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
        "parser": "cidr"
    },
    {
        "name": "Nirsoft",
        "url": "https://www.nirsoft.net/countryip/ir.html",
        "parser": "nirsoft"
    }
]

# ==================== پارس‌کننده‌ها ====================
def parse_ripe(data):
    nets = []
    try:
        for ip in data.get('data', {}).get('resources', {}).get('ipv4', []):
            try: nets.append(ipaddress.ip_network(ip.strip(), strict=False))
            except: pass
        for ip in data.get('data', {}).get('resources', {}).get('ipv6', []):
            try: nets.append(ipaddress.ip_network(ip.strip(), strict=False))
            except: pass
    except: pass
    return nets

def parse_cidr(text):
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.version == 4:  # فقط IPv4 از IPDeny
                    nets.append(net)
            except: pass
    return nets

