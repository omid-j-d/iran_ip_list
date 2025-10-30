#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_all_iran_ips.py
جمع‌آوری IPهای ایرانی از چند منبع عمومی و خروجی در فایل data/ir_ips.txt

نیازمندی‌ها:
    pip install requests beautifulsoup4
"""

import re
import sys
import time
import ipaddress
from typing import List
import requests

# ---- منابع ----
DEFAULT_SOURCES = [
    "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_ir.netset",
    "https://raw.githubusercontent.com/Ramtiiin/iran-ip/main/ip-list.rsc",
    "https://ipv4.fetus.jp/ir",
    "https://www.nirsoft.net/countryip/ir.html",
    "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
]

HEADERS = {"User-Agent": "ir-ip-collector/1.0 (+https://github.com/omiddev/iran_ip_list)"}
TIMEOUT = 20

CIDR_RE = re.compile(r'\b(?P<ip>(?:\d{1,3}(?:\.\d{1,3}){3}))(?:/(?P<prefix>\d{1,2}))?\b')
CIDR_V6_RE = re.compile(r'\b[0-9a-fA-F:]{3,}(/\d{1,3})?\b')
MIKROTIK_ADDR_RE = re.compile(r'address\s*=\s*(?P<cidr>[\d\.:/a-fA-F]+)')


def fetch_text(url: str, tries=2) -> str:
    """دانلود محتوای یک URL با چند بار تلاش"""
    last_exc = None
    for attempt in range(1, tries + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            r.encoding = r.apparent_encoding or 'utf-8'
            return r.text
        except Exception as e:
            last_exc = e
            time.sleep(1)
    print(f"[!] دریافت از {url} ناموفق بود: {last_exc}", file=sys.stderr)
    return ""


def extract_candidate_strings(text: str) -> List[str]:
    """استخراج رشته‌های احتمالی IP/CIDR از متن"""
    items = set()
    for m in CIDR_RE.finditer(text):
        ip = m.group("ip")
        pre = m.group("prefix")
        if pre:
            items.add(f"{ip}/{pre}")
        else:
            items.add(ip)
    for m in CIDR_V6_RE.finditer(text):
        s = m.group(0)
        if ":" in s:
            if "/" in s:
                items.add(s)
            else:
                items.add(s + "/128")
    for m in MIKROTIK_ADDR_RE.finditer(text):
        items.add(m.group("cidr"))
    return sorted(items)


def parse_to_networks(items: List[str]) -> List[ipaddress._BaseNetwork]:
    """تبدیل رشته‌ها به اشیاء شبکه"""
    nets = []
    for s in items:
        s = s.strip()
        if not s:
            continue
        if "/" not in s:
            s += "/32" if ":" not in s else "/128"
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except Exception:
            s2 = re.sub(r'[,\s;]+$', '', s)
            try:
                nets.append(ipaddress.ip_network(s2, strict=False))
            except Exception:
                continue
    return nets


def collapse_and_sort(nets: List[ipaddress._BaseNetwork]) -> List[ipaddress._BaseNetwork]:
    """ادغام و مرتب‌سازی شبکه‌ها"""
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6))

    collapsed_v4.sort(key=lambda x: (int(x.network_address), x.prefixlen))
    collapsed_v6.sort(key=lambda x: (int(x.network_address), x.prefixlen))

    print(f"بعد از ادغام: {len(collapsed_v4)} IPv4 + {len(collapsed_v6)} IPv6")
    return collapsed_v4 + collapsed_v6


def extract_from_html_nirsoft(text: str) -> List[str]:
    """استخراج IP از صفحه HTML سایت Nirsoft"""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []
    try:
        soup = BeautifulSoup(text, "html.parser")
        items = set()
        for td in soup.find_all(['td', 'pre', 'li', 'code']):
            txt = td.get_text(separator=" ", strip=True)
            for m in CIDR_RE.finditer(txt):
                ip = m.group("ip")
                pre = m.group("prefix")
                if pre:
                    items.add(f"{ip}/{pre}")
                else:
                    items.add(ip)
            for m in CIDR_V6_RE.finditer(txt):
                s = m.group(0)
                items.add(s if "/" in s else s + "/128")
        return sorted(items)
    except Exception:
        return []


def collect_from_sources(sources: List[str]) -> List[ipaddress._BaseNetwork]:
    """جمع‌آوری IPها از منابع مختلف"""
    collected = []
    for src in sources:
        print(f"[+] دریافت از: {src}")
        txt = fetch_text(src)
        if not txt:
            print(f"    -> شکست در دریافت.", file=sys.stderr)
            continue

        items = []
        if "nirsoft.net" in src:
            html_items = extract_from_html_nirsoft(txt)
            if html_items:
                items.extend(html_items)

        items.extend(extract_candidate_strings(txt))
        items = sorted(set(items))
        nets = parse_to_networks(items)
        print(f"    -> استخراج {len(nets)} شبکه/IP")
        collected.extend(nets)

    return collected


def write_output(nets: List[ipaddress._BaseNetwork], filename="data/ir_ips.txt"):
    """نوشتن خروجی در فایل"""
    import os
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        for n in nets:
            f.write(str(n.with_prefixlen) + "\n")
    print(f"[+] {len(nets)} رکورد در '{filename}' ذخیره شد.")


def main():
    print("[*] شروع جمع‌آوری IPهای ایران ...")
    nets = collect_from_sources(DEFAULT_SOURCES)
    if not nets:
        print("[!] هیچ IPای پیدا نشد. بررسی شبکه یا منابع لازم است.")
        sys.exit(1)
    merged = collapse_and_sort(nets)
    write_output(merged)
    print("[*] پایان عملیات.")


if __name__ == "__main__":
    main()
