#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_all_iran_ips.py
Collects Iranian IP ranges from multiple public sources (CIDR lists, text, html, rsc),
merges, deduplicates, and outputs them into 'data/ir_ips.txt'.

Requirements:
    pip install requests beautifulsoup4
"""

import re
import sys
import time
import ipaddress
from typing import List
import requests
import os

# ---- Sources ----
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
    """Fetch URL content with retry logic."""
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
    print(f"[!] Failed to fetch {url}: {last_exc}", file=sys.stderr)
    return ""


def extract_candidate_strings(text: str) -> List[str]:
    """Extract potential IP/CIDR strings from plain text."""
    items = set()
    for m in CIDR_RE.finditer(text):
        ip = m.group("ip")
        pre = m.group("prefix")
        items.add(f"{ip}/{pre}" if pre else ip)

    for m in CIDR_V6_RE.finditer(text):
        s = m.group(0)
        if ":" in s:
            items.add(s if "/" in s else s + "/128")

    for m in MIKROTIK_ADDR_RE.finditer(text):
        items.add(m.group("cidr"))

    return sorted(items)


def parse_to_networks(items: List[str]) -> List[ipaddress._BaseNetwork]:
    """Convert string items to ip_network objects."""
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
    """Collapse overlapping networks and sort them."""
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6))

    collapsed_v4.sort(key=lambda x: (int(x.network_address), x.prefixlen))
    collapsed_v6.sort(key=lambda x: (int(x.network_address), x.prefixlen))

    print(f"[+] After collapsing: {len(collapsed_v4)} IPv4 + {len(collapsed_v6)} IPv6")
    return collapsed_v4 + collapsed_v6


def extract_from_html_nirsoft(text: str) -> List[str]:
    """Extract IPs from Nirsoft HTML tables."""
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
                items.add(f"{ip}/{pre}" if pre else ip)
            for m in CIDR_V6_RE.finditer(txt):
                s = m.group(0)
                items.add(s if "/" in s else s + "/128")
        return sorted(items)
    except Exception:
        return []


def collect_from_sources(sources: List[str]) -> List[ipaddress._BaseNetwork]:
    """Collect and parse IPs from multiple sources."""
    collected = []
    for src in sources:
        print(f"[+] Fetching: {src}")
        txt = fetch_text(src)
        if not txt:
            print(f"    -> Failed or empty.", file=sys.stderr)
            continue

        items = []
        if "nirsoft.net" in src:
            html_items = extract_from_html_nirsoft(txt)
            if html_items:
                items.extend(html_items)

        items.extend(extract_candidate_strings(txt))
        items = sorted(set(items))
        nets = parse_to_networks(items)
        print(f"    -> Extracted {len(nets)} networks/IPs")
        collected.extend(nets)

    return collected


def write_output(nets: List[ipaddress._BaseNetwork], filename="data/ir_ips.txt"):
    """Write the final IP list to file."""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        for n in nets:
            f.write(str(n.with_prefixlen) + "\n")
    print(f"[+] Wrote {len(nets)} entries to '{filename}'")


def main():
    print("[*] Starting Iranian IP collection ...")
    nets = collect_from_sources(DEFAULT_SOURCES)
    if not nets:
        print("[!] No IPs found. Check your network or sources.")
        sys.exit(1)
    merged = collapse_and_sort(nets)
    write_output(merged)
    print("[*] Done.")


if __name__ == "__main__":
    main()
