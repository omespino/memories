#!/usr/bin/env python3
"""
Shodan organization recon — enumerate hosts and group services by IP.

Usage:
    SHODAN_API_KEY=xxx python recon_org.py "Target Company"

Cost: 1 query credit per search call (paginated).
"""
import os
import sys
import shodan


def recon_org(api: shodan.Shodan, org_name: str) -> dict:
    query = f'org:"{org_name}"'
    results = api.search(query)
    print(f"[*] {results['total']} hosts for {org_name}")

    hosts: dict[str, list[dict]] = {}
    for r in results['matches']:
        hosts.setdefault(r['ip_str'], []).append({
            'port': r['port'],
            'product': r.get('product', 'unknown'),
        })

    for ip, svcs in hosts.items():
        print(f"\n[+] {ip}")
        for s in svcs:
            print(f"    - {s['port']}/tcp ({s['product']})")
    return hosts


if __name__ == '__main__':
    key = os.environ.get('SHODAN_API_KEY')
    if not key:
        sys.exit("error: set SHODAN_API_KEY")
    if len(sys.argv) < 2:
        sys.exit(f"usage: {sys.argv[0]} <org_name>")
    recon_org(shodan.Shodan(key), sys.argv[1])
