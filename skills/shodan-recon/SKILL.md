---
name: shodan-recon
description: Shodan reconnaissance for authorized pentest and bug-bounty engagements. Use when the user mentions Shodan, asks for passive recon on a target organization/CIDR/domain/ASN, wants to find exposed services (databases, webcams, IoT, industrial control, RDP, VNC, FTP, MongoDB, Elasticsearch, Redis, Docker, Jenkins, Kubernetes), needs vulnerable-service hunting by CVE, asset discovery, SSL/TLS certificate analysis, or network monitoring with alerts. Covers CLI commands, REST API, InternetDB (free, no key), search filter syntax, on-demand scanning, credit costs, and free-vs-paid features. Spanish triggers — "shodan", "reconocimiento pasivo", "buscar expuestos", "internetdb", "scan submit", "filtros shodan".
---

# Shodan Reconnaissance and Pentesting

## Important — interaction rules
- Any command that consumes **query credits** (filtered search, stats, download), **scan credits** (`shodan scan submit`), or that contacts an external IP belonging to a target must be presented as a proposed command first. Do not execute it without the user's explicit approval (per `feedback_no_auto_requests.md`).
- Free recon (no key, no credits) — `shodan host`, `shodan count`, `shodan domain`, `internetdb.shodan.io`, `shodan info`, `shodan myip` — can be proposed and run after a one-line "ok" confirmation.

## Purpose

Provide systematic methodologies for leveraging Shodan as a reconnaissance tool during authorized penetration testing and bug bounty engagements. Covers the Shodan web interface, CLI, REST API, search filters, on-demand scanning, network monitoring (alerts) and InternetDB.

## Inputs / Prerequisites

- **Shodan account**: free signup, paid plans for advanced filters/scan/monitor.
- **API key**: from the account dashboard. Membership ($1 lifetime, legacy) gave 100/100 credits; new free accounts get 0 query/0 scan credits — most useful CLI features need at least Membership or Freelancer.
- **Target authorisation**: written permission for any active scanning (`shodan scan submit`).
- **Shodan CLI**: Python package.

## Outputs / Deliverables

- Asset inventory (hosts, ports, services).
- Vulnerability list (CVEs from Shodan banners, paid feature).
- Banner data with software versions.
- Geographic / organisational distribution.
- Screenshot gallery for exposed UIs.
- JSON / CSV exports for further analysis.

## Core Workflow

### 1. Setup and Configuration

#### Install Shodan CLI
```bash
# Recommended
pip install shodan

# Arch / BlackArch
sudo pacman -S python-shodan
```
> Note: `easy_install` is deprecated and removed from Python ≥ 3.12 — do not use it.

#### Initialize API Key
```bash
shodan init YOUR_API_KEY
shodan info
```
Real `shodan info` output for a Membership account:
```
Query credits available: 100
Scan credits available: 100
```
Free signup (without Membership) shows `0 / 0`.

#### Account utilities
```bash
shodan info        # credits & plan
shodan myip        # your external IP
shodan version     # CLI version
```

### 2. Free recon — no credits

#### `shodan host` — full host record
```bash
shodan host 1.1.1.1
```
Returns hostnames, country, org, open ports and banners as Shodan last crawled them.

#### `shodan count` — result count for any query
```bash
shodan count openssh
shodan count 'product:nginx country:US'
```
Even filtered counts cost 0 credits — a great way to size a result set before paying for the download.

#### `shodan domain` — subdomain + DNS dump
```bash
shodan domain example.com
```
Returns all subdomains Shodan knows for a domain, along with A/AAAA/MX/NS records. Often the cheapest way to enumerate a target's surface.

#### `shodan honeyscore` — honeypot probability
```bash
shodan honeyscore 192.168.1.100
```
Real output is a single float between `0.0` (not a honeypot) and `1.0` (likely honeypot). Treat anything > 0.5 as suspicious. (The legacy honeyscore endpoint at `honeyscore.shodan.io` is being phased out; the CLI command still works.)

#### InternetDB — free, no API key, no credits
```bash
curl -s https://internetdb.shodan.io/1.1.1.1 | jq
```
Returns ports, hostnames, vulns, tags and CPEs for any IPv4. Ideal for high-volume passive recon over a CIDR — no auth, no rate-limit signaling. Pair with `xargs -P` for parallel queries.

### 3. Search Queries

#### Basic search (free if no filter)
```bash
shodan search apache
shodan search --fields ip_str,port,os smb
```

#### Filtered search (1 credit per query)
```bash
shodan search 'product:mongodb'
shodan search 'product:nginx country:US city:"New York"'
```
> Negation: prefix the entire filter with `-`, e.g. `-port:443`. Tag-style negation (`-authentication`) is NOT valid Shodan syntax.

#### Download results
```bash
# Default 1000 results
shodan download results.json.gz "apache country:US"

# Custom limit (1 query credit per 100 results)
shodan download --limit 5000 results.json.gz "nginx"

# All available
shodan download --limit -1 all_results.json.gz "query"
```

#### Parse downloaded data
```bash
shodan parse --fields ip_str,port,hostnames results.json.gz
shodan parse --fields location.country_code3,ip_str -f port:22 results.json.gz
shodan parse --fields ip_str,port,org --separator , results.json.gz > results.csv
```

#### Convert downloaded data to other formats
```bash
shodan convert results.json.gz csv     # → results.csv
shodan convert results.json.gz xlsx    # → results.xlsx
shodan convert results.json.gz kml     # → results.kml (Google Earth)
```

### 4. Search Filters Reference

#### Network
```
ip:1.2.3.4                  Specific IP
net:192.168.0.0/24          CIDR range
hostname:example.com        Hostname contains
port:22                     Port
asn:AS15169                 ASN
```

#### Geographic
```
country:US                  ISO-3166-1 alpha-2 ONLY (no full names)
city:"San Francisco"        City
state:CA                    State / region
postal:94102                Postal code
geo:37.7,-122.4             Latitude,longitude
```

#### Organisation
```
org:"Google"
isp:"Comcast"
```

#### Service / Product
```
product:nginx
version:1.14.0
os:"Windows Server 2019"
http.title:"Dashboard"
http.html:"login"
http.status:200
http.component:wordpress
ssl.cert.subject.cn:*.example.com
ssl.cert.expired:true
ssl:true
tag:cloud                   tag:cdn, tag:vpn, tag:starlink, etc.
```

#### Vulnerability  *(Small Business plan or higher)*
```
vuln:CVE-2019-0708
has_vuln:true
```

#### Screenshots  *(Freelancer plan or higher)*
```
has_screenshot:true
screenshot.label:webcam
```

#### Negation / boolean
```
-port:443                   exclude port 443
+port:80                    require port 80
"exact phrase"
```

### 5. On-Demand Scanning  *(propose first, then run)*

Active scanning. Always confirm authorisation in writing. 1 scan credit per IP.

```bash
shodan scan submit 192.0.2.10
shodan scan submit --verbose 192.0.2.10
shodan scan submit --filename scan_results.json.gz 192.0.2.10
shodan scan list
shodan scan status SCAN_ID
shodan download --limit -1 results.json.gz "scan:SCAN_ID"

# Show all available scanner modules / protocols (~80+)
shodan scan protocols
```
Same target cannot be re-scanned within 24h on non-Enterprise plans.

### 6. Statistics and Analysis

```bash
# Default top 10 by country and org
shodan stats nginx

# Custom facets
shodan stats --facets domain,port,asn --limit 5 nginx

# Save to CSV
shodan stats --facets country,org -O stats.csv apache
```

Common facets: `country`, `org`, `port`, `product`, `version`, `vuln`, `domain`, `asn`, `city`, `ssl.version`, `http.component`, `tag`.

### 7. Network Monitoring (Alerts)

#### From the CLI
```bash
# Create an alert (define a network range to monitor)
shodan alert create "my-net" 192.0.2.0/24

# List alerts
shodan alert list

# Get alert info
shodan alert info ALERT_ID

# Set up trigger notifications
shodan alert triggers                       # available trigger types
shodan alert enable ALERT_ID TRIGGER_NAME   # e.g. new_service, vulnerable, open_database
shodan alert disable ALERT_ID TRIGGER_NAME

# Stream alerts in real time
shodan alert remove ALERT_ID
shodan stream --alert ALERT_ID
```

#### From the web UI
1. Monitor Dashboard → Add IP/range/domain.
2. Configure notification (email, Slack, webhook).
3. Pick triggers (`new_service`, `ssl_expired`, `vulnerable`, `open_database`, `industrial_control_system`, etc.).

### 8. REST API Usage

#### Direct calls
```bash
curl -s "https://api.shodan.io/api-info?key=YOUR_KEY" | jq
curl -s "https://api.shodan.io/shodan/host/1.1.1.1?key=YOUR_KEY" | jq
curl -s "https://api.shodan.io/shodan/host/search?key=YOUR_KEY&query=apache" | jq
curl -s "https://api.shodan.io/dns/domain/example.com?key=YOUR_KEY" | jq
curl -s "https://internetdb.shodan.io/1.1.1.1" | jq        # no key
```

#### Python library
```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')

results = api.search('apache')
print(f'Results found: {results["total"]}')
for result in results['matches']:
    print(result['ip_str'], result['port'])

host = api.host('1.1.1.1')
print(host['ip_str'], host.get('org', 'n/a'))
for item in host['data']:
    print(item['port'])
```

## Quick Reference

### Essential CLI Commands

| Command | Description | Credits |
|---|---|---|
| `shodan init KEY` | Initialize API key | 0 |
| `shodan info` | Show account info | 0 |
| `shodan myip` | Show your IP | 0 |
| `shodan host IP` | Host details | 0 |
| `shodan domain DOMAIN` | Subdomains + DNS | 0 |
| `shodan count QUERY` | Result count | 0 |
| `shodan search QUERY` | Search (0 if no filter) | 0 / 1 |
| `shodan download FILE QUERY` | Save results | 1 / 100 results |
| `shodan parse FILE` | Extract fields | 0 |
| `shodan convert FILE FORMAT` | Convert to csv/xlsx/kml | 0 |
| `shodan stats QUERY` | Statistics | 1 |
| `shodan scan submit IP` | On-demand scan | 1 / IP |
| `shodan scan protocols` | List scan modules | 0 |
| `shodan alert create/list/...` | Network monitoring | 0 (uses monitored-IP quota) |
| `shodan honeyscore IP` | Honeypot probability | 0 |
| `shodan stream --alert ID` | Real-time alert stream | 0 |
| `curl https://internetdb.shodan.io/IP` | Free passive recon | 0 / no key |

### Common Search Queries

| Purpose | Query |
|---|---|
| Find webcams | `webcam has_screenshot:true` |
| MongoDB databases | `product:mongodb` |
| Redis servers | `product:redis` |
| Elasticsearch | `product:elastic port:9200` |
| Default passwords | `"default password"` |
| Vulnerable RDP (paid) | `port:3389 vuln:CVE-2019-0708` |
| Industrial systems | `port:502 modbus` |
| Cisco devices | `product:cisco` |
| Open VNC | `port:5900 "authentication disabled"` |
| Anonymous FTP | `"230 Login successful" port:21` |
| WordPress sites | `http.component:wordpress` |
| HP printers | `"HP-ChaiSOE" port:80` |
| RTSP cameras | `port:554 has_screenshot:true` |
| Jenkins servers | `"X-Jenkins" port:8080` |
| Exposed Docker API | `port:2375 product:docker` |
| Log4Shell candidates (paid) | `vuln:CVE-2021-44228` |
| Exposed K8s API | `product:"kubernetes" port:6443` |
| Exposed etcd | `product:etcd` |

### Useful Filter Combinations

| Scenario | Query |
|---|---|
| Target org recon | `org:"Company Name"` |
| Domain enumeration | `hostname:example.com` |
| Network range scan | `net:192.168.0.0/24` |
| SSL cert search | `ssl.cert.subject.cn:*.target.com` |
| Self-signed certs | `ssl.cert.issuer.cn:self-signed` |
| Expired certs | `ssl.cert.expired:true org:"Company"` |
| Exposed admin panels | `http.title:"admin" port:443` |
| Common DBs exposed | `port:3306,5432,27017,6379` |

### Credit System

| Action | Credit Type | Cost |
|---|---|---|
| Basic keyword search | Query | 0 (no filter) |
| Filtered search | Query | 1 |
| Download 100 results | Query | 1 |
| Generate report | Query | 1 |
| Scan 1 IP | Scan | 1 |
| Network monitoring | Monitored IPs | depends on plan |

### Paid-only features (heads-up)
- `vuln:` / `has_vuln:` filters → Small Business plan or higher.
- `has_screenshot:true` and `screenshot.*` → Freelancer plan or higher.
- Historical banners → Corporate plan.
- Bulk export of >10k results, full real-time stream — Enterprise.

## Constraints and Limitations

### Operational
- ~1 request per second rate limit on the REST API.
- `shodan scan submit` is asynchronous (poll with `shodan scan status`).
- Cannot re-scan the same IP within 24h (non-Enterprise).
- Free signup credits = 0/0; usable workflow needs at least Membership.
- Some data (vulns, screenshots, history) requires paid plans.

### Data Freshness
- Crawl data may be days to weeks old.
- On-demand scans are current but cost credits.
- Historical data is paid.

### Legal / authorisation
- Passive lookup (`host`, `count`, `domain`, InternetDB, search) is generally legal but verify jurisdiction for your engagement.
- `shodan scan submit` is **active probing** — always with prior written authorisation.
- Document everything: scan IDs, queries, timestamps.

## Examples

### Example 1 — Organization Reconnaissance (passive, 0 cost)
```bash
shodan domain target.com
shodan count 'org:"Target Company"'
shodan stats --facets port,product,country 'org:"Target Company"'
```
Then, if budget allows:
```bash
shodan download target_data.json.gz 'org:"Target Company"'
shodan parse --fields ip_str,port,product target_data.json.gz
shodan convert target_data.json.gz csv
```

### Example 2 — Vulnerable service discovery (paid)
```bash
shodan search 'vuln:CVE-2019-0708 country:US'
shodan search 'product:elastic port:9200 -ssl'
shodan search 'vuln:CVE-2021-44228'
```

### Example 3 — IoT discovery (uses screenshot facet, paid)
```bash
shodan search 'webcam has_screenshot:true country:US'
shodan search 'port:502 product:modbus'
shodan search '"HP-ChaiSOE" port:80'
shodan search 'product:nest'
```

### Example 4 — SSL/TLS analysis
```bash
shodan search 'ssl.cert.subject.cn:*.example.com'
shodan search 'ssl.cert.expired:true org:"Company"'
shodan search 'ssl.cert.issuer.cn:self-signed'
```

### Example 5 — Python automation
See `scripts/recon_org.py` for a ready-to-use Python script that enumerates an organization's hosts and groups services by IP.

### Example 6 — Free CIDR sweep with InternetDB (no key, no credits)
```bash
# Walk an authorised /24 in parallel
seq 1 254 | xargs -P 20 -I {} \
  curl -s "https://internetdb.shodan.io/192.0.2.{}" \
  | jq -c '{ip, ports, vulns, hostnames}' \
  | tee internetdb_sweep.jsonl
```

### Example 7 — Monitor a CIDR and stream alerts
```bash
shodan alert create "engagement-1" 192.0.2.0/24
shodan alert list
shodan alert enable ALERT_ID new_service
shodan alert enable ALERT_ID vulnerable
shodan stream --alert ALERT_ID
```

## Troubleshooting

| Issue | Cause | Solution |
|---|---|---|
| `No API Key Configured` | Key not initialised | `shodan init YOUR_API_KEY`, verify with `shodan info` |
| `Query credits exhausted` | Monthly credits used | Use credit-free commands (`host`, `count`, `domain`, InternetDB), wait for reset, or upgrade |
| `Host recently crawled` | <24h since last scan | Use `shodan host IP` for cached data, or wait |
| Rate-limited | >1 req/sec | Add `time.sleep(1)` between API requests |
| Empty results | Filter too tight or syntax | Quote phrases (`'org:"Company Name"'`), check valid filter names |
| Downloaded file won't parse | Truncated / corrupted gzip | `gunzip -t file.json.gz`; re-download with explicit `--limit` |
| `country:"United States"` returns 0 | Filter requires ISO-2 code | Use `country:US` |
| `vuln:` returns 0 always | Filter is paid (Small Business+) | Upgrade or use cached `internetdb.shodan.io/<ip>` for `vulns` field |
