---
name: h1-bugbounty
description: HackerOne techniques from 43 real reports (9 resolved: Slack, Yahoo Mail, Twitter, Criteo x3, MercadoLibre x2, Reddit). For HackerOne programs and Live Hacking Events (LHE). Confirmed — XSS via SVG/XML upload in iOS app viewers (Slack, Yahoo Mail); URL filter bypass via ASCII homoglyphs (MercadoLibre, Reddit, Bitly/TinyURL); SSRF in webhooks/IPN (Mercado Pago); subdomain takeover via Heroku dangling CNAME (Criteo); credential exposure via GitHub dorks (trufflehog, gitleaks); CVE-2018-0296 Cisco ASA path traversal; CVE-2019-11510 Pulse Secure VPN file read; SWEET32 / POODLE TLS detection on mail/VPN. Additional — APK/IPA secret extraction; XSS via .pptx javascript: links; SSRF via image URL / IPv6 bypass; auth bypass trailing slash (Zomato); GraphQL disclosure; WAF bypass SQLi case; SSH key on GitHub → RCE (Lyft); WordPress authenticated file deletion; XML Billion Laughs DoS. Spanish triggers — "hackerone", "h1", "bug bounty en h1", "live hacking event", "lhe".
---

## Findings profile (HackerOne)

- **Total reports:** 43
- **Resolved (confirmed):** 9 — Slack, Yahoo Mail, Twitter, Criteo (x3), MercadoLibre (x2), Reddit
- **Programs:** Public Bug Bounty + Live Hacking Events (LHE BugCon MX, LHE-MLM-2022)

---

## Confirmed skills (resolved reports)

### 1. Stored XSS via file upload — SVG/XML in iOS apps
Original technique with multiple resolutions (Slack, Yahoo Mail).
- Upload `.xml` or `.svg` files with embedded payload
- The vector triggers when the iOS app renders the file in a webview or "raw view"
- Base payload: `<svg onload="prompt(document.domain);" xmlns="http://www.w3.org/2000/svg"></svg>`
- Variant: `<svg><script>prompt(document.location)</script></svg>` inside XML
- **Ideal targets:** Mobile apps with attachment file viewers, messaging platforms, iOS webmail

### 2. Content moderation / URL filter bypass — ASCII homoglyphs
Technique with 2 independent resolutions (MercadoLibre, Reddit).
- Replace URL characters with circled Unicode/ASCII equivalents: `bⒾt.lⓎ` instead of `bit.ly`
- Works against Bitly, TinyURL filters and forbidden domains in messaging systems and posts
- **Ideal targets:** Content moderation systems, e-commerce platforms with internal messaging, social networks

### 3. SSRF in webhooks / IPN notifications
Resolution at MercadoLibre (Mercado Pago IPN).
- Vector: webhook configuration endpoint that performs HTTP POST without filtering internal destinations
- Test: `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254` (AWS metadata), `http://0.0.0.0`
- **Ideal targets:** Developer panels with webhooks, payment notification systems (IPN), third-party integrations

### 4. Subdomain takeover — Heroku dangling CNAME
Resolution at Criteo (video.criteo.com).
- Identify subdomains pointing to unclaimed Heroku instances
- Create app on Heroku and associate the CNAME to take control
- **Tools:** `subfinder`, `dnsx`, `nuclei -t takeovers/`
- **Ideal targets:** Companies with multiple legacy subdomains; also check AWS S3, Azure, GitHub Pages

### 5. Credential exposure via GitHub recon
Resolution at Criteo (FTP credentials in public repository).
- Search on GitHub: `org:target filename:.env`, `org:target password ftp`, `org:target api_key`
- Validate found credentials before reporting
- **Tools:** GitHub dorks, `trufflehog`, `gitleaks`

### 6. Known CVE exploitation — Path traversal in Cisco ASA
Resolution at Criteo (CVE-2018-0296).
- Identify software versions on the attack surface
- Exploit public CVEs with available PoC (e.g. `github.com/yassineaboukir/CVE-2018-0296`)
- **Workflow:** nmap → version fingerprint → search CVE → PoC → validate

### 7. SSL/TLS legacy protocol detection
Resolution at Twitter (POODLE SSLv3 on SMTP servers).
- Command: `nmap -sV --script ssl-poodle -p 25,443,465,587 <target>`
- Also look for: SWEET32 (3DES), SSLv2, TLS 1.0/1.1 on non-HTTP services
- **Ideal targets:** Mail servers, VPNs, exposed internal services

---

## Additional skills (unresolved reports but with valid technique)

### Mobile app secret extraction
- Decompile APKs with `apktool` or `jadx` to extract hardcoded API keys
- Exposed SDKs found: Twitter, LinkedIn, Filestack, finAPI, Pilgrim (Foursquare), Comscore
- Also applies to IPA (iOS): unzip with `unzip`, search strings in binary
- **Tools:** `jadx`, `apktool`, `strings`, `grep -r "api_key\|secret\|token" ./`

### XSS via Office files — javascript: URI in hyperlinks
- Create PPT/PPTX file with hyperlink pointing to `javascript:prompt(document.cookie)`
- Save as "Slide Show" (.ppsx) and upload as attachment
- The vector triggers when the platform renders or serves the file without sanitizing
- Identified at Slack (files.slack.com)

### XSS via data URI base64
- Inject content via `data:text/html;base64,<payload>` in URL parameters or file fields
- Useful when SVG/XML are filtered but data URIs are not
- Identified at hackerone-attachments.s3.amazonaws.com

### SSRF via image parameter / external URL
- Product or avatar parameters that accept image URL can make internal requests
- Test: `http://localhost`, `http://127.0.0.1:<port>` for internal port scan
- Identified at Shopify (my-store.myshopify.com products image)

### SSRF bypass with IPv6 payloads
- When filters block IPs in IPv4, try IPv6 variants: `http://[::1]`, `http://[::ffff:127.0.0.1]`
- Identified as bypass of the SSRF report on MercadoPago IPN (#1350652)

### Authentication bypass via trailing slash
- Adding `/` at the end of URLs protected by basic auth can skip validation
- `https://target.com/dashboard` → `https://target.com/dashboard/`
- Identified at Zomato (send.zomato.com)

### 2FA session persistence — logical flaw
- Active sessions on other devices remain valid when 2FA is enabled
- Impact: an attacker with a previously stolen session keeps access even if the victim enables 2FA
- Identified at HackerOne

### GraphQL information disclosure
- Banned/disabled users remain accessible via the `User` object in GraphQL
- Test full introspection + access to other users' object fields without authentication
- Identified at HackerOne

### Metadata / information disclosure
- PDFs may contain internal paths, usernames, software used — `exiftool file.pdf`
- Staging/API endpoints exposing: gems with versions, environment variables, endpoint structure
- Exchange/OWA servers leak internal CAS IPs in response headers
- **Tools:** `exiftool`, `strings`, check `X-*` and `Received:` headers

### WAF bypass — SQLi via case manipulation
- Vary upper/lowercase in parameters to evade signature-based WAF rules
- Identified at Zomato (`client_manage_handler.php`)

### Mobile authentication bypass
- Local brute force of 4-digit PIN without rate limiting (0000–9999)
- Bypass via "Forgot PIN" option without additional validation
- Identified at Pornhub Android (brute force) and Ashley Madison Android (forgot pin)

### RCE via exposed SSH private key on GitHub
- GitHub dork in employee repos: `filename:id_rsa`, `filename:config Host`
- Download key + SSH config from public employee repos → direct access to EC2 instances
- Identified at Lyft (employee with key and config in public repo)

### Known CVE — Pulse Secure VPN arbitrary file read
- CVE-2019-11510: arbitrary file read without authentication in Pulse Secure VPN
- Identify instances with nmap/shodan, apply public exploit
- **Tools:** `nuclei -t cves/2019/CVE-2019-11510.yaml`

### SSL/TLS — SWEET32 (3DES)
- CVE-2016-2183: 3DES ciphers in TLS/SSL/IPSec — birthday attack on long sessions
- Detect with: `nmap --script ssl-enum-ciphers -p 443,8443 <target>` and look for `3DES`
- Identified at Twitter Juniper SSL VPN

### Anonymous FTP login / exposed credentials
- Test anonymous login on non-standard FTP ports (2121, 2020, etc.)
- Combine with GitHub recon to find valid FTP credentials in public repos
- Identified at Zomato (anonymous) and Criteo (real credentials on GitHub)

### Exposed internal API structure
- API endpoints without auth that list routes, methods, parameters and internal structure
- Look for: `/api/`, `/api/v1/`, `/swagger`, `/graphql`, unprotected staging endpoints
- Identified at Twitter (jss.svc.twttr.com:8443/api/) and Shipt (staging)

### Exposed registration on internal apps
- Unprotected registration endpoints on internal or employee applications
- Allows account creation and access to internal functionality
- Identified at Sony (tekzone.spe.sony.com)

### Information disclosure via public logs
- Management tool instances (McAfee, etc.) with publicly accessible logs
- Identified at Sony (snap.sel.sony.com — McAfee Agent Activity logs)

### Link shortener — resource enumeration and information disclosure
- Iterate or predict URLs in internal shortener services to discover private resources
- Identified at Twitter t.co — link to internal Google Hangouts staff meeting publicly accessible
- Separate vector: DoS to the shortener by saturating requests to t.co — identified at Twitter

### XML Billion Laughs / DoS via entity expansion (LoLbillion)
- Upload XML file with recursive nested entities that explode in memory when parsed
- Causes DoS on the server processing the XML without expansion limit
- Classic payload: entities that expand exponentially (`&lol9;` → millions of chars)
- Identified at hackerone-attachments.s3.amazonaws.com (combined with XSS via data URI)

### Private program enumeration via platform features
- On HackerOne: when upvoting a private program report, the hunter is visible to others
- Allows discovery of which other hunters are invited to the same private program
- Look for "react", "upvote" or "follow" features that expose private program participants

### Missing security notification — account changes
- Email/password change without user notification (confirmation email missing or incomplete)
- Allows an attacker who took over the account to change credentials without alerting the original owner
- Identified at HackerOne (email change without success notification)

### WordPress authenticated arbitrary file deletion
- WordPress <= 4.9.6: authenticated user can delete arbitrary server files
- Impact: deleting `wp-config.php` forces re-installation and allows site takeover
- Identified at Shipt (www.shipt.com)
- **Tool:** look for WordPress version in `/readme.html` or meta generator, apply public PoC

---

## Methodology context

- Participation in **Live Hacking Events (LHE)**: BugCon MX, MercadoLibre MLM-2022 — good results in on-site events with reduced scope and real-time competition.
- Historical focus: messaging platforms, iOS mobile apps, payment systems, exposed legacy infrastructure.
- Reporting style: clear reproducible steps, attached working PoC, demonstrated impact.
