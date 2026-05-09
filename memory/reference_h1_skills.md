---
name: HackerOne Bug Bounty Skills
description: Skills and techniques derived from omespino's real HackerOne reports (43 reports, 9 resolved). Patterns, vectors, and methodologies that have produced confirmed findings.
type: reference
---

## Perfil de hallazgos (HackerOne)

- **Total reportes:** 43
- **Resueltos (confirmados):** 9 — Slack, Yahoo Mail, Twitter, Criteo (x3), MercadoLibre (x2), Reddit
- **Programas:** Bug Bounty públicos + Live Hacking Events (LHE BugCon MX, LHE-MLM-2022)

---

## Skills confirmados (reportes resueltos)

### 1. Stored XSS via file upload — SVG/XML en apps iOS
Técnica propia con múltiples resoluciones (Slack, Yahoo Mail).
- Subir archivos `.xml` o `.svg` con payload embebido
- El vector se activa cuando la app iOS renderiza el archivo en un webview o "raw view"
- Payload base: `<svg onload="prompt(document.domain);" xmlns="http://www.w3.org/2000/svg"></svg>`
- Variante: `<svg><script>prompt(document.location)</script></svg>` dentro de XML
- **Targets ideales:** Apps móviles con visor de archivos adjuntos, plataformas de mensajería, webmail iOS

### 2. Content moderation / URL filter bypass — ASCII homoglyphs
Técnica con 2 resoluciones independientes (MercadoLibre, Reddit).
- Reemplazar caracteres de URLs con equivalentes Unicode/ASCII encirculados: `bⒾt.lⓎ` en lugar de `bit.ly`
- Funciona contra filtros de Bitly, TinyURL y dominios prohibidos en sistemas de mensajería y posts
- **Targets ideales:** Sistemas de moderación de contenido, plataformas de e-commerce con mensajería interna, redes sociales

### 3. SSRF en webhooks / IPN notifications
Resolución en MercadoLibre (Mercado Pago IPN).
- Vector: endpoint de configuración de webhooks que realiza HTTP POST sin filtrar destinos internos
- Probar: `http://localhost`, `http://127.0.0.1`, `http://169.254.169.254` (AWS metadata), `http://0.0.0.0`
- **Targets ideales:** Paneles de desarrollador con webhooks, sistemas de notificación de pagos (IPN), integraciones de terceros

### 4. Subdomain takeover — Heroku dangling CNAME
Resolución en Criteo (video.criteo.com).
- Identificar subdominios que apuntan a instancias Heroku no reclamadas
- Crear app en Heroku y asociar el CNAME para tomar control
- **Herramientas:** `subfinder`, `dnsx`, `nuclei -t takeovers/`
- **Targets ideales:** Empresas con múltiples subdominios legacy; verificar también AWS S3, Azure, GitHub Pages

### 5. Credential exposure via GitHub recon
Resolución en Criteo (credenciales FTP en repositorio público).
- Buscar en GitHub: `org:target filename:.env`, `org:target password ftp`, `org:target api_key`
- Validar credenciales encontradas antes de reportar
- **Herramientas:** GitHub dorks, `trufflehog`, `gitleaks`

### 6. Known CVE exploitation — Path traversal en Cisco ASA
Resolución en Criteo (CVE-2018-0296).
- Identificar versiones de software en superficie de ataque
- Explotar CVEs públicos con PoC disponible (ej. `github.com/yassineaboukir/CVE-2018-0296`)
- **Workflow:** nmap → fingerprint de versión → buscar CVE → PoC → validar

### 7. SSL/TLS legacy protocol detection
Resolución en Twitter (POODLE SSLv3 en servidores SMTP).
- Comando: `nmap -sV --script ssl-poodle -p 25,443,465,587 <target>`
- Buscar también: SWEET32 (3DES), SSLv2, TLS 1.0/1.1 en servicios no-HTTP
- **Targets ideales:** Servidores de correo, VPNs, servicios internos expuestos

---

## Skills adicionales (reportes no resueltos pero con técnica válida)

### Mobile app secret extraction
- Descompilar APKs con `apktool` o `jadx` para extraer API keys hardcodeadas
- SDKs encontrados expuestos: Twitter, LinkedIn, Filestack, finAPI, Pilgrim (Foursquare), Comscore
- Aplica también a IPA (iOS): descomprimir con `unzip`, buscar strings en binario
- **Herramientas:** `jadx`, `apktool`, `strings`, `grep -r "api_key\|secret\|token" ./`

### XSS via Office files — javascript: URI en hyperlinks
- Crear archivo PPT/PPTX con hipervínculo apuntando a `javascript:prompt(document.cookie)`
- Guardar como "Slide Show" (.ppsx) y subir como adjunto
- El vector se activa cuando la plataforma renderiza o sirve el archivo sin sanitizar
- Identificado en Slack (files.slack.com)

### XSS via data URI base64
- Inyectar contenido via `data:text/html;base64,<payload>` en parámetros de URL o campos de archivo
- Útil cuando SVG/XML están filtrados pero data URIs no
- Identificado en hackerone-attachments.s3.amazonaws.com

### SSRF via parámetro de imagen / URL externa
- Parámetros de productos o avatares que aceptan URL de imagen pueden hacer requests internos
- Probar: `http://localhost`, `http://127.0.0.1:<puerto>` para port scan interno
- Identificado en Shopify (my-store.myshopify.com products image)

### SSRF bypass con IPv6 payloads
- Cuando filtros bloquean IPs en IPv4, probar variantes IPv6: `http://[::1]`, `http://[::ffff:127.0.0.1]`
- Identificado como bypass del reporte SSRF en MercadoPago IPN (#1350652)

### Authentication bypass via trailing slash
- Agregar `/` al final de URLs protegidas por basic auth puede omitir la validación
- `https://target.com/dashboard` → `https://target.com/dashboard/`
- Identificado en Zomato (send.zomato.com)

### 2FA session persistence — logical flaw
- Las sesiones activas en otros dispositivos permanecen válidas al activar 2FA
- Impacto: un atacante con sesión previa robada mantiene acceso aunque víctima active 2FA
- Identificado en HackerOne

### GraphQL information disclosure
- Usuarios baneados/deshabilitados siguen siendo accesibles via objeto `User` en GraphQL
- Probar introspection completa + acceso a campos de objetos de otros usuarios sin autenticación
- Identificado en HackerOne

### Metadata / information disclosure
- PDFs pueden contener rutas internas, nombres de usuario, software usado — `exiftool archivo.pdf`
- Endpoints de staging/API que exponen: gems con versiones, variables de entorno, estructura de endpoints
- Servidores Exchange/OWA filtran IPs internas del CAS en headers de respuesta
- **Herramientas:** `exiftool`, `strings`, revisar headers `X-*` y `Received:`

### WAF bypass — SQLi via case manipulation
- Variar mayúsculas/minúsculas en parámetros para evadir reglas WAF basadas en firmas
- Identificado en Zomato (`client_manage_handler.php`)

### Mobile authentication bypass
- Fuerza bruta local de PIN de 4 dígitos sin rate limiting (0000–9999)
- Bypass via opción "Forgot PIN" sin validación adicional
- Identificado en Pornhub Android (brute force) y Ashley Madison Android (forgot pin)

### RCE via exposed SSH private key on GitHub
- GitHub dork en repos de empleados: `filename:id_rsa`, `filename:config Host`
- Descargar key + config SSH de repos públicos de empleados → acceso directo a instancias EC2
- Identificado en Lyft (empleado con key y config en repo público)

### Known CVE — Pulse Secure VPN arbitrary file read
- CVE-2019-11510: lectura arbitraria de archivos sin autenticación en Pulse Secure VPN
- Identificar instancias con nmap/shodan, aplicar exploit público
- **Herramientas:** `nuclei -t cves/2019/CVE-2019-11510.yaml`

### SSL/TLS — SWEET32 (3DES)
- CVE-2016-2183: ciphers 3DES en TLS/SSL/IPSec — birthday attack en sesiones largas
- Detectar con: `nmap --script ssl-enum-ciphers -p 443,8443 <target>` y buscar `3DES`
- Identificado en Juniper SSL VPN de Twitter

### FTP anonymous login / credenciales expuestas
- Probar login anónimo en puertos FTP no estándar (2121, 2020, etc.)
- Combinar con GitHub recon para encontrar credenciales FTP válidas en repos públicos
- Identificado en Zomato (anónimo) y Criteo (credenciales reales en GitHub)

### Exposed internal API structure
- Endpoints de API sin auth que listan rutas, métodos, parámetros y estructura interna
- Buscar: `/api/`, `/api/v1/`, `/swagger`, `/graphql`, endpoints de staging sin proteger
- Identificado en Twitter (jss.svc.twttr.com:8443/api/) y Shipt (staging)

### Exposed registration on internal apps
- Endpoints de registro sin protección en aplicaciones internas o de empleados
- Permite crear cuenta y acceder a funcionalidad interna
- Identificado en Sony (tekzone.spe.sony.com)

### Information disclosure via logs públicos
- Instancias de herramientas de gestión (McAfee, etc.) con logs accesibles públicamente
- Identificado en Sony (snap.sel.sony.com — McAfee Agent Activity logs)

### Link shortener — resource enumeration e information disclosure
- Iterar o predecir URLs en servicios de shortener internos para descubrir recursos privados
- Identificado en Twitter t.co — link a Google Hangouts de reunión interna de staff accesible públicamente
- Vector separado: DoS al shortener saturando requests hacia t.co — identificado en Twitter

### XML Billion Laughs / DoS via entity expansion (LoLbillion)
- Subir archivo XML con entidades anidadas recursivas que explotan en memoria al parsear
- Causa DoS en el servidor que procesa el XML sin límite de expansión
- Payload clásico: entidades que se expanden exponencialmente (`&lol9;` → millones de chars)
- Identificado en hackerone-attachments.s3.amazonaws.com (combinado con XSS via data URI)

### Private program enumeration via platform features
- En HackerOne: al hacer upvote en un reporte de programa privado, el hunter es visible para otros
- Permite descubrir qué otros hunters están invitados al mismo programa privado
- Buscar features de "reacción", "upvote" o "follow" que exponen participantes de programas privados

### Missing security notification — account changes
- Cambio de email/contraseña sin notificación al usuario (email de confirmación ausente o incompleto)
- Permite a atacante que tomó la cuenta cambiar credenciales sin alertar al dueño original
- Identificado en HackerOne (cambio de email sin notificación de éxito)

### WordPress authenticated arbitrary file deletion
- WordPress <= 4.9.6: usuario autenticado puede eliminar archivos arbitrarios del servidor
- Impacto: eliminar `wp-config.php` fuerza re-instalación y permite tomar control del sitio
- Identificado en Shipt (www.shipt.com)
- **Herramienta:** buscar versión WordPress en `/readme.html` o meta generator, aplicar PoC público

---

## Contexto de metodología

- Participación en **Live Hacking Events (LHE)**: BugCon MX, MercadoLibre MLM-2022 — buenos resultados en eventos presenciales con scope reducido y competencia en tiempo real.
- Foco histórico: plataformas de mensajería, apps móviles iOS, sistemas de pagos, infraestructura legacy expuesta.
- Estilo de reporte: pasos claros reproducibles, PoC funcional adjunto, impacto demostrado.
