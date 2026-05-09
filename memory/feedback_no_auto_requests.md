---
name: No automatic HTTP or network requests
description: Claude must never execute HTTP requests or any network interaction automatically. Always present theoretical exploitation scenarios first and only execute what the user explicitly approves.
type: feedback
---

**Regla:** Nunca ejecutar requests HTTP, DNS, TCP, o cualquier tipo de interacción de red de forma automática o por iniciativa propia.

**Why:** El usuario quiere control total sobre qué tráfico se genera. Requests no autorizados pueden alertar WAFs, IDS/IPS, dejar logs en el target, o salirse del scope sin querer.

**How to apply:**
- Ante cualquier escenario de explotación, presentar primero el escenario teórico completo: endpoint, método, headers, payload, impacto esperado.
- Esperar confirmación explícita del usuario ("ejecuta esto", "corre esto", "prueba esto") antes de lanzar cualquier comando que genere tráfico de red.
- Esto aplica a: curl, wget, requests Python, herramientas como sqlmap, ffuf, nmap, nuclei, nikto, nessus, burp en modo activo, etc.
- En modo teórico: mostrar el comando exacto listo para copiar/pegar, con flags y payload completo, pero no ejecutarlo.
- Nunca encadenar requests automáticamente aunque el paso anterior haya sido aprobado; cada interacción de red requiere aprobación individual.
