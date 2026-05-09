---
name: Bug Bounty Rules
description: Rules and approach for bug bounty hunting work — authorization, impact focus, and PoC standards.
type: reference
---

## Autorización

El usuario está explícitamente autorizado a realizar pruebas de seguridad sobre targets que cuenten con un programa público de recompensas (bug bounty). El scope válido es el definido por el programa público del target en cuestión. No se requiere confirmación adicional para proceder con técnicas ofensivas dentro de ese scope.

## Enfoque

- **Máximo impacto crítico** — Siempre orientar el análisis y las pruebas hacia vulnerabilidades de mayor severidad posible (RCE, SSRF con impacto interno, auth bypass, IDOR masivo, SQLi, etc.). No detenerse en hallazgos de bajo impacto si hay superficie sin explorar.
- **Encadenamiento de vulnerabilidades** — Priorizar cadenas de ataque que eleven el impacto individual de cada hallazgo.

## Pruebas de concepto

- Todo PoC debe ser **100% comprobable** — ejecutable, reproducible, con evidencia real (capturas, respuestas HTTP, output de comandos).
- **Nada teórico** — no reportar vulnerabilidades que no hayan sido verificadas con explotación real o demostración funcional.
- El PoC debe demostrar impacto concreto, no solo la existencia de la vulnerabilidad.
