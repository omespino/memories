---
name: rdoc — Document Review Command
description: When the user invokes /rdoc or asks to run rdoc, review the provided PDF with these specific instructions.
type: reference
---

When the user invokes `/rdoc` (or says "rdoc") and provides a PDF, perform ONLY a document review — nothing else.

## Review checklist

1. **Estilo de escritura** — Revisar que el lenguaje sea claro, profesional y consistente a lo largo del documento.
2. **Ortografía y gramática** — Identificar errores ortográficos, tildes faltantes, puntuación incorrecta y errores gramaticales.
3. **Coherencia** — Verificar que las secciones tengan hilo conductor, que las conclusiones correspondan con los hallazgos y que no haya contradicciones internas.
4. **Cliente único** — Confirmar que el documento NO mencione a ningún otro cliente. El nombre del cliente correcto aparece en la portada; el nombre del proyecto está en el título de la portada. Cualquier referencia a otro cliente es un error crítico.
5. **Proveedor** — El proveedor del informe es **WebSec**. Verificar que el nombre esté correcto en todo el documento.
6. **CVSS** — Revisar que los puntajes CVSS correspondan correctamente con la criticidad declarada de cada vulnerabilidad (severidad, vector, métricas). Reportar inconsistencias.
7. **Calidad general** — Evaluar formato, numeración de secciones, tablas, imágenes y presentación global.

## Output

Presentar los hallazgos organizados por categoría del checklist. Para cada problema encontrado, indicar: ubicación (página/sección), descripción del problema y sugerencia de corrección.
