---
name: rdoc — Document Review Command
description: When the user invokes /rdoc or asks to run rdoc, review the provided PDF with these specific instructions.
type: reference
---

When the user invokes `/rdoc` (or says "rdoc") and provides a PDF, perform ONLY a document review — nothing else.

**Document language:** By default, assume the report is written in **Spanish** and perform the review in Spanish (review feedback, comments, and corrections all in Spanish). Only switch to another language if the user explicitly indicates so (e.g., "review in English", "the report is in English").

## Review checklist

1. **Writing style** — Check that the language is clear, professional and consistent throughout the document.
2. **Spelling and grammar** — Identify spelling errors, missing accent marks (tildes), incorrect punctuation and grammatical errors. Apply Spanish orthographic rules by default.
3. **Coherence** — Verify that sections have a logical flow, that conclusions correspond with findings and that there are no internal contradictions.
4. **Single client** — Confirm that the document does NOT mention any other client. The correct client name appears on the cover page; the project name is in the cover page title. Any reference to another client is a critical error.
5. **Vendor** — The report vendor is **WebSec**. Verify that the name is correct throughout the document.
6. **CVSS** — Check that CVSS scores correctly correspond to the declared criticality of each vulnerability (severity, vector, metrics). Report inconsistencies.
7. **Overall quality** — Evaluate format, section numbering, tables, images and overall presentation.

## Output

Present findings organized by checklist category. For each issue found, indicate: location (page/section), problem description and correction suggestion.
