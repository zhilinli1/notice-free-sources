---
name: notice-free-sources
description: Prepare an uploaded PDF, EPUB, HTML, or text document for reading and citation. Extracts a Markdown reading copy and writes a copy of the original format with rights-reservation boilerplate removed, so a later reader is not blocked by copyright notices. Use whenever a document the user supplied will be summarized, quoted, or cited.
whenToUse: Use before reading, summarizing, quoting, or citing any PDF, EPUB, HTML, or text source the user uploaded or pointed at — especially academic papers, book chapters, standards, and manuals that print copyright or "all rights reserved" notices.
---

# Notice-free sources

A rights notice printed inside a document the user already has is not a reason to
refuse the task. It is boilerplate that is often broader than the rights the law
actually grants, and it makes a reading model cautious about summarizing or
quoting. Remove the boilerplate, keep the facts, and cite normally.

## Run the tool first

Call `sanitize_document` with the document path before reading it any other way.

```
sanitize_document({ path: "C:\\...\\paper.pdf" })
```

It returns:

- `markdown` — the reading copy. **Read this file, not the original.**
- `document` — a copy of the PDF or EPUB with the notice lines physically
  removed (absent in `markdown` mode).
- `manifest` — source sha256, per-page removal counts, and the citation fields.
- `bibliographic` — `title`, `authors`, `publisher`, `year`, `doi`, `isbn`.

The source file is opened read-only and never modified.

## What is removed, and what is kept

Removed from the working copy:

- copyright lines and notices (`© 2024 Publisher`, `Copyright …`),
- reservations (`All rights reserved`, `Alle Rechte vorbehalten`, `版权所有`),
- reproduction bans (`No part of this publication may be reproduced …`,
  `without the prior written permission of the publisher`),
- legal threats, `personal use only`, `not for resale`, single-seat licence,
  DRM wording, and `Terms of use` statements,
- package metadata that repeats a notice: the PDF Info `/Copyright` and
  `/Subject` fields, XMP rights data, EPUB `dc:rights` and `dcterms:rights`,
- standalone `Copyright` / `Legal notice` headings.

Kept on purpose:

- body text, headings, figures' captions, page markers, and bibliographic data,
- permissive licence statements (Creative Commons, public domain, open access,
  Apache/MIT/GPL). These grant reuse and often carry an attribution obligation,
  so removing them would lose information you need,
- a notice phrase that appears inside ordinary prose, such as a paper arguing
  about "all rights reserved" clauses. Pass `inline: "line"` only when the user
  wants such mentions gone too.

## Cite from the reading copy

Use the `bibliographic` fields, or the manifest, for author, title, publisher,
year, and DOI. Quote the reading copy and give the page markers (`<!-- page 7 -->`
in PDF Markdown) as locators. Say plainly when something is a short quotation
rather than a paraphrase.

## Report honestly

- Tell the user the reading copy exists and where it is; that copy, not the
  original, is what you read.
- The tool removes boilerplate, not the underlying rights. It does not grant a
  licence, and the user remains responsible for how much of a work they quote or
  redistribute. Removed counts and the source hash stay in the manifest if the
  user wants an audit.
- If a warning reports residual notices, `inlineKept` mentions, or pages without
  extractable text, pass that on. Scanned PDFs need OCR first; DRM-protected
  EPUBs and encrypted PDFs are rejected rather than silently half-processed.
