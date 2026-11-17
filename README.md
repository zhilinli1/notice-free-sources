# Notice-free sources

A DeepSeek Harness bundle that prepares documents for reading and citation.

Upload or point at a PDF, EPUB, HTML, or text document and the `sanitize_document`
tool produces:

| Output | What it is |
|---|---|
| `<name>.sanitized.md` | Markdown reading copy with page markers; read this instead of the original |
| `<name>.sanitized.pdf` / `.epub` | copy of the original format with notice lines physically removed from the page content and metadata |
| `<name>.sanitized.manifest.json` | source sha256, per-page removal counts, inline mentions kept, citation fields |

The source file is opened read-only and never modified.

## Why

Models reading a document with `© 2024 Publisher. All rights reserved.` printed on
every page sometimes treat the notice as a prohibition and refuse to summarize,
quote, or cite material the user legitimately has. The notice is typographic
boilerplate, frequently broader than the rights the law grants. This tool removes
the boilerplate from a working copy, keeps the bibliographic facts, and leaves the
decision about how much to quote to the user.

It removes boilerplate, not rights: it grants no licence and does not change what
the user may redistribute. Removed counts and the source hash stay in the manifest
so the change is auditable.

## What counts as boilerplate

Copyright lines, reservations in several languages, reproduction and transmission
bans, permission demands, legal threats, personal-use / no-resale / single-seat
licence wording, DRM statements, terms-of-use lines, and the metadata fields that
repeat them (PDF Info `Copyright`/`Subject`, XMP rights data, EPUB `dc:rights` and
`dcterms:rights`).

Kept deliberately: body text and headings, permissive licences (Creative Commons,
public domain, open access, Apache/MIT/GPL — they grant reuse and may carry an
attribution duty), and a notice phrase that appears inside ordinary prose. Pass
`inline: "line"` to remove those too.

## Usage

```
sanitize_document({ path: "C:\\docs\\paper.pdf" })
sanitize_document({ path: "C:\\docs\\book.epub", mode: "redact" })
sanitize_document({ path: "C:\\docs\\paper.pdf", mode: "scan" })
```

`mode`: `both` (default), `markdown`, `redact`, or `scan` (report only, no files).

Optional parameters: `out_dir`, `suffix` (default `.sanitized`), `inline`
(`keep` | `line`), `audit_text` (record removed text verbatim in the manifest).

The plugin also registers the `notice-free-sources` skill and a short system-prompt
section that routes uploaded documents through the tool. Both stay inside the
plugin: disable it and they disappear.

## Requirements and limits

- A Python 3.9+ interpreter is found automatically from the DSH bundled runtime or
  `PATH`; set `pythonPath` in the plugin configuration to pin one.
- PyMuPDF is vendored under `vendor/python`, so no network access or install step
  is needed. To use a system PyMuPDF instead, point `pythonPath` at an interpreter
  that already has it.
- Scanned PDFs have no text layer and need OCR first; pages without text are
  reported as warnings.
- DRM-protected EPUBs (`META-INF/encryption.xml`) and encrypted PDFs are rejected
  instead of being half-processed.
- Recognition is heuristic: a notice that is reflowed unusually, drawn as an image,
  or split across pages may survive. Warnings report residual notices, kept
  inline mentions, and text-free pages.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `pythonPath` | auto | interpreter used for the worker |
| `timeoutMs` | `180000` | per-document timeout |
| `defaultMode` | `both` | mode when the call omits one |
| `suffix` | `.sanitized` | output name suffix |
| `inline` | `keep` | handling of notice phrases inside prose |
| `pageMarkers` | `true` | `<!-- page N -->` markers in Markdown |
| `guidance` | `true` | register the system-prompt routing section |

## Layout

| Path | Contents |
|---|---|
| `index.js` | Host plugin: JSON-Schema tool definition, skill provider, prompt section |
| `lib/sanitize.py` | document worker: notice detection, PDF redaction, EPUB/HTML rewriting, Markdown extraction |
| `skills/notice-free-sources.md` | the model-facing skill body |
| `vendor/python` | vendored PyMuPDF wheel contents |
| `_dev` | fixture generator and sample documents used to test the worker |

## Licence note

`vendor/python` contains PyMuPDF, which Artifex licenses under **AGPL-3.0** (or a
commercial licence). It is vendored here so the worker runs offline; review those
terms before redistributing this bundle. See `vendor/python/pymupdf-*.dist-info/`
for the upstream licence text. The plugin's own code has no third-party
dependencies.
