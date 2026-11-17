#!/usr/bin/env python3
"""Notice-free document worker.

Reads a JSON job file, prepares a readable working copy of one document, and
writes a JSON result file.  Two independent outputs are possible:

* a Markdown extraction that a model reads directly, and
* a copy of the original format (PDF or EPUB) with notice lines physically
  removed from the page content and metadata.

The source file is opened read-only and never modified in place.

Run as::

    python sanitize.py <job.json> <result.json>
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unicodedata
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote

SCHEMA = "dsh-notice-free-sources/manifest@1"
MAX_ENTRIES = 400
MAX_CONTINUATION_LINES = 8
MAX_CONTINUATION_CHARS = 1400

# --------------------------------------------------------------------------
# Pattern table
# --------------------------------------------------------------------------
# kind: reserve | reproduce | threat | restriction | permissive
#
# "permissive" patterns are kept by default: a licence that grants reuse does
# not block citation, and its notice can carry an attribution obligation.

PATTERNS: list[tuple[str, str, str]] = [
    # -- reservations ------------------------------------------------------
    ("reservation", "reserve", r"\ball\s+rights\s+(?:are\s+)?reserved\b"),
    (
        "reservation-i18n",
        "reserve",
        r"\b(?:alle\s+rechte\s+vorbehalten|todos\s+los\s+derechos\s+reservados"
        r"|tous\s+droits\s+r[eé]serv[eé]s|alle\s+rechten\s+voorbehouden)\b",
    ),
    (
        "reservation-cjk",
        "reserve",
        r"(?:版权所有|版權所有|無断転載を禁じ|無断複写|転載を禁じ|複製を禁ず)",
    ),
    ("copyright-mark", "reserve", r"(?:©|\(c\)|copyright)\s*(?:19|20)\d{2}"),
    ("copyright-mark-cjk", "reserve", r"(?:©|版权所有|版權所有|著作権)\s*(?:19|20)\d{2}"),
    (
        "copyright-owner",
        "reserve",
        r"\bcopyright\s+(?:by|of|holder|owner|notice|law)\b"
        r"|\bcopyright\s+and\s+(?:related|moral)\s+rights\b"
        r"|\bmoral\s+rights?\b",
    ),
    (
        "protected-work",
        "reserve",
        r"\bprotected\s+by\s+copyright\b"
        r"|\bcopyright[-\s]protected\b"
        r"|\bsubject\s+to\s+copyright\b"
        r"|\bthis\s+(?:work|book|article|document|publication)\s+is\s+copyrighted\b",
    ),
    # -- reproduction bans -------------------------------------------------
    (
        "no-part",
        "reproduce",
        r"\bno\s+part\s+of\s+this\s+(?:publication|book|work|document|e-?book"
        r"|title|volume|article|text|material|site|website|edition)\b",
    ),
    (
        "may-not",
        "reproduce",
        r"\bmay\s+not\s+be\s+(?:reproduced|reprinted|stored|transmitted|distributed"
        r"|copied|used|shared|resold)\b",
    ),
    (
        "without-permission",
        "reproduce",
        r"\bwithout\s+(?:the\s+)?(?:prior\s+)?(?:written\s+)?(?:express\s+)?permission\b"
        r"|\bpermission\s+of\s+the\s+(?:publisher|copyright\s+holder|author)\b",
    ),
    (
        "reproduction-banned",
        "reproduce",
        r"\b(?:reproduction|copying|redistribution|duplication|re-?transmission)"
        r"\s+(?:is\s+)?(?:strictly\s+|otherwise\s+)?(?:prohibited|forbidden|not\s+permitted)\b"
        r"|\b(?:strictly\s+)?prohibited\s+without\b",
    ),
    (
        "cjk-no-copy",
        "reproduce",
        r"(?:未经|未經|不得|严禁|嚴禁|禁止)[^。！？\n]{0,14}"
        r"(?:复制|複製|转载|轉載|翻印|传播|傳播|摘编|使用)",
    ),
    # -- threats and penalties --------------------------------------------
    (
        "legal-threat",
        "threat",
        r"\bviolators?\s+(?:will|shall|may)\s+be\s+prosecuted\b"
        r"|\b(?:civil|criminal)\s+(?:prosecution|penalt(?:y|ies)|liability|action)\b"
        r"|\bstatutory\s+damages\b"
        r"|\bfines?\s+of\s+up\s+to\b"
        r"|\bwill\s+be\s+(?:prosecuted|liable)\b",
    ),
    # -- use restrictions --------------------------------------------------
    (
        "personal-use",
        "restriction",
        r"\bfor\s+(?:your\s+)?(?:personal|private|individual|non-?commercial)"
        r"\s+(?:use|study|reference)\s+only\b"
        r"|\bpersonal\s+use\s+only\b",
    ),
    (
        "no-resale",
        "restriction",
        r"\bnot\s+for\s+(?:resale|redistribution|resell|commercial\s+use|sale)\b"
        r"|\bmust\s+not\s+be\s+(?:sold|resold|rented|lent)\b",
    ),
    (
        "licensed-copy",
        "restriction",
        r"\b(?:this\s+(?:copy|ebook|e-book|document|file|pdf)\s+is\s+)?"
        r"licen[cs]ed\s+(?:to|for\s+(?:a\s+)?(?:single|one))\b"
        r"|\bsingle[-\s](?:user|use|seat)\s+licen[cs]e\b",
    ),
    (
        "drm",
        "restriction",
        r"\bdigital\s+rights\s+management\b|\bdrm[-\s]?(?:protected|free|encrypted)\b",
    ),
    (
        "terms-of-use",
        "restriction",
        r"\bterms\s+and\s+conditions\s+(?:of\s+use|apply)\b"
        r"|\bterms\s+of\s+use\b"
        r"|\ball\s+use\s+is\s+subject\s+to\b",
    ),
    # -- permissive licences (kept by default) -----------------------------
    (
        "permissive",
        "permissive",
        r"\bcreative\s+commons\b"
        r"|\bcc[-\s]by\b"
        r"|\bpublic\s+domain\b"
        r"|\bopen[-\s]access\b"
        r"|\blicensed\s+under\s+(?:the\s+)?(?:creative|apache|mit|gnu|cc|bsd|mozilla)\b"
        r"|\b(?:apache|mit|bsd|gpl|lgpl|mozilla\s+public)\s+licen[cs]e\b",
    ),
]

COMPILED: list[tuple[str, str, re.Pattern[str]]] = [
    (pid, kind, re.compile(rx, re.IGNORECASE)) for pid, kind, rx in PATTERNS
]

CONTINUATION_WORDS = re.compile(
    r"(?:permission|prohibit|reproduc|retrieval|transmit|distribut|stored|written"
    r"|publisher|copyright|reserved|rights|form|means|otherwise|electronic"
    r"|mechanical|photocopy|recording|许可|轉載|转载|复制|複製|传播|傳播)",
    re.IGNORECASE,
)

# Patterns that only corroborate a notice; they never trigger removal alone.
WEAK_PATTERNS = frozenset({"terms-of-use", "drm"})

SENTENCE_END = re.compile(r"[.!?。！？][\"'”’)\]]?\s*$")
HEADING_ONLY = re.compile(
    r"^(?:copyright|legal\s+notice|rights\s+notice|notice|colophon"
    r"|版权|版權|版权声明|版權聲明)$",
    re.IGNORECASE,
)


def clean_text(value: str) -> str:
    """Collapse whitespace and drop invisible characters used in matching."""
    if not value:
        return ""
    value = (
        value.replace("\u00ad", "")
        .replace("\u200b", "")
        .replace("\ufeff", "")
        .replace("\u00a0", " ")
    )
    return re.sub(r"\s+", " ", value).strip()


def fold(value: str) -> str:
    """Normalize for matching only; never for writing back."""
    return unicodedata.normalize("NFKC", value).casefold()


def find_isbn(text: str) -> str:
    """Return the first well-formed ISBN in text, or an empty string."""
    for match in re.finditer(r"\b(?:97[89][\s-]?)?(?:\d[\s-]?){8,11}[\dXx]\b", text or ""):
        raw = clean_text(match.group(0))
        digits = re.sub(r"[^0-9Xx]", "", raw)
        if len(digits) in (10, 13):
            return raw
    return ""


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------


@dataclass
class Verdict:
    kind: str  # notice | inline | permissive
    patterns: list[str] = field(default_factory=list)
    coverage: float = 0.0


def _merged_len(spans: Iterable[tuple[int, int]]) -> int:
    ordered = sorted(spans)
    total = 0
    end = -1
    for start, stop in ordered:
        start = max(start, end)
        if stop > start:
            total += stop - start
            end = stop
    return total


def classify(text: str) -> Verdict | None:
    """Decide whether one line or paragraph is a rights notice."""
    raw = clean_text(text)
    if len(raw) < 4:
        return None
    folded = fold(raw)
    hits: list[tuple[str, str, int, int]] = []
    for pid, kind, rx in COMPILED:
        for match in rx.finditer(folded):
            hits.append((pid, kind, match.start(), match.end()))
    if not hits:
        return None

    strong = [h for h in hits if h[1] != "permissive"]
    if not strong:
        return Verdict("permissive", sorted({h[0] for h in hits}), 0.0)

    covered = _merged_len([(h[2], h[3]) for h in strong])
    coverage = covered / max(len(folded), 1)
    patterns = sorted({h[0] for h in strong})

    # Weak patterns describe a document as a whole; alone they do not make a
    # prose line a notice, so they never decide removal by themselves.
    if not any(pid not in WEAK_PATTERNS for pid in patterns) and coverage < 0.5:
        return Verdict("inline", patterns, coverage)
    if coverage >= 0.30:
        return Verdict("notice", patterns, coverage)
    if len(folded) <= 90 and coverage >= 0.10:
        return Verdict("notice", patterns, coverage)
    if len(folded) <= 140 and coverage >= 0.15:
        return Verdict("notice", patterns, coverage)
    return Verdict("inline", patterns, coverage)


# --------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------


@dataclass
class PdfLine:
    block: int
    number: int
    text: str
    rect: Any
    words: list[tuple]


def pdf_lines(page: Any, pymupdf: Any) -> list[PdfLine]:
    """Group the page's words into visual lines with tight bounding boxes."""
    groups: dict[tuple[int, int], list[tuple]] = {}
    order: list[tuple[int, int]] = []
    for word in page.get_text("words"):
        key = (word[5], word[6])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(word)

    lines: list[PdfLine] = []
    for key in order:
        words = sorted(groups[key], key=lambda w: w[7])
        text = " ".join(w[4] for w in words)
        rect = pymupdf.Rect(
            min(w[0] for w in words),
            min(w[1] for w in words),
            max(w[2] for w in words),
            max(w[3] for w in words),
        )
        lines.append(PdfLine(key[0], key[1], text, rect, words))
    return lines


def _continues(lines: list[PdfLine], index: int, chars: int) -> bool:
    """Whether line ``index + 1`` continues the notice sentence at ``index``."""
    current, nxt = lines[index], lines[index + 1]
    if current.block != nxt.block:
        return False
    if SENTENCE_END.search(current.text):
        return False
    if len(clean_text(nxt.text)) > 200:
        return False
    if chars + len(nxt.text) > MAX_CONTINUATION_CHARS:
        return False
    stripped = clean_text(nxt.text)
    if not stripped:
        return False
    if stripped[0].islower() or CONTINUATION_WORDS.search(stripped):
        return True
    return classify(stripped) is not None


def plan_pdf_page(
    lines: list[PdfLine], inline_policy: str
) -> tuple[list[list[PdfLine]], list[dict[str, Any]]]:
    """Return line groups to remove plus inline mentions left in place."""
    groups: list[list[PdfLine]] = []
    inline: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        verdict = classify(lines[index].text)
        if verdict is not None and verdict.kind == "notice":
            group = [lines[index]]
            chars = len(lines[index].text)
            cursor = index
            while (
                cursor + 1 < len(lines)
                and len(group) < MAX_CONTINUATION_LINES
                and _continues(lines, cursor, chars)
            ):
                cursor += 1
                chars += len(lines[cursor].text)
                group.append(lines[cursor])
            groups.append(group)
            index = cursor + 1
            continue
        if verdict is not None and verdict.kind == "inline":
            if inline_policy == "line":
                groups.append([lines[index]])
            else:
                inline.append(
                    {
                        "line": index + 1,
                        "patterns": verdict.patterns,
                        "coverage": round(verdict.coverage, 3),
                        "chars": len(clean_text(lines[index].text)),
                    }
                )
        index += 1
    return groups, inline


def _read_pdf_metadata(doc: Any, pymupdf: Any) -> dict[str, Any]:
    info = doc.metadata or {}
    fields: dict[str, Any] = {}
    title = clean_text(info.get("title") or "")
    author = clean_text(info.get("author") or "")
    if title and classify(title) is None:
        fields["title"] = title
    if author and classify(author) is None:
        names = [part.strip() for part in re.split(r"[;,]|\band\b", author) if part.strip()]
        if names:
            fields["authors"] = names

    xml = ""
    try:
        xml = doc.get_xml_metadata() or ""
    except Exception:  # pragma: no cover - older builds
        xml = ""

    def first(pattern: str) -> str:
        match = re.search(pattern, xml, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        return clean_text(re.sub(r"<[^>]+>", "", match.group(1)))

    for key, pattern in (
        ("publisher", r"<dc:publisher>(.*?)</dc:publisher>"),
        ("language", r"<dc:language>(.*?)</dc:language>"),
        ("doi", r"<prism:doi>(.*?)</prism:doi>"),
        ("isbn", r"<prism:isbn[^>]*>(.*?)</prism:isbn>"),
    ):
        value = first(pattern)
        if value and classify(value) is None:
            fields[key] = value

    if "title" not in fields:
        xmp_title = first(r"<dc:title>(.*?)</dc:title>")
        if xmp_title and classify(xmp_title) is None:
            fields["title"] = xmp_title

    year = ""
    creation = clean_text(info.get("creationDate") or "")
    if creation:
        found = re.search(r"(19|20)\d{2}", creation)
        if found:
            year = found.group(0)
    if not year:
        year = first(r"<dc:date>(.*?)</dc:date>")[:4]
    if year and re.fullmatch(r"(19|20)\d{2}", year):
        fields["year"] = year
    return fields


def _scan_bibliography(pages_text: str, fields: dict[str, Any]) -> dict[str, Any]:
    if "doi" not in fields:
        match = re.search(r"\b10\.\d{4,9}/[-._;()/:a-zA-Z0-9]+", pages_text)
        if match:
            fields["doi"] = match.group(0).rstrip(".,;)")
    if "isbn" not in fields:
        isbn = find_isbn(pages_text)
        if isbn:
            fields["isbn"] = isbn
    return fields


def _block_text(block: dict[str, Any]) -> tuple[str, float]:
    """Join one text block's lines, undoing end-of-line hyphenation."""
    text = ""
    largest = 0.0
    for line in block.get("lines", []):
        spans = line.get("spans", [])
        if not spans:
            continue
        piece = "".join(span.get("text", "") for span in spans).strip()
        for span in spans:
            largest = max(largest, float(span.get("size") or 0.0))
        if not piece:
            continue
        if not text:
            text = piece
        elif text.endswith("-"):
            text = text + piece
        else:
            text = text + " " + piece
    return clean_text(text), largest


def _pdf_to_markdown(doc: Any, page_markers: bool) -> str:
    """Render a readable Markdown approximation from positioned text blocks."""
    sizes: dict[float, int] = {}
    pages: list[list[tuple[str, float]]] = []
    for page in doc:
        blocks: list[tuple[str, float]] = []
        for block in page.get_text("dict").get("blocks", []):
            if block.get("type") != 0:
                continue
            text, size = _block_text(block)
            if not text:
                continue
            blocks.append((text, size))
            rounded = round(size * 2) / 2
            sizes[rounded] = sizes.get(rounded, 0) + len(text)
        pages.append(blocks)

    body = max(sizes, key=lambda key: sizes[key]) if sizes else 10.0

    chunks: list[str] = []
    for number, blocks in enumerate(pages, start=1):
        parts: list[str] = []
        for text, size in blocks:
            if size >= body * 1.45:
                parts.append(f"## {text}")
            elif size >= body * 1.18:
                parts.append(f"### {text}")
            else:
                parts.append(text)
        if page_markers:
            chunks.append(f"<!-- page {number} -->")
        if parts:
            chunks.append("\n\n".join(parts))
    return "\n\n".join(chunks)


def sanitize_pdf(path: Path, options: dict[str, Any]) -> dict[str, Any]:
    try:
        import pymupdf  # type: ignore
    except ImportError:  # pragma: no cover - PyMuPDF < 2 exposes fitz
        import fitz as pymupdf  # type: ignore

    doc = pymupdf.open(path)
    try:
        if doc.needs_pass:
            raise RuntimeError("encrypted PDF: unlock it before sanitizing")

        bibliographic = _read_pdf_metadata(doc, pymupdf)
        raw_text = "\n".join(page.get_text("text") for page in doc)
        bibliographic = _scan_bibliography(raw_text, bibliographic)

        removals: list[dict[str, Any]] = []
        inline: list[dict[str, Any]] = []
        empty_pages: list[int] = []
        total_chars = 0

        for number, page in enumerate(doc, start=1):
            lines = pdf_lines(page, pymupdf)
            if not lines:
                empty_pages.append(number)
                continue
            groups, mentions = plan_pdf_page(lines, options["inline"])
            for entry in mentions:
                entry["page"] = number
                inline.append(entry)
            for group in groups:
                rects = [line.rect for line in group]
                for rect in rects:
                    page.add_redact_annot(rect)
                text = " ".join(line.text for line in group)
                total_chars += len(text)
                if len(removals) < MAX_ENTRIES:
                    record: dict[str, Any] = {
                        "page": number,
                        "kind": "notice",
                        "lines": len(group),
                        "chars": len(text),
                        "patterns": sorted(
                            {
                                pid
                                for line in group
                                for verdict in [classify(line.text)]
                                if verdict is not None
                                for pid in verdict.patterns
                            }
                        ),
                    }
                    if options["audit_text"]:
                        record["text"] = text
                    removals.append(record)

        images = getattr(pymupdf, "PDF_REDACT_IMAGE_NONE", 0)
        graphics = getattr(pymupdf, "PDF_REDACT_LINE_ART_NONE", 0)
        for page in doc:
            try:
                if not list(page.annots() or []):
                    continue
                page.apply_redactions(images=images, graphics=graphics)
            except TypeError:  # pragma: no cover - older signatures
                page.apply_redactions()

        residual = 0
        if doc.page_count and removals:
            for page in doc:
                for line in pdf_lines(page, pymupdf):
                    verdict = classify(line.text)
                    if verdict is not None and verdict.kind == "notice":
                        residual += 1

        markdown = _pdf_to_markdown(doc, options["page_markers"])

        result: dict[str, Any] = {
            "format": "pdf",
            "pages": doc.page_count,
            "bibliographic": bibliographic,
            "removals": removals,
            "inline": inline,
            "emptyPages": empty_pages,
            "removedChars": total_chars,
            "residual": residual,
            "markdown": markdown,
        }

        if options["redact"]:
            allowed = (
                "author", "title", "subject", "keywords", "creator", "producer",
                "creationDate", "modDate", "trapped",
            )
            current = doc.metadata or {}
            info: dict[str, str] = {}
            for key in allowed:
                value = current.get(key) or ""
                verdict = classify(value) if value else None
                info[key] = "" if verdict is not None and verdict.kind == "notice" else value
            try:
                doc.set_metadata(info)
            except Exception:
                pass
            try:
                if hasattr(doc, "del_xml_metadata"):
                    doc.del_xml_metadata()
                else:  # pragma: no cover - older builds
                    doc.set_xml_metadata("<x:xmpmeta xmlns:x='adobe:ns:meta/'/>")
            except Exception:
                pass
            target = options["document_path"]
            doc.save(target, garbage=4, deflate=True, clean=True)
            result["document"] = str(target)

        return result
    finally:
        doc.close()


def verify_saved_pdf(path: Path) -> list[str]:
    """Reopen a saved PDF and report rights text that survived anywhere."""
    try:
        import pymupdf  # type: ignore
    except ImportError:  # pragma: no cover
        import fitz as pymupdf  # type: ignore

    findings: list[str] = []
    doc = pymupdf.open(path)
    try:
        for key, value in (doc.metadata or {}).items():
            if isinstance(value, str) and value:
                verdict = classify(value)
                if verdict is not None and verdict.kind == "notice":
                    findings.append(f"metadata field '{key}'")
        for number, page in enumerate(doc, start=1):
            for line in pdf_lines(page, pymupdf):
                verdict = classify(line.text)
                if verdict is not None and verdict.kind == "notice":
                    findings.append(f"page {number} text")
                    break
    finally:
        doc.close()
    return findings


def verify_saved_epub(path: Path) -> list[str]:
    """Reopen a saved EPUB and report rights text that survived anywhere."""
    findings: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if not name.lower().endswith((".xhtml", ".html", ".htm", ".opf", ".ncx")):
                continue
            text = archive.read(name).decode("utf-8", "replace")
            if name.lower().endswith(".opf") and re.search(r"rights", text, re.IGNORECASE):
                findings.append(f"{name} metadata")
                continue
            if ".opf" in name.lower():
                continue
            from lxml import html as lxml_html

            try:
                document = lxml_html.document_fromstring(text)
            except Exception:
                continue
            for element in document.iter():
                if not isinstance(element.tag, str):
                    continue
                content = clean_text(" ".join(element.itertext()))
                if not content:
                    continue
                verdict = classify(content)
                if verdict is not None and verdict.kind == "notice":
                    findings.append(f"{name} text")
                    break
    return findings


# --------------------------------------------------------------------------
# EPUB / HTML
# --------------------------------------------------------------------------


def _scrub_markup(source: bytes | str, options: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Remove notice elements and headings from one HTML/XHTML document."""
    from lxml import html as lxml_html
    from lxml import etree

    if isinstance(source, bytes):
        document = lxml_html.document_fromstring(source)
    else:
        document = lxml_html.document_fromstring(
            re.sub(r"^\s*<\?xml[^>]*\?>", "", source)
        )

    removals: list[dict[str, Any]] = []
    inline: list[dict[str, Any]] = []

    def local_name(element: Any) -> str:
        tag = element.tag
        if not isinstance(tag, str):
            return ""
        return tag.rsplit("}", 1)[-1].lower()

    block_tags = {
        "p", "div", "section", "article", "blockquote", "li", "h1", "h2", "h3",
        "h4", "h5", "h6", "td", "th", "dd", "dt", "figcaption", "header", "footer",
        "aside", "pre",
    }

    # Notification-shaped metadata that is not body text: the document title and
    # a meta description are the two places a notice hides outside the body.
    for element in list(document.iter()):
        if not isinstance(element.tag, str):
            continue
        name = local_name(element)
        if name == "title":
            text = clean_text(" ".join(element.itertext()))
            if text and HEADING_ONLY.match(text):
                element.text = ""
                for child in list(element):
                    element.remove(child)
                removals.append({"kind": "title", "chars": len(text), "patterns": ["notice-heading"]})
        elif name == "meta":
            content = element.get("content") or ""
            verdict = classify(content) if content else None
            if verdict is not None and verdict.kind == "notice":
                element.set("content", "")
                removals.append({"kind": "meta", "chars": len(content), "patterns": verdict.patterns})

    for element in list(document.iter()):
        if not isinstance(element.tag, str):
            continue
        name = local_name(element)
        if name not in block_tags:
            continue
        text = clean_text(" ".join(element.itertext()))
        if not text:
            continue
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"} and HEADING_ONLY.match(text):
            parent = element.getparent()
            if parent is not None:
                removals.append({"kind": "heading", "chars": len(text), "patterns": ["notice-heading"]})
                parent.remove(element)
            continue
        # A container whose text is just the aggregated text of descendants that
        # are themselves handled; only judge leaf-ish blocks to avoid double work.
        if any(isinstance(child.tag, str) and local_name(child) in block_tags for child in element):
            continue
        verdict = classify(text)
        if verdict is None:
            continue
        if verdict.kind == "notice":
            parent = element.getparent()
            if parent is None:
                continue
            record: dict[str, Any] = {
                "kind": "element",
                "chars": len(text),
                "patterns": verdict.patterns,
            }
            if options["audit_text"]:
                record["text"] = text
            removals.append(record)
            parent.remove(element)
        elif verdict.kind == "inline":
            if options["inline"] == "line":
                parent = element.getparent()
                if parent is not None:
                    removals.append(
                        {
                            "kind": "element",
                            "chars": len(text),
                            "patterns": verdict.patterns,
                        }
                    )
                    parent.remove(element)
            else:
                inline.append(
                    {
                        "patterns": verdict.patterns,
                        "coverage": round(verdict.coverage, 3),
                        "chars": len(text),
                    }
                )

    serialized = lxml_html.tostring(document, encoding="unicode", method="html")
    return serialized, removals, inline


def _html_to_markdown(source: str) -> str:
    from lxml import html as lxml_html

    document = lxml_html.document_fromstring(re.sub(r"^\s*<\?xml[^>]*\?>", "", source))
    lines: list[str] = []

    def walk(element: Any, depth: int = 0) -> None:
        tag = element.tag if isinstance(element.tag, str) else ""
        name = tag.rsplit("}", 1)[-1].lower() if tag else ""
        if name in {"script", "style", "head", "nav"}:
            return
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            text = clean_text(" ".join(element.itertext()))
            if text:
                level = int(name[1])
                lines.append("#" * min(level + 1, 6) + " " + text)
            return
        if name in {"p", "div", "section", "article", "blockquote", "pre", "figcaption"}:
            text = clean_text(" ".join(element.itertext()))
            if text:
                lines.append(text)
            return
        if name == "li":
            text = clean_text(" ".join(element.itertext()))
            if text:
                lines.append("- " + text)
            return
        if name in {"br"}:
            return
        for child in element:
            if isinstance(child.tag, str):
                walk(child, depth + 1)

    body = document.find(".//body")
    root = body if body is not None else document
    for child in root:
        if isinstance(child.tag, str):
            walk(child)
    # De-duplicate consecutive identical paragraphs left by nested blocks.
    deduped: list[str] = []
    for line in lines:
        if not deduped or deduped[-1] != line:
            deduped.append(line)
    return "\n\n".join(deduped)


def sanitize_epub(path: Path, options: dict[str, Any]) -> dict[str, Any]:
    from lxml import etree

    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "META-INF/encryption.xml" in names:
            raise RuntimeError(
                "DRM-protected EPUB (META-INF/encryption.xml): remove the DRM first"
            )
        payload = {name: archive.read(name) for name in names}
        infos = {name: archive.getinfo(name) for name in names}

    container = etree.fromstring(payload["META-INF/container.xml"])
    rootfile = container.find(".//{*}rootfile")
    if rootfile is None:
        raise RuntimeError("EPUB container.xml has no rootfile")
    opf_path = rootfile.get("full-path")
    if not opf_path or opf_path not in payload:
        raise RuntimeError("EPUB package document is missing")

    opf_text = payload[opf_path].decode("utf-8", "replace")
    bibliographic = _epub_bibliography(opf_text)

    runtime_ns = "{http://www.idpf.org/2007/opf}"
    opf = etree.fromstring(payload[opf_path])
    manifest_items: dict[str, str] = {}
    media_types: dict[str, str] = {}
    for item in opf.iter(f"{runtime_ns}item"):
        item_id = item.get("id")
        href = item.get("href")
        if item_id and href:
            manifest_items[item_id] = href
            media_types[href] = (item.get("media-type") or "").lower()
    spine_paths: list[str] = []
    for itemref in opf.iter(f"{runtime_ns}itemref"):
        item_id = itemref.get("idref")
        if item_id and item_id in manifest_items:
            spine_paths.append(manifest_items[item_id])

    opf_dir = os.path.dirname(opf_path)

    def resolve_href(href: str) -> str:
        href = unquote(href)
        if opf_dir:
            return os.path.normpath(os.path.join(opf_dir, href)).replace("\\", "/")
        return href

    # Package metadata: drop rights statements and notice-only descriptions.
    scrubbed_opf = re.sub(
        r"<(?:\w+:)?rights\b[^>]*>.*?</(?:\w+:)?rights>",
        "",
        opf_text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    scrubbed_opf = re.sub(
        r"<meta\b[^>]*(?:property|name)=\"(?:dcterms:rights|dc:rights|rights)\"[^>]*?(?:/>|>.*?</meta>)",
        "",
        scrubbed_opf,
        flags=re.IGNORECASE | re.DOTALL,
    )
    payload[opf_path] = scrubbed_opf.encode("utf-8")
    metadata_removals = len(
        re.findall(
            r"<(?:\w+:)?rights\b[^>]*>", opf_text, re.IGNORECASE
        )
    ) + len(
        re.findall(
            r"<meta\b[^>]*(?:property|name)=\"(?:dcterms:rights|dc:rights|rights)\"",
            opf_text,
            re.IGNORECASE,
        )
    )

    removals: list[dict[str, Any]] = []
    inline: list[dict[str, Any]] = []
    documents: list[tuple[str, str]] = []

    for href in spine_paths:
        full = resolve_href(href)
        if full not in payload:
            continue
        media = media_types.get(href, "")
        if media and "html" not in media and "xml" not in media:
            continue
        raw = payload[full]
        try:
            cleaned, found, mentions = _scrub_markup(raw, options)
        except Exception as error:  # pragma: no cover - malformed markup
            removals.append({"kind": "error", "doc": full, "chars": 0, "patterns": [str(error)]})
            continue
        if raw.lstrip().startswith(b"<?xml") and not cleaned.lstrip().startswith("<?xml"):
            cleaned = '<?xml version="1.0" encoding="utf-8"?>\n' + cleaned
        for record in found:
            record["doc"] = full
            removals.append(record)
        for record in mentions:
            record["doc"] = full
            inline.append(record)
        payload[full] = cleaned.encode("utf-8")
        documents.append((full, cleaned))

    markdown_chunks: list[str] = []
    for index, (full, cleaned) in enumerate(documents, start=1):
        if options["page_markers"]:
            markdown_chunks.append(f"<!-- document {index}: {os.path.basename(full)} -->")
        body = _html_to_markdown(cleaned)
        if body.strip():
            markdown_chunks.append(body)

    result: dict[str, Any] = {
        "format": "epub",
        "pages": len(documents),
        "bibliographic": bibliographic,
        "removals": removals,
        "inline": inline,
        "emptyPages": [],
        "removedChars": sum(int(record.get("chars", 0)) for record in removals),
        "residual": 0,
        "markdown": "\n\n".join(markdown_chunks),
        "metadataRemovals": max(metadata_removals, 0),
    }

    if options["redact"]:
        target = options["document_path"]
        with zipfile.ZipFile(target, "w") as out:
            ordered = [name for name in names if name == "mimetype"]
            ordered += [name for name in names if name != "mimetype"]
            for name in ordered:
                info = zipfile.ZipInfo(name, date_time=infos[name].date_time)
                info.compress_type = zipfile.ZIP_STORED if name == "mimetype" else zipfile.ZIP_DEFLATED
                info.external_attr = infos[name].external_attr
                out.writestr(info, payload[name])
        result["document"] = str(target)

    return result


def _epub_bibliography(opf_text: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}

    def grab(pattern: str) -> str:
        match = re.search(pattern, opf_text, re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        return clean_text(re.sub(r"<[^>]+>", "", match.group(1)))

    title = grab(r"<(?:\w+:)?title\b[^>]*>(.*?)</(?:\w+:)?title>")
    if title and classify(title) is None:
        fields["title"] = title
    publisher = grab(r"<(?:\w+:)?publisher\b[^>]*>(.*?)</(?:\w+:)?publisher>")
    if publisher and classify(publisher) is None:
        fields["publisher"] = publisher
    language = grab(r"<(?:\w+:)?language\b[^>]*>(.*?)</(?:\w+:)?language>")
    if language:
        fields["language"] = language
    creators = re.findall(
        r"<(?:\w+:)?creator\b[^>]*>(.*?)</(?:\w+:)?creator>",
        opf_text,
        re.IGNORECASE | re.DOTALL,
    )
    names = [clean_text(re.sub(r"<[^>]+>", "", value)) for value in creators]
    names = [name for name in names if name and classify(name) is None]
    if names:
        fields["authors"] = names
    date = grab(r"<(?:\w+:)?date\b[^>]*>(.*?)</(?:\w+:)?date>")
    year = re.search(r"(19|20)\d{2}", date or "")
    if year:
        fields["year"] = year.group(0)
    identifier = grab(r"<(?:\w+:)?identifier\b[^>]*>(.*?)</(?:\w+:)?identifier>")
    isbn = find_isbn(identifier)
    if isbn:
        fields["isbn"] = isbn
    return fields


# --------------------------------------------------------------------------
# Plain text and standalone HTML
# --------------------------------------------------------------------------


def _scrub_plain(text: str, options: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    removals: list[dict[str, Any]] = []
    inline: list[dict[str, Any]] = []
    kept: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        verdict = classify(line)
        if verdict is not None and verdict.kind == "notice":
            record: dict[str, Any] = {
                "page": number,
                "kind": "line",
                "chars": len(line),
                "patterns": verdict.patterns,
            }
            if options["audit_text"]:
                record["text"] = line
            removals.append(record)
            continue
        if verdict is not None and verdict.kind == "inline":
            if options["inline"] == "line":
                removals.append({"page": number, "kind": "line", "chars": len(line), "patterns": verdict.patterns})
                continue
            inline.append(
                {
                    "page": number,
                    "patterns": verdict.patterns,
                    "coverage": round(verdict.coverage, 3),
                    "chars": len(line),
                }
            )
        kept.append(line)
    return "\n".join(kept), removals, inline


def scrub_markdown(text: str, options: dict[str, Any]) -> tuple[str, int]:
    """Final pass over generated Markdown; never rewrites inline prose."""
    kept: list[str] = []
    removed = 0
    for line in text.splitlines():
        stripped = re.sub(r"^[#>*\-+\s]+", "", line).strip()
        verdict = classify(stripped)
        if verdict is not None and verdict.kind == "notice":
            removed += 1
            continue
        kept.append(line)
    return "\n".join(kept), removed


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".epub":
        return "epub"
    if suffix in {".html", ".htm", ".xhtml"}:
        return "html"
    if suffix in {".txt", ".md", ".markdown", ".rst", ".text"}:
        return "text"
    raise RuntimeError("unsupported file type: " + (suffix or "no extension"))


def run(job: dict[str, Any]) -> dict[str, Any]:
    source = Path(job["path"]).expanduser().resolve()
    if not source.is_file():
        raise RuntimeError(f"no such file: {source}")
    fmt = detect_format(source)

    mode = job.get("mode") or "both"
    if mode not in {"both", "markdown", "redact", "scan"}:
        raise RuntimeError(f"unsupported mode: {mode}")
    wants_markdown = mode in {"both", "markdown"}
    wants_document = mode in {"both", "redact"}
    wants_files = mode != "scan"

    suffix = job.get("suffix") or ".sanitized"
    out_dir = Path(job.get("outDir") or source.parent).expanduser().resolve()
    if wants_files:
        out_dir.mkdir(parents=True, exist_ok=True)

    stem = source.stem
    markdown_path = out_dir / f"{stem}{suffix}.md"
    document_path = out_dir / f"{stem}{suffix}{source.suffix if fmt in {'pdf', 'epub'} else '.txt'}"
    manifest_path = out_dir / f"{stem}{suffix}.manifest.json"

    options: dict[str, Any] = {
        "redact": wants_document,
        "inline": "line" if job.get("inline") == "line" else "keep",
        "audit_text": bool(job.get("auditText")),
        "page_markers": job.get("pageMarkers", True) is not False,
        "document_path": document_path,
    }

    if fmt == "pdf":
        outcome = sanitize_pdf(source, options)
    elif fmt == "epub":
        outcome = sanitize_epub(source, options)
    elif fmt == "html":
        raw = source.read_text(encoding="utf-8", errors="replace")
        cleaned, removals, inline = _scrub_markup(raw, options)
        outcome = {
            "format": "html",
            "pages": 1,
            "bibliographic": {},
            "removals": removals,
            "inline": inline,
            "emptyPages": [],
            "removedChars": sum(int(r.get("chars", 0)) for r in removals),
            "residual": 0,
            "markdown": _html_to_markdown(cleaned),
            "cleaned": cleaned,
        }
        if wants_document:
            document_path = out_dir / f"{stem}{suffix}.html"
            document_path.write_text(cleaned, encoding="utf-8")
            outcome["document"] = str(document_path)
    else:
        raw = source.read_text(encoding="utf-8", errors="replace")
        cleaned, removals, inline = _scrub_plain(raw, options)
        outcome = {
            "format": "text",
            "pages": len(raw.splitlines()),
            "bibliographic": {},
            "removals": removals,
            "inline": inline,
            "emptyPages": [],
            "removedChars": sum(int(r.get("chars", 0)) for r in removals),
            "residual": 0,
            "markdown": cleaned,
        }
        if wants_document:
            document_path = out_dir / f"{stem}{suffix}{source.suffix}"
            document_path.write_text(cleaned, encoding="utf-8")
            outcome["document"] = str(document_path)

    warnings: list[str] = []
    markdown = outcome.pop("markdown", "")
    cleaned_markdown, extra = scrub_markdown(markdown, options)
    if extra:
        warnings.append(f"{extra} notice line(s) removed from the Markdown extraction")

    if wants_markdown and wants_files:
        markdown_path.write_text(cleaned_markdown.strip() + "\n", encoding="utf-8")
        produced_markdown = str(markdown_path)
    else:
        produced_markdown = None

    if outcome.get("emptyPages"):
        sample = ", ".join(str(page) for page in outcome["emptyPages"][:8])
        warnings.append(
            f"{len(outcome['emptyPages'])} page(s) have no extractable text (scanned image?): {sample}"
        )
    residual = int(outcome.get("residual") or 0)
    if residual:
        warnings.append(
            f"{residual} notice line(s) still detectable after redaction; "
            "rerun with inline='line' to remove the containing lines"
        )

    document_path = outcome.get("document")
    if document_path and fmt == "pdf":
        leftovers = verify_saved_pdf(Path(document_path))
        if leftovers:
            warnings.append(
                "saved PDF still carries notice text in: "
                + ", ".join(sorted(set(leftovers))[:6])
            )
    elif document_path and fmt == "epub":
        leftovers = verify_saved_epub(Path(document_path))
        if leftovers:
            warnings.append(
                "saved EPUB still carries notice text in: "
                + ", ".join(sorted(set(leftovers))[:6])
            )

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {
            "path": str(source),
            "format": outcome["format"],
            "bytes": source.stat().st_size,
            "sha256": sha256_of(source),
        },
        "outputs": {
            "markdown": produced_markdown,
            "document": outcome.get("document"),
        },
        "bibliographic": outcome.get("bibliographic") or {},
        "removed": {
            "count": len(outcome["removals"]),
            "totalChars": int(outcome.get("removedChars") or 0),
            "metadataFields": int(outcome.get("metadataRemovals") or 0),
            "entries": outcome["removals"][:MAX_ENTRIES],
        },
        "inlineMentions": outcome.get("inline") or [],
        "notes": (
            "Body text is unchanged apart from removed boilerplate notice lines and "
            "metadata rights fields. The source file was not modified."
        ),
    }
    if wants_files:
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    result: dict[str, Any] = {
        "ok": True,
        "source": str(source),
        "format": outcome["format"],
        "pages": int(outcome.get("pages") or 0),
        "markdown": produced_markdown,
        "document": outcome.get("document"),
        "manifest": str(manifest_path) if wants_files else None,
        "removedCount": len(outcome["removals"]),
        "removedChars": int(outcome.get("removedChars") or 0),
        "metadataRemovals": int(outcome.get("metadataRemovals") or 0),
        "inlineKept": len(outcome.get("inline") or []),
        "residual": residual,
        "bibliographic": outcome.get("bibliographic") or {},
        "warnings": warnings,
    }
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        sys.stderr.write("usage: sanitize.py <job.json> <result.json>\n")
        return 2
    job_path, result_path = argv[1], argv[2]
    try:
        with open(job_path, "r", encoding="utf-8-sig") as handle:
            job = json.load(handle)
    except Exception as error:
        _write(result_path, {"ok": False, "error": f"cannot read job: {error}"})
        return 2

    try:
        payload = run(job)
    except ImportError as error:
        _write(
            result_path,
            {
                "ok": False,
                "error": (
                    "PyMuPDF is not importable for this interpreter "
                    f"({error}). Install it with: python -m pip install pymupdf"
                ),
            },
        )
        return 3
    except Exception as error:
        _write(result_path, {"ok": False, "error": f"{type(error).__name__}: {error}"})
        return 1

    _write(result_path, payload)
    return 0


def _write(path: str, payload: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
