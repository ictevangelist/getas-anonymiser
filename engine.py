"""Finds and redacts identifying details in awards entry PDFs."""

import base64
import json

import anthropic
import pymupdf

MODEL = "claude-opus-5-5"
MAX_PDF_BYTES = 30 * 1024 * 1024  # API request limit is 32 MB

INSTRUCTIONS = """You are preparing entries to the Global EdTech Awards for blind judging. \
Judges must not be able to tell who entered, who is nominated, or which school or \
company the entry is about. List every piece of text in this document that could \
identify them.

Redact:
- names of people: the nominee, the entrant, colleagues, pupils, parents, and the \
authors or signatories of testimonials, including first names, surnames, initials \
and nicknames used on their own
- schools, trusts, academies, districts, local authorities, universities and \
companies, including acronyms and short forms
- the entry's own product, platform, app or service names and brand names
- towns, cities, counties, states and regions (country names may stay)
- email addresses, phone numbers, web addresses, social media handles, postal \
addresses and postcodes
- anything else unique enough to identify them: school or company registration \
numbers, inspection report references, named awards they have won, named events \
they ran

Keep widely used third-party tools the entry merely uses (for example Google \
Classroom, Microsoft Teams, ChatGPT, Canva): judges need these to understand the \
work. Keep job titles, subjects, year groups, statistics and country names.

Give each item exactly as it appears in the document (same spelling and \
capitalisation), once per distinct form. Keep each item short: the name itself, \
not the sentence around it. Also list the page numbers (starting at 1) of any \
page with a logo, photo, letterhead, signature or screenshot that shows a name, \
face or brand."""

SCHEMA = {
    "type": "object",
    "properties": {
        "redactions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": ["person", "school", "organisation", "product",
                                 "place", "contact", "other"],
                    },
                },
                "required": ["text", "kind"],
                "additionalProperties": False,
            },
        },
        "image_pages": {"type": "array", "items": {"type": "integer"}},
        "notes": {"type": "string"},
    },
    "required": ["redactions", "image_pages", "notes"],
    "additionalProperties": False,
}


def find_identifiers(pdf_path, known_names):
    """Ask Claude for everything identifying in one PDF."""
    if pdf_path.stat().st_size <= MAX_PDF_BYTES:
        source = {"type": "document", "source": {
            "type": "base64", "media_type": "application/pdf",
            "data": base64.standard_b64encode(pdf_path.read_bytes()).decode()}}
    else:  # too large to send whole: send the text only
        with pymupdf.open(pdf_path) as doc:
            text = "\n\n".join(f"--- Page {i} ---\n{p.get_text()}"
                               for i, p in enumerate(doc, 1))
        source = {"type": "text", "text": text}

    prompt = INSTRUCTIONS
    if known_names:
        prompt += ("\n\nNames given on the entry form (look for these and any "
                   "variants of them): " + "; ".join(known_names))

    response = anthropic.Anthropic().beta.messages.create(
        model=MODEL,
        max_tokens=16000,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "high",
                       "format": {"type": "json_schema", "schema": SCHEMA}},
        messages=[{"role": "user",
                   "content": [source, {"type": "text", "text": prompt}]}],
    )
    if response.stop_reason == "refusal":
        raise RuntimeError("Claude declined to read this file")
    if response.stop_reason == "max_tokens":
        raise RuntimeError("Claude's response was cut short")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)


def redact(src_path, findings, add_names, keep, judge_path, preview_path):
    """Write the redacted PDF and a highlighted preview. Returns a report."""
    keep = {k.lower() for k in keep}
    terms = {r["text"].strip(): r["kind"] for r in findings["redactions"]}
    for name in add_names:
        terms.setdefault(name, "person")
    terms = {t: k for t, k in terms.items() if t and t.lower() not in keep}
    image_pages = sorted(set(findings["image_pages"]))

    doc = pymupdf.open(src_path)
    preview = pymupdf.open(src_path)
    hits = dict.fromkeys(terms, 0)

    # Longest first, so "Oak Hill Academy" is matched before "Oak Hill".
    for term in sorted(terms, key=len, reverse=True):
        for page, pv_page in zip(doc, preview):
            for quad in page.search_for(term, quads=True):
                hits[term] += 1
                page.add_redact_annot(quad, text=f"[{terms[term]}]",
                                      fontsize=7, fill=(0, 0, 0),
                                      text_color=(1, 1, 1))
                pv_page.add_highlight_annot(quad)

    for number in image_pages:
        if 1 <= number <= len(doc):
            page, pv_page = doc[number - 1], preview[number - 1]
            for info in page.get_image_info():
                box = pymupdf.Rect(info["bbox"])
                page.add_redact_annot(box, text="[image]", fill=(0, 0, 0),
                                      text_color=(1, 1, 1))
                annot = pv_page.add_rect_annot(box)
                annot.set_colors(stroke=(0.91, 0.3, 0.24))
                annot.set_border(width=3)
                annot.update()

    scanned = not any(page.get_text().strip() for page in doc)
    for page in doc:
        page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_REMOVE)
    doc.scrub()  # metadata, links, attachments, hidden text, form data
    doc.save(judge_path, garbage=4, deflate=True)
    preview.save(preview_path, garbage=4, deflate=True)

    return {
        "redacted": [{"text": t, "kind": terms[t], "count": n}
                     for t, n in hits.items() if n],
        "not_found": [t for t, n in hits.items() if not n],
        "image_pages": image_pages,
        "notes": findings.get("notes", ""),
        "scanned": scanned,
        "pages": len(preview),
    }
