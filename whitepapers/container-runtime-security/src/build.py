#!/usr/bin/env python3
"""Build the KubeArmor container runtime security paper as a print-ready PDF.

Pipeline
    1. Fetch the brand webfonts (Poppins, Source Serif 4, Source Code Pro) into
       ``.fonts/``. Cached, so only the first run needs the network.
    2. Render ``paper.html`` with headless Chromium via Playwright.
    3. Read the heading positions back out of that first render, write the real
       page numbers into the table of contents, and render a second time.
    4. Stamp the running foot and folio on the body pages, attach the PDF
       outline, and set the document metadata.

Usage
    pip install playwright pymupdf && python -m playwright install chromium
    python build.py
"""

from __future__ import annotations

import re
import ssl
import sys
import urllib.request
from pathlib import Path

import fitz  # PyMuPDF
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "Container-Runtime-Security-Comparative-Insights.pdf"
FONT_DIR = HERE / ".fonts"
BUILD_HTML = HERE / ".paper.build.html"

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"}

WEBFONT_CSS = {
    "poppins": "https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap",
    "serif": "https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;0,8..60,700;1,8..60,400&display=swap",
    "mono": "https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@400;600&display=swap",
}

# Static TTFs, used by PyMuPDF when it stamps the running foot.
STAMP_FONTS = {
    "poppins-light": "https://raw.githubusercontent.com/google/fonts/main/ofl/poppins/Poppins-Light.ttf",
    "poppins-medium": "https://raw.githubusercontent.com/google/fonts/main/ofl/poppins/Poppins-Medium.ttf",
}

# Section order drives both the table of contents and the PDF outline.
SECTIONS = [
    ("sec-1", 1, "1", "Introduction"),
    ("sec-2", 1, "2", "Characteristics of a runtime security solution"),
    ("sec-2-1", 2, "2.1", "Detection capabilities"),
    ("sec-2-2", 2, "2.2", "Response capabilities"),
    ("sec-2-3", 2, "2.3", "Prevention capabilities"),
    ("sec-2-4", 2, "2.4", "Sandboxing capabilities"),
    ("sec-2-5", 2, "2.5", "Performance impact"),
    ("sec-2-6", 2, "2.6", "Ease of deployment on hardened distributions"),
    ("sec-2-7", 2, "2.7", "Ease of runtime policy enforcement"),
    ("sec-2-8", 2, "2.8", "Policies adhering to zero trust principles"),
    ("sec-3", 1, "3", "Runtime security with detect and respond"),
    ("sec-3-1", 2, "3.1", "Killing a process is not an effective remediation strategy"),
    ("sec-3-2", 2, "3.2", "The response depends on a chain of actions"),
    ("sec-4", 1, "4", "Engine analysis"),
    ("sec-4-1", 2, "4.1", "Falco"),
    ("sec-4-2", 2, "4.2", "Tetragon"),
    ("sec-4-3", 2, "4.3", "NeuVector"),
    ("sec-4-4", 2, "4.4", "Palo Alto Prisma and TwistLock"),
    ("sec-4-5", 2, "4.5", "gVisor"),
    ("sec-4-6", 2, "4.6", "KubeArmor"),
    ("sec-5", 1, "5", "Case study: file integrity monitoring"),
    ("sec-6", 1, "6", "Summary"),
]

RUNNING_FOOT = "KubeArmor  ·  Container Runtime Security"

NAVY = (8 / 255, 44 / 255, 116 / 255)
GREY = (0.42, 0.46, 0.53)
RULE = (0.80, 0.83, 0.88)
PAPER = (0.9895, 0.9937, 1.0)


# --------------------------------------------------------------------- fonts

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url: str) -> bytes:
    return urllib.request.urlopen(
        urllib.request.Request(url, headers=UA), context=_ssl_ctx(), timeout=90
    ).read()


def fetch_fonts() -> None:
    css_path = FONT_DIR / "fonts.css"
    if css_path.exists() and all((FONT_DIR / n).with_suffix(".ttf").exists() for n in STAMP_FONTS):
        print("fonts: cached")
        return

    FONT_DIR.mkdir(exist_ok=True)
    (FONT_DIR / ".gitignore").write_text("*\n", encoding="utf-8")

    seen: dict[str, str] = {}
    blocks = []
    for family, url in WEBFONT_CSS.items():
        css = _get(url).decode("utf-8")

        def swap(match: re.Match) -> str:
            href = match.group(1)
            if href not in seen:
                ext = ".woff2" if ".woff2" in href else ".ttf"
                name = f"{family}-{len(seen)}{ext}"
                (FONT_DIR / name).write_bytes(_get(href))
                seen[href] = name
            return f"url({seen[href]})"

        blocks.append(re.sub(r"url\((https://[^)]+)\)", swap, css))

    css_path.write_text("\n".join(blocks), encoding="utf-8")

    for name, url in STAMP_FONTS.items():
        (FONT_DIR / f"{name}.ttf").write_bytes(_get(url))

    print(f"fonts: fetched {len(seen)} webfont files")


# --------------------------------------------------------------------- render

# The cover and the back cover are full-bleed A4. If they sit in the same
# layout pass as the body, Chromium shrinks the whole document so the widest
# element fits inside the body page margins. So each half is laid out on its
# own, and the two results are spliced together.

HIDE_PLATES = "<style>.plate{display:none !important}</style>"
ONLY_PLATES = "<style>main{display:none !important}@page{size:A4;margin:0}</style>"


def _print(html: str, dest: Path) -> None:
    BUILD_HTML.write_text(html, encoding="utf-8")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.goto(BUILD_HTML.as_uri(), wait_until="networkidle")
        page.emulate_media(media="print")
        page.evaluate("document.fonts.ready")
        page.pdf(
            path=str(dest),
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
            display_header_footer=False,
        )
        browser.close()


def render(tokens: dict[str, str], dest: Path) -> None:
    html = (HERE / "paper.html").read_text(encoding="utf-8")
    for key, value in tokens.items():
        html = html.replace(f"__P_{key}__", value)
    html = re.sub(r"__P_[a-z0-9-]+__", "&nbsp;", html)

    body_pdf = HERE / ".body.pdf"
    plates_pdf = HERE / ".plates.pdf"
    _print(html.replace("</head>", HIDE_PLATES + "</head>"), body_pdf)
    _print(html.replace("</head>", ONLY_PLATES + "</head>"), plates_pdf)

    plates = fitz.open(plates_pdf)
    body = fitz.open(body_pdf)
    out = fitz.open()
    out.insert_pdf(plates, from_page=0, to_page=0)
    out.insert_pdf(body)
    out.insert_pdf(plates, from_page=plates.page_count - 1, to_page=plates.page_count - 1)
    out.save(str(dest))
    for doc in (out, body, plates):
        doc.close()
    body_pdf.unlink(missing_ok=True)
    plates_pdf.unlink(missing_ok=True)


def heading_pages(pdf: Path) -> dict[str, int]:
    """Map section id to 1-based page, using the rendered heading type sizes.

    Headings are the only Poppins runs set at 23pt (h1) and 15pt (h2), so the
    table of contents rows never collide with them.
    """
    doc = fitz.open(pdf)
    found: dict[str, int] = {}
    by_title = {title: sid for sid, _, _, title in SECTIONS}
    by_title["About this paper"] = "sec-about"
    by_title["Contents"] = "sec-toc"

    for index, page in enumerate(doc, start=1):
        for block in page.get_text("dict")["blocks"]:
            parts = []
            for line in block.get("lines", []):
                heads = [s for s in line["spans"]
                         if "SemiBold" in s["font"]
                         and (14.3 <= s["size"] <= 15.6 or 22.2 <= s["size"] <= 23.8)]
                if heads:
                    parts.append("".join(s["text"] for s in heads))
            if not parts:
                continue
            text = re.sub(r"\s+", " ", " ".join(parts)).strip()
            text = re.sub(r"^\d+(\.\d+)?\s*", "", text).strip()
            sid = by_title.get(text)
            if sid and sid not in found:
                found[sid] = index
    doc.close()
    return found


# --------------------------------------------------------------------- stamp

def finish(pdf: Path, pages: dict[str, int]) -> None:
    doc = fitz.open(pdf)
    last = doc.page_count

    light_path = FONT_DIR / "poppins-light.ttf"
    medium_path = FONT_DIR / "poppins-medium.ttf"
    light_font = fitz.Font(fontfile=str(light_path))
    medium_font = fitz.Font(fontfile=str(medium_path))

    # Which section owns each page, so the running foot can name it.
    owner: dict[int, str] = {}
    current = ""
    tops = {}
    for sid, level, num, title in SECTIONS:
        if level == 1 and sid in pages:
            tops[pages[sid]] = f"{num}  {title}"
    for index in range(1, last + 1):
        current = tops.get(index, current)
        owner[index] = current

    for index in range(2, last):  # cover and back cover stay clean
        page = doc[index - 1]
        width, height = page.rect.width, page.rect.height

        # Chromium paints the html background inside the page margins only, so
        # the sheet tint is laid down here, underneath everything already drawn.
        page.draw_rect(page.rect, color=None, fill=PAPER, overlay=False)

        y = height - 46
        page.draw_line(fitz.Point(85, y), fitz.Point(width - 85, y), color=RULE, width=0.4)

        page.insert_font(fontname="pl", fontfile=str(light_path))
        page.insert_font(fontname="pm", fontfile=str(medium_path))

        label = owner.get(index) or RUNNING_FOOT
        while light_font.text_length(label, 7.4) > width - 205:
            label = label[:-2].rstrip() + "…"
        page.insert_text(
            fitz.Point(85, y + 12), label, fontsize=7.4, fontname="pl", color=GREY,
        )
        folio = str(index)
        page.insert_text(
            fitz.Point(width - 85 - medium_font.text_length(folio, 9), y + 12.4),
            folio, fontsize=9, fontname="pm", color=NAVY,
        )

    toc = []
    for sid, level, num, title in SECTIONS:
        if sid in pages:
            toc.append([level, f"{num}  {title}", pages[sid]])
    front = [[1, "Cover", 1],
             [1, "About this paper", pages.get("sec-about", 2)],
             [1, "Contents", pages.get("sec-toc", 3)]]
    doc.set_toc(front + toc + [[1, "About KubeArmor", last]])

    doc.set_metadata({
        "title": "Container Runtime Security: Comparative Insights",
        "author": "Rahul Jadhav",
        "subject": "A comparison of detection, response, and prevention capabilities across "
                   "Falco, Tetragon, Tracee, NeuVector, gVisor, Prisma, and KubeArmor.",
        "keywords": "KubeArmor, runtime security, eBPF, LSM, BPF-LSM, container security, "
                    "Kubernetes, CNCF, zero trust, sandboxing",
        "creator": "The KubeArmor project",
        "producer": "KubeArmor whitepaper build (Chromium + PyMuPDF)",
    })

    doc.save(str(OUT), garbage=4, deflate=True, clean=True)
    doc.close()


def main() -> int:
    fetch_fonts()

    draft = HERE / ".paper.pass1.pdf"
    print("render: pass 1")
    render({}, draft)

    pages = heading_pages(draft)
    missing = [sid for sid, *_ in SECTIONS if sid not in pages]
    if missing:
        print(f"warning: no page found for {missing}", file=sys.stderr)

    print("render: pass 2")
    render({sid: str(page) for sid, page in pages.items()}, draft)

    # Page numbers can shift by one when a folio grows a digit. Settle it.
    for _ in range(3):
        again = heading_pages(draft)
        if again == pages:
            break
        pages = again
        render({sid: str(page) for sid, page in pages.items()}, draft)

    finish(draft, pages)

    for tmp in (draft, BUILD_HTML):
        tmp.unlink(missing_ok=True)

    size = OUT.stat().st_size / 1024
    with fitz.open(OUT) as doc:
        print(f"built {OUT.name}: {doc.page_count} pages, {size:.0f} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
