"""Render the plan document set (Markdown) into one PDF with a TOC, bookmarks and page numbers.

Usage: python tools/build_plan_pdf.py [docs_dir] [out.pdf]
Needs: markdown-it-py, reportlab, DejaVu fonts (/usr/share/fonts/truetype/dejavu).
"""

import re
import sys
from pathlib import Path

from markdown_it import MarkdownIt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (
    BaseDocTemplate, Frame, ListFlowable, ListItem, NextPageTemplate, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle, XPreformatted,
)
from reportlab.platypus.tableofcontents import TableOfContents

REPO = Path(__file__).resolve().parent.parent
DOCS = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "docs"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else DOCS / "LLM_Diversion_Development_Plan.pdf"

PARTS = [
    ("DEVELOPMENT_PLAN.md", "Part I", "Development Plan"),
    ("AUTOMATION_FEASIBILITY.md", "Part II", "Automation Feasibility and Tool Inventory"),
    ("ENGINEERING_STANDARDS.md", "Part III", "Engineering Standards"),
    ("DEPLOYMENT.md", "Part IV", "Deployment on a Separate Server"),
    ("TRACKING.md", "Part V", "Tracking Interfaces"),
]
ANCHOR = {fn: f"part{i + 1}" for i, (fn, _, _) in enumerate(PARTS)}

FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
pdfmetrics.registerFont(TTFont("Sans", FONT_DIR + "DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("Sans-Bold", FONT_DIR + "DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Mono", FONT_DIR + "DejaVuSansMono.ttf"))
pdfmetrics.registerFont(TTFont("Mono-Bold", FONT_DIR + "DejaVuSansMono-Bold.ttf"))
pdfmetrics.registerFontFamily("Sans", normal="Sans", bold="Sans-Bold", italic="Sans", boldItalic="Sans-Bold")

INK = colors.HexColor("#1d2433")
ACCENT = colors.HexColor("#2457a6")
MUTED = colors.HexColor("#5b6578")
RULE = colors.HexColor("#d5dae3")
CODE_BG = colors.HexColor("#f4f6f9")
HEAD_BG = colors.HexColor("#e8edf5")
CODE_INK = "#8a1c3b"

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
TEXT_W = PAGE_W - 2 * MARGIN

S = {
    "body": ParagraphStyle("body", fontName="Sans", fontSize=9.2, leading=13, textColor=INK, spaceAfter=5),
    "H1": ParagraphStyle("H1", fontName="Sans-Bold", fontSize=20, leading=25, textColor=ACCENT, spaceAfter=4),
    "partlabel": ParagraphStyle("partlabel", fontName="Sans-Bold", fontSize=10, leading=13, textColor=MUTED, spaceAfter=2),
    "H2": ParagraphStyle("H2", fontName="Sans-Bold", fontSize=13.5, leading=18, textColor=INK, spaceBefore=12, spaceAfter=5),
    "H3": ParagraphStyle("H3", fontName="Sans-Bold", fontSize=11, leading=15, textColor=ACCENT, spaceBefore=9, spaceAfter=4),
    "H4": ParagraphStyle("H4", fontName="Sans-Bold", fontSize=9.8, leading=13, textColor=INK, spaceBefore=7, spaceAfter=3),
    "cell": ParagraphStyle("cell", fontName="Sans", fontSize=7.6, leading=10, textColor=INK),
    "cellhead": ParagraphStyle("cellhead", fontName="Sans-Bold", fontSize=7.6, leading=10, textColor=INK),
    "code": ParagraphStyle("code", fontName="Mono", fontSize=6.9, leading=8.6, textColor=INK),
    "quote": ParagraphStyle("quote", fontName="Sans", fontSize=9, leading=12.5, textColor=MUTED),
    "toc1": ParagraphStyle("toc1", fontName="Sans-Bold", fontSize=10.5, leading=15, spaceBefore=6, textColor=INK),
    "toc2": ParagraphStyle("toc2", fontName="Sans", fontSize=8.8, leading=12, leftIndent=14, textColor=INK),
}
TOC_TITLE = ParagraphStyle("TOCTitle", parent=S["H2"])  # distinct name so it is not a TOC entry

md = MarkdownIt("commonmark").enable("table").enable("strikethrough")


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def link_target(href: str) -> str | None:
    """Map cross-document links to part anchors; keep external links; drop local-file links."""
    if href.startswith(("http://", "https://")):
        return href
    for fn, anchor in ANCHOR.items():
        if href.startswith(fn):
            return "#" + anchor
    return None


def inline(tok) -> str:
    out = []
    link_stack = []
    for c in tok.children or []:
        t = c.type
        if t == "text":
            txt = c.content.replace("[ ]", "☐").replace("[x]", "☑")
            if link_stack and link_stack[-1]:
                for fn, label, title in PARTS:
                    txt = txt.replace(fn, f"{label} ({title})")
            out.append(esc(txt))
        elif t == "code_inline":
            out.append(f'<font face="Mono" color="{CODE_INK}">{esc(c.content)}</font>')
        elif t == "strong_open":
            out.append("<b>")
        elif t == "strong_close":
            out.append("</b>")
        elif t == "em_open":
            out.append('<font color="#33415c">')
        elif t == "em_close":
            out.append("</font>")
        elif t == "s_open":
            out.append("<strike>")
        elif t == "s_close":
            out.append("</strike>")
        elif t == "link_open":
            target = link_target(c.attrGet("href") or "")
            link_stack.append(bool(target))
            if target:
                out.append(f'<a href="{esc(target)}" color="#2457a6">')
        elif t == "link_close":
            if link_stack.pop():
                out.append("</a>")
        elif t == "softbreak":
            out.append("<br/>")
        elif t == "hardbreak":
            out.append("<br/>")
        elif t in ("image", "html_inline"):
            out.append(esc(c.content))
    return "".join(out)


def plain(tok) -> str:
    return "".join(c.content for c in (tok.children or []) if c.type in ("text", "code_inline"))


class Doc(BaseDocTemplate):
    def __init__(self, filename, **kw):
        super().__init__(filename, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                         topMargin=MARGIN + 4 * mm, bottomMargin=MARGIN, **kw)
        frame = Frame(MARGIN, MARGIN, TEXT_W, PAGE_H - 2 * MARGIN - 4 * mm, id="f", leftPadding=0, rightPadding=0)
        self.addPageTemplates([
            PageTemplate(id="cover", frames=[frame]),
            PageTemplate(id="body", frames=[frame], onPageEnd=self._decorate),
        ])
        self.current_part = ""
        self._bm = 0

    def beforeDocument(self):
        self._bm = 0
        self.current_part = ""

    def _decorate(self, canv, doc):
        canv.saveState()
        canv.setFont("Sans", 7.5)
        canv.setFillColor(MUTED)
        canv.drawString(MARGIN, PAGE_H - MARGIN + 2 * mm, "LLM Diversion Research: Development Plan")
        canv.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 2 * mm, self.current_part)
        canv.setStrokeColor(RULE)
        canv.setLineWidth(0.5)
        canv.line(MARGIN, PAGE_H - MARGIN + 0.5 * mm, PAGE_W - MARGIN, PAGE_H - MARGIN + 0.5 * mm)
        canv.restoreState()

    def afterFlowable(self, f):
        if not isinstance(f, Paragraph) or f.style.name not in ("H1", "H2"):
            return
        text = f.getPlainText()
        key = getattr(f, "_anchor", None) or f"bm{self._bm}"
        self._bm += 1
        self.canv.bookmarkPage(key)
        level = 0 if f.style.name == "H1" else 1
        if level == 0:
            self.current_part = text
        self.canv.addOutlineEntry(text, key, level=level, closed=(level == 1))
        self.notify("TOCEntry", (level, text, self.page, key))


class NumberedCanvas(rl_canvas.Canvas):
    """Two-pass canvas so every page can say 'Page n of N'."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            if self._pageNumber > 1:
                self.setFont("Sans", 7.5)
                self.setFillColor(MUTED)
                self.drawCentredString(PAGE_W / 2, MARGIN - 8 * mm, f"Page {self._pageNumber} of {total}")
            super().showPage()
        super().save()


def code_block(text: str):
    t = Table([[XPreformatted(esc(text.rstrip("\n")), S["code"])]], colWidths=[TEXT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [t, Spacer(1, 6)]


def column_widths(rows, ncol):
    lengths = [0] * ncol
    longest = [0.0] * ncol
    for r in rows:
        for j, cell in enumerate(r):
            txt = re.sub(r"<[^>]+>", " ", cell).replace("&amp;", "&")
            lengths[j] = max(lengths[j], min(len(txt), 220))
            # every column must fit its longest unbreakable word (measured in the wider mono font)
            for word in txt.split():
                longest[j] = max(longest[j], pdfmetrics.stringWidth(word, "Mono", 7.6) + 10)
    weights = [max(8, n) ** 0.75 for n in lengths]
    widths = [TEXT_W * w / sum(weights) for w in weights]
    floor = [min(max(16 * mm, lw), TEXT_W * 0.42) for lw in longest]
    for _ in range(4):
        widths = [max(w, f) for w, f in zip(widths, floor)]
        extra = sum(widths) - TEXT_W
        if extra <= 0.5:
            break
        slack = [w - f for w, f in zip(widths, floor)]
        widths = [w - extra * sl / (sum(slack) or 1) for w, sl in zip(widths, slack)]
    scale = TEXT_W / sum(widths)
    return [w * scale for w in widths]


def build_table(rows, header_rows):
    ncol = max(len(r) for r in rows)
    data = []
    for i, r in enumerate(rows):
        style = S["cellhead"] if i < header_rows else S["cell"]
        data.append([Paragraph(c or "", style) for c in r] + [Paragraph("", style)] * (ncol - len(r)))
    t = Table(data, colWidths=column_widths(rows, ncol), repeatRows=header_rows, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, header_rows - 1), HEAD_BG),
        ("GRID", (0, 0), (-1, -1), 0.35, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return [t, Spacer(1, 7)]


def blocks(tokens, i, end_types, style="body"):
    """Convert block tokens to flowables until a closing token in end_types."""
    out = []
    while i < len(tokens):
        tok = tokens[i]
        t = tok.type
        if t in end_types:
            return out, i
        if t == "heading_open":
            inl = tokens[i + 1]
            out.append(("heading", int(tok.tag[1]), inline(inl), plain(inl)))
            i += 3
        elif t == "paragraph_open":
            out.append(Paragraph(inline(tokens[i + 1]), S[style]))
            i += 3
        elif t in ("fence", "code_block"):
            out.extend(code_block(tok.content))
            i += 1
        elif t in ("bullet_list_open", "ordered_list_open"):
            ordered = t == "ordered_list_open"
            close = "ordered_list_close" if ordered else "bullet_list_close"
            start = int(tok.attrGet("start") or 1)
            indent = 15 if ordered else 12
            items = []
            i += 1
            while tokens[i].type != close:
                sub, i = blocks(tokens, i + 1, {"list_item_close"}, style)
                sub = [f for f in sub if not isinstance(f, tuple)]
                items.append(ListItem(sub or [Paragraph("", S[style])], leftIndent=indent))
                i += 1
            kw = (dict(bulletType="1", start=start, bulletFontName="Sans-Bold", bulletFontSize=8.5) if ordered
                  else dict(bulletType="bullet", start="•", bulletFontName="Sans", bulletFontSize=8.5))
            out.append(ListFlowable(items, leftIndent=indent, spaceAfter=4, bulletColor=MUTED, **kw))
            i += 1
        elif t == "table_open":
            rows, header_rows, in_head, row = [], 0, False, None
            i += 1
            while tokens[i].type != "table_close":
                tt = tokens[i].type
                if tt == "thead_open":
                    in_head = True
                elif tt == "thead_close":
                    in_head = False
                elif tt == "tr_open":
                    row = []
                elif tt == "tr_close":
                    rows.append(row)
                    header_rows += in_head
                elif tt == "inline":
                    row.append(inline(tokens[i]))
                i += 1
            out.extend(build_table(rows, max(header_rows, 1)))
            i += 1
        elif t == "blockquote_open":
            sub, i = blocks(tokens, i + 1, {"blockquote_close"}, "quote")
            q = Table([[[f for f in sub if not isinstance(f, tuple)]]], colWidths=[TEXT_W - 4])
            q.setStyle(TableStyle([
                ("LINEBEFORE", (0, 0), (0, -1), 2.2, ACCENT),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fc")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            out.extend([q, Spacer(1, 6)])
            i += 1
        else:  # hr and anything unhandled
            i += 1
    return out, i


def rule(weight):
    return Table([[""]], colWidths=[TEXT_W], rowHeights=[2], style=[("LINEABOVE", (0, 0), (-1, -1), weight, ACCENT)])


def render_part(md_text, part_label, part_title, anchor):
    flows, _ = blocks(md.parse(md_text), 0, set())
    story, first_h1 = [], True
    for f in flows:
        if not isinstance(f, tuple):
            story.append(f)
            continue
        _, level, html, _text = f
        if level == 1 and first_h1:
            first_h1 = False
            title = Paragraph(esc(part_title), S["H1"])
            title._anchor = anchor
            story += [Paragraph(part_label.upper(), S["partlabel"]), title, rule(1.2), Spacer(1, 6)]
        else:
            story.append(Paragraph(html, S[{1: "H2", 2: "H2", 3: "H3"}.get(level, "H4")]))
    return story


def cover():
    title = ParagraphStyle("ct", fontName="Sans-Bold", fontSize=27, leading=33, textColor=INK)
    sub = ParagraphStyle("cs", fontName="Sans", fontSize=12.5, leading=17, textColor=ACCENT)
    meta = ParagraphStyle("cm", fontName="Sans", fontSize=9.5, leading=14, textColor=MUTED)
    rows = [[Paragraph(f"<b>{p}</b>", S["cell"]), Paragraph(t, S["cell"])] for _, p, t in PARTS]
    parts = Table(rows, colWidths=[28 * mm, TEXT_W - 28 * mm], hAlign="LEFT")
    parts.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.35, RULE),
                               ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return [
        Spacer(1, 52 * mm),
        Paragraph("LLM DIVERSION RESEARCH", ParagraphStyle("k", fontName="Sans-Bold", fontSize=10, textColor=MUTED, leading=14)),
        Spacer(1, 4 * mm),
        Paragraph("Test Harness Development Plan", title),
        Spacer(1, 3 * mm),
        Paragraph("Automated LLM attack-agent testing against planted-prompt defences: "
                  "architecture, feasibility, engineering standards, deployment and tracking", sub),
        Spacer(1, 10 * mm), rule(1.4), Spacer(1, 6 * mm),
        Paragraph("Companion to the research plan <i>Do Planted Prompts Stop LLM Attack Agents?</i> "
                  "(12 October 2026, target USENIX Security ’27)", meta),
        Paragraph("Status: plan for approval; repositories set up, harness code not yet written.", meta),
        Spacer(1, 12 * mm),
        Paragraph("<b>Contents</b>", ParagraphStyle("cc", fontName="Sans-Bold", fontSize=10, textColor=INK, leading=14, spaceAfter=4)),
        parts,
        NextPageTemplate("body"),
        PageBreak(),
    ]


def main():
    doc = Doc(str(OUT), title="LLM Diversion Research: Test Harness Development Plan",
              author="LLM Diversion Research team", subject="Development plan")
    toc = TableOfContents()
    toc.levelStyles = [S["toc1"], S["toc2"]]
    toc.dotsMinLevel = 0
    story = cover() + [Paragraph("Table of Contents", TOC_TITLE), Spacer(1, 4), toc, PageBreak()]
    for idx, (fn, label, title) in enumerate(PARTS):
        story += render_part((DOCS / fn).read_text(), label, title, ANCHOR[fn])
        if idx < len(PARTS) - 1:
            story.append(PageBreak())
    doc.multiBuild(story, canvasmaker=NumberedCanvas)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
