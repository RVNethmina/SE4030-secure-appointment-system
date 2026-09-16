"""Build the SE4030 security report as an IEEE-style (two-column, A4) PDF.

Usage (from the repository root):
    python docs/report/build_report.py

Requires: reportlab, and the Times New Roman / Courier New TrueType fonts
(Windows: C:\\Windows\\Fonts). Output: SE4030_Security_Report.pdf
"""

import math
import os
import sys

from reportlab.graphics.shapes import Drawing, Line, Polygon, PolyLine, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Frame,
    FrameBreak,
    KeepTogether,
    NextPageTemplate,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUTPUT = os.path.join(ROOT, "SE4030_Security_Report.pdf")

# --------------------------------------------------------------------------
# Fonts
# --------------------------------------------------------------------------
FONT_DIR = os.environ.get("REPORT_FONT_DIR", r"C:\Windows\Fonts")


def register_family(name, files):
    for suffix, file in zip(["", "-B", "-I", "-BI"], files):
        pdfmetrics.registerFont(TTFont(name + suffix, os.path.join(FONT_DIR, file)))
    pdfmetrics.registerFontFamily(
        name, normal=name, bold=name + "-B", italic=name + "-I", boldItalic=name + "-BI"
    )


register_family("TNR", ["times.ttf", "timesbd.ttf", "timesi.ttf", "timesbi.ttf"])
register_family("CNR", ["cour.ttf", "courbd.ttf", "couri.ttf", "courbi.ttf"])

# --------------------------------------------------------------------------
# Page geometry (IEEE conference template, A4)
# --------------------------------------------------------------------------
PAGE_W, PAGE_H = A4
LM = RM = 14.3 * mm
TM = 19 * mm
BM = 22 * mm
GAP = 4.2 * mm
FULL_W = PAGE_W - LM - RM
COL_W = (FULL_W - GAP) / 2
FOOTNOTE_H = 15 * mm

# --------------------------------------------------------------------------
# Styles
# --------------------------------------------------------------------------
BLACK = colors.black
ST = {
    "title": ParagraphStyle("title", fontName="TNR", fontSize=22, leading=26, alignment=TA_CENTER),
    "author": ParagraphStyle("author", fontName="TNR", fontSize=10.5, leading=12.5, alignment=TA_CENTER),
    "affil": ParagraphStyle("affil", fontName="TNR", fontSize=9, leading=11, alignment=TA_CENTER),
    "affil_i": ParagraphStyle("affil_i", fontName="TNR-I", fontSize=9, leading=11, alignment=TA_CENTER),
    "abstract": ParagraphStyle(
        "abstract", fontName="TNR-B", fontSize=9, leading=10.6, alignment=TA_JUSTIFY,
        firstLineIndent=10, spaceAfter=5,
    ),
    "body": ParagraphStyle(
        "body", fontName="TNR", fontSize=10, leading=11.6, alignment=TA_JUSTIFY,
        firstLineIndent=10, allowWidows=0, allowOrphans=0,
    ),
    "bullet": ParagraphStyle(
        "bullet", fontName="TNR", fontSize=10, leading=11.6, alignment=TA_JUSTIFY,
        leftIndent=13, bulletIndent=4, spaceBefore=1, allowWidows=0, allowOrphans=0,
        bulletFontName="TNR", bulletFontSize=10,
    ),
    "h1": ParagraphStyle(
        "h1", fontName="TNR", fontSize=10, leading=12, alignment=TA_CENTER,
        spaceBefore=9, spaceAfter=4, keepWithNext=0,
    ),
    "h2": ParagraphStyle(
        "h2", fontName="TNR-I", fontSize=10, leading=12, alignment=TA_LEFT,
        spaceBefore=6, spaceAfter=2, keepWithNext=0,
    ),
    "cap_tab": ParagraphStyle(
        "cap_tab", fontName="TNR", fontSize=8, leading=9.6, alignment=TA_CENTER,
        spaceBefore=7, spaceAfter=3, keepWithNext=1,
    ),
    "cap_fig": ParagraphStyle(
        "cap_fig", fontName="TNR", fontSize=8, leading=9.6, alignment=TA_JUSTIFY,
        spaceBefore=3, spaceAfter=8,
    ),
    "cell": ParagraphStyle("cell", fontName="TNR", fontSize=7.5, leading=8.7, alignment=TA_LEFT),
    "cell_b": ParagraphStyle("cell_b", fontName="TNR-B", fontSize=7.5, leading=8.7, alignment=TA_LEFT),
    "code": ParagraphStyle("code", fontName="CNR", fontSize=6.9, leading=8.1),
    "ref": ParagraphStyle(
        "ref", fontName="TNR", fontSize=8, leading=9.4, alignment=TA_LEFT,
        leftIndent=17, bulletIndent=0, spaceAfter=1.5, bulletFontName="TNR", bulletFontSize=8,
    ),
    "footnote": ParagraphStyle("footnote", fontName="TNR", fontSize=7.5, leading=8.8, alignment=TA_LEFT),
}


def esc(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def smallcaps(text, size=10):
    """Emulate small capitals: lowercase letters become smaller capitals."""
    small = round(size * 0.8, 1)
    out, run = [], ""
    for ch in text:
        if ch.islower():
            run += ch
        else:
            if run:
                out.append(f'<font size="{small}">{esc(run.upper())}</font>')
                run = ""
            out.append(esc(ch))
    if run:
        out.append(f'<font size="{small}">{esc(run.upper())}</font>')
    return "".join(out)


def c(code):
    """Inline code."""
    return f'<font face="CNR" size="8.6">{esc(code)}</font>'


# --------------------------------------------------------------------------
# Citations (IEEE: numbered in order of first citation)
# --------------------------------------------------------------------------
REFERENCES = {
    "owasp10": "OWASP Foundation, \u201cOWASP Top 10:2021,\u201d 2021. Accessed: Sep. 2026. [Online]. Available: https://owasp.org/Top10/",
    "cwe": "The MITRE Corporation, \u201cCommon Weakness Enumeration (CWE).\u201d Accessed: Sep. 2026. [Online]. Available: https://cwe.mitre.org/",
    "repo_base": "RVNethmina, \u201cAppointmentBookingSystem,\u201d GitHub repository, baseline commit 2c2bad8, Feb. 2025. [Online]. Available: https://github.com/RVNethmina/AppointmentBookingSystem",
    "repo_hard": "RVNethmina, \u201cSE4030-secure-appointment-system,\u201d GitHub repository, Sep. 2026. [Online]. Available: https://github.com/RVNethmina/SE4030-secure-appointment-system",
    "asvs": "OWASP Foundation, \u201cApplication Security Verification Standard 4.0.3,\u201d Oct. 2021. [Online]. Available: https://owasp.org/www-project-application-security-verification-standard/",
    "cvss": "FIRST, \u201cCommon Vulnerability Scoring System v3.1: Specification document,\u201d Jun. 2019. [Online]. Available: https://www.first.org/cvss/v3.1/specification-document",
    "npmaudit": "npm, Inc., \u201cnpm-audit,\u201d npm Docs. Accessed: Sep. 2026. [Online]. Available: https://docs.npmjs.com/cli/commands/npm-audit",
    "gitleaks": "Gitleaks, \u201cGitleaks,\u201d GitHub repository. Accessed: Sep. 2026. [Online]. Available: https://github.com/gitleaks/gitleaks",
    "codeql": "GitHub, Inc., \u201cAbout code scanning with CodeQL,\u201d GitHub Docs. Accessed: Sep. 2026. [Online]. Available: https://docs.github.com/en/code-security/code-scanning",
    "rfc7519": "M. Jones, J. Bradley, and N. Sakimura, \u201cJSON Web Token (JWT),\u201d IETF RFC 7519, May 2015.",
    "rfc8725": "Y. Sheffer, D. Hardt, and M. Jones, \u201cJSON Web Token best current practices,\u201d IETF RFC 8725, Feb. 2020.",
    "wstg": "OWASP Foundation, \u201cTesting for NoSQL injection,\u201d in <i>OWASP Web Security Testing Guide</i>, v4.2, Dec. 2020. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/",
    "nist63b": "P. A. Grassi et al., \u201cDigital identity guidelines: Authentication and lifecycle management,\u201d NIST Special Publication 800-63B, Jun. 2017.",
    "express_proxy": "Express, \u201cExpress behind proxies,\u201d Express documentation. Accessed: Sep. 2026. [Online]. Available: https://expressjs.com/en/guide/behind-proxies.html",
    "prehijack": "A. Sudhodanan and A. Paverd, \u201cPre-hijacked accounts: An empirical study of security failures in user account creation on the web,\u201d in <i>Proc. 31st USENIX Security Symp.</i>, Boston, MA, USA, Aug. 2022.",
    "oidc": "N. Sakimura, J. Bradley, M. Jones, B. de Medeiros, and C. Mortimore, \u201cOpenID Connect Core 1.0 incorporating errata set 2,\u201d OpenID Foundation, Dec. 2023. [Online]. Available: https://openid.net/specs/openid-connect-core-1_0.html",
    "rfc6749": "D. Hardt, Ed., \u201cThe OAuth 2.0 authorization framework,\u201d IETF RFC 6749, Oct. 2012.",
    "gis": "Google, \u201cSign in with Google for web,\u201d Google for Developers. Accessed: Sep. 2026. [Online]. Available: https://developers.google.com/identity/gsi/web",
    "gis_verify": "Google, \u201cVerify the Google ID token on your server side,\u201d Google for Developers. Accessed: Sep. 2026. [Online]. Available: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token",
    "csp3": "W3C, \u201cContent Security Policy Level 3,\u201d W3C Working Draft. Accessed: Sep. 2026. [Online]. Available: https://www.w3.org/TR/CSP3/",
    "docker_cs": "OWASP Foundation, \u201cDocker security cheat sheet,\u201d OWASP Cheat Sheet Series. Accessed: Sep. 2026. [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    "ssdf": "M. Souppaya, K. Scarfone, and D. Dodson, \u201cSecure Software Development Framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities,\u201d NIST Special Publication 800-218, Feb. 2022.",
    "sdl": "M. Howard and S. Lipner, <i>The Security Development Lifecycle</i>. Redmond, WA, USA: Microsoft Press, 2006.",
    "mcgraw": "G. McGraw, <i>Software Security: Building Security In</i>. Boston, MA, USA: Addison-Wesley, 2006.",
}
CITE_ORDER = []


def cite(*keys):
    nums = []
    for key in keys:
        if key not in REFERENCES:
            raise KeyError(key)
        if key not in CITE_ORDER:
            CITE_ORDER.append(key)
        nums.append(CITE_ORDER.index(key) + 1)
    return ", ".join(f"[{n}]" for n in sorted(nums))


# --------------------------------------------------------------------------
# Story helpers
# --------------------------------------------------------------------------
story = []
ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"]
counters = {"section": 0, "sub": 0, "table": 0, "fig": 0, "listing": 0}


def section(title):
    counters["section"] += 1
    counters["sub"] = 0
    # Enough room for the heading, a subsection heading and a few lines of text.
    story.append(CondPageBreak(90))
    story.append(Paragraph(f"{ROMAN[counters['section'] - 1]}. {smallcaps(title)}", ST["h1"]))


def subsection(title):
    counters["sub"] += 1
    letter = chr(ord("A") + counters["sub"] - 1)
    # Headings never end a column: move on unless a few lines fit below them.
    story.append(CondPageBreak(45))
    story.append(Paragraph(f"{letter}. {esc(title)}", ST["h2"]))


def p(text):
    story.append(Paragraph(text, ST["body"]))


def runin(label, text):
    """IEEE third-level run-in heading, e.g. '1) Heading: text'."""
    p(f"<i>{label}:</i> {text}")


def bullets(items):
    for item in items:
        story.append(Paragraph(item, ST["bullet"], bulletText="\u2022"))


def table(caption, header, rows, widths, split=False):
    counters["table"] += 1
    number = ROMAN[counters["table"] - 1]
    cap = Paragraph(f"{smallcaps('Table', 8)} {number}<br/>{smallcaps(caption, 8)}", ST["cap_tab"])
    data = [[Paragraph(h, ST["cell_b"]) for h in header]]
    data += [[Paragraph(cell, ST["cell"]) for cell in row] for row in rows]
    tbl = Table(data, colWidths=[w * COL_W for w in widths], repeatRows=1, hAlign="CENTER")
    tbl.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 0.8, BLACK),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, BLACK),
        ("LINEBELOW", (0, -1), (-1, -1), 0.8, BLACK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 1.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6),
    ]))
    if split:
        cap.keepWithNext = 0
        story.extend([CondPageBreak(110), cap, tbl, Spacer(1, 6)])
    else:
        story.append(KeepTogether([cap, tbl, Spacer(1, 6)]))
    return number


def listing(caption, code):
    counters["listing"] += 1
    box = Table([[Preformatted(code.strip("\n"), ST["code"])]], colWidths=[COL_W])
    box.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#777777")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F4F4F4")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    cap = Paragraph(f"Listing {counters['listing']}. {caption}", ST["cap_fig"])
    story.append(KeepTogether([Spacer(1, 3), box, cap]))
    return counters["listing"]


def figure(drawing, caption):
    counters["fig"] += 1
    cap = Paragraph(f"Fig. {counters['fig']}. {caption}", ST["cap_fig"])
    story.append(KeepTogether([Spacer(1, 4), drawing, cap]))
    return counters["fig"]


# --------------------------------------------------------------------------
# Vector diagrams
# --------------------------------------------------------------------------
GREY = colors.HexColor("#555555")
LIGHT = colors.HexColor("#EDEDED")


def sw(text, font="TNR", size=6.0):
    return pdfmetrics.stringWidth(text, font, size)


def box(d, x, y, w, h, lines, fill=LIGHT, dashed=False):
    d.add(Rect(x, y, w, h, fillColor=fill, strokeColor=BLACK, strokeWidth=0.6,
               strokeDashArray=[2, 1.5] if dashed else None, rx=1.5, ry=1.5))
    sizes = [7.0] + [6.0] * (len(lines) - 1)
    total = sum(s + 1.2 for s in sizes)
    cy = y + h / 2 + total / 2 - sizes[0]
    for i, (line, size) in enumerate(zip(lines, sizes)):
        d.add(String(x + w / 2, cy, line, fontName="TNR-B" if i == 0 else "TNR",
                     fontSize=size, textAnchor="middle"))
        cy -= size + 1.2


def arrow(d, points, dashed=False, head=True, width=0.7):
    flat = [v for pt in points for v in pt]
    d.add(PolyLine(flat, strokeColor=BLACK, strokeWidth=width,
                   strokeDashArray=[2.5, 1.5] if dashed else None))
    if head:
        (x1, y1), (x2, y2) = points[-2], points[-1]
        ang = math.atan2(y2 - y1, x2 - x1)
        L, W = 4.6, 1.9
        bx, by = x2 - L * math.cos(ang), y2 - L * math.sin(ang)
        px, py = -math.sin(ang) * W, math.cos(ang) * W
        d.add(Polygon([x2, y2, bx + px, by + py, bx - px, by - py],
                      fillColor=BLACK, strokeColor=BLACK, strokeWidth=0.3))


def label(d, x, y, text, size=5.8, anchor="middle", bg=True, italic=False):
    font = "TNR-I" if italic else "TNR"
    w = sw(text, font, size)
    left = {"middle": x - w / 2, "start": x, "end": x - w}[anchor]
    if bg:
        d.add(Rect(left - 1, y - 1.6, w + 2, size + 1.8, fillColor=colors.white, strokeColor=None))
    d.add(String(x, y, text, fontName=font, fontSize=size, textAnchor=anchor))


def architecture_diagram():
    W, H = COL_W, 250
    d = Drawing(W, H)
    # Docker network boundary
    d.add(Rect(3, 4, 183, 188, fillColor=None, strokeColor=GREY, strokeWidth=0.7,
               strokeDashArray=[3, 2]))
    label(d, 8, 183, "Docker Compose network", size=6.2, anchor="start", italic=True)
    # Clients
    box(d, 8, 202, 80, 26, ["Patient browser", "React SPA"], fill=colors.white)
    box(d, 100, 202, 80, 26, ["Admin / doctor browser", "React SPA"], fill=colors.white)
    # Web tier
    box(d, 10, 136, 82, 36, ["frontend (nginx)", "host port 5173", "CSP \u00b7 /api reverse proxy"])
    box(d, 98, 136, 82, 36, ["admin (nginx)", "host port 5174", "CSP \u00b7 /api reverse proxy"])
    # API and database
    box(d, 36, 72, 120, 40, ["backend API (Node.js, Express)", "non-root \u00b7 read-only filesystem",
                             "no published port"])
    box(d, 46, 12, 100, 36, ["MongoDB 7", "authentication \u00b7 named volume", "no published port"])
    # External services
    box(d, 196, 146, 52, 34, ["Google Identity", "Services (OIDC)"], fill=colors.white)
    box(d, 196, 74, 52, 30, ["Cloudinary", "image hosting"], fill=colors.white)
    # Flows
    arrow(d, [(48, 202), (51, 172.5)])
    arrow(d, [(140, 202), (139, 172.5)])
    arrow(d, [(51, 136), (74, 112.5)])
    arrow(d, [(139, 136), (118, 112.5)])
    label(d, 56, 121, "/api")
    label(d, 134, 121, "/api")
    arrow(d, [(96, 72), (96, 48.5)])
    label(d, 99, 57, "Mongoose", anchor="start")
    arrow(d, [(156, 88), (195.5, 89)])
    label(d, 176, 92, "uploads")
    arrow(d, [(156, 104), (195.5, 150)])
    label(d, 170, 129, "keys")
    arrow(d, [(30, 228), (30, 240), (222, 240), (222, 180.5)], dashed=True)
    label(d, 126, 242.5, "Sign in with Google: ID token returned to the browser", size=5.8)
    return d


def sequence_diagram():
    W, H = COL_W, 240
    d = Drawing(W, H)
    xs = {"B": 30, "G": 94, "A": 160, "M": 225}
    heads = {"B": ["Browser", "patient app"], "G": ["Google Identity", "Services"],
             "A": ["Backend API", "Express"], "M": ["MongoDB", "users"]}
    top = H - 3
    for key, x in xs.items():
        box(d, x - 26, top - 22, 52, 22, heads[key], fill=LIGHT)
        d.add(Line(x, top - 22, x, 4, strokeColor=GREY, strokeWidth=0.5, strokeDashArray=[2, 2]))

    def msg(y, a, b, text, dashed=False, text2=None):
        xa, xb = xs[a], xs[b]
        arrow(d, [(xa, y), (xb - 1.5 if xb > xa else xb + 1.5, y)], dashed=dashed, width=0.6)
        mid = (xa + xb) / 2
        if text2:
            label(d, mid, y + 9.3, text)
            label(d, mid, y + 2.6, text2)
        else:
            label(d, mid, y + 2.6, text)

    y = top - 38
    msg(y, "B", "A", "1. GET /api/user/auth/google/nonce"); y -= 21
    msg(y, "A", "B", "2. nonce + nonceToken (signed, 10 min, jti)", dashed=True); y -= 21
    msg(y, "B", "G", "3. sign in (client_id, nonce)"); y -= 21
    msg(y, "G", "B", "4. ID token (RS256 JWT)", dashed=True); y -= 26
    msg(y, "B", "A", "5. POST /api/user/auth/google", text2="{ credential, nonceToken }"); y -= 21
    msg(y, "A", "G", "6. Google public keys (cached)"); y -= 12
    # Server-side checks
    note_h = 31
    d.add(Rect(102, y - note_h, 118, note_h, fillColor=colors.white, strokeColor=BLACK, strokeWidth=0.6))
    for i, line in enumerate(["7. verify signature, iss, aud, exp;", "email_verified; nonce equals",
                              "nonceToken.nonce; consume jti once"]):
        d.add(String(161, y - 9 - i * 7.6, line, fontName="TNR", fontSize=5.9, textAnchor="middle"))
    y -= note_h + 14
    msg(y, "A", "M", "8. find sub / link / create"); y -= 21
    msg(y, "A", "B", "9. app JWT (HS256, role = user, 1 day)", dashed=True)
    return d


def owasp_chart():
    cats = [
        ("A01 Broken Access Control", 0, 1),
        ("A02 Cryptographic Failures", 2, 0),
        ("A03 Injection", 1, 0),
        ("A04 Insecure Design", 1, 2),
        ("A05 Security Misconfiguration", 1, 0),
        ("A06 Vulnerable & Outdated Components", 1, 0),
        ("A07 Identification & Auth. Failures", 3, 5),
        ("A08 Software & Data Integrity Failures", 0, 1),
        ("A09 Logging & Monitoring Failures", 1, 1),
        ("A10 Server-Side Request Forgery", 0, 0),
    ]
    W, H = COL_W, 158
    d = Drawing(W, H)
    x0, unit, row, top = 131, 12.2, 12.6, H - 22
    dark, light = colors.HexColor("#4A4A4A"), colors.HexColor("#BDBDBD")
    # Legend
    d.add(Rect(x0 - 60, H - 9, 7, 6, fillColor=dark, strokeColor=None))
    d.add(String(x0 - 50, H - 8.5, "Round 1 (Jul. 2026)", fontName="TNR", fontSize=6.3))
    d.add(Rect(x0 + 30, H - 9, 7, 6, fillColor=light, strokeColor=None))
    d.add(String(x0 + 40, H - 8.5, "Round 2 (Sep. 2026)", fontName="TNR", fontSize=6.3))
    for i, (name, r1, r2) in enumerate(cats):
        y = top - i * row
        d.add(String(x0 - 4, y + 1.5, name, fontName="TNR", fontSize=6.3, textAnchor="end"))
        if r1:
            d.add(Rect(x0, y, r1 * unit, 8, fillColor=dark, strokeColor=None))
        if r2:
            d.add(Rect(x0 + r1 * unit, y, r2 * unit, 8, fillColor=light, strokeColor=None))
        d.add(String(x0 + (r1 + r2) * unit + 3, y + 1.5, str(r1 + r2), fontName="TNR", fontSize=6.3))
    d.add(Line(x0, top + 10, x0, top - 9 * row - 2, strokeColor=BLACK, strokeWidth=0.6))
    return d


# ==========================================================================
# CONTENT
# ==========================================================================
TITLE = ("Security Assessment, Remediation and OpenID Connect Integration "
         "for a MERN-Stack Doctor Appointment Booking System")

AUTHORS = [
    ("Nethmina W.P.R.", "IT22253958"),
    ("Appuhami M.N.H.", "IT22140852"),
    ("Madurapperuma H.A.S.I.", "IT22230942"),
    ("Aron Charles J.", "IT22203380"),
]

# ---- Title block (full width, page 1) ------------------------------------
title_block = [Paragraph(TITLE, ST["title"]), Spacer(1, 12)]
author_cells = []
for name, index in AUTHORS:
    author_cells.append([
        Paragraph(name, ST["author"]),
        Paragraph("Faculty of Computing", ST["affil_i"]),
        Paragraph("Sri Lanka Institute of Information Technology", ST["affil"]),
        Paragraph("Malabe, Sri Lanka", ST["affil"]),
        Paragraph(index, ST["affil"]),
    ])
author_table = Table([author_cells], colWidths=[FULL_W / 4] * 4)
author_table.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 3),
    ("RIGHTPADDING", (0, 0), (-1, -1), 3),
]))
title_block += [author_table, Spacer(1, 10)]
TITLE_H = sum(f.wrap(FULL_W, PAGE_H)[1] for f in title_block) + 6
story.extend(title_block)
story.append(FrameBreak())
story.append(NextPageTemplate("later"))

# ---- Abstract ---------------------------------------------------------------
story.append(Paragraph(
    "<i>Abstract</i>\u2014This report presents the security assessment and hardening of "
    "Prescripto, a MERN-stack (MongoDB, Express, React, Node.js) doctor appointment booking "
    "system with patient, doctor and administrator roles. Using manual white-box code review, "
    "software composition analysis, dynamic testing against a running instance and automated "
    "regression tests, we identified twenty distinct vulnerabilities spanning nine of the OWASP "
    "Top 10:2021 categories. They include committed production credentials, an administrator "
    "token that embedded the administrator password, a four-character JWT signing secret, NoSQL "
    "operator injection, account pre-hijacking through social login, a rate-limit bypass via "
    "spoofed proxy headers and a race condition that allowed double booking. All twenty were "
    "fixed in individually documented commits and verified by 41 automated security tests and a "
    "23-check end-to-end test against a containerised deployment. We also implemented Google "
    "Sign-In based on OpenID Connect, with server-side ID-token validation and a server-issued, "
    "single-use nonce that prevents token replay. Finally, we added a continuous security "
    "pipeline and a hardened Docker deployment, and we discuss residual risks and the "
    "secure-development practices that would have prevented these flaws.",
    ST["abstract"]))
story.append(Paragraph(
    "<i>Index Terms</i>\u2014secure software development, web application security, OWASP "
    "Top 10, OpenID Connect, JSON Web Token, NoSQL injection, DevSecOps, container security.",
    ST["abstract"]))

# ---- I. Introduction -------------------------------------------------------
section("Introduction")
p("Web applications that manage medical appointments process personal data such as names, "
  "telephone numbers, addresses and dates of birth, and they expose authentication and "
  "booking workflows directly to the Internet. Their typical weaknesses are well documented "
  f"by the OWASP Top 10 {cite('owasp10')} and the Common Weakness Enumeration (CWE) "
  f"{cite('cwe')}, yet they continue to appear in many projects where functionality is "
  "prioritised over security.")
p("This work was carried out for the SE4030 Secure Software Development module, which requires "
  "identifying and fixing at least seven distinct vulnerabilities in an existing application "
  "and implementing a feature based on OAuth 2.0 or OpenID Connect. We selected Prescripto, a "
  f"MERN-stack doctor appointment booking system {cite('repo_base')}. It offers sufficient scope: "
  "three trust levels (patient, doctor, administrator), token-based authentication, file uploads "
  "to a third-party media service, and 24 REST endpoints. It is not a deliberately vulnerable "
  "teaching application. The hardened version, including the full commit history, is published "
  f"separately {cite('repo_hard')}.")
p("The main contributions of this work are:")
bullets([
    "a two-round assessment that identified 20 distinct vulnerabilities, each mapped to the OWASP "
    "Top 10:2021 and CWE and supported by before-and-after evidence;",
    "remediation of all 20 vulnerabilities, each in an individually documented commit;",
    "Google Sign-In based on OpenID Connect with server-side token validation, nonce-based replay "
    "protection and safe account linking;",
    "an automated security regression suite, a continuous security pipeline and a hardened "
    "container deployment; and",
    "an analysis of residual risks and of the development practices that would have prevented "
    "the vulnerabilities.",
])
p("Section II describes the system, Section III the methodology and Section IV the "
  "vulnerabilities and their fixes. Section V lists issues that were not fixed. Section VI "
  "presents the OpenID Connect implementation, Section VII the verification, Section VIII the "
  "secure deployment and Section IX the preventive practices. Sections X and XI give the "
  "individual contributions and the conclusion.")

# ---- II. System overview ------------------------------------------------------
section("System Overview")
subsection("Architecture")
p("Prescripto consists of three deployable parts, summarised in Table I. The back end is an "
  "Express 4 REST API that uses Mongoose 8 models for users, doctors and appointments, JSON Web "
  f"Tokens (JWT) {cite('rfc7519')} for sessions, bcrypt for password hashing and Multer for "
  "multipart uploads, which are forwarded to Cloudinary. Two React 18 single-page applications "
  "built with Vite provide the patient interface and a combined administrator and doctor panel. "
  "Figure 1 shows the hardened deployment described in Section VIII.")
subsection("Assets, Trust Boundaries and Threat Actors")
p("The assets are patient personal data and appointment records, doctor and administrator "
  "accounts, the administrator's ability to create doctors and view all appointments, and the "
  "secrets that protect them (database credentials, the JWT signing key and third-party API "
  "keys). The main trust boundaries are browser to API, API to external services (MongoDB, "
  "Cloudinary, Google) and developer to repository. We considered three threat actors: an "
  "unauthenticated Internet attacker; an authenticated patient or doctor attempting to exceed "
  "their privileges; and anyone able to read the source repository.")
table("Application Components", ["Component", "Technology", "Responsibility"], [
    ["backend", "Node.js, Express 4.22, Mongoose 8.24, jsonwebtoken, bcrypt, Multer",
     "REST API (24 endpoints): authentication, booking, profiles, uploads"],
    ["frontend", "React 18.3, Vite 6.4, axios, @react-oauth/google",
     "Patient app: doctors, booking, profile, Google sign-in"],
    ["admin", "React 18.3, Vite 6.4, axios",
     "Administrator panel (doctors, all appointments) and doctor panel"],
    ["External", "MongoDB, Cloudinary, Google Identity Services",
     "Persistence, image hosting, OpenID Connect provider"],
], [0.17, 0.43, 0.40])
figure(architecture_diagram(),
       "Hardened deployment. Only the two nginx containers publish ports; they serve the "
       "single-page applications and proxy /api requests to the API, which alone can reach "
       "MongoDB.")
subsection("Baseline")
p(f"The unmodified application at commit {c('2c2bad8')} (February 2025) was imported as the "
  "first commit of the hardened repository. Live external credentials were redacted during "
  "import, but the weak secrets were kept so that the corresponding findings remain "
  "reproducible. Every later change is a separate, descriptively commented commit.")

# ---- III. Methodology -------------------------------------------------------------
section("Methodology")
subsection("Approach")
p("The assessment was performed in two rounds. Round 1 (July 2026) reviewed the original "
  "application and fixed ten vulnerabilities. Round 2 (September 2026) reviewed the hardened "
  "code again, including the round 1 fixes themselves, and found ten further vulnerabilities. "
  "Two of them (V12 and V13) had been missed or even introduced by round 1 fixes, which shows "
  "the value of reviewing security changes as critically as feature code.")
subsection("Techniques and Tools")
p("Table II lists the techniques used. Manual white-box review covered every controller, "
  "middleware, route, model and configuration file of the API, and the authentication and "
  "session handling of both clients. The review was guided by the authentication, session "
  f"management, access control and validation requirements of OWASP ASVS {cite('asvs')}. "
  "Dynamic tests sent crafted requests to a locally running instance, and each confirmed "
  "vulnerability was turned into an automated regression test.")
table("Assessment Techniques and Tools", ["Activity", "Technique / tool", "Scope"], [
    ["White-box review", f"Manual review guided by OWASP ASVS {cite('asvs')}",
     "All API code; client authentication and logging"],
    ["Composition analysis", f"npm audit {cite('npmaudit')}; Dependabot",
     "backend, frontend and admin packages"],
    ["Secret detection", f"Git history inspection; gitleaks {cite('gitleaks')}",
     "Repository history and every push"],
    ["Static analysis", f"GitHub CodeQL, security-extended queries {cite('codeql')}",
     "All JavaScript code, in CI"],
    ["Dynamic testing", "curl against a running API",
     "Injection, forged tokens, CORS, uploads, proxy headers"],
    ["Regression and E2E", "node:test + supertest; Node.js E2E script",
     "41 tests; 23 checks against Docker"],
], [0.24, 0.42, 0.34])
subsection("Severity Rating")
p("Each vulnerability was rated Critical, High, Medium or Low from its exploitability (for "
  "example, whether an attacker must be authenticated) and its impact on confidentiality, "
  "integrity and availability. The ratings follow the reasoning of the CVSS v3.1 base metrics "
  f"{cite('cvss')} but are qualitative, not numeric scores.")

# ---- IV. Vulnerabilities --------------------------------------------------------------
section("Vulnerability Assessment and Remediation")
p("Table III summarises the 20 vulnerabilities. Fig. 2 shows their distribution across the "
  "OWASP Top 10:2021 categories: nine of the ten categories are represented, and "
  "identification and authentication failures (A07) dominate. The remainder of this section "
  "describes each vulnerability, its impact, the fix and how the fix was verified.")
table("Summary of Identified Vulnerabilities", ["ID", "Vulnerability", "OWASP", "CWE", "Severity"], [
    ["V1", "Secrets committed to version control", "A02, A07", "798, 312", "Critical"],
    ["V2", "Forgeable admin token containing the admin password", "A07", "287, 522", "Critical"],
    ["V3", "Non-expiring JWTs with a 4-character secret", "A02, A07", "613, 326", "Critical"],
    ["V4", "No brute-force protection on login", "A07", "307", "High"],
    ["V5", "Wildcard CORS and missing security headers", "A05", "942, 693", "Medium"],
    ["V6", "NoSQL operator injection and user enumeration", "A03", "943, 204", "High"],
    ["V7", "Unrestricted file upload", "A04", "434, 400", "Medium"],
    ["V8", "Passwords in logs; verbose error messages", "A09, A04", "532, 209", "Medium"],
    ["V9", "Weak password policy", "A07", "521", "Medium"],
    ["V10", "Vulnerable third-party components", "A06", "1104", "High"],
    ["V11", "Missing role enforcement; unpinned JWT algorithm", "A01", "863, 347", "Medium"],
    ["V12", "Upload processed before authentication", "A04, A07", "306, 434", "High"],
    ["V13", "Rate-limit bypass via X-Forwarded-For", "A07", "348, 307", "High"],
    ["V14", "Account pre-hijacking; login oracles", "A07", "287, 204, 208", "High"],
    ["V15", "Weak admin credential accepted at boot", "A07", "521, 208", "Medium"],
    ["V16", "Double-booking race; booking logic flaws", "A04", "362, 20, 840", "Medium"],
    ["V17", "Mass assignment in profile updates", "A08", "915, 20", "Medium"],
    ["V18", "Replayable Google ID tokens (no nonce)", "A07", "294", "Medium"],
    ["V19", "Passwords, tokens and PII in browser console", "A09", "532, 359", "Medium"],
    ["V20", "Rejected sessions not cleared by clients", "A07", "613", "Low"],
], [0.085, 0.475, 0.14, 0.15, 0.15], split=True)
figure(owasp_chart(),
       "Number of vulnerabilities per primary OWASP Top 10:2021 category, by assessment round.")

subsection("Round 1 Findings")
runin("V1) Secrets committed to version control",
      f"The original repository tracked {c('backend/.env')}, which contained the MongoDB Atlas "
      "connection string with its password, the Cloudinary API key and secret, a Razorpay key, "
      f"the administrator password ({c('qwerty123')}) and the JWT signing secret "
      f"({c('RBRO')}). Anyone able to read the repository gained full database access and "
      "control of the media store, and could forge sessions (V2, V3). Because git keeps "
      "history, deleting the file later does not end the exposure.")
runin("Remediation",
      f"All {c('.env')} files were removed from version control, {c('.gitignore')} now excludes "
      f"them, and {c('.env.example')} templates document the required variables without values. "
      "The credentials that were exposed must be rotated by their owners (Section V), and a "
      "gitleaks job now fails any push that contains a credential (Section VII).")

runin("V2) Forgeable administrator token",
      "The administrator login compared the submitted credentials with environment variables "
      f"and issued {c('jwt.sign(email + password, secret)')}, so the token payload was the "
      "concatenated email address and password. The middleware accepted any token whose payload "
      "equalled that string (Listing 1). JWT payloads are only Base64url-encoded, so anyone who "
      "obtained an administrator token, for example from browser storage or a proxy log, could "
      "read the administrator password in cleartext. The token never expired, and anyone who "
      "knew the committed secret (V1, V3) could create one offline. The administrator role can "
      "create doctor accounts and read every patient's appointments.")
listing("Administrator token issuance and check, before and after.", """
// Before: adminController.js and authAdmin.js
const token = jwt.sign(email + password,
                       process.env.JWT_SECRET);
if (token_decode !== process.env.ADMIN_EMAIL
                   + process.env.ADMIN_PASSWORD) { ... }

// After
const token = signAccessToken({ role: "admin", email });
if (token_decode.role !== "admin")
  return res.status(403).json({ success: false, ... });
""")
runin("Remediation",
      "Tokens now carry a role claim and an expiry, and the middleware authorises requests only "
      "on the verified role claim, returning HTTP 401 or 403 on failure. Credentials are "
      "compared in constant time (strengthened in V15). A regression test confirms that a token "
      "built with the original scheme is rejected.")

runin("V3) Non-expiring tokens with a four-character secret",
      f"User and doctor tokens were created with {c('jwt.sign({ id }, secret)')} and no "
      "expiry, so a stolen token remained valid forever. The HMAC secret had four characters "
      "and can be brute-forced offline from any single token within seconds; it had also been "
      "committed (V1). Knowing the secret allows forging a token for any user or doctor, which "
      "means taking over any account.")
runin("Remediation",
      f"A new module {c('utils/token.js')} performs all signing with a mandatory expiry "
      f"({c('JWT_EXPIRES_IN')}, default one day), reads bearer tokens consistently, and provides "
      f"{c('assertJwtSecret()')}, which stops the server at start-up if the secret has fewer than "
      "32 characters. In round 2, verification was restricted to HS256, as recommended by the "
      f"JWT best current practices {cite('rfc8725')}. Tests confirm that tokens signed with the "
      "old secret, expired tokens and tokens using other algorithms are rejected, and that the "
      "server refuses to start with the old secret.")

runin("V4) No brute-force protection",
      "The login endpoints of all three roles and the registration endpoint accepted unlimited "
      "requests. This enabled online password guessing and credential stuffing at machine speed, "
      "made worse by the enumeration oracle described in V6.")
runin("Remediation",
      f"{c('express-rate-limit')} now allows 10 authentication requests per client IP address "
      "per 15 minutes (login, registration and Google sign-in) and 300 requests per 15 minutes "
      "to the API as a whole. Excess requests receive HTTP 429. Round 2 later found that this "
      "limit could be bypassed (V13).")

runin("V5) Wildcard CORS and missing security headers",
      f"{c('app.use(cors())')} returned {c('Access-Control-Allow-Origin: *')} on every "
      "endpoint, and no security headers were sent: no content-type sniffing protection, "
      f"framing protection, HSTS or Content Security Policy, while {c('X-Powered-By')} revealed "
      "the framework. Because the API reads tokens from custom headers rather than cookies, a "
      "malicious site could not ride a victim's session. The impact was therefore a loss of "
      "defence in depth: any origin could script the API with a stolen token and read the "
      "responses, and the browser applied no protective policies.")
runin("Remediation",
      f"CORS is now restricted to the origins listed in {c('ALLOWED_ORIGINS')}, and other "
      f"origins receive HTTP 403. {c('helmet')} sets security headers, and a central error "
      "handler returns only generic messages. In the Docker deployment, nginx also sends a "
      "strict Content Security Policy (Section VIII).")

runin("V6) NoSQL operator injection and user enumeration",
      f"The login handlers passed the request body directly to {c('findOne({ email })')}. "
      "Because the JSON parser accepts nested objects, an email value such as "
      f"{c('{\"$regex\": \"^a\"}')} turns the lookup into an operator query "
      f"{cite('wstg')}. The patient login returned different messages depending on whether an "
      "account matched (Listing 2). This was a yes/no oracle: an attacker could recover every "
      "registered email address character by character, and try passwords against accounts "
      "whose addresses they did not know. bcrypt rejects non-string passwords, which prevented a "
      "full authentication bypass, but the resulting exception text was returned to the client "
      "(V8).")
listing("Blind extraction of registered email addresses (original code).", """
POST /api/user/login
{"email": {"$regex": "^a"}, "password": "x"}

-> "User doesn't exit"      no address starts with "a"
-> "Invalid Credentials!"   an address starts with "a"
""")
runin("Remediation",
      f"{c('express-mongo-sanitize')} removes keys that start with {c('$')} or contain a "
      "dot. Explicit string type checks run before any query, and all login failures return the "
      "same message. Round 2 also made the response time independent of whether the account "
      "exists (V14).")

runin("V7) Unrestricted file upload",
      "Multer saved uploads in the operating system's temporary directory under the file name "
      "chosen by the client, with no limit on size, number or type. An attacker could exhaust "
      "the disk with large files. Two uploads with the same name also overwrote each other "
      "before being sent to Cloudinary, so one person's photograph could end up on another "
      "person's profile or doctor record. Multer strips directory components from file names, so "
      "path traversal was not possible.")
runin("Remediation",
      "Uploads are now written to a dedicated directory under random 128-bit names, only JPEG, "
      "PNG and WEBP types and extensions are accepted, and requests are limited to one file of "
      "at most 2 MB. Round 2 added authentication before upload parsing, verification of the "
      "file's actual content, and deletion of temporary files (V12).")

runin("V8) Passwords in logs and verbose error messages",
      "The add-doctor handler wrote the complete request body, including the new doctor's "
      "plaintext password, to the server log. Every error handler also returned the raw "
      "exception message to the client, revealing database driver errors and token library "
      "messages that help an attacker plan further attacks.")
runin("Remediation",
      "The sensitive logging was removed. Handlers now log details on the server only and "
      "return generic messages, and a central error handler applies the same policy to "
      "unexpected errors.")

runin("V9) Weak password policy",
      "Registration and doctor creation only required eight characters, so passwords such as "
      f"{c('password')} and {c('12345678')} were accepted, which makes bcrypt hashing far less "
      "effective against guessing. The appointment cancellation handler also crashed with HTTP "
      "500 when the appointment did not exist.")
runin("Remediation",
      "Passwords must now contain at least eight characters including an uppercase letter, a "
      "lowercase letter, a digit and a symbol. NIST SP 800-63B favours longer passphrases "
      f"checked against lists of breached passwords over composition rules {cite('nist63b')}; "
      "we list this as future work in Section V. The cancellation handler now handles missing "
      "appointments safely.")

runin("V10) Vulnerable third-party components",
      "npm audit reported 17 advisories for the back end, including a critical issue in "
      "form-data and high-severity axios issues, and 22 advisories for each client, including a "
      "critical one.")
runin("Remediation",
      "The dependencies were updated with npm audit fix, and bcrypt was upgraded from version "
      "5 to 6, which removes a vulnerable install-time dependency chain. A misspelled Cloudinary "
      "variable name that silently disabled the media configuration was also corrected. The "
      "round 2 re-audit is discussed in Section IV-C.")

subsection("Round 2 Findings")
runin("V11) Missing role enforcement and unpinned algorithm",
      "The patient middleware accepted any valid token, so doctor and administrator tokens were "
      "treated as patient sessions. The doctor middleware rejected only tokens that carried a "
      "different role, so a token without a role claim was accepted. Controllers read the "
      f"caller's identity from {c('req.body')}, which is safe only as long as no later "
      f"middleware rebuilds the body. {c('jwt.verify()')} also accepted any HMAC algorithm.")
runin("Remediation",
      f"Each middleware now requires the exact role claim and a subject identifier, and answers "
      f"HTTP 403 otherwise. The identity is attached to {c('req.auth')} and never read from the "
      "request body, and verification accepts only HS256. Tests cover every cross-role "
      "combination.")

runin("V12) Upload processed before authentication",
      f"On {c('POST /api/user/update-profile')}, the Multer middleware ran before the "
      "authentication middleware. Anonymous clients could therefore write files of up to 2 MB "
      "to the server's disk without any credentials, limited only by the general API rate "
      "limit. The round 1 type "
      "check trusted the client-declared MIME type and extension, so any content renamed to "
      "PNG was accepted. Temporary files were also never deleted after being sent to "
      "Cloudinary.")
runin("Remediation",
      "The middleware order is now authentication, then Multer, then a content check that "
      "reads the file's first bytes and accepts only genuine JPEG, PNG and WEBP data. Temporary "
      "files are deleted after every request, and upload errors return HTTP 400. Tests confirm "
      "that an anonymous upload receives HTTP 401 without any file being written, and that a PHP "
      "script renamed to .png is rejected.")

runin("V13) Rate-limit bypass via spoofed X-Forwarded-For",
      f"Round 1 enabled Express's {c('trust proxy')} setting unconditionally. When the API is "
      "reached directly, Express then takes the client IP address from the X-Forwarded-For "
      f"header, which the attacker controls {cite('express_proxy')}, and the rate limiter counts "
      "attempts per that value. Listing 3 reproduces the bypass: after ten attempts the real "
      "address was throttled, but twelve further attempts, each with a different header value, "
      "were never throttled.")
listing("Status codes of 12 login attempts (V13).", """
same client address     400 x10, 429, 429
spoofed XFF per request 400 400 400 400 400 400
                        400 400 400 400 400 400
after the fix (spoofed) 400 x10, 429, 429
""")
runin("Remediation",
      f"The proxy setting is now enabled only when {c('TRUST_PROXY')} is configured. In the "
      "Docker deployment, nginx overwrites X-Forwarded-For with the real client address and the "
      "API has no published port, so trusting exactly one proxy is safe there. This was "
      "verified both in-process and end-to-end through nginx.")

runin("V14) Account pre-hijacking and login oracles",
      "Local registration does not verify that the user owns the email address, but the first "
      "Google sign-in implementation linked a Google identity to any existing account with the "
      "same address. An attacker could therefore register a victim's Gmail address with a "
      "password of their choosing. When the real owner later signed in with Google, the account "
      "was linked but the attacker's password still worked, giving the attacker lasting access. "
      f"This is the account pre-hijacking pattern described by Sudhodanan and Paverd "
      f"{cite('prehijack')}. In addition, logging in to a Google-only account (which has no "
      "password hash) made bcrypt throw an exception, returning HTTP 500 instead of \u201cInvalid "
      "Credentials!\u201d. The handlers also skipped bcrypt for unknown email addresses, so both "
      "the status code and the response time revealed which accounts existed.")
runin("Remediation",
      "When a Google identity is first linked to an existing account, the unverified local "
      "password is removed, the account is marked as a Google account, and all sessions issued "
      f"before that moment are revoked through a new {c('sessionsValidAfter')} timestamp. The "
      "patient middleware checks this timestamp, and also rejects tokens of deleted accounts. A "
      f"new {c('verifyPassword()')} function always performs exactly one bcrypt comparison (with "
      "a dummy hash when no hash exists) and never throws. In our measurement, logins for "
      "missing accounts took 58 ms and wrong passwords 56 ms. As a trade-off, users who "
      "registered locally continue with Google sign-in once they have used it.")

runin("V15) Weak administrator credential accepted",
      "The administrator credential is read from environment variables, and nothing prevented "
      "a deployment from keeping the original weak password. The round 1 constant-time "
      "comparison also returned early when the lengths differed, which revealed the length of "
      "the password through response timing.")
runin("Remediation",
      f"{c('assertAdminCredentials()')} stops the server at start-up unless the administrator "
      "email is valid and the password has at least 12 characters with mixed character classes. "
      "Both values are hashed with SHA-256 before a constant-time comparison.")

runin("V16) Double-booking race condition and booking logic flaws",
      "The booking handler read the doctor's map of booked slots, checked availability in "
      "JavaScript, saved the appointment and then wrote the entire map back. Concurrent requests "
      "for the same slot all passed the check (a time-of-check to time-of-use race), and "
      "concurrent bookings of different slots could overwrite each other. The inputs were not "
      "validated: a malformed doctor identifier crashed the handler, past or impossible dates "
      f"could be booked, and arbitrary strings, including {c('__proto__')}, were used as map "
      "keys. Completed appointments could be cancelled, and cancelled ones completed. Repeated "
      "cancellations released the slot again, while a doctor's cancellation never released it "
      "at all. Appointment records also stored fields that other roles did not need, such as "
      "the doctor's email address and Google identifiers.")
listing("Atomic check-and-reserve with a single conditional update.", """
const doctor = await doctorModel.findOneAndUpdate(
  { _id: docId, available: true,
    [`slots_booked.${slotDate}`]: { $ne: slotTime } },
  { $push: { [`slots_booked.${slotDate}`]: slotTime } });
if (!doctor) return "Slot not Available!";
""")
runin("Remediation",
      "Listing 4 reserves a slot in one conditional update that matches only when the doctor is "
      "available and the slot is free. MongoDB applies it atomically to a single document, so "
      "only one concurrent request can succeed; if saving the appointment then fails, the slot "
      "is released again. Validators check identifiers, real calendar dates from yesterday up to "
      "60 days ahead, and time formats. Status changes are atomic, with ownership included in "
      "the update filter, slots are released with an atomic removal, and appointment records "
      "store only the fields that are displayed. Against a real MongoDB 7 container, ten "
      "concurrent requests for the same slot produced exactly one booking and nine refusals.")

runin("V17) Mass assignment in profile updates",
      "The doctor profile handler copied the fee, address and availability fields from the "
      "request straight into the database. A doctor could therefore set a negative or "
      "non-numeric fee, which becomes the amount charged for new appointments, or store "
      "arbitrary nested objects as the address. The patient profile handler parsed the address "
      "JSON without any checks, so malformed input caused HTTP 500, and it accepted any name, "
      "phone number, date of birth and gender. The add-doctor handler had the same address and "
      "fee problems.")
runin("Remediation",
      "Only listed fields are accepted now, and each is validated: the address keeps only two "
      "text lines of at most 200 characters, fees must be finite numbers between 0 and 1,000,000, "
      "and phone numbers, dates of birth and gender values must match allowed formats or values. "
      "Invalid input receives HTTP 400.")

runin("V18) Replayable Google ID tokens",
      "The first OpenID Connect implementation accepted any valid Google ID token issued for our "
      "client ID. No nonce was requested or checked, so an ID token captured anywhere (from "
      "browser history, a logging proxy, or a different login attempt) could be exchanged for "
      "an application session until it expired, typically after one hour. OpenID Connect Core "
      f"defines the nonce parameter to bind an ID token to a client session and prevent replay "
      f"{cite('oidc')}. The fix is described in Section VI.")

runin("V19) Credentials and personal data in browser consoles",
      "Before submitting, the administrator panel printed every form field to the browser "
      "console, including the new doctor's plaintext password. The doctor login printed the "
      "session token, and the administrator, doctor and patient views printed complete API "
      "responses containing patients' names, telephone numbers, addresses and dates of birth. "
      "This data was visible to anyone with access to the workstation, a shared screen or a "
      "browser extension.")
runin("Remediation",
      "The logging statements were removed. The fix also repaired the administrator and doctor "
      "login handler: misnamed state setters meant a successful login only took effect after a "
      "page reload, and an empty error handler silently ignored HTTP 401 and 429 responses.")

runin("V20) Rejected sessions not cleared by the clients",
      "After a token expired or was revoked, the clients kept it in local storage. Every request "
      "failed, and the patient login page redirected any user who held a token, so the user "
      "could not sign in again without manually clearing browser storage.")
runin("Remediation",
      "A shared axios response interceptor, installed when the application loads, clears the "
      "matching session on HTTP 401 and shows the API's generic error message instead of "
      "axios's default text.")

subsection("Dependency Re-assessment")
p("Table IV compares the two dependency audits. Within two months of the round 1 fix, new "
  "advisories affected all three packages: denial-of-service issues in brace-expansion and qs, "
  "incorrect address classification in ip-address (which can defeat SSRF protections) in the "
  "back end, and a CSRF bypass in React Router in both clients. The back end also still used "
  "the deprecated 1.x series of Multer, whose upload denial-of-service fixes exist only in "
  "version 2. All issues were resolved and Multer was upgraded to 2.4. This result motivates "
  "the weekly scheduled audit described in Section VII.")
table("npm Audit Results (Advisories Before and After Each Fix)",
      ["Package", "Jul. 2026", "Sep. 2026 re-audit"], [
          ["backend", "17 \u2192 0", "5 (2 high) \u2192 0"],
          ["frontend", "22 \u2192 0", "2 (2 high) \u2192 0"],
          ["admin", "22 \u2192 0", "2 (2 high) \u2192 0"],
      ], [0.3, 0.3, 0.4])

# ---- V. Not fixed ------------------------------------------------------------------------
section("Vulnerabilities Not Fixed")
p("Table V lists the weaknesses that remain, with the reason each was not fixed and the "
  "recommended action. Most require infrastructure (an email provider, a shared cache, logging "
  "services) or architectural changes that go beyond the scope of this assignment.")
table("Remaining Weaknesses", ["Issue", "Reason not fixed", "Recommendation"], [
    ["Leaked secrets remain in the original repository's history",
     "Rotation is done in the provider dashboards, not in code",
     "Rotate all keys; purge history with git filter-repo"],
    ["JWTs stored in localStorage",
     "httpOnly cookies need CSRF protection and CORS changes in three apps; partly mitigated by "
     "the CSP (Section VIII)",
     "httpOnly, SameSite cookies with CSRF tokens"],
    ["No logout endpoint or refresh-token rotation",
     "Account-wide revocation exists; per-token revocation needs a token store",
     "Short-lived access tokens, rotating refresh tokens"],
    ["No email verification for local accounts",
     "Requires an email provider; the linking attack (V14) is already closed",
     "Verify ownership before activating an account"],
    ["Single administrator from environment variables, no MFA",
     "Needs a database-backed administrator model and an MFA flow",
     "Role-based admin accounts with TOTP or WebAuthn"],
    ["In-memory rate limits and nonce cache",
     "Correct only while a single API instance runs",
     "Shared Redis or MongoDB TTL store"],
    ["Composition-based password rules",
     "Simple to implement and explain",
     f"Passphrases and breached-password screening {cite('nist63b')}"],
    ["Razorpay payment not implemented",
     "No server-side payment endpoint exists in the application",
     "Server-side order creation and signature verification"],
    ["No security event logging or alerting",
     "Requires logging and monitoring infrastructure",
     "Structured audit logs for logins and admin actions"],
], [0.33, 0.37, 0.30])

# ---- VI. OpenID Connect -------------------------------------------------------------------
section("OpenID Connect Sign-In")
subsection("Protocol Choice")
p(f"OpenID Connect (OIDC) {cite('oidc')} adds an identity layer on top of OAuth 2.0 "
  f"{cite('rfc6749')}: the identity provider issues a signed ID token that states who the user is. "
  f"We used Google Identity Services {cite('gis')}. Its Sign in with Google button returns an ID "
  "token directly to the browser, which corresponds to the OIDC implicit flow with the "
  "id_token response type. The application uses Google only for authentication: it requests "
  "the openid, email and profile scopes, receives no Google access token, and therefore stores "
  "no refresh tokens or client secret. With this flow, the main risks are forged, misdirected "
  "or replayed ID tokens, and unsafe linking to existing accounts. The implementation addresses "
  "each of them.")
figure(sequence_diagram(),
       "OpenID Connect sign-in sequence with a server-issued, single-use nonce.")
subsection("Sign-In Flow")
p("Fig. 3 shows the message sequence. (1, 2) The patient application requests a nonce. The API "
  "generates a random 256-bit value and returns it together with a nonce token: a JWT with a "
  "unique identifier (jti), a ten-minute expiry, and a signature made with a key derived from "
  f"the application secret by HMAC-SHA-256 with the label {c('google-oidc-nonce')}. Because of "
  "this separate key, a nonce token can never be accepted as an access token. The response is "
  "marked as non-cacheable. (3, 4) The Google button is created with the nonce; after the user "
  "consents, Google returns an RS256-signed ID token containing that nonce. (5) The browser "
  "posts the ID token together with the nonce token. (6, 7) The API validates both, as "
  "described below. (8) It finds, links or creates the user, and (9) issues the application's "
  "own role-scoped JWT.")
subsection("Server-Side Validation")
p(f"Listing 5 shows the core checks. {c('verifyIdToken')} from google-auth-library checks the "
  "RS256 signature against Google's published keys, the issuer, the audience (which must equal "
  f"our client ID) and the expiry {cite('gis_verify')}. The API then requires a Google-verified "
  "email address, requires the token's nonce to equal the one in the nonce token, and marks the "
  "nonce token's jti as used, so a captured request cannot be replayed. Accounts are looked up "
  "by Google's stable subject identifier first and by email address second; linking follows the "
  "V14 rules.")
listing("ID-token validation in the sign-in handler (abridged).", """
const nonceClaims = verifyNonceToken(nonceToken);
const ticket = await googleClient.verifyIdToken({
  idToken: credential,
  audience: process.env.GOOGLE_CLIENT_ID });
const payload = ticket.getPayload();
if (payload?.nonce !== nonceClaims.nonce)  return 401;
if (!consumeNonceId(nonceClaims.jti, nonceClaims.exp))
  return 401;                          // replay
if (!payload.email_verified)               return 401;
// ...find, link or create the user by payload.sub
const token = signAccessToken({ id: user._id,
                                role: "user" });
""")
subsection("Client and Provider Configuration")
p("The OAuth client in Google Cloud is a web application whose authorised JavaScript origins "
  "are the application's origins; users are restricted to registered test users while the app "
  "is in testing mode. The client ID is public and is built into the patient application; no "
  "client secret is used. The Google button is rendered only once a nonce is available, and it "
  "is recreated with a fresh nonce after every attempt. The nginx headers are compatible with "
  "the provider: the Content Security Policy allows Google's sign-in script, frame and style "
  "origins, Cross-Origin-Opener-Policy allows the sign-in popup, and the Referrer-Policy keeps "
  "the origin information that Google requires.")
subsection("Verification")
p("Automated tests cover the following cases: nonces are random and non-cacheable; a missing "
  "nonce token is rejected with HTTP 400; a nonce token used as an access token is rejected; an "
  "ID token issued for a different nonce is rejected; linking removes a pre-set password and "
  "revokes earlier sessions; and replaying a successful request fails. In manual tests with "
  "real Google accounts, sign-in, account provisioning and profile loading worked end to end.")

# ---- VII. Verification ------------------------------------------------------------------------
section("Verification and Continuous Security")
subsection("Automated Regression Tests")
p(f"To make the API testable, the Express application was separated ({c('app.js')}) from "
  f"start-up, which loads configuration, performs the secret checks and connects to the "
  f"database ({c('server.js')}). The suite uses Node's built-in test runner and supertest. It "
  "runs against the API in the same process with database calls replaced by stubs, so it needs "
  "no database or external accounts. It contains 41 tests grouped as shown in Table VI.")
table("Verification Summary", ["Suite", "Content", "Result"], [
    ["npm test", "HTTP hardening (3), JWT and roles (11), start-up secret checks (2), injection and "
     "login oracles (2), uploads (5), input validation (4), OIDC (5), rate limiting (1), "
     "validators and password helper (8)", "41 / 41 pass"],
    ["End-to-end", "23 checks through nginx against MongoDB 7, including the concurrent booking "
     "race, patient, doctor and admin flows, and spoofed-header throttling", "23 / 23 pass"],
    ["npm audit", "backend, frontend, admin; high and critical advisories", "0 found"],
    ["CI", "GitHub Actions and CodeQL on every push, pull request and weekly", "Passing"],
], [0.18, 0.60, 0.22])
subsection("End-to-End Test")
p("A script exercised the Docker deployment through the nginx proxies. It confirmed the "
  "security headers and single-page-application routing, that port 4000 is not published, "
  "that foreign origins are rejected, and the patient registration, profile, booking and "
  "cancellation flows, doctor and administrator logins, and dashboards. It also confirmed "
  "exactly-once booking under ten concurrent requests, slot release on cancellation, refusal "
  "of a second cancellation, minimal appointment records and throttling despite spoofed "
  "headers. The script removes its test data afterwards.")
subsection("Continuous Security Pipeline")
p("A GitHub Actions workflow runs on every push, on every pull request and weekly. It executes "
  "the regression tests, fails the build on any high or critical npm advisory in the three "
  "packages, builds both clients and scans pushed commits for credentials with gitleaks. A "
  f"separate workflow runs CodeQL with the security-extended query suite {cite('codeql')}, and "
  "Dependabot proposes dependency updates weekly. At the time of writing, both workflows passed "
  "on the main branch.")

# ---- VIII. Deployment -----------------------------------------------------------------------------
section("Secure Deployment")
p("The system is packaged as three images plus MongoDB 7 and orchestrated with Docker Compose "
  f"(Fig. 1), following the OWASP Docker security guidance {cite('docker_cs')}. The API image is "
  "based on Node.js 22 Alpine, contains only production dependencies and runs as a non-root "
  "user. Each client is built with Vite and served by an unprivileged nginx image, which also "
  "proxies API requests, so browsers talk to a single origin.")
bullets([
    "<i>Network exposure:</i> only the two web containers publish ports. The API and MongoDB are "
    "reachable only inside the Compose network, and nginx overwrites X-Forwarded-For, so the "
    "rate limiter always sees the real client address (V13).",
    "<i>Least privilege:</i> the API runs as UID 1000 and nginx as UID 101. The application "
    "containers have "
    "read-only root filesystems, drop all Linux capabilities and set no-new-privileges; only "
    "/tmp and the upload directory are writable, as in-memory filesystems.",
    f"<i>Browser policies:</i> nginx sends a Content Security Policy {cite('csp3')} that allows "
    "scripts only from the application's own origin, Google's sign-in service and Razorpay, and "
    "forbids plugins, framing and foreign form targets. Together with X-Frame-Options, "
    "nosniff, Referrer-Policy and Permissions-Policy, this reduces the impact of cross-site "
    "scripting on tokens stored in local storage.",
    "<i>Secrets and data:</i> MongoDB requires authentication and stores data in a named volume. "
    "Secrets come from git-ignored environment files and are excluded from images, and health "
    "checks enforce the start-up order (database, then API, then web servers).",
])

# ---- IX. Best practices ---------------------------------------------------------------------------
section("Preventive Best Practices")
p(f"Each vulnerability corresponds to a practice of the NIST Secure Software Development "
  f"Framework {cite('ssdf')} and established security development lifecycles "
  f"{cite('sdl', 'mcgraw')} that was missing:")
bullets([
    "<i>Threat modelling and abuse cases</i> for authentication, social-login account linking "
    "and concurrent booking would have exposed V2, V14 and V16 at design time.",
    "<i>Secure defaults and shared security components</i>, namely one token module, one "
    "validation layer and a hardened Express template, prevent the inconsistent checks behind "
    "V3, V5, V11 and V17.",
    "<i>Secrets management</i>: environment templates, a secrets manager, and secret scanning "
    "before commits and in CI address V1 and V15.",
    "<i>Checklist-based code review</i> (for example with ASVS) that covers middleware order, "
    "logging of sensitive data and client-side logging would have caught V8, V12 and V19.",
    "<i>Continuous security testing</i>: static analysis, dependency scanning, dynamic testing "
    "and a regression test for every fixed vulnerability detect V4, V6 and V10 early and keep "
    "fixes from regressing.",
    "<i>Reviewing security fixes themselves</i>: V12 and V13 remained after, or were introduced "
    "by, round 1 hardening and were found only by a second independent review.",
])

# ---- X. Contributions -----------------------------------------------------------------------------
section("Individual Contributions")
p("Table VII lists each member's primary responsibilities.")
table("Individual Contributions", ["Member", "Area", "Work items"], [
    ["Nethmina W.P.R. (IT22253958)", "Authentication and session security",
     "V2, V3, V11, V15, V20; repository setup and CI pipeline"],
    ["Appuhami M.N.H. (IT22140852)", "Injection, input validation and uploads",
     "V6, V7, V12, V16, V17"],
    ["Madurapperuma H.A.S.I. (IT22230942)", "Configuration, secrets, dependencies and deployment",
     "V1, V4, V5, V10, V13; Docker deployment"],
    ["Aron Charles J. (IT22203380)", "OpenID Connect and data protection",
     "Google sign-in, V8, V9, V14, V18, V19"],
], [0.33, 0.33, 0.34])

# ---- XI. Conclusion -------------------------------------------------------------------------------
section("Conclusion")
p("We assessed and hardened Prescripto, a MERN-stack doctor appointment booking system. Two "
  "rounds of review identified 20 distinct vulnerabilities across nine OWASP Top 10:2021 "
  "categories, ranging from committed secrets and forgeable administrator tokens to account "
  "pre-hijacking, a race condition in booking and a rate-limit bypass introduced by an earlier "
  "fix. All were remediated in documented commits and are protected against regression by 41 "
  "automated tests, a 23-check end-to-end test and a continuous security pipeline. Google "
  "Sign-In based on OpenID Connect was added with complete server-side validation, single-use "
  "nonces and safe account linking, and the system now runs in hardened containers. Future work "
  "includes cookie-based sessions with CSRF protection, multi-factor authentication for "
  "administrators, email verification, breached-password screening, and dynamic scanning (for "
  "example with OWASP ZAP) and container image scanning in the pipeline. The source code and "
  f"commit history are available in the project repository {cite('repo_hard')}.")

# ---- References ---------------------------------------------------------------------------------------
story.append(CondPageBreak(60))
story.append(Paragraph(smallcaps("References"), ST["h1"]))
for n, key in enumerate(CITE_ORDER, start=1):
    story.append(Paragraph(REFERENCES[key], ST["ref"], bulletText=f"[{n}]"))

unused = set(REFERENCES) - set(CITE_ORDER)
if unused:
    sys.exit(f"Uncited references: {sorted(unused)}")


# ==========================================================================
# Document assembly
# ==========================================================================
def first_page(canvas, doc):
    canvas.saveState()
    y = BM + FOOTNOTE_H - 3
    canvas.setLineWidth(0.4)
    canvas.line(LM, y, LM + 40 * mm, y)
    note = Paragraph(
        "This report was prepared for the SE4030 Secure Software Development module, "
        "Sri Lanka Institute of Information Technology, September 2026. Source code of the "
        "hardened system: https://github.com/RVNethmina/SE4030-secure-appointment-system.",
        ST["footnote"])
    _, h = note.wrap(COL_W, FOOTNOTE_H)
    note.drawOn(canvas, LM, y - 3 - h)
    page_number(canvas, doc)
    canvas.restoreState()


def page_number(canvas, doc):
    canvas.setFont("TNR", 8)
    canvas.drawCentredString(PAGE_W / 2, 11 * mm, str(doc.page))


def later_pages(canvas, doc):
    canvas.saveState()
    page_number(canvas, doc)
    canvas.restoreState()


def build():
    doc = BaseDocTemplate(
        OUTPUT, pagesize=A4, leftMargin=LM, rightMargin=RM, topMargin=TM, bottomMargin=BM,
        title=TITLE,
        author="Nethmina W.P.R.; Appuhami M.N.H.; Madurapperuma H.A.S.I.; Aron Charles J.",
        subject="SE4030 Secure Software Development - security assessment report",
        keywords="OWASP Top 10, OpenID Connect, JWT, NoSQL injection, DevSecOps, Docker",
        creator="docs/report/build_report.py",
    )
    col_top = PAGE_H - TM - TITLE_H
    first = PageTemplate(id="first", onPage=first_page, frames=[
        Frame(LM, PAGE_H - TM - TITLE_H, FULL_W, TITLE_H, id="title",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        Frame(LM, BM + FOOTNOTE_H, COL_W, col_top - BM - FOOTNOTE_H, id="c1",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        Frame(LM + COL_W + GAP, BM, COL_W, col_top - BM, id="c2",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
    ])
    later = PageTemplate(id="later", onPage=later_pages, frames=[
        Frame(LM, BM, COL_W, PAGE_H - TM - BM, id="l1",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
        Frame(LM + COL_W + GAP, BM, COL_W, PAGE_H - TM - BM, id="l2",
              leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0),
    ])
    doc.addPageTemplates([first, later])
    doc.build(story)
    print(f"wrote {OUTPUT} ({doc.page} pages)")


if __name__ == "__main__":
    build()
