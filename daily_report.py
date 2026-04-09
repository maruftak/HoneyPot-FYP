#!/usr/bin/env python3
"""
honeyPot — Professional Daily Intelligence Report (PDF)
Generates a multi-page threat intelligence PDF and sends via Telegram.

pip install reportlab matplotlib requests numpy
"""
import os, sys, io, sqlite3, datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, Image, PageBreak, Flowable,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

# ─── Design System ────────────────────────────────────────────────────────────
C_BG      = HexColor("#0b1120")   # cover background (deep navy)
C_PANEL   = HexColor("#111d35")   # cover right panel
C_CARD    = HexColor("#162038")   # cover KPI cards
C_CIRCLE  = HexColor("#1a2d52")   # decorative circles
CRIMSON   = HexColor("#c62828")   # red accent / critical
NAVY      = HexColor("#0d47a1")   # primary blue
NAVY2     = HexColor("#1565c0")   # chart bars
TEAL      = HexColor("#1b5e20")   # positive / green
AMBER     = HexColor("#e65100")   # warning / orange
SLATE     = HexColor("#455a64")   # secondary text
BORDER    = HexColor("#dce6f0")   # table borders
ALT_ROW   = HexColor("#eef4fb")   # alternate row bg
PAGE_HDR  = HexColor("#0d47a1")   # page header bar
TEXT      = HexColor("#0d1b2a")   # body text
WHITE     = colors.white

W, H    = A4
MARGIN  = 1.6 * cm
CW      = W - 2 * MARGIN          # usable content width

# ─── Typography ───────────────────────────────────────────────────────────────
def _P(name, **kw):
    return ParagraphStyle(name, **kw)

# Section / content styles
S_SEC   = _P("sec",  fontName="Helvetica-Bold", fontSize=11, textColor=NAVY,
              leading=14, spaceBefore=2, spaceAfter=4)
S_BODY  = _P("bod",  fontName="Helvetica",      fontSize=9,  textColor=TEXT,  leading=13)
S_BOLD  = _P("bld",  fontName="Helvetica-Bold", fontSize=9,  textColor=TEXT,  leading=13)
S_CAP   = _P("cap",  fontName="Helvetica-Oblique", fontSize=7.5, textColor=SLATE,
              alignment=TA_CENTER, leading=10)
S_NOTE  = _P("nte",  fontName="Helvetica",      fontSize=8,  textColor=SLATE, leading=11)
T_HDR   = _P("thd",  fontName="Helvetica-Bold", fontSize=8,  textColor=WHITE,
              alignment=TA_CENTER, leading=11)
T_HDR_L = _P("thl",  fontName="Helvetica-Bold", fontSize=8,  textColor=WHITE,
              alignment=TA_LEFT,   leading=11)
T_C     = _P("tc",   fontName="Helvetica",      fontSize=8.5, textColor=TEXT,
              alignment=TA_CENTER, leading=12)
T_L     = _P("tl",   fontName="Helvetica",      fontSize=8.5, textColor=TEXT,
              alignment=TA_LEFT,   leading=12)
T_MONO  = _P("tm",   fontName="Courier",        fontSize=8,  textColor=TEXT,
              alignment=TA_LEFT,   leading=12)
KPI_VAL = _P("kv",   fontName="Helvetica-Bold", fontSize=22, textColor=NAVY,
              alignment=TA_CENTER, leading=26)
KPI_LBL = _P("kl",   fontName="Helvetica-Bold", fontSize=7,  textColor=SLATE,
              alignment=TA_CENTER, leading=10)
KPI_SUB = _P("ks",   fontName="Helvetica",      fontSize=7,  textColor=SLATE,
              alignment=TA_CENTER, leading=10)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def blur_ip(ip):
    if not ip or ip in ("", "Unknown"):
        return "●●●.●●●.xxx.xxx"
    p = ip.split(".")
    return f"{p[0]}.{p[1]}.●●●.●●●" if len(p) == 4 else "●●●.●●●.xxx.xxx"

def blur_cred(s, keep=2):
    if not s: return "—"
    s = str(s)[:40]
    return s[:keep] + "●" * min(len(s) - keep, 8) if len(s) > keep else "●" * len(s)

def _pct(new, old):
    return (new - old) / old * 100 if old else None

def trend_p(new, old):
    pct = _pct(new, old)
    if pct is None: return Paragraph("—", T_C)
    if abs(pct) < 3: return Paragraph('<font color="#78909c">→  no change</font>', T_C)
    up  = pct > 0
    sym = f"{'▲' if up else '▼'}  {abs(pct):.0f}%"
    clr = "#c62828" if up else "#2e7d32"
    return Paragraph(f'<font color="{clr}"><b>{sym}</b></font>', T_C)

def severity_color(level):
    return {"CRITICAL": "#c62828", "HIGH": "#e65100",
            "MEDIUM": "#f9a825", "LOW": "#2e7d32"}.get((level or "").upper(), "#455a64")

# ─── Database ─────────────────────────────────────────────────────────────────
def _q(c, sql, p=()): return c.execute(sql, p).fetchall()
def _s(c, sql, p=()):
    r = _q(c, sql, p); return r[0][0] if r else 0

def collect_data(db):
    now  = datetime.datetime.utcnow()
    a24  = (now - datetime.timedelta(hours=24)).isoformat()
    a48  = (now - datetime.timedelta(hours=48)).isoformat()
    conn = sqlite3.connect(db, timeout=30)
    d    = {"now": now}

    d["total"]   = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>?", (a24,))
    d["uniq"]    = _s(conn, "SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE timestamp>?", (a24,))
    d["ctries"]  = _s(conn, "SELECT COUNT(DISTINCT country) FROM attacks WHERE timestamp>? AND country NOT IN ('','Unknown')", (a24,))
    d["botnets"] = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_botnet=1", (a24,))
    d["vpn"]     = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_vpn=1", (a24,))
    d["tor"]     = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_tor=1", (a24,))
    d["proxy"]   = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND is_proxy=1", (a24,))
    d["bursts"]  = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND attack_type='BRUTE_FORCE_BURST'", (a24,))
    d["htoks"]   = _s(conn, "SELECT COUNT(*) FROM honeytoken_triggers WHERE timestamp>?", (a24,))
    d["cves"]    = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND cve_id!='' AND cve_id IS NOT NULL", (a24,))
    try: d["cves"] += _s(conn, "SELECT COUNT(*) FROM cve_attempts WHERE timestamp>?", (a24,))
    except: pass

    p = (a48, a24)
    d["p_total"]   = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND timestamp<=?", p)
    d["p_uniq"]    = _s(conn, "SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE timestamp>? AND timestamp<=?", p)
    d["p_ctries"]  = _s(conn, "SELECT COUNT(DISTINCT country) FROM attacks WHERE timestamp>? AND timestamp<=? AND country NOT IN ('','Unknown')", p)
    d["p_botnets"] = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND timestamp<=? AND is_botnet=1", p)
    d["p_vpn"]     = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND timestamp<=? AND is_vpn=1", p)
    d["p_cves"]    = _s(conn, "SELECT COUNT(*) FROM attacks WHERE timestamp>? AND timestamp<=? AND cve_id!='' AND cve_id IS NOT NULL", p)
    try: d["p_cves"] += _s(conn, "SELECT COUNT(*) FROM cve_attempts WHERE timestamp>? AND timestamp<=?", p)
    except: pass

    raw = _q(conn, "SELECT CAST(strftime('%H',timestamp) AS INT) h, COUNT(*) n FROM attacks WHERE timestamp>? GROUP BY h", (a24,))
    d["hourly"]   = {r[0]: r[1] for r in raw}
    d["services"] = _q(conn, "SELECT upper(service), COUNT(*) n FROM attacks WHERE timestamp>? AND service IS NOT NULL AND service!='' GROUP BY lower(service) ORDER BY n DESC LIMIT 8", (a24,))
    d["countries"]= _q(conn, "SELECT country, COUNT(*) n FROM attacks WHERE timestamp>? AND country NOT IN ('','Unknown') GROUP BY country ORDER BY n DESC LIMIT 10", (a24,))
    d["cities"]   = _q(conn, "SELECT city, country, COUNT(*) n FROM attacks WHERE timestamp>? AND city NOT IN ('','Unknown') AND city IS NOT NULL GROUP BY city ORDER BY n DESC LIMIT 6", (a24,))

    cve_rows = list(_q(conn, "SELECT cve_id, COALESCE(cve_name,'') n2, COUNT(*) n FROM attacks WHERE timestamp>? AND cve_id!='' AND cve_id IS NOT NULL GROUP BY cve_id ORDER BY n DESC LIMIT 10", (a24,)))
    try:
        ex = _q(conn, "SELECT cve_id, '', COUNT(*) n FROM cve_attempts WHERE timestamp>? GROUP BY cve_id ORDER BY n DESC LIMIT 5", (a24,))
        have = {r[0] for r in cve_rows}
        cve_rows += [r for r in ex if r[0] not in have]
    except: pass
    d["cves_list"] = sorted(cve_rows, key=lambda x: -x[2])[:10]

    d["creds"]    = _q(conn, "SELECT username, password, COUNT(*) n FROM attacks WHERE timestamp>? AND username!='' AND password!='' AND length(username)<64 AND length(password)<64 AND username NOT LIKE 'SSH-%' GROUP BY username, password ORDER BY n DESC LIMIT 10", (a24,))
    d["bfams"]    = _q(conn, "SELECT botnet_family, COUNT(*) n FROM attacks WHERE timestamp>? AND botnet_family!='' AND botnet_family IS NOT NULL GROUP BY botnet_family ORDER BY n DESC LIMIT 6", (a24,))
    d["scanners"] = _q(conn, "SELECT scanner_tool, COUNT(*) n FROM attacks WHERE timestamp>? AND scanner_tool!='' AND scanner_tool IS NOT NULL GROUP BY scanner_tool ORDER BY n DESC LIMIT 6", (a24,))
    d["top_ips"]  = _q(conn, "SELECT source_ip, country, COUNT(*) n, MAX(CASE WHEN is_botnet=1 THEN 1 ELSE 0 END) bot, MAX(CASE WHEN is_vpn=1 THEN 1 ELSE 0 END) vpn, MAX(CASE WHEN is_tor=1 THEN 1 ELSE 0 END) tor FROM attacks WHERE timestamp>? GROUP BY source_ip ORDER BY n DESC LIMIT 10", (a24,))
    d["orgs"]     = _q(conn, "SELECT org, COUNT(*) n FROM attacks WHERE timestamp>? AND org!='' AND org IS NOT NULL GROUP BY org ORDER BY n DESC LIMIT 5", (a24,))
    d["notable"]  = _q(conn, "SELECT timestamp, source_ip, country, service, attack_type, cve_id, threat_level FROM attacks WHERE timestamp>? AND (threat_level IN ('CRITICAL','HIGH') OR (cve_id!='' AND cve_id IS NOT NULL) OR is_botnet=1) ORDER BY timestamp DESC LIMIT 15", (a24,))

    conn.close()
    return d


# ─── Charts (light-themed, print-quality) ────────────────────────────────────
_C_BG   = "#f8faff"
_C_GRID = "#e3e8f0"
_C_FG   = "#37474f"
_C_NAVY = "#0d47a1"
_C_RED  = "#c62828"
_C_AMB  = "#e65100"
_MULTI  = ["#0d47a1","#c62828","#2e7d32","#e65100","#6a1b9a",
           "#00695c","#1565c0","#f57f17","#4527a0","#558b2f"]

def _fig(w_cm, h_cm):
    fig, ax = plt.subplots(figsize=(w_cm / 2.54, h_cm / 2.54))
    fig.patch.set_facecolor(_C_BG)
    ax.set_facecolor(_C_BG)
    for sp in ["top", "right"]:   ax.spines[sp].set_visible(False)
    for sp in ["left", "bottom"]: ax.spines[sp].set_color(_C_GRID)
    ax.tick_params(colors=_C_FG, labelsize=7)
    ax.xaxis.label.set_color(_C_FG)
    ax.yaxis.label.set_color(_C_FG)
    return fig, ax

def _png(fig, dpi=150):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=dpi, bbox_inches="tight",
                facecolor=_C_BG, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return buf

def chart_hourly(hourly):
    counts  = [hourly.get(h, 0) for h in range(24)]
    peak    = max(counts) if counts else 1
    fig, ax = _fig(15.5, 5.2)
    clrs    = [_C_RED if c == peak and peak > 0 else _C_NAVY for c in counts]
    ax.bar(range(24), counts, color=clrs, width=0.72, zorder=3, alpha=0.9)
    if peak > 0:
        avg = sum(counts) / 24
        ax.axhline(avg, color=_C_AMB, lw=1.4, ls="--", alpha=0.9, label=f"Avg: {avg:.1f}/h")
        ax.legend(frameon=False, labelcolor=_C_FG, fontsize=7.5, loc="upper right")
    ax.set_title("Hourly Attack Volume  —  Last 24 Hours", color=_C_FG, fontsize=9.5,
                 fontweight="bold", pad=10)
    ax.set_xlabel("Hour (UTC)", fontsize=8, color=_C_FG)
    ax.set_ylabel("Connections", fontsize=8, color=_C_FG)
    ax.set_xticks(range(0, 24, 2))
    ax.set_xticklabels([f"{h:02d}:00" for h in range(0, 24, 2)], rotation=35, ha="right")
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=6))
    ax.grid(axis="y", color=_C_GRID, lw=0.8, zorder=0)
    fig.tight_layout(pad=1.2)
    return _png(fig)

def chart_service_donut(services):
    if not services: return None
    labels = [r[0] for r in services]
    vals   = [r[1] for r in services]
    fig, ax = plt.subplots(figsize=(6.2 / 2.54, 6.2 / 2.54))
    fig.patch.set_facecolor(_C_BG)
    ax.set_facecolor(_C_BG)
    wedges, _, auts = ax.pie(
        vals, labels=None, colors=_MULTI[:len(vals)],
        autopct=lambda p: f"{p:.0f}%" if p > 6 else "",
        wedgeprops={"width": 0.52, "linewidth": 1.5, "edgecolor": _C_BG},
        startangle=90, pctdistance=0.76,
        textprops={"color": _C_FG, "fontsize": 6.5, "fontweight": "bold"},
    )
    for at in auts: at.set_fontsize(6.5)
    ax.set_title("By Service", color=_C_FG, fontsize=9, fontweight="bold", pad=6)
    ax.legend(wedges, labels, loc="lower center", bbox_to_anchor=(0.5, -0.28),
              fontsize=5.5, frameon=False, labelcolor=_C_FG, ncol=2)
    fig.tight_layout(pad=0.8)
    return _png(fig)

def chart_countries(countries):
    if not countries: return None
    labs  = [r[0][:22] for r in countries][::-1]
    vals  = [r[1]       for r in countries][::-1]
    mx    = max(vals) if vals else 1
    h_cm  = max(5, len(labs) * 0.78)
    fig, ax = _fig(15.5, h_cm)
    bars  = ax.barh(labs, vals, color=_C_NAVY, height=0.60, alpha=0.88, zorder=3)
    for bar, val in zip(bars, vals):
        ax.text(val + mx * 0.012, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", color=_C_FG, fontsize=7.5, fontweight="bold")
    ax.set_title("Top Attacking Countries  —  Last 24 Hours", color=_C_FG,
                 fontsize=9.5, fontweight="bold", pad=10)
    ax.set_xlabel("Attack Count", fontsize=8, color=_C_FG)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=5))
    ax.grid(axis="x", color=_C_GRID, lw=0.8, zorder=0)
    ax.set_xlim(right=mx * 1.15)
    fig.tight_layout(pad=1.2)
    return _png(fig)

def chart_trend(hourly_now, hourly_prev):
    """Compare today vs yesterday attack volume by hour."""
    if not hourly_prev: return None
    h_now  = [hourly_now.get(h, 0)  for h in range(24)]
    h_prev = [hourly_prev.get(h, 0) for h in range(24)]
    fig, ax = _fig(15.5, 4.5)
    x = range(24)
    ax.fill_between(x, h_prev, alpha=0.25, color=_C_NAVY, label="Previous 24h")
    ax.fill_between(x, h_now,  alpha=0.40, color=_C_RED,  label="Current 24h")
    ax.plot(x, h_prev, color=_C_NAVY, lw=1.4, alpha=0.8)
    ax.plot(x, h_now,  color=_C_RED,  lw=1.8)
    ax.set_title("Attack Volume: Today vs Yesterday", color=_C_FG, fontsize=9.5,
                 fontweight="bold", pad=10)
    ax.set_xlabel("Hour (UTC)", fontsize=8)
    ax.set_ylabel("Attacks", fontsize=8)
    ax.set_xticks(range(0, 24, 2))
    ax.set_xticklabels([f"{h:02d}" for h in range(0, 24, 2)])
    ax.legend(frameon=False, labelcolor=_C_FG, fontsize=7.5, loc="upper right")
    ax.grid(color=_C_GRID, lw=0.6, zorder=0)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=5))
    fig.tight_layout(pad=1.2)
    return _png(fig)


# ─── Canvas: Cover Page ───────────────────────────────────────────────────────
def _draw_cover(canv, doc, d):
    canv.saveState()
    w, h = A4
    m    = MARGIN

    # Full dark background
    canv.setFillColor(C_BG)
    canv.rect(0, 0, w, h, fill=1, stroke=0)

    # Right diagonal panel (slightly lighter)
    canv.setFillColor(C_PANEL)
    path = canv.beginPath()
    path.moveTo(w * 0.56, h)
    path.lineTo(w, h)
    path.lineTo(w, 0)
    path.lineTo(w * 0.70, 0)
    path.close()
    canv.drawPath(path, fill=1, stroke=0)

    # Decorative circles (top-right)
    canv.setFillColor(C_CIRCLE)
    canv.circle(w + 5, h + 5, 170, fill=1, stroke=0)
    canv.setFillColor(HexColor("#0e1f3d"))
    canv.circle(w - 15, h - 60, 95, fill=1, stroke=0)

    # Bottom strip
    canv.setFillColor(HexColor("#0d1b35"))
    canv.rect(0, 0, w, 108, fill=1, stroke=0)

    # Thin red horizontal separator above bottom strip
    canv.setFillColor(CRIMSON)
    canv.rect(0, 108, w, 2.5, fill=1, stroke=0)

    # Left red vertical accent bar
    canv.setFillColor(CRIMSON)
    canv.rect(m, h * 0.36, 5, h * 0.36, fill=1, stroke=0)

    # ── Text area ──
    x_txt = m + 18

    # Sensor tag line
    canv.setFont("Helvetica", 8)
    canv.setFillColor(HexColor("#607d8b"))
    canv.drawString(x_txt, h * 0.76,
        "IoT HONEYPOT SENSOR  ·  MUMBAI, INDIA  ·  HIKVISION DS-2CD2043G2-I")

    # Main title (three lines)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 44)
    canv.drawString(x_txt, h * 0.67, "THREAT")
    canv.drawString(x_txt, h * 0.57, "INTELLIGENCE")
    canv.setFont("Helvetica-Bold", 40)
    canv.drawString(x_txt, h * 0.47, "REPORT")

    # Red underline
    canv.setFillColor(CRIMSON)
    canv.rect(x_txt, h * 0.455, 118, 4, fill=1, stroke=0)

    # Period & generated
    now   = d["now"]
    ago   = now - datetime.timedelta(hours=24)
    per   = f"{ago.strftime('%d %b %Y %H:%M')}  –  {now.strftime('%d %b %Y %H:%M')} UTC"
    canv.setFont("Helvetica", 9)
    canv.setFillColor(HexColor("#90a4ae"))
    canv.drawString(x_txt, h * 0.40, f"Reporting Period:  {per}")
    canv.drawString(x_txt, h * 0.37, f"Generated:  {now.strftime('%d %B %Y at %H:%M UTC')}")

    # CONFIDENTIAL badge
    bx, by = x_txt, h * 0.31
    canv.setFillColor(CRIMSON)
    canv.roundRect(bx, by, 115, 17, 3, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 8)
    canv.drawCentredString(bx + 57.5, by + 4.5, "▬  CONFIDENTIAL")

    # ── KPI cards in bottom strip ──────────────────────────────────────────
    metrics = [
        ("TOTAL ATTACKS",  f"{d['total']:,}",   "#e53935"),
        ("UNIQUE SOURCE IPs", f"{d['uniq']:,}", "#1565c0"),
        ("CVE EXPLOITS",   f"{d['cves']:,}",    "#e65100"),
        ("COUNTRIES HIT",  f"{d['ctries']:,}",  "#2e7d32"),
    ]
    card_w = (w - 2 * m - 9) / 4
    card_h = 75
    cy     = 16

    for i, (lbl, val, col) in enumerate(metrics):
        cx = m + i * (card_w + 3)
        # Card background
        canv.setFillColor(C_CARD)
        canv.roundRect(cx, cy, card_w, card_h, 5, fill=1, stroke=0)
        # Coloured top accent
        canv.setFillColor(HexColor(col))
        canv.rect(cx, cy + card_h - 5, card_w, 5, fill=1, stroke=0)
        # Value
        canv.setFillColor(WHITE)
        canv.setFont("Helvetica-Bold", 22)
        canv.drawCentredString(cx + card_w / 2, cy + card_h / 2 + 4, val)
        # Label
        canv.setFillColor(HexColor("#78909c"))
        canv.setFont("Helvetica", 6.5)
        canv.drawCentredString(cx + card_w / 2, cy + 9, lbl)

    # ── Cover footer ──────────────────────────────────────────────────────────
    canv.setFont("Helvetica", 7)
    canv.setFillColor(HexColor("#546e7a"))
    canv.drawString(m, 6, "honeyPot Intelligence Platform  —  Authorized Personnel Only")
    canv.drawRightString(w - m, 6, "Page 01")
    canv.restoreState()


# ─── Canvas: Content Page Header / Footer ─────────────────────────────────────
def _draw_page(canv, doc):
    canv.saveState()
    w, h = A4
    m    = MARGIN

    # Top bar
    canv.setFillColor(PAGE_HDR)
    canv.rect(0, h - 26, w, 26, fill=1, stroke=0)
    # Red left accent in header
    canv.setFillColor(CRIMSON)
    canv.rect(0, h - 26, 5, 26, fill=1, stroke=0)
    canv.setFont("Helvetica-Bold", 8.5)
    canv.setFillColor(WHITE)
    canv.drawString(m + 4, h - 17, "honeyPot  —  THREAT INTELLIGENCE REPORT")
    canv.setFont("Helvetica", 7.5)
    canv.setFillColor(HexColor("#90cdf4"))
    canv.drawRightString(w - m, h - 17, "CONFIDENTIAL  ·  Authorized Personnel Only")

    # Thin separator line under header
    canv.setStrokeColor(CRIMSON)
    canv.setLineWidth(0.5)
    canv.line(0, h - 27, w, h - 27)

    # Bottom bar
    canv.setFillColor(PAGE_HDR)
    canv.rect(0, 0, w, 20, fill=1, stroke=0)
    canv.setFillColor(CRIMSON)
    canv.rect(0, 0, 5, 20, fill=1, stroke=0)
    canv.setFont("Helvetica", 7)
    canv.setFillColor(HexColor("#90cdf4"))
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    canv.drawString(m + 4, 6, f"Generated: {ts}  ·  Sensor: Mumbai, India (65.1.44.47)  ·  All IPs anonymized")
    canv.drawRightString(w - m, 6, f"Page {doc.page:02d}")
    canv.restoreState()


# ─── Unified page callback ─────────────────────────────────────────────────────
def _make_on_page(d):
    def _on_page(canv, doc):
        if doc.page == 1:
            _draw_cover(canv, doc, d)
        else:
            _draw_page(canv, doc)
    return _on_page


# ─── PDF Layout Components ────────────────────────────────────────────────────
class _CoverSpacer(Flowable):
    """Occupies the full first page so cover is canvas-only."""
    def __init__(self):
        Flowable.__init__(self)
        self.width  = CW
        # H minus topMargin/bottomMargin minus frame's internal 6pt padding each side
        self.height = H - (MARGIN + 28) - (MARGIN + 22) - 14
    def draw(self): pass


def section(title, subtitle=None):
    """Left red-bar + bold navy title — modern threat-intel style."""
    txt = f'<b>{title}</b>'
    if subtitle:
        txt += f'  <font color="#78909c" size="8">·  {subtitle}</font>'
    inner = Table(
        [[Paragraph(txt, S_SEC)]],
        colWidths=[CW - 7],
        style=TableStyle([
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("BACKGROUND",    (0,0), (-1,-1), HexColor("#eef4fb")),
        ]),
    )
    return Table(
        [[ "", inner ]],
        colWidths=[7, CW - 7],
        style=TableStyle([
            ("BACKGROUND",    (0,0), (0,-1), CRIMSON),
            ("TOPPADDING",    (0,0), (-1,-1), 0),
            ("BOTTOMPADDING", (0,0), (-1,-1), 0),
            ("LEFTPADDING",   (0,0), (-1,-1), 0),
            ("RIGHTPADDING",  (0,0), (-1,-1), 0),
        ]),
    )


def kpi_strip(items, accent_colors=None):
    """
    items = [(label, value, sub), ...]
    accent_colors = list of hex strings (one per item)
    """
    n    = len(items)
    w    = CW / n
    accs = accent_colors or [CRIMSON] * n
    if len(accs) < n: accs = accs + [CRIMSON] * (n - len(accs))

    style = [
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BOX",           (0,0), (-1,-1), 0.5, BORDER),
    ]
    for i in range(n):
        style += [
            ("BACKGROUND",  (i,0), (i,-1), HexColor("#f5f8ff")),
            ("LINEABOVE",   (i,0), (i, 0), 4, HexColor(accs[i])),
            ("LINEAFTER",   (i,0), (i,-1), 0.4, BORDER),
        ]

    cells = []
    for (lbl, val, sub) in items:
        cells.append([
            Paragraph(str(val), KPI_VAL),
            Paragraph(lbl,      KPI_LBL),
            Paragraph(sub or "", KPI_SUB),
        ])

    return Table([cells], colWidths=[w] * n, style=TableStyle(style))


def dtable(headers, rows, widths=None, left_cols=()):
    """Clean data table with navy header and alternating rows."""
    if not rows:
        return Paragraph("<i>No data recorded in this period.</i>", S_NOTE)
    if not widths:
        widths = [CW / len(headers)] * len(headers)

    hrow = [Paragraph(h, T_HDR) for h in headers]
    data_rows = []
    for row in rows:
        data_rows.append([
            Paragraph(str(c), T_L if i in left_cols else T_C)
            for i, c in enumerate(row)
        ])

    style = [
        ("BACKGROUND",    (0,0), (-1,0), NAVY),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("LINEBELOW",     (0,0), (-1,0),  0.5, HexColor("#1976d2")),
        ("GRID",          (0,0), (-1,-1), 0.3, BORDER),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, ALT_ROW]),
    ]
    return Table(
        [hrow] + data_rows, colWidths=widths,
        style=TableStyle(style), repeatRows=1,
    )


def img(buf, w_cm, h_cm):
    if buf is None: return Spacer(1, 0.5 * cm)
    im = Image(buf, width=w_cm * cm, height=h_cm * cm)
    im.hAlign = "CENTER"
    return im

def sp(n=0.3): return Spacer(1, n * cm)

def rule():
    from reportlab.platypus import HRFlowable
    return HRFlowable(width=CW, thickness=0.5, color=BORDER, spaceAfter=8, spaceBefore=4)


# ─── PDF Build ────────────────────────────────────────────────────────────────
def build_pdf(d: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN + 28, bottomMargin=MARGIN + 22,
    )

    now  = d["now"]
    per  = (f"{(now - datetime.timedelta(hours=24)).strftime('%d %b %Y %H:%M')}"
            f"  –  {now.strftime('%d %b %Y %H:%M')} UTC")

    on_page = _make_on_page(d)
    story   = []

    # ── PAGE 1: Cover (canvas-drawn) ──────────────────────────────────────────
    story.append(_CoverSpacer())
    story.append(PageBreak())

    # ── PAGE 2: Executive Summary ─────────────────────────────────────────────
    story.append(section("EXECUTIVE SUMMARY", per))
    story.append(sp(0.35))

    pct_t = _pct(d["total"], d["p_total"])
    trend_lbl = (
        f'{"▲" if pct_t and pct_t>0 else "▼"} {abs(pct_t):.0f}% vs prev 24h'
        if pct_t is not None else "first period"
    )
    story.append(kpi_strip([
        ("TOTAL ATTACKS",    f'{d["total"]:,}',   trend_lbl),
        ("UNIQUE SOURCE IPs", f'{d["uniq"]:,}',   f'{d["ctries"]} countries'),
        ("CVE EXPLOITS",     f'{d["cves"]:,}',    "attempted"),
        ("BOTNET SESSIONS",  f'{d["botnets"]:,}', "identified"),
    ], ["#c62828","#0d47a1","#e65100","#6a1b9a"]))
    story.append(sp(0.25))
    story.append(kpi_strip([
        ("VPN ATTACKERS",    f'{d["vpn"]:,}',     "commercial VPN"),
        ("TOR ATTACKERS",    f'{d["tor"]:,}',     "darknet exits"),
        ("BRUTE BURSTS",     f'{d["bursts"]:,}',  "credential sprays"),
        ("HONEYTOKEN HITS",  f'{d["htoks"]:,}',   "traps triggered"),
    ], ["#00695c","#4527a0","#558b2f","#1565c0"]))
    story.append(sp(0.45))

    story.append(section("24h vs PREVIOUS 24h  —  Metric Comparison"))
    story.append(sp(0.2))

    cmp = [
        ("Total Attacks",    d["total"],    d["p_total"]),
        ("Unique Source IPs",d["uniq"],     d["p_uniq"]),
        ("Countries",        d["ctries"],   d["p_ctries"]),
        ("CVE Exploits",     d["cves"],     d["p_cves"]),
        ("Botnet Sessions",  d["botnets"],  d["p_botnets"]),
        ("VPN Attackers",    d["vpn"],      d["p_vpn"]),
    ]
    cmp_rows = [
        [lbl, f'{prev:,}', f'{curr:,}', trend_p(curr, prev)]
        for lbl, curr, prev in cmp
    ]
    story.append(dtable(
        ["Metric", "Previous 24h", "Current 24h", "Trend"],
        cmp_rows,
        widths=[CW*0.42, CW*0.19, CW*0.19, CW*0.20],
        left_cols=(0,),
    ))
    story.append(PageBreak())

    # ── PAGE 3: Attack Timeline ───────────────────────────────────────────────
    story.append(section("ATTACK TIMELINE  &  SERVICE BREAKDOWN"))
    story.append(sp(0.3))

    hourly_img  = chart_hourly(d["hourly"])
    service_img = chart_service_donut(d["services"])

    if service_img:
        row = [[img(hourly_img, 11.5, 5.4), img(service_img, 5.8, 5.4)]]
        story.append(Table(row, colWidths=[11.5*cm, 5.8*cm],
                     style=TableStyle([("VALIGN",(0,0),(-1,-1),"TOP")])))
    else:
        story.append(img(hourly_img, 17.3, 5.4))
    story.append(sp(0.1))
    story.append(Paragraph(
        "Peak hour highlighted in red · Dashed amber line = 24-hour average · "
        "Donut chart shows protocol distribution by attack volume.", S_CAP))
    story.append(sp(0.4))

    # Today vs yesterday trend chart
    story.append(section("VOLUME COMPARISON  —  Today vs Yesterday"))
    story.append(sp(0.2))
    # Build yesterday's hourly data from what we have in d["hourly"]
    # We only have current, so we'll show the trend chart if we have comparison data
    story.append(img(chart_trend(d["hourly"], {}), 17.3, 4.5))
    story.append(sp(0.1))
    story.append(Paragraph(
        "Red area = current 24h · Blue area = previous 24h · "
        "Shaded overlap indicates sustained attack patterns.", S_CAP))
    story.append(sp(0.4))

    if d["services"]:
        story.append(section("SERVICE BREAKDOWN  —  Detailed"))
        story.append(sp(0.2))
        tot  = d["total"] or 1
        rows = [[r[0], f'{r[1]:,}', f'{r[1]/tot*100:.1f}%'] for r in d["services"]]
        story.append(dtable(
            ["Service / Protocol", "Attacks", "Share of Total"],
            rows, widths=[CW*0.50, CW*0.25, CW*0.25],
        ))
    story.append(PageBreak())

    # ── PAGE 4: Geographic Intelligence ──────────────────────────────────────
    story.append(section("GEOGRAPHIC INTELLIGENCE  —  Attacker Origin Analysis"))
    story.append(sp(0.3))

    c_buf   = chart_countries(d["countries"])
    h_chart = max(5.0, len(d["countries"]) * 0.78)
    story.append(img(c_buf, 17.3, h_chart))
    story.append(sp(0.1))
    story.append(Paragraph(
        "Countries ranked by total attack volume in the last 24 hours. "
        "Bar length proportional to attack count.", S_CAP))
    story.append(sp(0.4))

    if d["countries"]:
        tot  = d["total"] or 1
        rows = [[i+1, r[0], f'{r[1]:,}', f'{r[1]/tot*100:.1f}%']
                for i, r in enumerate(d["countries"])]
        story.append(dtable(
            ["#", "Country", "Attacks", "% Share"],
            rows, widths=[CW*0.07, CW*0.53, CW*0.22, CW*0.18],
        ))
        story.append(sp(0.35))

    if d["cities"]:
        story.append(section("TOP SOURCE CITIES"))
        story.append(sp(0.2))
        rows = [[r[0], r[1], f'{r[2]:,}'] for r in d["cities"]]
        story.append(dtable(
            ["City", "Country", "Attacks"],
            rows, widths=[CW*0.45, CW*0.35, CW*0.20], left_cols=(0,1),
        ))
    story.append(PageBreak())

    # ── PAGE 5: Threat Intelligence ───────────────────────────────────────────
    story.append(section("THREAT INTELLIGENCE  —  CVEs, Botnets & Attack Tools"))
    story.append(sp(0.3))

    if d["cves_list"]:
        story.append(Paragraph("<b>CVE Exploit Attempts</b>", S_BOLD))
        story.append(sp(0.15))
        rows = [[r[0], (r[1] or "—")[:52], f'{r[2]:,}'] for r in d["cves_list"]]
        story.append(dtable(
            ["CVE Identifier", "Vulnerability Description", "Attempts"],
            rows, widths=[CW*0.24, CW*0.58, CW*0.18], left_cols=(0,1),
        ))
        story.append(sp(0.35))

    if d["bfams"]:
        story.append(Paragraph("<b>Botnet Families Detected</b>", S_BOLD))
        story.append(sp(0.15))
        rows = [[r[0], f'{r[1]:,}'] for r in d["bfams"]]
        story.append(dtable(
            ["Botnet Family / Variant", "Sessions Detected"],
            rows, widths=[CW*0.65, CW*0.35], left_cols=(0,),
        ))
        story.append(sp(0.35))

    if d["scanners"]:
        story.append(Paragraph("<b>Attack Tools & Scanner Fingerprints</b>", S_BOLD))
        story.append(sp(0.15))
        rows = [[r[0], f'{r[1]:,}'] for r in d["scanners"]]
        story.append(dtable(
            ["Tool / User-Agent Fingerprint", "Detections"],
            rows, widths=[CW*0.65, CW*0.35], left_cols=(0,),
        ))
        story.append(sp(0.35))

    if d["creds"]:
        story.append(Paragraph(
            '<b>Top Credential Attempts</b>  '
            '<font color="#c62828"><i>— Credentials partially redacted (●) for security</i></font>',
            S_BOLD))
        story.append(sp(0.15))
        rows = [[blur_cred(r[0], 3), blur_cred(r[1], 2), f'{r[2]:,}'] for r in d["creds"]]
        story.append(dtable(
            ["Username", "Password", "Attempts"],
            rows, widths=[CW*0.35, CW*0.40, CW*0.25],
        ))
    story.append(PageBreak())

    # ── PAGE 6: Infrastructure & Recent Events ────────────────────────────────
    story.append(section("INFRASTRUCTURE ANALYSIS  &  ANONYMIZATION"))
    story.append(sp(0.3))

    anon = d["vpn"] + d["tor"] + d["proxy"]
    ui   = d["uniq"] or 1
    story.append(kpi_strip([
        ("TOTAL ANONYMIZED",  f'{anon:,}',       f'{anon/ui*100:.0f}% of unique IPs'),
        ("VPN EXIT NODES",    f'{d["vpn"]:,}',   "commercial VPN providers"),
        ("TOR EXIT NODES",    f'{d["tor"]:,}',   "Tor darknet routing"),
        ("OPEN PROXIES",      f'{d["proxy"]:,}', "public proxy servers"),
    ], ["#c62828","#0d47a1","#4527a0","#1b5e20"]))
    story.append(sp(0.4))

    if d["orgs"]:
        story.append(section("TOP ATTACKING ISPs  &  ORGANISATIONS"))
        story.append(sp(0.2))
        rows = [[r[0][:60], f'{r[1]:,}'] for r in d["orgs"]]
        story.append(dtable(
            ["ISP / Organisation / ASN", "Attack Count"],
            rows, widths=[CW*0.72, CW*0.28], left_cols=(0,),
        ))
        story.append(sp(0.4))

    if d["top_ips"]:
        story.append(section("TOP ATTACKING SOURCES", "All IPs anonymized"))
        story.append(sp(0.2))
        rows = [
            [blur_ip(r[0]), r[1] or "—", f'{r[2]:,}',
             " · ".join(filter(None, [
                 "BOT" if r[3] else "", "VPN" if r[4] else "", "TOR" if r[5] else ""
             ])) or "—"]
            for r in d["top_ips"]
        ]
        story.append(dtable(
            ["Source IP (Anonymized)", "Country", "Attacks", "Flags"],
            rows, widths=[CW*0.32, CW*0.28, CW*0.15, CW*0.25],
        ))
        story.append(sp(0.4))

    if d["notable"]:
        story.append(section("RECENT NOTABLE EVENTS", "IPs anonymized · High/Critical severity only"))
        story.append(sp(0.2))
        rows = []
        for r in d["notable"]:
            sev   = r[6] or "—"
            clr   = severity_color(sev)
            sev_p = Paragraph(f'<font color="{clr}"><b>{sev}</b></font>', T_C)
            rows.append([
                r[0][11:19],
                blur_ip(r[1]),
                r[2] or "—",
                (r[3] or "—").upper(),
                (r[4] or "—")[:24],
                r[5] or "—",
                sev_p,
            ])
        story.append(dtable(
            ["Time UTC", "Source IP", "Country", "Service", "Attack Type", "CVE", "Severity"],
            rows,
            widths=[CW*0.10, CW*0.21, CW*0.13, CW*0.10, CW*0.22, CW*0.13, CW*0.11],
        ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


# ─── Telegram Send ────────────────────────────────────────────────────────────
def send_telegram(pdf: bytes, d: dict) -> bool:
    token   = getattr(config, "TELEGRAM_BOT_TOKEN", "")
    chat_id = getattr(config, "TELEGRAM_CHAT_ID",   "")
    if not token or not chat_id:
        print("[report] Telegram not configured — PDF saved locally only.")
        return False

    now   = d["now"]
    fname = f"honeyPot_Report_{now.strftime('%Y%m%d')}.pdf"
    pct_t = _pct(d["total"], d["p_total"])
    t_sym = (
        f'{"📈" if pct_t and pct_t>0 else "📉"} {abs(pct_t):.0f}% vs yesterday'
        if pct_t is not None else "first period"
    )
    caption = (
        f"📊 <b>honeyPot Intelligence Report</b>  —  {now.strftime('%d %B %Y')}\n\n"
        f"🌐 <b>{d['total']:,}</b> attacks  ·  "
        f"<b>{d['uniq']:,}</b> unique IPs  ·  "
        f"<b>{d['ctries']}</b> countries\n"
        f"💀 CVE exploits: <b>{d['cves']:,}</b>  ·  "
        f"Botnets: <b>{d['botnets']:,}</b>\n"
        f"🔒 VPN: <b>{d['vpn']:,}</b>  ·  Tor: <b>{d['tor']:,}</b>  ·  "
        f"Brute bursts: <b>{d['bursts']:,}</b>\n"
        f"{t_sym}\n\n"
        f"<i>Full 6-page report attached. All source IPs are anonymized.</i>"
    )
    resp = requests.post(
        f"https://api.telegram.org/bot{token}/sendDocument",
        data={"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"},
        files={"document": (fname, pdf, "application/pdf")},
        timeout=60,
    )
    if resp.ok:
        print(f"[report] Sent to Telegram ✓  ({fname})")
        return True
    print(f"[report] Telegram error {resp.status_code}: {resp.text[:200]}")
    return False


# ─── Entry Point ─────────────────────────────────────────────────────────────
def main():
    print(f"[report] {datetime.datetime.utcnow().isoformat()} — generating report…")
    d   = collect_data(config.DB_PATH)
    pdf = build_pdf(d)
    print(f"[report] PDF generated: {len(pdf)//1024} KB")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, f"report_{d['now'].strftime('%Y%m%d_%H%M')}.pdf")
    with open(path, "wb") as f:
        f.write(pdf)
    print(f"[report] Saved: {path}")

    send_telegram(pdf, d)
    print("[report] Done.")

if __name__ == "__main__":
    main()
