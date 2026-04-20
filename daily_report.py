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
C_BG      = HexColor("#0b1120")
C_PANEL   = HexColor("#111d35")
C_CARD    = HexColor("#162038")
C_CIRCLE  = HexColor("#1a2d52")
CRIMSON   = HexColor("#c62828")
NAVY      = HexColor("#0d47a1")
NAVY2     = HexColor("#1565c0")
TEAL      = HexColor("#1b5e20")
AMBER     = HexColor("#e65100")
SLATE     = HexColor("#455a64")
BORDER    = HexColor("#dce6f0")
ALT_ROW   = HexColor("#eef4fb")
PAGE_HDR  = HexColor("#0d47a1")
TEXT      = HexColor("#0d1b2a")
WHITE     = colors.white

W, H    = A4
MARGIN  = 1.6 * cm
CW      = W - 2 * MARGIN

# ─── Typography ───────────────────────────────────────────────────────────────
def _P(name, **kw):
    return ParagraphStyle(name, **kw)

S_SEC   = _P("sec",  fontName="Helvetica-Bold", fontSize=11, textColor=NAVY,
              leading=14, spaceBefore=2, spaceAfter=4)
S_BODY  = _P("bod",  fontName="Helvetica",      fontSize=9,  textColor=TEXT,  leading=13)
S_BOLD  = _P("bld",  fontName="Helvetica-Bold", fontSize=9,  textColor=TEXT,  leading=13)
S_CAP   = _P("cap",  fontName="Helvetica-Oblique", fontSize=7.5, textColor=SLATE,
              alignment=TA_CENTER, leading=10)
S_NOTE  = _P("nte",  fontName="Helvetica",      fontSize=8,  textColor=SLATE, leading=11)
S_NARR  = _P("nar",  fontName="Helvetica",      fontSize=9,  textColor=TEXT,
              leading=14, spaceBefore=4, spaceAfter=4)
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

def severity_badge(level):
    """Solid-background severity badge for use in table cells."""
    lv = (level or "—").upper()
    bg = severity_color(lv)
    fg = "#ffffff" if lv in ("CRITICAL", "HIGH", "LOW", "—") else "#1a1a1a"
    cell = Paragraph(f'<font color="{fg}"><b>{lv}</b></font>', T_HDR)
    t = Table([[cell]], colWidths=[1.7 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(bg)),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t

def priority_badge(level):
    """Priority badge for recommendations table."""
    lv = (level or "").upper()
    bg = severity_color(lv)
    fg = "#ffffff" if lv in ("CRITICAL", "HIGH", "LOW") else "#1a1a1a"
    cell = Paragraph(f'<font color="{fg}"><b>{lv}</b></font>', T_HDR)
    t = Table([[cell]], colWidths=[1.9 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(bg)),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


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

    # Hourly — current and previous period
    raw = _q(conn, "SELECT CAST(strftime('%H',timestamp) AS INT) h, COUNT(*) n FROM attacks WHERE timestamp>? GROUP BY h", (a24,))
    d["hourly"] = {r[0]: r[1] for r in raw}

    raw_p = _q(conn, "SELECT CAST(strftime('%H',timestamp) AS INT) h, COUNT(*) n FROM attacks WHERE timestamp>? AND timestamp<=? GROUP BY h", (a48, a24))
    d["hourly_prev"] = {r[0]: r[1] for r in raw_p}

    d["services"]  = _q(conn, "SELECT upper(service), COUNT(*) n FROM attacks WHERE timestamp>? AND service IS NOT NULL AND service!='' GROUP BY lower(service) ORDER BY n DESC LIMIT 8", (a24,))
    d["countries"] = _q(conn, "SELECT country, COUNT(*) n FROM attacks WHERE timestamp>? AND country NOT IN ('','Unknown') GROUP BY country ORDER BY n DESC LIMIT 10", (a24,))
    d["cities"]    = _q(conn, "SELECT city, country, COUNT(*) n FROM attacks WHERE timestamp>? AND city NOT IN ('','Unknown') AND city IS NOT NULL GROUP BY city ORDER BY n DESC LIMIT 6", (a24,))

    # Attack type distribution
    d["atk_types"] = _q(conn, "SELECT attack_type, COUNT(*) n FROM attacks WHERE timestamp>? AND attack_type!='' AND attack_type IS NOT NULL GROUP BY attack_type ORDER BY n DESC LIMIT 10", (a24,))

    # Severity distribution
    d["sev_dist"] = _q(conn, "SELECT UPPER(threat_level), COUNT(*) n FROM attacks WHERE timestamp>? AND threat_level IS NOT NULL AND threat_level!='' GROUP BY UPPER(threat_level) ORDER BY n DESC", (a24,))

    try:
        cve_rows = list(_q(conn, "SELECT cve_id, COALESCE(cve_name,'') n2, COUNT(*) n FROM attacks WHERE timestamp>? AND cve_id!='' AND cve_id IS NOT NULL GROUP BY cve_id ORDER BY n DESC LIMIT 10", (a24,)))
    except:
        cve_rows = list(_q(conn, "SELECT cve_id, '' n2, COUNT(*) n FROM attacks WHERE timestamp>? AND cve_id!='' AND cve_id IS NOT NULL GROUP BY cve_id ORDER BY n DESC LIMIT 10", (a24,)))
    try:
        ex = _q(conn, "SELECT cve_id, '', COUNT(*) n FROM cve_attempts WHERE timestamp>? GROUP BY cve_id ORDER BY n DESC LIMIT 5", (a24,))
        have = {r[0] for r in cve_rows}
        cve_rows += [r for r in ex if r[0] not in have]
    except: pass
    d["cves_list"] = sorted(cve_rows, key=lambda x: -x[2])[:10]

    d["creds"]    = _q(conn, "SELECT username, password, COUNT(*) n FROM attacks WHERE timestamp>? AND username!='' AND password!='' AND length(username)<64 AND length(password)<64 AND username NOT LIKE 'SSH-%' GROUP BY username, password ORDER BY n DESC LIMIT 10", (a24,))
    try:
        d["bfams"] = _q(conn, "SELECT botnet_family, COUNT(*) n FROM attacks WHERE timestamp>? AND botnet_family!='' AND botnet_family IS NOT NULL GROUP BY botnet_family ORDER BY n DESC LIMIT 6", (a24,))
    except:
        d["bfams"] = []
    d["scanners"] = _q(conn, "SELECT scanner_tool, COUNT(*) n FROM attacks WHERE timestamp>? AND scanner_tool!='' AND scanner_tool IS NOT NULL GROUP BY scanner_tool ORDER BY n DESC LIMIT 6", (a24,))
    d["top_ips"]  = _q(conn, "SELECT source_ip, country, COUNT(*) n, MAX(CASE WHEN is_botnet=1 THEN 1 ELSE 0 END) bot, MAX(CASE WHEN is_vpn=1 THEN 1 ELSE 0 END) vpn, MAX(CASE WHEN is_tor=1 THEN 1 ELSE 0 END) tor FROM attacks WHERE timestamp>? GROUP BY source_ip ORDER BY n DESC LIMIT 10", (a24,))
    d["orgs"]     = _q(conn, "SELECT org, COUNT(*) n FROM attacks WHERE timestamp>? AND org!='' AND org IS NOT NULL GROUP BY org ORDER BY n DESC LIMIT 5", (a24,))
    d["notable"]  = _q(conn, "SELECT timestamp, source_ip, country, service, attack_type, cve_id, threat_level FROM attacks WHERE timestamp>? AND (threat_level IN ('CRITICAL','HIGH') OR (cve_id!='' AND cve_id IS NOT NULL) OR is_botnet=1) ORDER BY timestamp DESC LIMIT 15", (a24,))

    # Honeytoken trigger details
    try:
        d["htok_detail"] = _q(conn, "SELECT timestamp, source_ip, country, token_type, token_value, service FROM honeytoken_triggers WHERE timestamp>? ORDER BY timestamp DESC LIMIT 10", (a24,))
    except:
        d["htok_detail"] = []

    conn.close()
    return d


# ─── Auto-generated Analyst Narrative ─────────────────────────────────────────
def _narrative(d):
    total = d["total"]
    uniq  = d["uniq"]
    cves  = d["cves"]
    bots  = d["botnets"]
    htoks = d["htoks"]
    pct_t = _pct(total, d["p_total"])

    if pct_t is None:
        trend_desc = "This is the first reporting period on record."
    elif abs(pct_t) < 3:
        trend_desc = "Attack volume remained <b>stable</b> compared to the previous 24-hour period."
    elif pct_t > 0:
        trend_desc = (f"Attack volume <b>increased by {abs(pct_t):.0f}%</b> compared to the previous "
                      f"24 hours, indicating an elevated threat posture.")
    else:
        trend_desc = (f"Attack volume <b>decreased by {abs(pct_t):.0f}%</b> compared to the previous "
                      f"24 hours.")

    top_country = d["countries"][0][0] if d["countries"] else "unknown origin"
    top_svc     = d["services"][0][0]  if d["services"]  else "unknown service"

    parts = [
        f"During the reporting period, the honeypot sensor recorded <b>{total:,} connection "
        f"attempts</b> from <b>{uniq:,} unique source IPs</b> spanning <b>{d['ctries']} "
        f"countries</b>. {trend_desc}"
    ]

    if cves:
        parts.append(
            f" <b>{cves:,} CVE exploit attempt(s)</b> were detected — these represent targeted "
            f"attacks against known vulnerabilities and warrant immediate review."
        )
    if bots:
        parts.append(
            f" <b>{bots:,} session(s)</b> were attributed to known botnet infrastructure, "
            f"suggesting automated scanning and credential-stuffing campaigns are active."
        )
    if htoks:
        parts.append(
            f" Critically, <b>{htoks} honeytoken trap(s) were triggered</b>, indicating "
            f"that attackers progressed beyond the perimeter and interacted with deliberately "
            f"planted bait assets — a strong indicator of targeted reconnaissance."
        )

    anon = d["vpn"] + d["tor"] + d["proxy"]
    if anon and d["uniq"]:
        pct_anon = anon / d["uniq"] * 100
        parts.append(
            f" Approximately <b>{pct_anon:.0f}% of unique sources</b> used anonymization "
            f"(VPN, Tor, or open proxy), complicating attribution."
        )

    parts.append(
        f" The dominant attack surface was <b>{top_svc}</b>; the highest volume of traffic "
        f"originated from <b>{top_country}</b>."
    )

    return Paragraph("".join(parts), S_NARR)


# ─── Recommendations ──────────────────────────────────────────────────────────
def _recommendations(d):
    rows = []

    if d["cves"] > 0:
        rows.append([
            priority_badge("CRITICAL"),
            Paragraph("Patch all systems targeted by detected CVE exploits", T_L),
            Paragraph(
                f"{d['cves']:,} CVE exploit attempt(s) detected. Cross-reference CVE identifiers "
                f"on page 5 against your asset inventory and apply vendor patches immediately.", T_L),
        ])
    if d["htoks"] > 0:
        rows.append([
            priority_badge("CRITICAL"),
            Paragraph("Investigate all honeytoken trigger events", T_L),
            Paragraph(
                f"{d['htoks']} honeytoken(s) triggered. Attackers accessed deliberately planted "
                f"bait credentials or files — indicative of deep intrusion or lateral movement.", T_L),
        ])
    if d["botnets"] > 0:
        rows.append([
            priority_badge("HIGH"),
            Paragraph("Block known botnet C2 IP ranges at the perimeter firewall", T_L),
            Paragraph(
                f"{d['botnets']:,} sessions attributed to known botnet families. Implement "
                f"automated threat-intel IP blocklists and review egress filtering.", T_L),
        ])
    if d["bursts"] > 0:
        rows.append([
            priority_badge("HIGH"),
            Paragraph("Enforce account lockout and adaptive rate limiting on all exposed services", T_L),
            Paragraph(
                f"{d['bursts']:,} brute-force credential spray burst(s) recorded. "
                f"Ensure MFA is enforced on SSH, HTTP admin panels, and camera management interfaces.", T_L),
        ])
    if d["tor"] > 0 or d["vpn"] > 0:
        rows.append([
            priority_badge("MEDIUM"),
            Paragraph("Evaluate geo-blocking and anonymizer IP blocklists", T_L),
            Paragraph(
                f"{d['tor']:,} Tor exit node(s) and {d['vpn']:,} VPN exit node(s) recorded. "
                f"Consider restricting access from known anonymizer ranges on non-public services.", T_L),
        ])
    rows.append([
        priority_badge("LOW"),
        Paragraph("Update CVE signature database and review honeypot sensor coverage", T_L),
        Paragraph(
            "Regular maintenance ensures accurate CVE matching, botnet family classification, "
            "and honeytoken coverage for emerging attack vectors.", T_L),
    ])
    return rows


# ─── Charts ───────────────────────────────────────────────────────────────────
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
    if not hourly_prev:
        return None
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

def chart_sev_distribution(sev_dist):
    if not sev_dist:
        return None
    order   = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    clr_map = {"CRITICAL": _C_RED, "HIGH": _C_AMB, "MEDIUM": "#f9a825", "LOW": "#2e7d32"}
    data    = {r[0]: r[1] for r in sev_dist if r[0]}
    labs    = [s for s in order if s in data]
    vals    = [data[s] for s in labs]
    if not labs:
        return None
    fig, ax = _fig(7.5, 4.5)
    clrs = [clr_map.get(l, _C_NAVY) for l in labs]
    bars = ax.bar(labs, vals, color=clrs, width=0.55, zorder=3, alpha=0.9)
    mx   = max(vals) if vals else 1
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, val + mx * 0.02,
                f"{val:,}", ha="center", color=_C_FG, fontsize=8, fontweight="bold")
    ax.set_title("Severity Distribution", color=_C_FG, fontsize=9, fontweight="bold", pad=8)
    ax.set_ylabel("Events", fontsize=8)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=5))
    ax.grid(axis="y", color=_C_GRID, lw=0.8, zorder=0)
    fig.tight_layout(pad=1.2)
    return _png(fig)


# ─── Canvas: Cover Page ───────────────────────────────────────────────────────
def _draw_cover(canv, doc, d):
    canv.saveState()
    w, h = A4
    m    = MARGIN

    canv.setFillColor(C_BG)
    canv.rect(0, 0, w, h, fill=1, stroke=0)

    canv.setFillColor(C_PANEL)
    path = canv.beginPath()
    path.moveTo(w * 0.56, h)
    path.lineTo(w, h)
    path.lineTo(w, 0)
    path.lineTo(w * 0.70, 0)
    path.close()
    canv.drawPath(path, fill=1, stroke=0)

    canv.setFillColor(C_CIRCLE)
    canv.circle(w + 5, h + 5, 170, fill=1, stroke=0)
    canv.setFillColor(HexColor("#0e1f3d"))
    canv.circle(w - 15, h - 60, 95, fill=1, stroke=0)

    canv.setFillColor(HexColor("#0d1b35"))
    canv.rect(0, 0, w, 108, fill=1, stroke=0)

    canv.setFillColor(CRIMSON)
    canv.rect(0, 108, w, 2.5, fill=1, stroke=0)

    canv.setFillColor(CRIMSON)
    canv.rect(m, h * 0.36, 5, h * 0.36, fill=1, stroke=0)

    x_txt = m + 18

    canv.setFont("Helvetica", 8)
    canv.setFillColor(HexColor("#607d8b"))
    canv.drawString(x_txt, h * 0.76,
        "IoT HONEYPOT SENSOR  ·  MUMBAI, INDIA  ·  HIKVISION DS-2CD2043G2-I")

    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 44)
    canv.drawString(x_txt, h * 0.67, "THREAT")
    canv.drawString(x_txt, h * 0.57, "INTELLIGENCE")
    canv.setFont("Helvetica-Bold", 40)
    canv.drawString(x_txt, h * 0.47, "REPORT")

    canv.setFillColor(CRIMSON)
    canv.rect(x_txt, h * 0.455, 118, 4, fill=1, stroke=0)

    now   = d["now"]
    ago   = now - datetime.timedelta(hours=24)
    per   = f"{ago.strftime('%d %b %Y %H:%M')}  –  {now.strftime('%d %b %Y %H:%M')} UTC"
    canv.setFont("Helvetica", 9)
    canv.setFillColor(HexColor("#90a4ae"))
    canv.drawString(x_txt, h * 0.40, f"Reporting Period:  {per}")
    canv.drawString(x_txt, h * 0.37, f"Generated:  {now.strftime('%d %B %Y at %H:%M UTC')}")

    bx, by = x_txt, h * 0.31
    canv.setFillColor(CRIMSON)
    canv.roundRect(bx, by, 115, 17, 3, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 8)
    canv.drawCentredString(bx + 57.5, by + 4.5, "▬  CONFIDENTIAL")

    metrics = [
        ("TOTAL ATTACKS",     f"{d['total']:,}",  "#e53935"),
        ("UNIQUE SOURCE IPs", f"{d['uniq']:,}",   "#1565c0"),
        ("CVE EXPLOITS",      f"{d['cves']:,}",   "#e65100"),
        ("COUNTRIES HIT",     f"{d['ctries']:,}", "#2e7d32"),
    ]
    card_w = (w - 2 * m - 9) / 4
    card_h = 75
    cy     = 16

    for i, (lbl, val, col) in enumerate(metrics):
        cx = m + i * (card_w + 3)
        canv.setFillColor(C_CARD)
        canv.roundRect(cx, cy, card_w, card_h, 5, fill=1, stroke=0)
        canv.setFillColor(HexColor(col))
        canv.rect(cx, cy + card_h - 5, card_w, 5, fill=1, stroke=0)
        canv.setFillColor(WHITE)
        canv.setFont("Helvetica-Bold", 22)
        canv.drawCentredString(cx + card_w / 2, cy + card_h / 2 + 4, val)
        canv.setFillColor(HexColor("#78909c"))
        canv.setFont("Helvetica", 6.5)
        canv.drawCentredString(cx + card_w / 2, cy + 9, lbl)

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

    canv.setFillColor(PAGE_HDR)
    canv.rect(0, h - 26, w, 26, fill=1, stroke=0)
    canv.setFillColor(CRIMSON)
    canv.rect(0, h - 26, 5, 26, fill=1, stroke=0)
    canv.setFont("Helvetica-Bold", 8.5)
    canv.setFillColor(WHITE)
    canv.drawString(m + 4, h - 17, "honeyPot  —  THREAT INTELLIGENCE REPORT")
    canv.setFont("Helvetica", 7.5)
    canv.setFillColor(HexColor("#90cdf4"))
    canv.drawRightString(w - m, h - 17, "CONFIDENTIAL  ·  Authorized Personnel Only")

    canv.setStrokeColor(CRIMSON)
    canv.setLineWidth(0.5)
    canv.line(0, h - 27, w, h - 27)

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


def _make_on_page(d):
    def _on_page(canv, doc):
        if doc.page == 1:
            _draw_cover(canv, doc, d)
        else:
            _draw_page(canv, doc)
    return _on_page


# ─── PDF Layout Components ────────────────────────────────────────────────────
class _CoverSpacer(Flowable):
    def __init__(self):
        Flowable.__init__(self)
        self.width  = CW
        self.height = H - (MARGIN + 28) - (MARGIN + 22) - 14
    def draw(self): pass


def section(title, subtitle=None):
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
    """Data table with navy header and alternating rows.
    Cells that are already Flowable objects (Table, Paragraph) are used as-is."""
    if not rows:
        return Paragraph("<i>No data recorded in this period.</i>", S_NOTE)
    if not widths:
        widths = [CW / len(headers)] * len(headers)

    hrow = [Paragraph(h, T_HDR) for h in headers]
    data_rows = []
    for row in rows:
        cells = []
        for i, c in enumerate(row):
            if isinstance(c, Flowable):
                cells.append(c)
            else:
                cells.append(Paragraph(str(c), T_L if i in left_cols else T_C))
        data_rows.append(cells)

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

    # ── PAGE 1: Cover ─────────────────────────────────────────────────────────
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
    story.append(sp(0.4))

    story.append(section("ANALYST ASSESSMENT"))
    story.append(sp(0.2))
    story.append(_narrative(d))
    story.append(sp(0.4))

    story.append(section("24h vs PREVIOUS 24h  —  Metric Comparison"))
    story.append(sp(0.2))

    cmp = [
        ("Total Attacks",     d["total"],   d["p_total"]),
        ("Unique Source IPs", d["uniq"],    d["p_uniq"]),
        ("Countries",         d["ctries"],  d["p_ctries"]),
        ("CVE Exploits",      d["cves"],    d["p_cves"]),
        ("Botnet Sessions",   d["botnets"], d["p_botnets"]),
        ("VPN Attackers",     d["vpn"],     d["p_vpn"]),
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
    sev_img     = chart_sev_distribution(d.get("sev_dist", []))

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

    trend_buf = chart_trend(d["hourly"], d.get("hourly_prev", {}))
    if trend_buf or sev_img:
        story.append(section("VOLUME COMPARISON  &  SEVERITY DISTRIBUTION"))
        story.append(sp(0.2))
        if trend_buf and sev_img:
            row = [[img(trend_buf, 10.5, 4.5), img(sev_img, 6.8, 4.5)]]
            story.append(Table(row, colWidths=[10.5*cm, 6.8*cm],
                         style=TableStyle([("VALIGN",(0,0),(-1,-1),"TOP")])))
            story.append(sp(0.1))
            story.append(Paragraph(
                "Red area = current 24h · Blue area = previous 24h · "
                "Right chart shows severity breakdown of all recorded events.", S_CAP))
        elif trend_buf:
            story.append(img(trend_buf, 17.3, 4.5))
            story.append(sp(0.1))
            story.append(Paragraph(
                "Red area = current 24h · Blue area = previous 24h.", S_CAP))
        else:
            story.append(img(sev_img, 8.0, 4.5))
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

    if d.get("atk_types"):
        story.append(sp(0.35))
        story.append(section("ATTACK TYPE CLASSIFICATION"))
        story.append(sp(0.2))
        tot  = d["total"] or 1
        rows = [
            [r[0].replace("_", " "), f'{r[1]:,}', f'{r[1]/tot*100:.1f}%']
            for r in d["atk_types"]
        ]
        story.append(dtable(
            ["Attack Classification", "Count", "Share of Total"],
            rows, widths=[CW*0.60, CW*0.20, CW*0.20], left_cols=(0,),
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

    if d.get("htok_detail"):
        story.append(sp(0.35))
        story.append(Paragraph("<b>Honeytoken Trigger Detail</b>", S_BOLD))
        story.append(sp(0.15))
        rows = [
            [r[0][11:19], blur_ip(r[1]), r[2] or "—",
             (r[3] or "—").replace("_", " "), blur_cred(r[4], 4), (r[5] or "—").upper()]
            for r in d["htok_detail"]
        ]
        story.append(dtable(
            ["Time UTC", "Source IP", "Country", "Token Type", "Value (redacted)", "Service"],
            rows,
            widths=[CW*0.10, CW*0.22, CW*0.12, CW*0.18, CW*0.23, CW*0.15],
            left_cols=(3, 4),
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
        story.append(section("RECENT NOTABLE EVENTS", "High/Critical severity · IPs anonymized"))
        story.append(sp(0.2))
        rows = []
        for r in d["notable"]:
            sev = (r[6] or "").upper() or "—"
            rows.append([
                r[0][11:19],
                blur_ip(r[1]),
                r[2] or "—",
                (r[3] or "—").upper(),
                (r[4] or "—").replace("_", " "),
                r[5] or "—",
                severity_badge(sev),
            ])
        story.append(dtable(
            ["Time UTC", "Source IP", "Country", "Service", "Attack Type", "CVE", "Severity"],
            rows,
            widths=[CW*0.09, CW*0.20, CW*0.12, CW*0.09, CW*0.25, CW*0.12, CW*0.13],
        ))

    story.append(PageBreak())

    # ── FINAL PAGE: Recommendations & Methodology ────────────────────────────
    story.append(section("RECOMMENDATIONS  &  MITIGATIONS"))
    story.append(sp(0.3))
    rec_rows = _recommendations(d)
    story.append(dtable(
        ["Priority", "Recommendation", "Rationale"],
        rec_rows,
        widths=[CW*0.14, CW*0.36, CW*0.50],
        left_cols=(1, 2),
    ))
    story.append(sp(0.5))

    story.append(section("REPORT METHODOLOGY"))
    story.append(sp(0.2))
    story.append(Paragraph(
        "This report is generated automatically by the honeyPot Intelligence Platform. "
        "The sensor emulates a Hikvision DS-2CD2043G2-I IP camera and associated IoT services "
        "(HTTP, SSH, Telnet, FTP, RTSP, ONVIF, CoAP, ADB, MQTT, TR-069, and others). "
        "All attack data is recorded to a local SQLite database and enriched with GeoIP, "
        "ASN, VPN/Tor detection, CVE signature matching, and botnet family classification. "
        "Source IPs are anonymized in this report; full IPs are retained in the database "
        "for internal use only. Threat levels are assigned based on attack signature matching "
        "and behavioral analysis. All timestamps are UTC.",
        S_BODY,
    ))
    story.append(sp(0.3))
    story.append(Paragraph(
        f"<i>Report generated: {now.strftime('%d %B %Y at %H:%M UTC')}  ·  "
        f"Platform: honeyPot v1.0  ·  Sensor location: Mumbai, India  ·  "
        f"Classification: CONFIDENTIAL — Authorized Personnel Only</i>",
        S_NOTE,
    ))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


# ─── Email Send ───────────────────────────────────────────────────────────────
def send_email(pdf: bytes, d: dict) -> bool:
    """Send daily report via email with AWS-style HTML template."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    if not getattr(config, "EMAIL_ENABLED", False):
        print("[report] Email not configured — skipping.")
        return False

    smtp_server  = getattr(config, "EMAIL_SMTP_SERVER", "")
    smtp_port    = getattr(config, "EMAIL_SMTP_PORT", 587)
    smtp_user    = getattr(config, "EMAIL_SMTP_USERNAME", "")
    smtp_pass    = getattr(config, "EMAIL_SMTP_PASSWORD", "")
    email_from   = getattr(config, "EMAIL_FROM", "")
    email_to     = getattr(config, "EMAIL_TO", "")

    if not all([smtp_server, email_from, email_to]):
        print("[report] Email settings incomplete — skipping.")
        return False

    now       = d["now"]
    date_str  = now.strftime("%d %B %Y")
    pct_t     = _pct(d["total"], d["p_total"])
    trend_txt = (
        f"{'↑' if pct_t and pct_t > 0 else '↓'} {abs(pct_t):.0f}% vs yesterday"
        if pct_t is not None else "First reporting period"
    )
    anon_total = d["vpn"] + d["tor"]

    # ── HTML body (AWS Security Hub style) ────────────────────────────────────
    country_rows = ""
    tot = d["total"] or 1
    for i, (country, count) in enumerate(d["countries"][:5]):
        bg = "#f9f9f9" if i % 2 else "#ffffff"
        country_rows += (
            f'<tr style="background:{bg};">'
            f'<td style="padding:7px 10px;font-size:12px;color:#232f3e;">{country}</td>'
            f'<td style="padding:7px 10px;font-size:12px;color:#232f3e;text-align:right;">{count:,}</td>'
            f'<td style="padding:7px 10px;font-size:12px;color:#545b64;text-align:right;">{count/tot*100:.1f}%</td>'
            f'</tr>'
        )

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.12);">

  <tr><td style="background:#232f3e;padding:20px 30px;">
    <table width="100%"><tr>
      <td><span style="color:#ff9900;font-size:22px;font-weight:bold;">&#9650; AWS</span>
          <span style="color:#fff;font-size:14px;margin-left:8px;">Security Hub &nbsp;|&nbsp; IoT Threat Intelligence</span></td>
      <td align="right"><span style="color:#8a9bb0;font-size:11px;">{now.strftime('%Y-%m-%d %H:%M UTC')}</span></td>
    </tr></table>
  </td></tr>

  <tr><td style="background:#ff9900;padding:10px 30px;">
    <span style="color:#232f3e;font-weight:bold;font-size:14px;">
      &#128272;&nbsp; Daily IoT Threat Intelligence Report &mdash; {date_str}
    </span>
  </td></tr>

  <tr><td style="padding:22px 30px 10px;">
    <p style="color:#232f3e;font-size:15px;margin:0 0 6px;font-weight:bold;">
      Your HoneyPot sensor has completed its daily analysis.
    </p>
    <p style="color:#545b64;font-size:12px;margin:0;">
      Sensor: Mumbai, India &nbsp;(ap-south-1)&nbsp;&middot;&nbsp;
      Device: Hikvision DS-2CD2043G2-I &nbsp;&middot;&nbsp; {date_str}
    </p>
  </td></tr>

  <tr><td style="padding:10px 30px;">
    <table width="100%" cellspacing="5">
      <tr>
        <td width="25%" style="background:#fef9f0;border:1px solid #f0d080;border-radius:4px;padding:14px;text-align:center;">
          <div style="font-size:28px;font-weight:bold;color:#c7511f;">{d['total']:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:4px;letter-spacing:.5px;">Total Attacks</div>
        </td>
        <td width="25%" style="background:#f0f4ff;border:1px solid #c5d5e8;border-radius:4px;padding:14px;text-align:center;">
          <div style="font-size:28px;font-weight:bold;color:#0073bb;">{d['uniq']:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:4px;letter-spacing:.5px;">Unique IPs</div>
        </td>
        <td width="25%" style="background:#fff5f5;border:1px solid #f5c6c6;border-radius:4px;padding:14px;text-align:center;">
          <div style="font-size:28px;font-weight:bold;color:#cc0000;">{d['cves']:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:4px;letter-spacing:.5px;">CVE Exploits</div>
        </td>
        <td width="25%" style="background:#f0fff4;border:1px solid #a8d5b5;border-radius:4px;padding:14px;text-align:center;">
          <div style="font-size:28px;font-weight:bold;color:#1a7340;">{d['ctries']}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:4px;letter-spacing:.5px;">Countries</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <tr><td style="padding:0 30px 14px;">
    <table width="100%" cellspacing="5">
      <tr>
        <td width="33%" style="background:#f8f8f8;border:1px solid #e0e0e0;border-radius:4px;padding:10px;text-align:center;">
          <div style="font-size:22px;font-weight:bold;color:#5a4d8a;">{d['botnets']:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:3px;">Botnet Sessions</div>
        </td>
        <td width="33%" style="background:#f8f8f8;border:1px solid #e0e0e0;border-radius:4px;padding:10px;text-align:center;">
          <div style="font-size:22px;font-weight:bold;color:#006666;">{anon_total:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:3px;">VPN / Tor Sources</div>
        </td>
        <td width="33%" style="background:#f8f8f8;border:1px solid #e0e0e0;border-radius:4px;padding:10px;text-align:center;">
          <div style="font-size:22px;font-weight:bold;color:#1a4f8a;">{d['htoks']:,}</div>
          <div style="font-size:10px;color:#545b64;text-transform:uppercase;margin-top:3px;">Honeytoken Hits</div>
        </td>
      </tr>
    </table>
  </td></tr>

  <tr><td style="padding:0 30px 14px;">
    <div style="background:#f0f4ff;border-left:4px solid #0073bb;padding:11px 16px;border-radius:0 4px 4px 0;">
      <span style="color:#0073bb;font-weight:bold;font-size:13px;">Trend:&nbsp;</span>
      <span style="color:#232f3e;font-size:13px;">{trend_txt}</span>
    </div>
  </td></tr>

  {f'''<tr><td style="padding:0 30px 16px;">
    <p style="font-weight:bold;color:#232f3e;font-size:13px;margin:0 0 6px;">Top Attacking Countries</p>
    <table width="100%" style="border-collapse:collapse;">
      <tr style="background:#232f3e;">
        <th style="color:#fff;padding:7px 10px;text-align:left;font-size:11px;">Country</th>
        <th style="color:#fff;padding:7px 10px;text-align:right;font-size:11px;">Attacks</th>
        <th style="color:#fff;padding:7px 10px;text-align:right;font-size:11px;">Share</th>
      </tr>
      {country_rows}
    </table>
  </td></tr>''' if d['countries'] else ''}

  <tr><td style="background:#f2f3f3;padding:14px 30px;border-top:1px solid #e0e0e0;">
    <p style="color:#687078;font-size:11px;margin:0;">
      This notification was generated automatically by the <strong>honeyPot Intelligence Platform</strong>
      running on Amazon EC2 (ap-south-1). The full PDF report is attached.
    </p>
    <p style="color:#687078;font-size:11px;margin:6px 0 0;">
      Sensor: Hikvision DS-2CD2043G2-I Emulation &nbsp;&middot;&nbsp;
      All source IPs anonymized in report &nbsp;&middot;&nbsp; CONFIDENTIAL
    </p>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    plain = (
        f"honeyPot Daily Threat Report — {date_str}\n\n"
        f"Total Attacks:    {d['total']:,}\n"
        f"Unique IPs:       {d['uniq']:,}\n"
        f"Countries:        {d['ctries']}\n"
        f"CVE Exploits:     {d['cves']:,}\n"
        f"Botnet Sessions:  {d['botnets']:,}\n"
        f"VPN/Tor Sources:  {anon_total:,}\n"
        f"Honeytoken Hits:  {d['htoks']:,}\n\n"
        f"Trend: {trend_txt}\n\n"
        f"Full PDF report attached.\n"
        f"-- honeyPot Intelligence Platform / AWS EC2 ap-south-1"
    )

    msg = MIMEMultipart("mixed")
    msg["Subject"] = (
        f"[AWS Security Hub] honeyPot Daily Report — {date_str} "
        f"({d['total']:,} attacks detected)"
    )
    msg["From"]    = f"honeyPot Security <{email_from}>"
    msg["To"]      = email_to
    msg["X-Mailer"] = "honeyPot Intelligence Platform v1.0"

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(plain, "plain"))
    alt.attach(MIMEText(html,  "html"))
    msg.attach(alt)

    fname = f"honeyPot_Report_{now.strftime('%Y%m%d')}.pdf"
    part  = MIMEBase("application", "octet-stream")
    part.set_payload(pdf)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
    msg.attach(part)

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as s:
            s.ehlo()
            if smtp_port in (587, 2587):
                s.starttls()
                s.ehlo()
            if smtp_user and smtp_pass:
                s.login(smtp_user, smtp_pass)
            s.sendmail(email_from, [a.strip() for a in email_to.split(",")], msg.as_string())
        print(f"[report] Email sent to {email_to} ✓")
        return True
    except Exception as e:
        print(f"[report] Email error: {e}")
        return False


# ─── Telegram Send ────────────────────────────────────────────────────────────
def send_telegram(pdf: bytes, d: dict) -> bool:
    token   = getattr(config, "TELEGRAM_BOT_TOKEN", "")
    chat_id = getattr(config, "TELEGRAM_CHAT_ID",   "")
    if not token or not chat_id:
        print("[report] Telegram not configured — PDF saved locally only.")
        return False

    sensor = getattr(config, "SENSOR_NAME", "honeyPot")
    now   = d["now"]
    fname = f"honeyPot_Report_{sensor.replace(' ','_')}_{now.strftime('%Y%m%d')}.pdf"
    pct_t = _pct(d["total"], d["p_total"])
    t_sym = (
        f'{"📈" if pct_t and pct_t>0 else "📉"} {abs(pct_t):.0f}% vs yesterday'
        if pct_t is not None else "first period"
    )
    caption = (
        f"📊 <b>honeyPot Intelligence Report</b>  —  {now.strftime('%d %B %Y')}\n"
        f"📡 <b>Sensor: {sensor}</b>\n\n"
        f"🌐 <b>{d['total']:,}</b> attacks  ·  "
        f"<b>{d['uniq']:,}</b> unique IPs  ·  "
        f"<b>{d['ctries']}</b> countries\n"
        f"💀 CVE exploits: <b>{d['cves']:,}</b>  ·  "
        f"Botnets: <b>{d['botnets']:,}</b>\n"
        f"🔒 VPN: <b>{d['vpn']:,}</b>  ·  Tor: <b>{d['tor']:,}</b>  ·  "
        f"Brute bursts: <b>{d['bursts']:,}</b>\n"
        f"{t_sym}\n\n"
        f"<i>Full report attached. All source IPs are anonymized.</i>"
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
    send_email(pdf, d)
    print("[report] Done.")

if __name__ == "__main__":
    main()
