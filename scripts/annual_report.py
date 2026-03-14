import io
import os
import argparse
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, HRFlowable, PageBreak, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.lib.colors import HexColor


# ─── Brand Colors ───────────────────────────────────────────────────────────
PRIMARY     = HexColor('#1A1F3A')   # Deep navy
ACCENT      = HexColor('#4361EE')   # Electric blue
ACCENT2     = HexColor('#F72585')   # Vivid pink
SUCCESS     = HexColor('#06D6A0')   # Mint green
WARNING     = HexColor('#FFB703')   # Amber
LIGHT_BG    = HexColor('#F0F4FF')   # Pale blue tint
LIGHT_GRAY  = HexColor('#F7F8FA')
MID_GRAY    = HexColor('#CBD5E1')
DARK_GRAY   = HexColor('#475569')
TEXT        = HexColor('#1E293B')
WHITE       = colors.white

W, H = A4  # 595.27 x 841.89 pts


# ─── Styles ──────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    custom = {}

    custom['display'] = ParagraphStyle('display',
        fontName='Helvetica-Bold', fontSize=26, textColor=WHITE,
        leading=32, spaceAfter=4)

    custom['sub_display'] = ParagraphStyle('sub_display',
        fontName='Helvetica', fontSize=12, textColor=HexColor('#A5B4FC'),
        leading=16, spaceAfter=0)

    custom['h1'] = ParagraphStyle('h1',
        fontName='Helvetica-Bold', fontSize=16, textColor=PRIMARY,
        leading=22, spaceBefore=18, spaceAfter=6,
        borderPad=0)

    custom['h2'] = ParagraphStyle('h2',
        fontName='Helvetica-Bold', fontSize=11, textColor=ACCENT,
        leading=16, spaceBefore=12, spaceAfter=4,
        textTransform='uppercase', letterSpacing=0.5)

    custom['body'] = ParagraphStyle('body',
        fontName='Helvetica', fontSize=9.5, textColor=DARK_GRAY,
        leading=15, spaceAfter=6, alignment=TA_JUSTIFY)

    custom['caption'] = ParagraphStyle('caption',
        fontName='Helvetica-Oblique', fontSize=8, textColor=DARK_GRAY,
        leading=12, spaceAfter=4, alignment=TA_CENTER)

    custom['kpi_value'] = ParagraphStyle('kpi_value',
        fontName='Helvetica-Bold', fontSize=22, textColor=ACCENT,
        leading=26, alignment=TA_CENTER)

    custom['kpi_label'] = ParagraphStyle('kpi_label',
        fontName='Helvetica', fontSize=8, textColor=DARK_GRAY,
        leading=11, alignment=TA_CENTER)

    custom['kpi_delta'] = ParagraphStyle('kpi_delta',
        fontName='Helvetica-Bold', fontSize=8.5, textColor=SUCCESS,
        leading=11, alignment=TA_CENTER)

    custom['insight_title'] = ParagraphStyle('insight_title',
        fontName='Helvetica-Bold', fontSize=9.5, textColor=ACCENT,
        leading=13, spaceAfter=3)

    custom['insight_body'] = ParagraphStyle('insight_body',
        fontName='Helvetica', fontSize=8.5, textColor=DARK_GRAY,
        leading=13, spaceAfter=0)

    custom['table_header'] = ParagraphStyle('table_header',
        fontName='Helvetica-Bold', fontSize=8.5, textColor=WHITE,
        leading=12, alignment=TA_CENTER)

    custom['table_cell'] = ParagraphStyle('table_cell',
        fontName='Helvetica', fontSize=8.5, textColor=TEXT,
        leading=12, alignment=TA_CENTER)

    custom['footer'] = ParagraphStyle('footer',
        fontName='Helvetica', fontSize=7.5, textColor=DARK_GRAY,
        leading=10, alignment=TA_CENTER)

    return custom


S = make_styles()


# ─── Custom Flowables ────────────────────────────────────────────────────────

class ColorRect(Flowable):
    """A filled rectangle, used for section dividers / accent bars."""
    def __init__(self, width, height, color, radius=0):
        self.width = width
        self.height = height
        self.color = color
        self.radius = radius
    def draw(self):
        self.canv.setFillColor(self.color)
        self.canv.roundRect(0, 0, self.width, self.height, self.radius, fill=1, stroke=0)
    def wrap(self, *args): return self.width, self.height


class KPICard(Flowable):
    """Single KPI card with value, label, delta."""
    def __init__(self, value, label, delta, delta_positive=True):
        self.value = value
        self.label = label
        self.delta = delta
        self.delta_positive = delta_positive
        self.width = 120
        self.height = 80
    def wrap(self, *args): return self.width, self.height
    def draw(self):
        c = self.canv
        # Card background
        c.setFillColor(WHITE)
        c.setStrokeColor(MID_GRAY)
        c.setLineWidth(0.5)
        c.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=1)
        # Accent top bar
        c.setFillColor(ACCENT)
        c.roundRect(0, self.height - 4, self.width, 4, 3, fill=1, stroke=0)

        delta_color = SUCCESS if self.delta_positive else ACCENT2
        c.setFillColor(ACCENT)
        c.setFont('Helvetica-Bold', 20)
        c.drawCentredString(self.width / 2, self.height - 38, self.value)
        c.setFillColor(DARK_GRAY)
        c.setFont('Helvetica', 7.5)
        c.drawCentredString(self.width / 2, self.height - 52, self.label)
        c.setFillColor(delta_color)
        c.setFont('Helvetica-Bold', 8)
        c.drawCentredString(self.width / 2, self.height - 66, self.delta)


class InsightBox(Flowable):
    """Highlighted insight / callout box."""
    def __init__(self, title, text, width, color=None, icon='▶'):
        self.title = title
        self.text = text
        self.bwidth = width
        self.color = color or ACCENT
        self.icon = icon
        self.height = 60

    def wrap(self, *args):
        return self.bwidth, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(LIGHT_BG)
        c.roundRect(0, 0, self.bwidth, self.height, 6, fill=1, stroke=0)
        c.setFillColor(self.color)
        c.rect(0, 0, 4, self.height, fill=1, stroke=0)
        c.setFillColor(self.color)
        c.setFont('Helvetica-Bold', 9)
        c.drawString(12, self.height - 16, f"{self.icon}  {self.title}")
        c.setFillColor(DARK_GRAY)
        c.setFont('Helvetica', 8.5)
        # Wrap text manually
        words = self.text.split()
        line, y = '', self.height - 30
        for w in words:
            test = line + (' ' if line else '') + w
            if c.stringWidth(test, 'Helvetica', 8.5) < self.bwidth - 20:
                line = test
            else:
                c.drawString(12, y, line)
                y -= 13
                line = w
        if line:
            c.drawString(12, y, line)


# ─── Page template callbacks ─────────────────────────────────────────────────

def header_footer(c, doc):
    """Header + footer for interior pages."""
    c.saveState()
    # Header bar
    c.setFillColor(PRIMARY)
    c.rect(0, H - 28, W, 28, fill=1, stroke=0)
    c.setFillColor(ACCENT)
    c.rect(0, H - 31, W, 3, fill=1, stroke=0)
    # Header text
    c.setFillColor(HexColor('#A5B4FC'))
    c.setFont('Helvetica', 7.5)
    c.drawString(40, H - 18, "ANNUAL PERFORMANCE REPORT  ·  FY 2024")
    c.setFillColor(WHITE)
    c.setFont('Helvetica-Bold', 7.5)
    c.drawRightString(W - 40, H - 18, "CONFIDENTIAL")
    # Footer
    c.setFillColor(LIGHT_GRAY)
    c.rect(0, 0, W, 22, fill=1, stroke=0)
    c.setStrokeColor(MID_GRAY)
    c.setLineWidth(0.5)
    c.line(40, 22, W - 40, 22)
    c.setFillColor(DARK_GRAY)
    c.setFont('Helvetica', 7.5)
    c.drawCentredString(W / 2, 7, f"Page {doc.page}")
    c.drawString(40, 7, "© 2024 Acme Analytics Corp")
    c.drawRightString(W - 40, 7, "analytics@acme.com")
    c.restoreState()


# ─── Chart generators ────────────────────────────────────────────────────────

def make_revenue_chart():
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    revenue_2023 = [3.1, 3.3, 3.8, 4.0, 4.2, 4.5, 4.1, 4.8, 5.0, 5.3, 5.5, 6.0]
    revenue_2024 = [3.8, 4.1, 4.5, 4.9, 5.2, 5.6, 5.3, 6.0, 6.4, 6.8, 7.1, 7.8]

    fig, ax = plt.subplots(figsize=(7.5, 3.2), facecolor='none')
    ax.set_facecolor('#F0F4FF')

    x = np.arange(len(months))
    ax.fill_between(x, revenue_2023, alpha=0.15, color='#4361EE')
    ax.fill_between(x, revenue_2024, alpha=0.20, color='#06D6A0')
    ax.plot(x, revenue_2023, 'o-', color='#4361EE', lw=2, ms=5, label='FY 2023')
    ax.plot(x, revenue_2024, 's-', color='#06D6A0', lw=2.5, ms=5, label='FY 2024')

    # Annotation
    ax.annotate('+30%', xy=(11, 7.8), xytext=(9.5, 7.2),
                arrowprops=dict(arrowstyle='->', color='#F72585', lw=1.5),
                fontsize=8.5, color='#F72585', fontweight='bold')

    ax.set_xticks(x); ax.set_xticklabels(months, fontsize=8)
    ax.set_ylabel('Revenue ($M)', fontsize=8.5, color='#475569')
    ax.yaxis.set_tick_params(labelsize=8)
    ax.spines[['top','right']].set_visible(False)
    ax.spines[['left','bottom']].set_color('#CBD5E1')
    ax.grid(axis='y', color='#E2E8F0', linestyle='--', linewidth=0.6)
    ax.legend(fontsize=8, framealpha=0)
    fig.tight_layout(pad=0.4)

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


def make_segment_donut():
    labels = ['Enterprise', 'Mid-Market', 'SMB', 'Consumer']
    sizes  = [38, 27, 21, 14]
    colors_list = ['#1A1F3A', '#4361EE', '#06D6A0', '#FFB703']
    explode = (0.04, 0, 0, 0)

    fig, ax = plt.subplots(figsize=(3.5, 3.0), facecolor='none')
    wedges, texts, autotexts = ax.pie(
        sizes, explode=explode, labels=None,
        colors=colors_list, autopct='%1.0f%%',
        pctdistance=0.72, startangle=140,
        wedgeprops=dict(width=0.52, edgecolor='white', linewidth=2))
    for at in autotexts:
        at.set_fontsize(7.5); at.set_color('white'); at.set_fontweight('bold')
    ax.legend(wedges, labels, loc='lower center', ncol=2,
              fontsize=7.5, framealpha=0, bbox_to_anchor=(0.5, -0.08))
    ax.text(0, 0, '$67.4M', ha='center', va='center',
            fontsize=11, fontweight='bold', color='#1A1F3A')
    ax.text(0, -0.22, 'Total', ha='center', va='center',
            fontsize=7.5, color='#475569')
    fig.tight_layout(pad=0.2)
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


def make_bar_chart():
    regions = ['North\nAmerica', 'Europe', 'Asia\nPacific', 'Latin\nAmerica', 'MEA']
    q1 = [18.2, 12.5, 9.8, 5.1, 3.2]
    q2 = [20.1, 13.8, 11.2, 5.9, 3.7]

    x = np.arange(len(regions))
    w = 0.38

    fig, ax = plt.subplots(figsize=(7.5, 2.8), facecolor='none')
    ax.set_facecolor('#F7F8FA')

    b1 = ax.bar(x - w/2, q1, w, color='#4361EE', label='Q1 2024', zorder=3)
    b2 = ax.bar(x + w/2, q2, w, color='#06D6A0', label='Q2 2024', zorder=3)

    for bar in list(b1) + list(b2):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                f'{bar.get_height():.1f}', ha='center', va='bottom',
                fontsize=7, color='#475569', fontweight='bold')

    ax.set_xticks(x); ax.set_xticklabels(regions, fontsize=8)
    ax.set_ylabel('Revenue ($M)', fontsize=8.5, color='#475569')
    ax.yaxis.set_tick_params(labelsize=8)
    ax.spines[['top','right']].set_visible(False)
    ax.spines[['left','bottom']].set_color('#CBD5E1')
    ax.grid(axis='y', color='#E2E8F0', linestyle='--', linewidth=0.6, zorder=0)
    ax.legend(fontsize=8, framealpha=0)
    fig.tight_layout(pad=0.4)
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


# ─── Build Document ──────────────────────────────────────────────────────────

OUTPUT = 'annual_report.pdf'


def build_report(output_path: str, data: dict | None = None):
    """Builds the PDF report.

    If `data` is provided, it can override the hardcoded example values.
    """

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=40, rightMargin=40,
        topMargin=50, bottomMargin=35,
        title="Annual Performance Report FY 2024",
        author="Acme Analytics Corp"
    )

    story = []
    INNER_W = W - 80  # usable text width

    # -- Cover (canvas background + draw function) --

    class CoverBackground(Flowable):
        def wrap(self, *args): return W, H
        def draw(self):
            c = self.canv
            # Navy top half
            c.setFillColor(ACCENT)
            c.rect(0, H/2, W, H/2, fill=1, stroke=0)
            # Decorative circles
            c.setFillColor(HexColor('#2D3561'))
            c.circle(W - 60, H - 70, 120, fill=1, stroke=0)
            c.setFillColor(HexColor('#3048A8'))
            c.circle(W - 30, H - 210, 80, fill=1, stroke=0)
            c.setFillColor(ACCENT2)
            c.circle(55, H - 55, 30, fill=1, stroke=0)
            # White divider line
            c.setStrokeColor(WHITE)
            c.setLineWidth(1)
            c.line(40, H/2, W-40, H/2)
            # Bottom half light
            c.setFillColor(LIGHT_BG)
            c.rect(0, 0, W, H/2, fill=1, stroke=0)
            # Accent bottom bar
            c.setFillColor(ACCENT)
            c.rect(0, 0, 6, H/2, fill=1, stroke=0)

    story.append(PageBreak())  # Start from page 2 (cover is drawn separately)

    # -- Executive summary page --
    story.append(Paragraph("Executive Summary", S['h1']))
    story.append(ColorRect(50, 3, ACCENT))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Fiscal Year 2024 marked a transformative period for Acme Analytics Corp. "
        "Despite macroeconomic headwinds, the company delivered record-breaking revenue "
        "of <b>$67.4M</b>, representing a <b>30% year-over-year increase</b> compared to FY 2023. "
        "Enterprise segment expansion, successful product launches in Asia Pacific, and "
        "disciplined cost management were the primary growth drivers.",
        S['body']))
    story.append(Paragraph(
        "Net Recurring Revenue (NRR) reached 118%, indicating strong customer expansion "
        "and low churn. The company added 142 net-new enterprise logos, bringing total "
        "enterprise customers to 487. Gross margin improved by 3.2 percentage points to 74.1%, "
        "reflecting the continued shift toward high-margin software and professional services.",
        S['body']))

    story.append(Spacer(1, 12))

    kpis = [
        ("$67.4M",  "Total Revenue",          "▲ +30% YoY",  True),
        ("118%",    "Net Revenue Retention",   "▲ +4pp YoY",  True),
        ("74.1%",   "Gross Margin",            "▲ +3.2pp",    True),
        ("487",     "Enterprise Customers",    "▲ +142 net",  True),
        ("$8.2M",   "Operating Income",        "▲ +52% YoY",  True),
    ]

    kpi_cells = [[KPICard(v, l, d, pos) for v, l, d, pos in kpis]]
    kpi_table = Table(kpi_cells, colWidths=[INNER_W / 5] * 5)
    kpi_table.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'CENTER'),
                                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                                    ('TOPPADDING', (0,0), (-1,-1), 6),
                                    ('BOTTOMPADDING', (0,0), (-1,-1), 6)]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    insights = [
        ("🏆 Record Enterprise Growth",
         "Enterprise segment grew 42% YoY and now represents 38% of total revenue. "
         "Average contract value expanded from $82K to $118K.",
         SUCCESS),
        ("⚠️ Watch: SMB Churn Elevated",
         "SMB segment churn ticked up to 8.2% in H2. Retention programs launched in Q3 "
         "show early promise with churn stabilizing in December.",
         WARNING),
    ]

    insight_cells = [[InsightBox(t, b, INNER_W/2 - 8, c) for t, b, c in insights]]
    insight_table = Table(insight_cells, colWidths=[INNER_W/2]*2)
    insight_table.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'LEFT'),
                                        ('LEFTPADDING', (0,0), (-1,-1), 4),
                                        ('RIGHTPADDING', (0,0), (-1,-1), 4)]))
    story.append(insight_table)
    story.append(Spacer(1, 6))

    # -- Revenue analysis page --
    story.append(PageBreak())
    story.append(Paragraph("Revenue Analysis", S['h1']))
    story.append(ColorRect(50, 3, ACCENT))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Monthly Revenue Trend — FY 2023 vs FY 2024", S['h2']))
    story.append(Spacer(1, 4))

    rev_buf = make_revenue_chart()
    rev_img = Image(rev_buf, width=INNER_W, height=INNER_W * 0.42)
    story.append(rev_img)
    story.append(Paragraph(
        "Figure 1: Monthly revenue comparison between FY 2023 and FY 2024. "
        "The +30% annotation highlights December's peak performance versus prior year.",
        S['caption']))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Revenue by Segment & Region", S['h2']))
    story.append(Spacer(1, 4))

    seg_buf  = make_segment_donut()
    bar_buf  = make_bar_chart()

    seg_img  = Image(seg_buf,  width=INNER_W * 0.38, height=INNER_W * 0.38)
    bar_img  = Image(bar_buf,  width=INNER_W * 0.60, height=INNER_W * 0.38 * (2.8/3.5))

    chart_data = [[seg_img, bar_img]]
    chart_table = Table(chart_data, colWidths=[INNER_W*0.38 + 6, INNER_W*0.60 + 6])
    chart_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 2),
        ('RIGHTPADDING', (0,0), (-1,-1), 2),
    ]))
    story.append(chart_table)

    cap_data = [["Figure 2: Revenue split by customer segment.", "Figure 3: Regional revenue Q1 vs Q2 FY 2024."]]
    cap_table = Table(cap_data, colWidths=[INNER_W*0.38+6, INNER_W*0.60+6])
    cap_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Oblique'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('TEXTCOLOR', (0,0), (-1,-1), DARK_GRAY),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
    ]))
    story.append(cap_table)

    # -- Quarterly detail page --
    story.append(PageBreak())
    story.append(Paragraph("Quarterly Performance Detail", S['h1']))
    story.append(ColorRect(50, 3, ACCENT))
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "The table below provides a full breakdown of key financial and operational metrics "
        "across all four quarters of FY 2024, enabling period-over-period comparison "
        "and trend identification.",
        S['body']))
    story.append(Spacer(1, 10))

    def hp(txt): return Paragraph(txt, S['table_header'])
    def cp(txt, bold=False, color=None):
        st = ParagraphStyle('tc', fontName='Helvetica-Bold' if bold else 'Helvetica',
                            fontSize=8.5, textColor=color or TEXT,
                            leading=12, alignment=TA_CENTER)
        return Paragraph(txt, st)

    headers = ["Metric", "Q1 2024", "Q2 2024", "Q3 2024", "Q4 2024", "FY 2024"]
    rows = [
        ["Revenue ($M)",          "15.2", "16.4", "17.1", "18.7", "67.4"],
        ["YoY Growth (%)",        "24%",  "27%",  "31%",  "38%",  "30%"],
        ["Gross Profit ($M)",     "10.9", "12.1", "12.7", "14.2", "49.9"],
        ["Gross Margin (%)",      "71.7%","73.8%","74.3%","75.9%","74.1%"],
        ["Operating Income ($M)", "1.4",  "1.8",  "2.1",  "2.9",  "8.2"],
        ["New Customers",         "108",  "124",  "131",  "158",  "521"],
        ["Enterprise Logos",      "28",   "35",   "37",   "42",   "142"],
        ["NRR (%)",               "114%", "116%", "119%", "123%", "118%"],
        ["CAC Payback (months)",  "14.2", "13.8", "13.1", "12.4", "13.4"],
        ["Headcount (EoP)",       "312",  "341",  "368",  "395",  "395"],
    ]

    col_w = [INNER_W * 0.32] + [INNER_W * 0.136] * 5
    table_data = [[hp(h) for h in headers]]

    for i, row in enumerate(rows):
        formatted = [cp(row[0], bold=True, color=PRIMARY)]
        for j, v in enumerate(row[1:-1], 1):
            formatted.append(cp(v))
        formatted.append(cp(row[-1], bold=True, color=ACCENT))
        table_data.append(formatted)

    perf_table = Table(table_data, colWidths=col_w, repeatRows=1)
    ts = [
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [LIGHT_BG, WHITE]),
        ('TEXTCOLOR', (0,0), (-1,0), WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('ALIGN', (0,1), (0,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (0,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.4, MID_GRAY),
        ('LINEBELOW', (0,0), (-1,0), 1.5, ACCENT),
        ('BACKGROUND', (-1,1), (-1,-1), LIGHT_BG),
        ('LINEAFTER', (-2,0), (-2,-1), 1, MID_GRAY),
    ]
    perf_table.setStyle(TableStyle(ts))
    story.append(perf_table)
    story.append(Spacer(1, 14))

    story.append(HRFlowable(width=INNER_W, thickness=0.5, color=MID_GRAY))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<i>Notes: Revenue figures are unaudited. NRR = Net Revenue Retention calculated on "
        "trailing 12-month cohort basis. CAC Payback based on blended customer acquisition cost. "
        "Headcount excludes contractors.</i>", S['caption']))

    story.append(Spacer(1, 14))

    story.append(Paragraph("Key Takeaways", S['h2']))
    story.append(Spacer(1, 6))

    takeaways = [
        ("📈 Accelerating Growth",
         "YoY growth accelerated from 24% in Q1 to 38% in Q4 — strong momentum heading into FY 2025.",
         ACCENT),
        ("💰 Margin Expansion",
         "Gross margin expanded 4.2pp across the year driven by product mix shift and cloud efficiency gains.",
         SUCCESS),
        ("🎯 Enterprise Traction",
         "Enterprise logos grew by 142 net-new, beating the 120-logo target by 18%. "
         "Pipeline for FY 2025 is 2.4× prior year.",
         PRIMARY),
    ]

    for title, body, color in takeaways:
        story.append(InsightBox(title, body, INNER_W, color))
        story.append(Spacer(1, 6))

    story.append(PageBreak())
    story.append(Paragraph("FY 2025 Outlook & Strategic Priorities", S['h1']))
    story.append(ColorRect(50, 3, ACCENT2))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "Building on the momentum of FY 2024, management is guiding for <b>$90–95M</b> "
        "in revenue for FY 2025, representing approximately <b>35–40% growth</b>. "
        "Key strategic priorities are outlined below.",
        S['body']))
    story.append(Spacer(1, 10))

    priorities = [
        ("P1", "International Expansion",    "Accelerate APAC & EMEA go-to-market. Target: 35% of revenue from international by Q4 2025."),
        ("P2", "Product-Led Growth Motion",  "Launch self-serve tier in Q1 2025 to address mid-market and SMB at lower CAC."),
        ("P3", "Platform Ecosystem",         "Onboard 25+ technology partners onto integration marketplace; target $12M in influenced ARR."),
        ("P4", "Operational Excellence",     "Drive gross margin to 76%+ through infrastructure optimization and AI-assisted support."),
        ("P5", "Talent & Culture",           "Grow team to 480 FTEs with focus on engineering (40% of new hires) and customer success."),
    ]

    pdata = [["#", "Initiative", "Description"]] + [[p, t, d] for p, t, d in priorities]
    pcols = [INNER_W*0.07, INNER_W*0.25, INNER_W*0.68]
    ptable = Table(pdata, colWidths=pcols)
    ptable.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), PRIMARY),
        ('TEXTCOLOR', (0,0), (-1,0), WHITE),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,1), (1,-1), 'Helvetica-Bold'),
        ('FONTNAME', (2,1), (2,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 8.5),
        ('TEXTCOLOR', (0,1), (0,-1), WHITE),
        ('BACKGROUND', (0,1), (0,-1), ACCENT),
        ('ROWBACKGROUNDS', (1,1), (-1,-1), [LIGHT_BG, WHITE]),
        ('ALIGN', (0,0), (1,-1), 'CENTER'),
        ('ALIGN', (2,0), (2,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING', (2,0), (2,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.4, MID_GRAY),
        ('LINEBELOW', (0,0), (-1,0), 1.5, ACCENT),
    ]))
    story.append(ptable)
    story.append(Spacer(1, 20))

    story.append(HRFlowable(width=INNER_W, thickness=0.8, color=MID_GRAY))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Appendix A — Definitions & Methodology", S['h2']))
    story.append(Spacer(1, 6))

    defs = [
        ("<b>ARR (Annual Recurring Revenue):</b> Annualized value of all active subscription contracts at period end."),
        ("<b>NRR (Net Revenue Retention):</b> Expansion + contraction + churn within the prior-year cohort, divided by prior-year ARR."),
        ("<b>CAC (Customer Acquisition Cost):</b> Total sales and marketing spend divided by new customers acquired in the period."),
        ("<b>Gross Margin:</b> (Revenue − Cost of Revenue) / Revenue. Cost of Revenue includes hosting, support, and professional services delivery."),
        ("<b>Enterprise:</b> Customers with ACV ≥ $50,000. Mid-Market: $15K–$49.9K. SMB: $5K–$14.9K. Consumer: < $5K."),
    ]
    for d in defs:
        story.append(Paragraph(d, S['body']))

    def draw_cover(c):
        c.setFillColor(ACCENT)
        c.rect(0, H/2, W, H/2, fill=1, stroke=0)
        c.setFillColor(HexColor('#2D3561'))
        c.circle(W - 60, H - 70, 120, fill=1, stroke=0)
        c.setFillColor(HexColor('#3048A8'))
        c.circle(W - 30, H - 210, 80, fill=1, stroke=0)
        c.setFillColor(ACCENT2)
        c.circle(55, H - 55, 30, fill=1, stroke=0)
        c.setStrokeColor(WHITE)
        c.setLineWidth(1)
        c.line(40, H/2, W-40, H/2)
        c.setFillColor(LIGHT_BG)
        c.rect(0, 0, W, H/2, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.rect(0, 0, 6, H/2, fill=1, stroke=0)
        c.setFillColor(HexColor('#A5B4FC'))
        c.setFont('Helvetica-Bold', 9)
        c.drawString(50, H * 0.82, "ACME ANALYTICS CORP  \u00b7  FISCAL YEAR 2024")
        c.setFillColor(WHITE)
        c.setFont('Helvetica-Bold', 34)
        c.drawString(50, H * 0.72, "Annual Performance")
        c.drawString(50, H * 0.72 - 42, "Report")
        c.setFillColor(HexColor('#DBEAFE'))
        c.setFont('Helvetica', 13)
        c.drawString(50, H * 0.72 - 72, "Revenue, Growth & Strategic Insights")
        c.setStrokeColor(HexColor('#A5B4FC'))
        c.setLineWidth(1)
        c.line(50, H * 0.72 - 85, 300, H * 0.72 - 85)
        meta = [
            ("Prepared by",    "Finance & Strategy Team"),
            ("Period",         "January \u2013 December 2024"),
            ("Classification", "Confidential"),
            ("Version",        "1.0 Final"),
        ]
        y = H * 0.44
        for label, val in meta:
            c.setFillColor(DARK_GRAY)
            c.setFont('Helvetica-Bold', 8.5)
            c.drawString(60, y, label)
            c.setFillColor(TEXT)
            c.setFont('Helvetica', 8.5)
            c.drawString(200, y, val)
            c.setStrokeColor(MID_GRAY)
            c.setLineWidth(0.4)
            c.line(60, y - 4, W - 60, y - 4)
            y -= 26
        c.setFillColor(ACCENT)
        c.roundRect(W-130, 30, 90, 26, 4, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont('Helvetica-Bold', 9)
        c.drawCentredString(W - 85, 40, "FY 2024")

    def on_page(c, doc):
        if doc.page == 1:
            draw_cover(c)
        else:
            header_footer(c, doc)

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)


def main():
    parser = argparse.ArgumentParser(description='Generate a styled annual report PDF.')
    parser.add_argument('--output', '-o', default='annual_report.pdf',
                        help='Output PDF file path')
    parser.add_argument('--data', '-d', help='Optional JSON file to drive values (not required)')
    args = parser.parse_args()

    data = None
    if args.data:
        if not os.path.exists(args.data):
            raise FileNotFoundError(f"Data file not found: {args.data}")
        with open(args.data, 'r', encoding='utf-8') as f:
            data = json.load(f)

    build_report(args.output, data)
    print(f"PDF generated: {os.path.abspath(args.output)}")


if __name__ == '__main__':
    main()
