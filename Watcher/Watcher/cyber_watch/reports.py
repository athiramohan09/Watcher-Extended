# coding=utf-8
import os
import logging
from datetime import timedelta
from collections import Counter

from django.conf import settings
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import User
from django.core.mail import EmailMessage, get_connection

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Group
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend

from .models import CVEAlert, RansomwareGroup, RansomwareVictim, WatchRule, WatchRuleHit, Subscriber
from connectors.core import get_smtp_config

logger = logging.getLogger('watcher.cyber_watch')


def _safe(text):
    """Escape DB text for ReportLab Paragraph.

    CVE descriptions, victim/group names and hit text are plain text, not
    markup. If they contain <, > or & (e.g. 'value < 1024'), ReportLab's
    Paragraph parser treats it as an unclosed XML tag and crashes with
    'paraparser: syntax error: parse ended with 1 unclosed tags'.
    Unescape first so already-escaped '&amp;' in the DB is not doubled,
    then escape so it is shown literally in the PDF.
    """
    from html import unescape
    from xml.sax.saxutils import escape
    return escape(unescape(str(text or '')))


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically calculate and render total page count
    along with running header and footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        width, height = self._pagesize
        
        # Header accent bar (pages > 1)
        if self._pageNumber > 1:
            self.setFillColor(colors.HexColor('#0F172A'))
            self.rect(36, height - 28, width - 72, 1, fill=1, stroke=0)
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor('#1E293B'))
            self.drawString(36, height - 24, "CYBER WATCH | DAILY THREAT REPORT")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor('#64748B'))
            self.drawRightString(width - 36, height - 24, "TLP:AMBER / RESTRICTED")

        # Footer divider and text
        self.setFillColor(colors.HexColor('#E2E8F0'))
        self.rect(36, 30, width - 72, 1, fill=1, stroke=0)
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor('#64748B'))
        self.drawString(36, 18, "Watcher Automated Threat Intelligence Platform - Cyber Watch")
        self.drawRightString(width - 36, 18, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def _build_severity_chart(severity_counts):
    """Generate a clean vector pie chart showing CVE severity distribution."""
    labels = [k for k, v in severity_counts.items() if v > 0]
    data = [v for k, v in severity_counts.items() if v > 0]
    d = Drawing(240, 130)

    if not data or sum(data) == 0:
        d.add(Rect(0, 0, 240, 130, fillColor=colors.HexColor('#F8FAFC'), strokeColor=colors.HexColor('#CBD5E1'), strokeWidth=0.5))
        d.add(String(55, 62, "No CVEs in past 24h", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor('#64748B')))
        return d

    pie = Pie()
    pie.x = 10
    pie.y = 10
    pie.width = 110
    pie.height = 110
    pie.data = data
    pie.sideLabels = False

    color_map = {
        'CRITICAL': colors.HexColor('#DC2626'),
        'HIGH': colors.HexColor('#EA580C'),
        'MEDIUM': colors.HexColor('#EAB308'),
        'LOW': colors.HexColor('#16A34A'),
        'UNKNOWN': colors.HexColor('#64748B'),
    }
    for i, label in enumerate(labels):
        pie.slices[i].fillColor = color_map.get(label, colors.HexColor('#6366F1'))
        pie.slices[i].strokeColor = colors.white
        pie.slices[i].strokeWidth = 1

    d.add(pie)

    legend = Legend()
    legend.x = 135
    legend.y = 110
    legend.dx = 8
    legend.dy = 8
    legend.fontName = 'Helvetica'
    legend.fontSize = 7
    legend.boxAnchor = 'nw'
    legend.columnMaximum = 6
    legend.strokeWidth = 0
    legend.strokeColor = colors.transparent
    legend.colorNamePairs = [(pie.slices[i].fillColor, f"{labels[i]} ({data[i]})") for i in range(len(labels))]
    d.add(legend)
    return d


def _build_groups_chart(top_groups):
    """Generate a clean vector vertical bar chart showing top ransomware groups."""
    d = Drawing(240, 130)
    if not top_groups:
        d.add(Rect(0, 0, 240, 130, fillColor=colors.HexColor('#F8FAFC'), strokeColor=colors.HexColor('#CBD5E1'), strokeWidth=0.5))
        d.add(String(50, 62, "No Victims in past 24h", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor('#64748B')))
        return d

    names = [g[0][:11] for g in top_groups]
    counts = [g[1] for g in top_groups]

    chart = VerticalBarChart()
    chart.x = 30
    chart.y = 25
    chart.height = 90
    chart.width = 195
    chart.data = [counts]
    chart.categoryAxis.categoryNames = names
    chart.categoryAxis.labels.fontName = 'Helvetica'
    chart.categoryAxis.labels.fontSize = 6.5
    chart.categoryAxis.labels.angle = 15
    chart.categoryAxis.labels.dy = -10
    chart.valueAxis.valueMin = 0
    max_c = max(counts) if counts else 1
    chart.valueAxis.valueMax = max(max_c + 2, 5)
    chart.valueAxis.valueStep = max(1, (chart.valueAxis.valueMax) // 4)
    chart.valueAxis.labels.fontName = 'Helvetica'
    chart.valueAxis.labels.fontSize = 6.5
    chart.bars[0].fillColor = colors.HexColor('#2563EB')
    chart.bars[0].strokeColor = colors.HexColor('#1D4ED8')
    d.add(chart)
    return d


def generate_daily_threat_report(period_hours=24, output_dir=None):
    """
    Compile threat intelligence data from Cyber Watch for the last 24 hours,
    build an executive PDF report with tables and charts, and attempt to email it.

    Returns dict with summary counts, generated PDF path, and email status.
    """
    now = timezone.now()
    start_time = now - timedelta(hours=period_hours)

    # 1. Query records for the report period (last 24 hours) using exact required fields
    # CVEAlert: fetched_at, cve_id, cvss_score, severity, published
    cves_qs = CVEAlert.objects.filter(fetched_at__gte=start_time)
    new_cves_count = cves_qs.count()

    # Top 10 new CVEs by CVSS score
    top_10_cves = list(cves_qs.order_by(models.F('cvss_score').desc(nulls_last=True), '-published')[:10])

    # RansomwareVictim: fetched_at, victim_name, group
    victims_qs = RansomwareVictim.objects.filter(fetched_at__gte=start_time).select_related('group')
    new_victims_count = victims_qs.count()

    # Top 5 ransomware groups by victim count in the last 24 hours
    top_5_groups_qs = (
        victims_qs.values('group__name')
        .annotate(v_count=models.Count('id'))
        .order_by('-v_count')[:5]
    )
    top_5_groups = [(item['group__name'] or 'Unknown', item['v_count']) for item in top_5_groups_qs]

    # RansomwareGroup: fetched_at, name
    groups_qs = RansomwareGroup.objects.filter(fetched_at__gte=start_time)
    new_groups_count = groups_qs.count()

    # WatchRuleHit: hit_at, rule, hit_display, matched_keyword
    hits_qs = WatchRuleHit.objects.filter(hit_at__gte=start_time).select_related('rule')
    new_hits_count = hits_qs.count()

    # Hits per Watch Rule, count per rule name
    hits_per_rule_qs = (
        hits_qs.values('rule__name')
        .annotate(rule_hits_count=models.Count('id'))
        .order_by('-rule_hits_count')
    )
    hits_per_rule = [(item['rule__name'] or 'Unnamed Rule', item['rule_hits_count']) for item in hits_per_rule_qs]
    recent_hits = list(hits_qs.order_by('-hit_at')[:20])

    # Severity distribution for Chart 1
    severity_counter = Counter()
    for cve in cves_qs.only('severity'):
        sev = (cve.severity or 'UNKNOWN').upper()
        if sev not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}:
            sev = 'UNKNOWN'
        severity_counter[sev] += 1
    # Ensure standard order
    severity_dict = {
        'CRITICAL': severity_counter['CRITICAL'],
        'HIGH': severity_counter['HIGH'],
        'MEDIUM': severity_counter['MEDIUM'],
        'LOW': severity_counter['LOW'],
        'UNKNOWN': severity_counter['UNKNOWN'],
    }

    # 2. Output directory setup
    if not output_dir:
        output_dir = os.path.join(settings.BASE_DIR, 'reports')
    os.makedirs(output_dir, exist_ok=True)

    timestamp_str = now.strftime('%Y%m%d_%H%M%S')
    pdf_filename = f"cyber_watch_daily_threat_report_{timestamp_str}.pdf"
    pdf_path = os.path.join(output_dir, pdf_filename)

    # 3. Build PDF Document
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor('#475569'),
    )
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=10,
        spaceAfter=4,
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#1E293B'),
    )
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0F172A'),
    )
    badge_critical = ParagraphStyle(
        'BadgeCrit',
        parent=table_cell,
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#DC2626'),
    )
    badge_high = ParagraphStyle(
        'BadgeHigh',
        parent=table_cell,
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#EA580C'),
    )
    badge_medium = ParagraphStyle(
        'BadgeMed',
        parent=table_cell,
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#D97706'),
    )
    badge_low = ParagraphStyle(
        'BadgeLow',
        parent=table_cell,
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#16A34A'),
    )
    badge_muted = ParagraphStyle(
        'BadgeMuted',
        parent=table_cell,
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#64748B'),
    )
    notice_title = ParagraphStyle(
        'NoticeTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0F766E'),
    )
    notice_body = ParagraphStyle(
        'NoticeBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor('#134E4A'),
    )

    story = []

    # Title & Metadata Banner
    header_data = [
        [
            Paragraph("🛡️ <b>CYBER WATCH</b> — DAILY THREAT REPORT", title_style),
            Paragraph("<b>CLASSIFICATION:</b> TLP:AMBER<br/><b>PLATFORM:</b> Watcher CTI", subtitle_style)
        ],
        [
            Paragraph(
                f"<b>Reporting Period:</b> Last 24 Hours &nbsp;|&nbsp; "
                f"<b>From:</b> {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp; "
                f"<b>To:</b> {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                subtitle_style
            ),
            Paragraph(f"<b>Generated:</b> {now.strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[380, 160])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0F172A'), spaceBefore=4, spaceAfter=8))

    # Executive Summary Cards (Table of 4 cards)
    summary_card_data = [
        [
            Paragraph(f"<font size='16'><b>{new_cves_count}</b></font><br/><font color='#64748B' size='7.5'>NEW CVEs (24h)</font>", table_cell),
            Paragraph(f"<font size='16'><b>{new_victims_count}</b></font><br/><font color='#64748B' size='7.5'>NEW VICTIMS (24h)</font>", table_cell),
            Paragraph(f"<font size='16'><b>{new_groups_count}</b></font><br/><font color='#64748B' size='7.5'>NEW GROUPS (24h)</font>", table_cell),
            Paragraph(f"<font size='16'><b>{new_hits_count}</b></font><br/><font color='#64748B' size='7.5'>WATCH RULE HITS (24h)</font>", table_cell),
        ]
    ]
    summary_table = Table(summary_card_data, colWidths=[135, 135, 135, 135])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (0, 0), 1, colors.HexColor('#E2E8F0')),
        ('BOX', (1, 0), (1, 0), 1, colors.HexColor('#E2E8F0')),
        ('BOX', (2, 0), (2, 0), 1, colors.HexColor('#E2E8F0')),
        ('BOX', (3, 0), (3, 0), 1, colors.HexColor('#E2E8F0')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    # Visual Analytics Section (2 Charts side-by-side)
    story.append(Paragraph("Visual Threat Analytics (Last 24 Hours)", h2_style))
    chart1 = _build_severity_chart(severity_dict)
    chart2 = _build_groups_chart(top_5_groups)

    charts_table_data = [
        [
            Paragraph("<b>Chart 1: CVE Severity Breakdown</b>", table_cell_bold),
            Paragraph("<b>Chart 2: Top Ransomware Groups by Victims</b>", table_cell_bold),
        ],
        [chart1, chart2]
    ]
    charts_table = Table(charts_table_data, colWidths=[270, 270])
    charts_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 2),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FFFFFF')),
    ]))
    story.append(charts_table)
    story.append(Spacer(1, 10))

    # Section: Top 10 New CVEs by CVSS Score
    story.append(Paragraph("Top 10 New CVEs by CVSS Score (Last 24 Hours)", h2_style))
    cve_table_rows = [
        [
            Paragraph("<b>CVE ID</b>", table_cell_bold),
            Paragraph("<b>CVSS</b>", table_cell_bold),
            Paragraph("<b>Severity</b>", table_cell_bold),
            Paragraph("<b>Published</b>", table_cell_bold),
            Paragraph("<b>Description / Impact</b>", table_cell_bold),
        ]
    ]

    if top_10_cves:
        for cve in top_10_cves:
            score_str = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
            sev = (cve.severity or 'UNKNOWN').upper()
            if sev == 'CRITICAL':
                badge = badge_critical
            elif sev == 'HIGH':
                badge = badge_high
            elif sev == 'MEDIUM':
                badge = badge_medium
            elif sev == 'LOW':
                badge = badge_low
            else:
                badge = badge_muted

            pub_str = cve.published.strftime('%Y-%m-%d') if cve.published else "N/A"
            desc_text = (cve.description or "No description provided").strip()
            if len(desc_text) > 130:
                desc_text = desc_text[:127] + "..."

            cve_table_rows.append([
                Paragraph(f"<b>{_safe(cve.cve_id)}</b>", table_cell_bold),
                Paragraph(score_str, table_cell),
                Paragraph(sev, badge),
                Paragraph(pub_str, table_cell),
                Paragraph(_safe(desc_text), table_cell),
            ])
    else:
        cve_table_rows.append([
            Paragraph("<i>No new CVE alerts ingested in the last 24 hours.</i>", table_cell),
            Paragraph("-", table_cell),
            Paragraph("-", table_cell),
            Paragraph("-", table_cell),
            Paragraph("-", table_cell),
        ])

    cve_table = Table(cve_table_rows, colWidths=[90, 42, 60, 68, 280])
    cve_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(cve_table)
    story.append(Spacer(1, 10))

    # Section: Top 5 Ransomware Groups by Victim Count
    story.append(Paragraph("Top 5 Ransomware Groups by Victim Count (Last 24 Hours)", h2_style))
    groups_table_rows = [
        [
            Paragraph("<b>Rank</b>", table_cell_bold),
            Paragraph("<b>Ransomware Group</b>", table_cell_bold),
            Paragraph("<b>New Victims Count (24h)</b>", table_cell_bold),
            Paragraph("<b>Status / Threat Level</b>", table_cell_bold),
        ]
    ]

    if top_5_groups:
        for idx, (grp_name, v_cnt) in enumerate(top_5_groups, 1):
            threat_level = "High Activity" if v_cnt >= 5 else "Active"
            groups_table_rows.append([
                Paragraph(f"#{idx}", table_cell_bold),
                Paragraph(f"<b>{_safe(grp_name)}</b>", table_cell_bold),
                Paragraph(str(v_cnt), table_cell),
                Paragraph(threat_level, badge_high if v_cnt >= 5 else table_cell),
            ])
    else:
        groups_table_rows.append([
            Paragraph("1", table_cell),
            Paragraph("<i>No ransomware victims recorded in the last 24 hours.</i>", table_cell),
            Paragraph("0", table_cell),
            Paragraph("Inactive", table_cell),
        ])

    groups_table = Table(groups_table_rows, colWidths=[40, 240, 130, 130])
    groups_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(groups_table)
    story.append(Spacer(1, 10))

    # Section: Watch Rule Hits
    story.append(Paragraph("Watch Rule Hits & Alert Corroboration (Last 24 Hours)", h2_style))
    
    if new_hits_count == 0:
        # REQUIRED: Say clearly "No new hits in the last 24 hours", do not show an empty broken page
        no_hit_box = [
            [
                Paragraph("<b>No new hits in the last 24 hours</b>", notice_title),
            ],
            [
                Paragraph(
                    "All active Cyber Watch monitoring rules were systematically evaluated against all incoming "
                    "CVE alerts and ransomware victims ingested during this reporting period. No rule keywords "
                    "matched this batch.",
                    notice_body
                )
            ]
        ]
        no_hit_table = Table(no_hit_box, colWidths=[540])
        no_hit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F0FDFA')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#99F6E4')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(no_hit_table)
    else:
        # Hits breakdown per Watch Rule
        rule_summary_rows = [
            [
                Paragraph("<b>Watch Rule Name</b>", table_cell_bold),
                Paragraph("<b>Matched Hits Count</b>", table_cell_bold),
            ]
        ]
        for r_name, r_cnt in hits_per_rule:
            rule_summary_rows.append([
                Paragraph(f"<b>{_safe(r_name)}</b>", table_cell_bold),
                Paragraph(str(r_cnt), table_cell),
            ])
        rule_summary_table = Table(rule_summary_rows, colWidths=[380, 160])
        rule_summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(rule_summary_table)
        story.append(Spacer(1, 6))

        # Detail list of recent hits
        story.append(Paragraph("<b>Recent Hits Detail:</b>", table_cell_bold))
        hits_detail_rows = [
            [
                Paragraph("<b>Rule</b>", table_cell_bold),
                Paragraph("<b>Keyword</b>", table_cell_bold),
                Paragraph("<b>Timestamp (UTC)</b>", table_cell_bold),
                Paragraph("<b>Hit Detail / Object</b>", table_cell_bold),
            ]
        ]
        for hit in recent_hits:
            rule_name = hit.rule.name if hit.rule else 'Unknown Rule'
            hit_ts = hit.hit_at.strftime('%Y-%m-%d %H:%M') if hit.hit_at else 'N/A'
            display_text = (hit.hit_display or hit.object_id)[:110]
            hits_detail_rows.append([
                Paragraph(f"<b>{_safe(rule_name)}</b>", table_cell),
                Paragraph(_safe(hit.matched_keyword or '-'), table_cell_bold),
                Paragraph(hit_ts, table_cell),
                Paragraph(_safe(display_text), table_cell),
            ])
        hits_detail_table = Table(hits_detail_rows, colWidths=[120, 80, 80, 260])
        hits_detail_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F1F5F9')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(hits_detail_table)

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    logger.info(f"Daily threat report PDF generated successfully: {pdf_path}")

    # 4. Email Notification
    email_status = "skipped"
    smtp = get_smtp_config()

    if not smtp or not smtp.get('host') or not smtp.get('from_email'):
        logger.warning("SMTP not configured, PDF saved but email skipped")
        email_status = "SMTP not configured, PDF saved but email skipped"
    else:
        try:
            # Recipients from Subscriber or active users
            subscribers = Subscriber.objects.filter(email=True).select_related('user_rec')
            recipients = [s.user_rec.email for s in subscribers if s.user_rec and s.user_rec.email]
            if not recipients:
                recipients = [u.email for u in User.objects.filter(is_active=True, is_staff=True) if u.email]

            if not recipients:
                logger.warning("No email recipients configured for CyberWatch daily threat report.")
                email_status = "skipped (no recipients found)"
            else:
                connection = get_connection(
                    host=smtp['host'],
                    port=smtp['port'],
                    username=smtp['user'],
                    password=smtp['password'],
                    use_tls=smtp['use_tls'],
                    use_ssl=smtp['use_ssl'],
                )
                subject = f"[CyberWatch] Daily Threat Report - {now.strftime('%Y-%m-%d')}"
                body = (
                    f"Hello,\n\n"
                    f"Please find attached the Cyber Watch Daily Threat Report for {now.strftime('%Y-%m-%d')}.\n\n"
                    f"Summary counts for the last 24 hours:\n"
                    f" - New CVEs: {new_cves_count}\n"
                    f" - New Ransomware Victims: {new_victims_count}\n"
                    f" - New Ransomware Groups: {new_groups_count}\n"
                    f" - Watch Rule Hits: {new_hits_count}\n\n"
                    f"Regards,\nWatcher Threat Intelligence Platform"
                )
                email = EmailMessage(
                    subject=subject,
                    body=body,
                    from_email=smtp['from_email'],
                    to=recipients,
                    connection=connection,
                )
                email.attach_file(pdf_path)
                email.send(fail_silently=False)
                email_status = f"sent to {len(recipients)} recipient(s)"
                logger.info(f"Daily threat report emailed successfully to {recipients}")
        except Exception as exc:
            logger.error(f"Failed to send daily threat report email: {exc}")
            email_status = f"error: {exc}"

    return {
        'pdf_path': pdf_path,
        'pdf_filename': pdf_filename,
        'period_hours': period_hours,
        'start_time': start_time,
        'end_time': now,
        'counts': {
            'cves': new_cves_count,
            'victims': new_victims_count,
            'groups': new_groups_count,
            'hits': new_hits_count,
        },
        'top_5_groups': top_5_groups,
        'email_status': email_status,
    }
