"""
Professional PDF Report Generator for AWS Well-Architected Reviews

Generates comprehensive, beautifully formatted PDF reports from
AWS Landscape Assessment data.

Features:
- Executive summary with scores
- Pillar-by-pillar breakdown
- Findings with severity indicators
- Resource inventory
- Recommendations roadmap
- Cost optimization opportunities
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable, ListFlowable, ListItem
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.widgets.markers import makeMarker
from io import BytesIO
from datetime import datetime
from typing import Dict, List, Optional
import os

# Try to import landscape scanner types
try:
    from .landscape_scanner import LandscapeAssessment, Finding, WAFPillar, PillarScore
except (ImportError, Exception):
    # Define minimal types for standalone use
    LandscapeAssessment = None
    Finding = None
    WAFPillar = None
    PillarScore = None


# ============================================================================
# COLOR SCHEME
# ============================================================================

class Colors:
    """AWS-inspired color scheme"""
    AWS_ORANGE = colors.HexColor('#FF9900')
    AWS_DARK = colors.HexColor('#232F3E')
    AWS_LIGHT = colors.HexColor('#37475A')
    AWS_BLUE = colors.HexColor('#1A73E8')
    
    CRITICAL = colors.HexColor('#D32F2F')
    HIGH = colors.HexColor('#F57C00')
    MEDIUM = colors.HexColor('#FBC02D')
    LOW = colors.HexColor('#388E3C')
    INFO = colors.HexColor('#1976D2')
    
    HEADER_BG = colors.HexColor('#232F3E')
    SECTION_BG = colors.HexColor('#F5F5F5')
    WHITE = colors.white
    BLACK = colors.black
    GRAY = colors.HexColor('#666666')
    LIGHT_GRAY = colors.HexColor('#E0E0E0')


# ============================================================================
# CUSTOM STYLES
# ============================================================================

def get_custom_styles():
    """Create custom paragraph styles"""
    styles = getSampleStyleSheet()
    
    # Title style
    styles.add(ParagraphStyle(
        name='ReportTitle',
        parent=styles['Title'],
        fontSize=28,
        textColor=Colors.AWS_DARK,
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    # Subtitle
    styles.add(ParagraphStyle(
        name='ReportSubtitle',
        parent=styles['Normal'],
        fontSize=14,
        textColor=Colors.GRAY,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica'
    ))
    
    # Section Header
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=Colors.AWS_DARK,
        spaceBefore=20,
        spaceAfter=12,
        fontName='Helvetica-Bold',
        borderPadding=5,
        borderColor=Colors.AWS_ORANGE,
        borderWidth=0,
        leftIndent=0
    ))
    
    # Subsection Header
    styles.add(ParagraphStyle(
        name='SubsectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=Colors.AWS_LIGHT,
        spaceBefore=15,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    ))
    
    # Body text
    styles.add(ParagraphStyle(
        name='BodyText',
        parent=styles['Normal'],
        fontSize=10,
        textColor=Colors.BLACK,
        spaceAfter=8,
        alignment=TA_JUSTIFY,
        fontName='Helvetica'
    ))
    
    # Finding title
    styles.add(ParagraphStyle(
        name='FindingTitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=Colors.AWS_DARK,
        fontName='Helvetica-Bold',
        spaceAfter=4
    ))
    
    # Finding description
    styles.add(ParagraphStyle(
        name='FindingDesc',
        parent=styles['Normal'],
        fontSize=9,
        textColor=Colors.GRAY,
        spaceAfter=2,
        fontName='Helvetica'
    ))
    
    # Metric value
    styles.add(ParagraphStyle(
        name='MetricValue',
        parent=styles['Normal'],
        fontSize=24,
        textColor=Colors.AWS_DARK,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    # Metric label
    styles.add(ParagraphStyle(
        name='MetricLabel',
        parent=styles['Normal'],
        fontSize=10,
        textColor=Colors.GRAY,
        alignment=TA_CENTER,
        fontName='Helvetica'
    ))
    
    # Footer
    styles.add(ParagraphStyle(
        name='Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=Colors.GRAY,
        alignment=TA_CENTER,
        fontName='Helvetica'
    ))
    
    return styles


# ============================================================================
# DRAWING HELPERS
# ============================================================================

def create_score_gauge(score: int, width: int = 150, height: int = 80) -> Drawing:
    """Create a gauge chart for score visualization"""
    d = Drawing(width, height)
    
    # Determine color based on score
    if score >= 80:
        color = Colors.LOW
    elif score >= 60:
        color = Colors.MEDIUM
    elif score >= 40:
        color = Colors.HIGH
    else:
        color = Colors.CRITICAL
    
    # Background arc
    center_x = width / 2
    center_y = height - 10
    radius = 50
    
    # Draw background arc
    d.add(Circle(center_x, center_y, radius, strokeColor=Colors.LIGHT_GRAY, strokeWidth=12, fillColor=None))
    
    # Draw score arc (simplified as a colored segment)
    d.add(Circle(center_x, center_y, radius, strokeColor=color, strokeWidth=12, fillColor=None))
    
    # Score text
    d.add(String(center_x, center_y - 5, str(score), 
                 fontSize=24, fontName='Helvetica-Bold', 
                 fillColor=color, textAnchor='middle'))
    
    d.add(String(center_x, center_y - 25, '/100',
                 fontSize=10, fontName='Helvetica',
                 fillColor=Colors.GRAY, textAnchor='middle'))
    
    return d


def create_pillar_bar_chart(pillar_scores: Dict, width: int = 400, height: int = 200) -> Drawing:
    """Create a bar chart showing pillar scores"""
    d = Drawing(width, height)
    
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.width = width - 80
    chart.height = height - 60
    
    # Data
    pillar_names = []
    scores = []
    
    for name, score in pillar_scores.items():
        # Shorten names
        short_name = name.split()[0][:4]
        pillar_names.append(short_name)
        scores.append(score.score if hasattr(score, 'score') else score)
    
    chart.data = [scores]
    chart.categoryAxis.categoryNames = pillar_names
    chart.categoryAxis.labels.angle = 45
    chart.categoryAxis.labels.fontSize = 8
    
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 100
    chart.valueAxis.valueStep = 20
    
    # Bar colors based on score
    chart.bars[0].fillColor = Colors.AWS_ORANGE
    
    d.add(chart)
    
    return d


def create_severity_pie_chart(findings: List, width: int = 200, height: int = 150) -> Drawing:
    """Create pie chart showing finding severity distribution"""
    d = Drawing(width, height)
    
    # Count severities
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'MEDIUM')
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Only include non-zero
    data = []
    labels = []
    pie_colors = []
    
    color_map = {
        'CRITICAL': Colors.CRITICAL,
        'HIGH': Colors.HIGH,
        'MEDIUM': Colors.MEDIUM,
        'LOW': Colors.LOW
    }
    
    for sev, count in severity_counts.items():
        if count > 0:
            data.append(count)
            labels.append(f"{sev} ({count})")
            pie_colors.append(color_map[sev])
    
    if not data:
        data = [1]
        labels = ['No Findings']
        pie_colors = [Colors.LOW]
    
    pie = Pie()
    pie.x = 50
    pie.y = 20
    pie.width = 80
    pie.height = 80
    pie.data = data
    pie.labels = labels
    pie.slices.strokeWidth = 0.5
    
    for i, c in enumerate(pie_colors):
        pie.slices[i].fillColor = c
    
    pie.sideLabels = True
    pie.simpleLabels = False
    pie.slices.fontSize = 8
    
    d.add(pie)
    
    return d


# ============================================================================
# PAGE TEMPLATES
# ============================================================================

def add_header_footer(canvas, doc):
    """Add header and footer to each page"""
    canvas.saveState()
    
    # Header
    canvas.setFillColor(Colors.AWS_DARK)
    canvas.rect(0, doc.height + doc.topMargin, doc.width + doc.leftMargin + doc.rightMargin, 40, fill=True, stroke=False)
    
    canvas.setFillColor(Colors.AWS_ORANGE)
    canvas.setFont('Helvetica-Bold', 12)
    canvas.drawString(doc.leftMargin, doc.height + doc.topMargin + 15, "AWS Well-Architected Review")
    
    canvas.setFillColor(Colors.WHITE)
    canvas.setFont('Helvetica', 10)
    canvas.drawRightString(doc.width + doc.leftMargin, doc.height + doc.topMargin + 15, 
                          datetime.now().strftime('%Y-%m-%d'))
    
    # Footer
    canvas.setFillColor(Colors.GRAY)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(doc.leftMargin, 20, "Generated by AWS Well-Architected Advisor")
    canvas.drawRightString(doc.width + doc.leftMargin, 20, f"Page {doc.page}")
    
    # Footer line
    canvas.setStrokeColor(Colors.LIGHT_GRAY)
    canvas.line(doc.leftMargin, 35, doc.width + doc.leftMargin, 35)
    
    canvas.restoreState()


# ============================================================================
# REPORT SECTIONS
# ============================================================================

def build_cover_page(assessment, styles) -> List:
    """Build the cover page"""
    elements = []
    
    # Spacer
    elements.append(Spacer(1, 2*inch))
    
    # Title
    elements.append(Paragraph("AWS Well-Architected", styles['ReportTitle']))
    elements.append(Paragraph("Framework Review Report", styles['ReportTitle']))
    
    elements.append(Spacer(1, 0.5*inch))
    
    # Subtitle with date
    date_str = assessment.timestamp.strftime('%B %d, %Y') if hasattr(assessment, 'timestamp') else datetime.now().strftime('%B %d, %Y')
    elements.append(Paragraph(f"Assessment Date: {date_str}", styles['ReportSubtitle']))
    
    # Assessment ID
    assessment_id = getattr(assessment, 'assessment_id', 'N/A')
    elements.append(Paragraph(f"Assessment ID: {assessment_id}", styles['ReportSubtitle']))
    
    elements.append(Spacer(1, 1*inch))
    
    # Overall Score Box
    score = getattr(assessment, 'overall_score', 0)
    risk = getattr(assessment, 'overall_risk', 'Unknown')
    
    score_color = Colors.LOW if score >= 80 else Colors.MEDIUM if score >= 60 else Colors.HIGH if score >= 40 else Colors.CRITICAL
    
    score_table = Table([
        [Paragraph(f"<font size='48' color='{score_color.hexval()}'><b>{score}</b></font>", styles['BodyText'])],
        [Paragraph("Overall WAF Score", styles['MetricLabel'])],
        [Paragraph(f"Risk Level: <b>{risk}</b>", styles['BodyText'])]
    ], colWidths=[3*inch])
    
    score_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 2, Colors.AWS_ORANGE),
        ('BACKGROUND', (0, 0), (-1, -1), Colors.SECTION_BG),
        ('TOPPADDING', (0, 0), (-1, -1), 20),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
    ]))
    
    elements.append(score_table)
    
    elements.append(Spacer(1, 1*inch))
    
    # Accounts/Regions scanned
    accounts = getattr(assessment, 'accounts_scanned', [])
    regions = getattr(assessment, 'regions_scanned', [])
    
    info_text = f"Accounts Scanned: {len(accounts)} | Regions: {', '.join(regions) if regions else 'N/A'}"
    elements.append(Paragraph(info_text, styles['ReportSubtitle']))
    
    elements.append(PageBreak())
    
    return elements


def build_executive_summary(assessment, styles) -> List:
    """Build executive summary section"""
    elements = []
    
    elements.append(Paragraph("Executive Summary", styles['SectionHeader']))
    elements.append(HRFlowable(width="100%", thickness=2, color=Colors.AWS_ORANGE, spaceAfter=20))
    
    # Summary paragraph
    findings_count = len(getattr(assessment, 'findings', []))
    critical_count = sum(1 for f in getattr(assessment, 'findings', []) if getattr(f, 'severity', '') == 'CRITICAL')
    high_count = sum(1 for f in getattr(assessment, 'findings', []) if getattr(f, 'severity', '') == 'HIGH')
    
    score = getattr(assessment, 'overall_score', 0)
    risk = getattr(assessment, 'overall_risk', 'Unknown')
    
    summary_text = f"""
    This Well-Architected Review assessed your AWS environment across all six pillars of the 
    AWS Well-Architected Framework. The assessment identified <b>{findings_count} findings</b>, 
    including <b><font color="{Colors.CRITICAL.hexval()}">{critical_count} critical</font></b> and 
    <b><font color="{Colors.HIGH.hexval()}">{high_count} high</font></b> severity issues.
    
    Your overall WAF score is <b>{score}/100</b> with a <b>{risk}</b> risk level.
    """
    
    elements.append(Paragraph(summary_text, styles['BodyText']))
    elements.append(Spacer(1, 20))
    
    # Key metrics table
    services_scanned = len(getattr(assessment, 'services_scanned', {}))
    inventory = getattr(assessment, 'inventory', None)
    
    ec2_count = getattr(inventory, 'ec2_instances', 0) if inventory else 0
    rds_count = getattr(inventory, 'rds_instances', 0) if inventory else 0
    s3_count = getattr(inventory, 's3_buckets', 0) if inventory else 0
    
    metrics_data = [
        ['Metric', 'Value'],
        ['Services Scanned', str(services_scanned)],
        ['Total Findings', str(findings_count)],
        ['Critical Issues', str(critical_count)],
        ['High Issues', str(high_count)],
        ['EC2 Instances', str(ec2_count)],
        ['RDS Databases', str(rds_count)],
        ['S3 Buckets', str(s3_count)],
    ]
    
    metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
        ('BACKGROUND', (0, 1), (-1, -1), Colors.SECTION_BG),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    
    elements.append(metrics_table)
    elements.append(Spacer(1, 30))
    
    return elements


def build_pillar_scores_section(assessment, styles) -> List:
    """Build pillar scores section"""
    elements = []
    
    elements.append(Paragraph("Pillar Assessment Scores", styles['SectionHeader']))
    elements.append(HRFlowable(width="100%", thickness=2, color=Colors.AWS_ORANGE, spaceAfter=20))
    
    pillar_scores = getattr(assessment, 'pillar_scores', {})
    
    if not pillar_scores:
        elements.append(Paragraph("No pillar scores available.", styles['BodyText']))
        return elements
    
    # Pillar icons and descriptions
    pillar_info = {
        'Operational Excellence': ('⚙️', 'Run and monitor systems to deliver business value'),
        'Security': ('🔒', 'Protect information, systems, and assets'),
        'Reliability': ('🛡️', 'Recover from failures and meet demand'),
        'Performance Efficiency': ('⚡', 'Use computing resources efficiently'),
        'Cost Optimization': ('💰', 'Avoid unnecessary costs'),
        'Sustainability': ('🌱', 'Minimize environmental impact'),
    }
    
    # Create pillar score table
    pillar_data = [['Pillar', 'Score', 'Critical', 'High', 'Medium', 'Status']]
    
    for pillar_name, score_obj in pillar_scores.items():
        score = score_obj.score if hasattr(score_obj, 'score') else 0
        critical = score_obj.critical_count if hasattr(score_obj, 'critical_count') else 0
        high = score_obj.high_count if hasattr(score_obj, 'high_count') else 0
        medium = score_obj.medium_count if hasattr(score_obj, 'medium_count') else 0
        
        if score >= 80:
            status = 'Good'
        elif score >= 60:
            status = 'Needs Work'
        else:
            status = 'At Risk'
        
        pillar_data.append([
            pillar_name,
            f"{score}/100",
            str(critical),
            str(high),
            str(medium),
            status
        ])
    
    pillar_table = Table(pillar_data, colWidths=[2*inch, 0.8*inch, 0.7*inch, 0.7*inch, 0.8*inch, 1*inch])
    pillar_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
        ('BACKGROUND', (0, 1), (-1, -1), Colors.WHITE),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [Colors.WHITE, Colors.SECTION_BG]),
    ]))
    
    elements.append(pillar_table)
    elements.append(Spacer(1, 20))
    
    # Add bar chart
    try:
        chart = create_pillar_bar_chart(pillar_scores)
        elements.append(chart)
    except Exception:
        pass
    
    elements.append(PageBreak())
    
    return elements


def build_findings_section(assessment, styles) -> List:
    """Build detailed findings section"""
    elements = []
    
    elements.append(Paragraph("Detailed Findings", styles['SectionHeader']))
    elements.append(HRFlowable(width="100%", thickness=2, color=Colors.AWS_ORANGE, spaceAfter=20))
    
    findings = getattr(assessment, 'findings', [])
    
    if not findings:
        elements.append(Paragraph("No findings identified during this assessment.", styles['BodyText']))
        return elements
    
    # Group findings by severity
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    
    for severity in severity_order:
        severity_findings = [f for f in findings if getattr(f, 'severity', '') == severity]
        
        if not severity_findings:
            continue
        
        # Severity header
        severity_colors = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.HIGH,
            'MEDIUM': Colors.MEDIUM,
            'LOW': Colors.LOW,
            'INFO': Colors.INFO
        }
        
        color = severity_colors.get(severity, Colors.GRAY)
        
        elements.append(Paragraph(
            f"<font color='{color.hexval()}'><b>{severity} Severity</b></font> ({len(severity_findings)} findings)",
            styles['SubsectionHeader']
        ))
        
        # Findings table for this severity
        for idx, finding in enumerate(severity_findings[:10], 1):  # Limit to 10 per severity
            title = getattr(finding, 'title', 'Finding')
            description = getattr(finding, 'description', '')[:200]
            source = getattr(finding, 'source_service', '')
            pillar = getattr(finding, 'pillar', '')
            if hasattr(pillar, 'value'):
                pillar = pillar.value
            recommendation = getattr(finding, 'recommendation', '')[:150]
            
            finding_data = [
                [Paragraph(f"<b>{idx}. {title}</b>", styles['FindingTitle'])],
                [Paragraph(f"<b>Source:</b> {source} | <b>Pillar:</b> {pillar}", styles['FindingDesc'])],
                [Paragraph(f"<b>Description:</b> {description}", styles['FindingDesc'])],
            ]
            
            if recommendation:
                finding_data.append([Paragraph(f"<b>Recommendation:</b> {recommendation}", styles['FindingDesc'])])
            
            finding_table = Table(finding_data, colWidths=[6*inch])
            finding_table.setStyle(TableStyle([
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('BACKGROUND', (0, 0), (-1, -1), Colors.SECTION_BG),
                ('BOX', (0, 0), (-1, -1), 1, color),
            ]))
            
            elements.append(finding_table)
            elements.append(Spacer(1, 10))
        
        if len(severity_findings) > 10:
            elements.append(Paragraph(
                f"<i>...and {len(severity_findings) - 10} more {severity.lower()} findings</i>",
                styles['FindingDesc']
            ))
        
        elements.append(Spacer(1, 15))
    
    elements.append(PageBreak())
    
    return elements


def build_recommendations_section(assessment, styles) -> List:
    """Build recommendations roadmap section"""
    elements = []
    
    elements.append(Paragraph("Recommendations Roadmap", styles['SectionHeader']))
    elements.append(HRFlowable(width="100%", thickness=2, color=Colors.AWS_ORANGE, spaceAfter=20))
    
    elements.append(Paragraph(
        "Based on the findings, here are the recommended actions prioritized by impact and urgency:",
        styles['BodyText']
    ))
    elements.append(Spacer(1, 15))
    
    findings = getattr(assessment, 'findings', [])
    
    # Immediate actions (Critical + High)
    critical_findings = [f for f in findings if getattr(f, 'severity', '') == 'CRITICAL']
    high_findings = [f for f in findings if getattr(f, 'severity', '') == 'HIGH']
    
    if critical_findings or high_findings:
        elements.append(Paragraph(
            "<b>🚨 Immediate Actions (0-30 days)</b>",
            styles['SubsectionHeader']
        ))
        
        immediate_items = []
        for f in (critical_findings + high_findings)[:5]:
            rec = getattr(f, 'recommendation', '') or getattr(f, 'title', '')
            if rec:
                immediate_items.append(ListItem(Paragraph(rec[:100], styles['BodyText'])))
        
        if immediate_items:
            elements.append(ListFlowable(immediate_items, bulletType='bullet', leftIndent=20))
        
        elements.append(Spacer(1, 15))
    
    # Short-term actions (Medium)
    medium_findings = [f for f in findings if getattr(f, 'severity', '') == 'MEDIUM']
    
    if medium_findings:
        elements.append(Paragraph(
            "<b>⚡ Short-term Actions (30-90 days)</b>",
            styles['SubsectionHeader']
        ))
        
        short_term_items = []
        for f in medium_findings[:5]:
            rec = getattr(f, 'recommendation', '') or getattr(f, 'title', '')
            if rec:
                short_term_items.append(ListItem(Paragraph(rec[:100], styles['BodyText'])))
        
        if short_term_items:
            elements.append(ListFlowable(short_term_items, bulletType='bullet', leftIndent=20))
        
        elements.append(Spacer(1, 15))
    
    # Cost optimization
    cost_findings = [f for f in findings if hasattr(f, 'estimated_savings') and f.estimated_savings > 0]
    
    if cost_findings:
        elements.append(Paragraph(
            "<b>💰 Cost Optimization Opportunities</b>",
            styles['SubsectionHeader']
        ))
        
        total_savings = sum(f.estimated_savings for f in cost_findings)
        elements.append(Paragraph(
            f"Total potential annual savings: <b>${total_savings:,.2f}</b>",
            styles['BodyText']
        ))
        
        elements.append(Spacer(1, 10))
        
        cost_data = [['Opportunity', 'Est. Savings/Year']]
        for f in sorted(cost_findings, key=lambda x: x.estimated_savings, reverse=True)[:5]:
            cost_data.append([
                getattr(f, 'title', 'Opportunity')[:50],
                f"${f.estimated_savings:,.2f}"
            ])
        
        cost_table = Table(cost_data, colWidths=[4*inch, 1.5*inch])
        cost_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(cost_table)
    
    return elements


def build_resource_inventory_section(assessment, styles) -> List:
    """Build resource inventory section"""
    elements = []
    
    elements.append(PageBreak())
    elements.append(Paragraph("Resource Inventory", styles['SectionHeader']))
    elements.append(HRFlowable(width="100%", thickness=2, color=Colors.AWS_ORANGE, spaceAfter=20))
    
    inventory = getattr(assessment, 'inventory', None)
    
    if not inventory:
        elements.append(Paragraph("Resource inventory not available.", styles['BodyText']))
        return elements
    
    # Compute resources
    compute_data = [
        ['Resource Type', 'Count', 'Notes'],
        ['EC2 Instances', str(getattr(inventory, 'ec2_instances', 0)), 
         f"{getattr(inventory, 'ec2_running', 0)} running"],
        ['Lambda Functions', str(getattr(inventory, 'lambda_functions', 0)), ''],
        ['EKS Clusters', str(getattr(inventory, 'eks_clusters', 0)), ''],
        ['Load Balancers', str(getattr(inventory, 'load_balancers', 0)), ''],
    ]
    
    elements.append(Paragraph("<b>Compute Resources</b>", styles['SubsectionHeader']))
    
    compute_table = Table(compute_data, colWidths=[2.5*inch, 1*inch, 2*inch])
    compute_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_LIGHT),
        ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(compute_table)
    elements.append(Spacer(1, 20))
    
    # Storage/Database
    storage_data = [
        ['Resource Type', 'Count', 'Notes'],
        ['S3 Buckets', str(getattr(inventory, 's3_buckets', 0)),
         f"{getattr(inventory, 's3_public', 0)} public"],
        ['RDS Databases', str(getattr(inventory, 'rds_instances', 0)),
         f"{getattr(inventory, 'rds_multi_az', 0)} Multi-AZ"],
        ['EBS Volumes', str(getattr(inventory, 'ebs_volumes', 0)),
         f"{getattr(inventory, 'ebs_unattached', 0)} unattached"],
        ['DynamoDB Tables', str(getattr(inventory, 'dynamodb_tables', 0)), ''],
    ]
    
    elements.append(Paragraph("<b>Storage & Database</b>", styles['SubsectionHeader']))
    
    storage_table = Table(storage_data, colWidths=[2.5*inch, 1*inch, 2*inch])
    storage_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_LIGHT),
        ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(storage_table)
    elements.append(Spacer(1, 20))
    
    # Security/IAM
    iam_data = [
        ['Resource Type', 'Count', 'Notes'],
        ['IAM Users', str(getattr(inventory, 'iam_users', 0)),
         f"{getattr(inventory, 'iam_users_no_mfa', 0)} without MFA"],
        ['IAM Roles', str(getattr(inventory, 'iam_roles', 0)), ''],
        ['VPCs', str(getattr(inventory, 'vpcs', 0)), ''],
    ]
    
    elements.append(Paragraph("<b>Security & Networking</b>", styles['SubsectionHeader']))
    
    iam_table = Table(iam_data, colWidths=[2.5*inch, 1*inch, 2*inch])
    iam_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), Colors.AWS_LIGHT),
        ('TEXTCOLOR', (0, 0), (-1, 0), Colors.WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, Colors.LIGHT_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    elements.append(iam_table)
    
    return elements


# ============================================================================
# MAIN GENERATOR
# ============================================================================

def generate_waf_pdf_report(assessment: LandscapeAssessment, 
                           filename: str = None,
                           include_findings: bool = True,
                           include_inventory: bool = True) -> bytes:
    """
    Generate a comprehensive PDF report from WAF assessment
    
    Args:
        assessment: LandscapeAssessment object with scan results
        filename: Optional filename to save to (if None, returns bytes)
        include_findings: Whether to include detailed findings section
        include_inventory: Whether to include resource inventory section
    
    Returns:
        PDF file as bytes
    """
    
    # Create buffer
    buffer = BytesIO()
    
    # Create document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=1*inch,
        bottomMargin=0.75*inch
    )
    
    # Get styles
    styles = get_custom_styles()
    
    # Build document elements
    elements = []
    
    # Cover page
    elements.extend(build_cover_page(assessment, styles))
    
    # Executive summary
    elements.extend(build_executive_summary(assessment, styles))
    
    # Pillar scores
    elements.extend(build_pillar_scores_section(assessment, styles))
    
    # Detailed findings
    if include_findings:
        elements.extend(build_findings_section(assessment, styles))
    
    # Recommendations
    elements.extend(build_recommendations_section(assessment, styles))
    
    # Resource inventory
    if include_inventory:
        elements.extend(build_resource_inventory_section(assessment, styles))
    
    # Build PDF
    doc.build(elements, onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    
    # Get bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    # Save to file if filename provided
    if filename:
        with open(filename, 'wb') as f:
            f.write(pdf_bytes)
    
    return pdf_bytes


# Export
__all__ = [
    'generate_waf_pdf_report',
    'Colors',
    'get_custom_styles'
]
