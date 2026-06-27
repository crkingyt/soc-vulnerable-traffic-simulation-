import json
import pandas as pd
from datetime import datetime
from io import BytesIO

# Reportlab imports
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from database import Database

async def get_report_data(start_time: str = None, end_time: str = None) -> tuple:
    """
    Fetch alerts, blocked IPs, and incidents from database for report generation.
    """
    alert_query = "SELECT timestamp, source_ip, server, attack_type, mitre_id, kill_chain_stage, severity, confidence, threat_score, status FROM alerts WHERE 1=1"
    block_query = "SELECT ip, timestamp, reason, threat_score, blocked_by FROM blocked_ips WHERE 1=1"
    incident_query = "SELECT id, attack_type, severity, status, assigned_analyst, created_at FROM incidents WHERE 1=1"
    
    params = []
    if start_time:
        alert_query += " AND timestamp >= ?"
        block_query += " AND timestamp >= ?"
        incident_query += " AND created_at >= ?"
        params.append(start_time)
    if end_time:
        alert_query += " AND timestamp <= ?"
        block_query += " AND timestamp <= ?"
        incident_query += " AND created_at <= ?"
        params.append(end_time)
        
    alerts = [dict(r) for r in await Database.execute(alert_query, tuple(params))]
    blocked_ips = [dict(r) for r in await Database.execute(block_query, tuple(params))]
    incidents = [dict(r) for r in await Database.execute(incident_query, tuple(params))]
    
    return alerts, blocked_ips, incidents

async def get_offline_report_data(job_id: str) -> tuple:
    """
    Fetch offline alerts, blocked IPs, and incidents associated with an offline analysis job.
    """
    alert_query = """
        SELECT timestamp, source_ip, server, attack_type, mitre_technique as mitre_id, 
               kill_chain_stage, severity, confidence, threat_score, status 
        FROM offline_alerts 
        WHERE job_id = ?
    """
    block_query = """
        SELECT ip, timestamp, reason, threat_score, blocked_by 
        FROM blocked_ips 
        WHERE ip IN (SELECT DISTINCT source_ip FROM offline_alerts WHERE job_id = ?)
    """
    alerts = [dict(r) for r in await Database.execute(alert_query, (job_id,))]
    blocked_ips = [dict(r) for r in await Database.execute(block_query, (job_id,))]
    incidents = []  # No live incidents are linked directly in DB for offline runs unless escalated
    
    return alerts, blocked_ips, incidents

def generate_csv_report(alerts: list) -> str:
    """
    Exports a flat CSV alert log list using pandas.
    """
    if not alerts:
        return pd.DataFrame().to_csv(index=False)
        
    df = pd.DataFrame(alerts)
    return df.to_csv(index=False)

def generate_json_report(alerts: list, blocked_ips: list, incidents: list) -> str:
    """
    Exports structured JSON data of the entire SOC state.
    """
    report_data = {
        "report_generated_at": datetime.utcnow().isoformat() + "Z",
        "alerts_count": len(alerts),
        "blocked_ips_count": len(blocked_ips),
        "incidents_count": len(incidents),
        "alerts": alerts,
        "blocked_ips": blocked_ips,
        "incidents": incidents
    }
    return json.dumps(report_data, indent=4)

def generate_pdf_report(alerts: list, blocked_ips: list, incidents: list) -> bytes:
    """
    Builds a beautifully structured PDF document using reportlab.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=20
    )
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=14,
        spaceAfter=6
    )
    normal_style = styles['Normal']
    
    # Title
    story.append(Paragraph("Security Operations Center (SOC) Activity Report", title_style))
    story.append(Paragraph(f"Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    
    # 1. Metrics & Exec Summary
    story.append(Paragraph("1. Executive Summary", h2_style))
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        sev = a.get("severity")
        if sev in counts:
            counts[sev] += 1
            
    summary_text = (
        f"During the analyzed period, the threat monitoring dashboard detected <b>{len(alerts)}</b> total alerts "
        f"comprising <b>{counts['Critical']}</b> Critical, <b>{counts['High']}</b> High, "
        f"<b>{counts['Medium']}</b> Medium, and <b>{counts['Low']}</b> Low severity detections. "
        f"To mitigate these vulnerabilities, the response engine blocked <b>{len(blocked_ips)}</b> IP addresses "
        f"from further interaction, and security analysts opened <b>{len(incidents)}</b> formal incident records."
    )
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 10))
    
    # 2. Alerts Details Table
    story.append(Paragraph("2. Top Alerts (Limit 15)", h2_style))
    alert_headers = ["Timestamp", "Source IP", "Server", "Attack Type", "Severity", "Score"]
    alert_rows = [alert_headers]
    for a in alerts[:15]:
        # Strip timezone from timestamp for layout cleanliness
        ts_clean = a.get("timestamp")[:19].replace("T", " ")
        alert_rows.append([
            ts_clean,
            a.get("source_ip"),
            a.get("server").upper(),
            a.get("attack_type"),
            a.get("severity"),
            str(a.get("threat_score"))
        ])
        
    t_alerts = Table(alert_rows, colWidths=[110, 85, 55, 140, 75, 50])
    t_alerts.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 5),
        ('TOPPADDING', (0,0), (-1,0), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
    ]))
    story.append(t_alerts)
    story.append(Spacer(1, 10))
    
    # 3. Blocked IPs Table
    story.append(Paragraph("3. Active Defensive Blocks (Limit 10)", h2_style))
    block_headers = ["IP Address", "Timestamp", "Blocking Trigger / Reason", "Threat Score", "Blocked By"]
    block_rows = [block_headers]
    for b in blocked_ips[:10]:
        ts_clean = b.get("timestamp")[:19].replace("T", " ")
        block_rows.append([
            b.get("ip"),
            ts_clean,
            b.get("reason"),
            str(b.get("threat_score")),
            b.get("blocked_by").upper()
        ])
        
    t_blocks = Table(block_rows, colWidths=[90, 110, 180, 50, 85])
    t_blocks.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#475569')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 5),
        ('TOPPADDING', (0,0), (-1,0), 5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
    ]))
    story.append(t_blocks)
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
