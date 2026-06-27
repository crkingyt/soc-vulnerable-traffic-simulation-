import os
import re
import csv
import json
import gzip
import uuid
import chardet
from datetime import datetime, timedelta
import asyncio

# Attempt importing python-magic, fallback to extension/header inspect if unavailable
try:
    import magic
except ImportError:
    magic = None

from database import Database
from normalizer import normalize_line
from detection import detect_attack
from mitre import get_mitre_mapping
from threat_intel import check_ip
from scoring import calculate_score

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../storage/uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Regex patterns for Syslog parsing
SYSLOG_3164_RE = re.compile(
    r'^<(\d+)>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$'
)
SYSLOG_5424_RE = re.compile(
    r'^<(\d+)>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+(.*)$'
)

def is_gzip_file(filepath):
    """
    Check for gzip magic bytes 1F 8B.
    """
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'\x1f\x8b'
    except Exception:
        return False

def detect_file_encoding(filepath):
    """
    Detect file encoding using chardet.
    """
    try:
        if is_gzip_file(filepath):
            with gzip.open(filepath, 'rb') as f:
                raw = f.read(10000)
        else:
            with open(filepath, 'rb') as f:
                raw = f.read(10000)
        result = chardet.detect(raw)
        return result.get('encoding') or 'utf-8'
    except Exception:
        return 'utf-8'

def detect_log_format(filepath, encoding):
    """
    Read the first 50 lines and auto-detect log format.
    Returns: (format_name, confidence)
    """
    lines = []
    try:
        opener = gzip.open if is_gzip_file(filepath) else open
        mode = 'rt' if is_gzip_file(filepath) else 'r'
        
        with opener(filepath, mode, encoding=encoding, errors='ignore') as f:
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                lines.append(line.strip())
    except Exception as e:
        print(f"[DETECT] Error reading lines for detection: {e}")
        return "apache", 0.5

    if not lines:
        return "apache", 0.5

    # 1. Check IIS W3C format (typically starts with comment lines like #Software, #Fields)
    iis_score = 0
    for line in lines:
        if line.startswith("#Fields:") or line.startswith("#Software:"):
            return "iis", 1.0
        # If it matches the standard W3C regex
        # Date Time ClientIP Method URI Status UserAgent
        parts = line.split()
        if len(parts) >= 6 and re.match(r'^\d{4}-\d{2}-\d{2}$', parts[0]) and re.match(r'^\d{2}:\d{2}:\d{2}$', parts[1]):
            iis_score += 1

    if iis_score > len(lines) * 0.5:
        return "iis", 0.9

    # 2. Check JSON / JSONL
    json_score = 0
    for line in lines:
        if line.startswith("{") and line.endswith("}"):
            try:
                json.loads(line)
                json_score += 1
            except Exception:
                pass
    if json_score > len(lines) * 0.5:
        return "json", 0.95

    # 3. Check Syslog
    syslog_score = 0
    for line in lines:
        if SYSLOG_3164_RE.match(line) or SYSLOG_5424_RE.match(line) or re.match(r'^<(\d+)>', line):
            syslog_score += 1
    if syslog_score > len(lines) * 0.5:
        return "syslog", 0.95

    # 4. Check CSV
    csv_score = 0
    # Try to sniff delimiter
    try:
        sample = "\n".join(lines[:5])
        dialect = csv.Sniffer().sniff(sample)
        if dialect.delimiter in [',', ';', '\t']:
            csv_score = 0.8
    except Exception:
        pass
    
    # 5. Check Apache CLF (Common/Combined Log Format)
    # 127.0.0.1 - - [25/Jun/2026:17:20:22 +0530] "GET /index.html HTTP/1.1" 200 45
    apache_score = 0
    from normalizer import APACHE_REGEX
    for line in lines:
        if APACHE_REGEX.match(line):
            apache_score += 1
    
    if apache_score > len(lines) * 0.5:
        return "apache", 0.95
        
    if csv_score > 0.5:
        return "csv", csv_score

    # Default fallback
    return "apache", 0.5

def parse_syslog_timestamp(ts_str):
    """
    Parse syslog timestamp strings into ISO format.
    E.g., "Oct 11 22:14:15" or "2003-10-11T22:14:15.003Z".
    """
    try:
        # Check if ISO format
        if "T" in ts_str:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).isoformat()
        
        # Else, RFC 3164 format (Oct 11 22:14:15) - Add current year
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
        # If timestamp is in future due to year wrap, subtract one year
        if dt > datetime.now():
            dt = dt.replace(year=current_year - 1)
        return dt.isoformat() + "Z"
    except Exception:
        return datetime.utcnow().isoformat() + "Z"

def parse_syslog_line(line):
    """
    Parse a syslog RFC 3164 / 5424 log line.
    """
    match = SYSLOG_5424_RE.match(line) or SYSLOG_3164_RE.match(line)
    if not match:
        return None
        
    pri = match.group(1)
    timestamp_str = match.group(2)
    source_ip = match.group(3)
    
    # The message body is the last match group
    message = match.group(len(match.groups()))
    
    # Parse syslog timestamp
    timestamp = parse_syslog_timestamp(timestamp_str)
    
    # Default values
    method = "GET"
    uri = "/"
    status_code = 200
    user_agent = "syslog-agent"
    
    # Check if message contains an embedded web request
    http_match = re.search(
        r'(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+HTTP/\d\.\d.*?(\d{3})', 
        message, 
        re.IGNORECASE
    )
    if http_match:
        method = http_match.group(1).upper()
        uri = http_match.group(2)
        status_code = int(http_match.group(3))
        
        # Extract user agent if in quotes in the message
        ua_match = re.search(r'"([^"]*?)"\s*$', message)
        if ua_match:
            user_agent = ua_match.group(1)
    else:
        # Fallback: treat the message content as URI for signature matches
        uri = message.strip()
        
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server": "syslog",
        "raw_log": line
    }

def parse_json_line(line):
    """
    Parse standard JSON log line.
    """
    try:
        data = json.loads(line)
    except Exception:
        return None
        
    # Standard mapping for common fields
    timestamp = (
        data.get("timestamp") or 
        data.get("time") or 
        data.get("@timestamp") or 
        datetime.utcnow().isoformat() + "Z"
    )
    source_ip = (
        data.get("source_ip") or 
        data.get("client_ip") or 
        data.get("ip") or 
        data.get("host") or 
        "127.0.0.1"
    )
    method = (data.get("method") or data.get("request_method") or "GET").upper()
    uri = data.get("uri") or data.get("url") or data.get("path") or "/"
    status_code = int(data.get("status_code") or data.get("status") or 200)
    user_agent = data.get("user_agent") or data.get("agent") or data.get("ua") or "-"
    server = data.get("server") or data.get("service") or "json_log"
    
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server": server,
        "raw_log": line
    }

def parse_csv_line(row, column_mapping):
    """
    Parse a CSV row based on column index or key mapping.
    column_mapping is a dict mapping standard schema keys to CSV headers/index.
    """
    # Required keys
    # timestamp, source_ip, method, uri, status_code, user_agent
    
    # Helper to resolve mapped column value
    def get_val(key, default):
        col = column_mapping.get(key)
        if col is None:
            return default
        try:
            # If map points to index
            idx = int(col)
            if idx < len(row):
                return row[idx]
        except ValueError:
            # If map points to dict key (handled outside if row is dict)
            if isinstance(row, dict):
                return row.get(col, default)
        return default

    # If row is list/tuple
    if isinstance(row, (list, tuple)):
        timestamp = get_val("timestamp", datetime.utcnow().isoformat() + "Z")
        source_ip = get_val("source_ip", "127.0.0.1")
        method = get_val("method", "GET").upper()
        uri = get_val("uri", "/")
        status_code = int(get_val("status_code", 200))
        user_agent = get_val("user_agent", "-")
    elif isinstance(row, dict):
        timestamp = row.get(column_mapping.get("timestamp"), datetime.utcnow().isoformat() + "Z")
        source_ip = row.get(column_mapping.get("source_ip"), "127.0.0.1")
        method = row.get(column_mapping.get("method"), "GET").upper()
        uri = row.get(column_mapping.get("uri"), "/")
        status_code = int(row.get(column_mapping.get("status_code"), 200))
        user_agent = row.get(column_mapping.get("user_agent"), "-")
    else:
        return None

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server": "csv_log",
        "raw_log": ",".join(map(str, row)) if isinstance(row, (list, tuple)) else str(row)
    }

async def create_upload_job(job_id, filename, format_name, size_bytes, file_path):
    """
    Inserts a new upload job record into SQLite.
    """
    uploaded_at = datetime.utcnow().isoformat() + "Z"
    await Database.insert("""
        INSERT INTO upload_jobs (job_id, filename, format, size_bytes, uploaded_at, status, file_path)
        VALUES (?, ?, ?, ?, ?, 'queued', ?)
    """, (job_id, filename, format_name, size_bytes, uploaded_at, file_path))

async def update_job_status(job_id, status, total_lines=0, total_alerts=0):
    """
    Updates the status and counts of an active job.
    """
    completed_at = None
    if status == 'complete':
        completed_at = datetime.utcnow().isoformat() + "Z"
        await Database.execute("""
            UPDATE upload_jobs 
            SET status = ?, total_lines = ?, total_alerts = ?, completed_at = ?
            WHERE job_id = ?
        """, (status, total_lines, total_alerts, completed_at, job_id))
    else:
        await Database.execute("""
            UPDATE upload_jobs 
            SET status = ?, total_lines = ?, total_alerts = ?
            WHERE job_id = ?
        """, (status, total_lines, total_alerts, job_id))

async def process_offline_log_task(job_id, file_path, format_name, column_mapping=None):
    """
    Asynchronous background worker that runs the full offline ingestion pipeline.
    """
    try:
        # Detect encoding
        encoding = detect_file_encoding(file_path)
        
        # Update status to 'detecting' / 'parsing'
        await update_job_status(job_id, 'parsing')
        
        opener = gzip.open if is_gzip_file(file_path) else open
        mode = 'rt' if is_gzip_file(file_path) else 'r'
        
        parsed_events = []
        
        # Read the entire log file line by line
        line_count = 0
        
        # For CSV format, we parse using python's csv reader
        if format_name == 'csv':
            with opener(file_path, mode, encoding=encoding, errors='ignore') as f:
                reader = csv.reader(f)
                header = next(reader, None) # Skip header or extract columns
                
                # If column_mapping is not provided, try to build default mapping from header
                if not column_mapping and header:
                    # Low case matching
                    col_map = {}
                    for i, col in enumerate(header):
                        col_l = col.lower()
                        if 'time' in col_l or 'date' in col_l:
                            col_map['timestamp'] = i
                        elif 'ip' in col_l or 'host' in col_l or 'client' in col_l:
                            col_map['source_ip'] = i
                        elif 'method' in col_l:
                            col_map['method'] = i
                        elif 'uri' in col_l or 'url' in col_l or 'path' in col_l:
                            col_map['uri'] = i
                        elif 'status' in col_l or 'code' in col_l:
                            col_map['status_code'] = i
                        elif 'agent' in col_l or 'ua' in col_l:
                            col_map['user_agent'] = i
                    column_mapping = col_map
                
                # If still empty, map positionally
                if not column_mapping:
                    column_mapping = {
                        "timestamp": 0, "source_ip": 1, "method": 2, 
                        "uri": 3, "status_code": 4, "user_agent": 5
                    }
                
                for row in reader:
                    line_count += 1
                    if not row:
                        continue
                    try:
                        event = parse_csv_line(row, column_mapping)
                        if event:
                            parsed_events.append(event)
                    except Exception as e:
                        print(f"[CSV PARSE] Line {line_count} error: {e}")
        else:
            # Parse line by line
            with opener(file_path, mode, encoding=encoding, errors='ignore') as f:
                for line in f:
                    line_count += 1
                    if not line.strip():
                        continue
                    
                    event = None
                    try:
                        if format_name == 'apache':
                            event = normalize_line(line, 'apache')
                        elif format_name == 'iis':
                            event = normalize_line(line, 'iis')
                        elif format_name == 'syslog':
                            event = parse_syslog_line(line)
                        elif format_name == 'json':
                            event = parse_json_line(line)
                            
                        if event:
                            parsed_events.append(event)
                    except Exception as e:
                        print(f"[PARSE ERROR] Line {line_count}: {e}")

        # Update lines count in SQLite
        await Database.execute("UPDATE upload_jobs SET total_lines = ? WHERE job_id = ?", (line_count, job_id))

        if not parsed_events:
            # Done, but empty/no events parsed
            await update_job_status(job_id, 'complete', total_lines=line_count, total_alerts=0)
            await save_analytics_summary(job_id, parsed_events, [])
            return

        # Chronological sorting for relative rolling frequency counts
        def parse_iso(ts):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception:
                return datetime.min
        
        parsed_events.sort(key=lambda ev: parse_iso(ev["timestamp"]))

        # Detection, scoring, mapping loop
        alerts = []
        
        # We track IP alert timestamps in memory to calculate log-relative frequency counts
        ip_alert_history = {} # source_ip -> list of datetimes
        
        for event in parsed_events:
            # Run detection rules
            attack_details = detect_attack(event)
            if not attack_details:
                continue
                
            attack_type = attack_details["attack_type"]
            severity = attack_details["severity"]
            confidence = attack_details["confidence"]
            
            # Map to MITRE
            mitre_mapping = get_mitre_mapping(attack_type)
            mitre_id = mitre_mapping["technique_id"]
            kill_chain_stage = mitre_mapping["kill_chain_stage"]
            
            # Check threat intelligence (mock/cache lookup)
            ti_details = check_ip(event["source_ip"])
            ti_matched = ti_details["matched"]
            
            # Log-relative 5-minute rolling frequency count
            evt_dt = parse_iso(event["timestamp"])
            if event["source_ip"] not in ip_alert_history:
                ip_alert_history[event["source_ip"]] = []
                
            # Filter history to keep only timestamps within the last 5 minutes of this log event
            cutoff = evt_dt - timedelta(minutes=5)
            ip_alert_history[event["source_ip"]] = [
                ts for ts in ip_alert_history[event["source_ip"]] if ts >= cutoff
            ]
            
            # Count and record
            freq_count = len(ip_alert_history[event["source_ip"]])
            ip_alert_history[event["source_ip"]].append(evt_dt)
            
            # Threat score
            threat_score = calculate_score(severity, mitre_id, ti_matched, freq_count)
            
            # Save offline alert to list
            alert_record = {
                "job_id": job_id,
                "timestamp": event["timestamp"],
                "source_ip": event["source_ip"],
                "method": event["method"],
                "uri": event["uri"],
                "status_code": event["status_code"],
                "user_agent": event["user_agent"],
                "server": event["server"],
                "attack_type": attack_type,
                "severity": severity,
                "confidence": confidence,
                "threat_score": threat_score,
                "mitre_technique": mitre_id,
                "kill_chain_stage": kill_chain_stage,
                "status": "Active"
            }
            alerts.append(alert_record)

        # Batch insert offline alerts into database
        if alerts:
            # We can use single executes or build a helper. SQLite requires values sequence.
            async with Database.get_connection() as conn:
                await conn.executemany("""
                    INSERT INTO offline_alerts (
                        job_id, timestamp, source_ip, method, uri, status_code, 
                        user_agent, server, attack_type, severity, confidence, 
                        threat_score, mitre_technique, kill_chain_stage, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    (
                        al["job_id"], al["timestamp"], al["source_ip"], al["method"],
                        al["uri"], al["status_code"], al["user_agent"], al["server"],
                        al["attack_type"], al["severity"], al["confidence"],
                        al["threat_score"], al["mitre_technique"], al["kill_chain_stage"],
                        al["status"]
                    ) for al in alerts
                ])
                await conn.commit()

        # Update job stats to complete
        await update_job_status(job_id, 'complete', total_lines=line_count, total_alerts=len(alerts))
        
        # Save analytics summary to DB
        await save_analytics_summary(job_id, parsed_events, alerts)
        
    except Exception as e:
        print(f"[JOB WORKER] Error in job {job_id}: {e}")
        await Database.execute("UPDATE upload_jobs SET status = 'failed' WHERE job_id = ?", (job_id,))

async def save_analytics_summary(job_id, parsed_events, alerts):
    """
    Aggregates threat analytics and saves to the offline_analytics table.
    """
    total_lines = len(parsed_events)
    total_alerts = len(alerts)
    
    # 1. Severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for al in alerts:
        sev = al["severity"]
        if sev in sev_counts:
            sev_counts[sev] += 1
            
    # 2. Attack type distribution
    attack_counts = {}
    for al in alerts:
        atk = al["attack_type"]
        attack_counts[atk] = attack_counts.get(atk, 0) + 1
        
    # 3. Top IPs by alert count
    ip_counts = {}
    for al in alerts:
        ip = al["source_ip"]
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(
        [{"ip": ip, "count": count} for ip, count in ip_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )[:10]
    
    # 4. Timeline distribution (hourly/daily buckets based on time span)
    timeline = []
    if alerts:
        # Group by date-hour "YYYY-MM-DD HH:00"
        time_buckets = {}
        for al in alerts:
            ts = al["timestamp"]
            # Extract "YYYY-MM-DD HH"
            bucket = ts[:13] + ":00" if len(ts) >= 13 else "Unknown"
            time_buckets[bucket] = time_buckets.get(bucket, 0) + 1
            
        timeline = sorted(
            [{"time": time, "count": count} for time, count in time_buckets.items()],
            key=lambda x: x["time"]
        )

    # 5. MITRE Kill Chain Coverage
    # Check which stages out of 7 were hit
    stages = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command and Control", "Actions on Objectives"]
    kill_chain_hit = {stage: False for stage in stages}
    for al in alerts:
        stage = al["kill_chain_stage"]
        if stage in kill_chain_hit:
            kill_chain_hit[stage] = True
            
    # 6. Highest scoring event
    highest_event = None
    if alerts:
        highest_event = max(alerts, key=lambda x: x["threat_score"])

    # 7. Recommended actions based on observed attack types
    recs = []
    observed_attacks = set(attack_counts.keys())
    for atk in observed_attacks:
        mapping = get_mitre_mapping(atk)
        recs.append({
            "attack_type": atk,
            "mitigation": mapping["mitigation"]
        })
        
    summary_data = {
        "total_lines": total_lines,
        "total_alerts": total_alerts,
        "detection_rate": round((total_alerts / total_lines * 100), 2) if total_lines > 0 else 0,
        "severity_distribution": sev_counts,
        "attack_distribution": attack_counts,
        "top_ips": top_ips,
        "timeline": timeline,
        "kill_chain_coverage": kill_chain_hit,
        "avg_threat_score": round(sum(al["threat_score"] for al in alerts) / total_alerts, 1) if total_alerts > 0 else 0,
        "highest_scoring_event": highest_event,
        "recommended_actions": recs,
        "unique_attackers": len(ip_counts)
    }
    
    generated_at = datetime.utcnow().isoformat() + "Z"
    await Database.execute("""
        INSERT OR REPLACE INTO offline_analytics (job_id, summary_json, generated_at)
        VALUES (?, ?, ?)
    """, (job_id, json.dumps(summary_data), generated_at))
