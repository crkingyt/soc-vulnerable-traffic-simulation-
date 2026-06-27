import re
from datetime import datetime

# Regex for Apache Custom Log: "%{X-Forwarded-For}i %h %l %u %t \"%r\" %>s %b \"%{User-Agent}i\""
# Example: "192.168.1.10 127.0.0.1 - - [25/Jun/2026:17:20:22 +0530] \"GET /index.html HTTP/1.1\" 200 45 \"Mozilla/5.0\""
APACHE_REGEX = re.compile(
    r'^(\S+) (\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d{3}) (\S+)(?: "(.*?)")?$'
)

# Regex for IIS-Nginx W3C Log: "$w3c_date $w3c_time $client_ip $request_method $request_uri $status $http_user_agent"
# Example: "2026-06-25 11:51:22 192.168.1.10 GET /index.html 200 Mozilla/5.0"
IIS_REGEX = re.compile(
    r'^(\S+) (\S+) (\S+) (\S+) (\S+) (\d{3}) (.*)$'
)

def parse_apache_timestamp(ts_str):
    # E.g. "25/Jun/2026:17:20:22 +0530" or "25/Jun/2026:17:20:22"
    try:
        # Check if there is timezone offset
        if " " in ts_str:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        else:
            dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
        return dt.astimezone().isoformat()
    except Exception:
        # Fallback to current time if parsing fails
        return datetime.utcnow().isoformat() + "Z"

def parse_iis_timestamp(date_str, time_str):
    # E.g. "2026-06-25" and "11:51:22"
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
        return dt.isoformat() + "Z"
    except Exception:
        return datetime.utcnow().isoformat() + "Z"

def parse_apache_line(line: str) -> dict:
    match = APACHE_REGEX.match(line.strip())
    if not match:
        return None
        
    xff = match.group(1)
    client_ip = match.group(2)
    timestamp = parse_apache_timestamp(match.group(5))
    request_line = match.group(6)
    status_code = int(match.group(7))
    user_agent = match.group(9) or "-"
    
    # Resolve source IP: use X-Forwarded-For if set and valid, else client IP
    source_ip = xff if (xff and xff != "-") else client_ip
    
    # Split request line
    method = "GET"
    uri = "/"
    parts = request_line.split()
    if len(parts) >= 2:
        method = parts[0]
        uri = parts[1]
        
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server": "apache",
        "raw_log": line.strip()
    }

def parse_iis_line(line: str) -> dict:
    match = IIS_REGEX.match(line.strip())
    if not match:
        return None
        
    date_str = match.group(1)
    time_str = match.group(2)
    source_ip = match.group(3)
    method = match.group(4)
    uri = match.group(5)
    status_code = int(match.group(6))
    user_agent = match.group(7)
    
    timestamp = parse_iis_timestamp(date_str, time_str)
    
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "user_agent": user_agent,
        "server": "iis",
        "raw_log": line.strip()
    }

def normalize_line(line: str, server_type: str) -> dict:
    if not line or line.strip() == "":
        return None
        
    # Ignore comments in W3C format (lines starting with #)
    if server_type == "iis" and line.strip().startswith("#"):
        return None
        
    try:
        if server_type == "apache":
            return parse_apache_line(line)
        elif server_type == "iis":
            return parse_iis_line(line)
    except Exception as e:
        print(f"Error normalizing line for server {server_type}: {e}")
        
    return None
