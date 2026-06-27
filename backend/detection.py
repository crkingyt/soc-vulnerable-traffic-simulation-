import re

# Regex signatures
SQLI_RE = re.compile(
    r"(?i)('\s*OR\s*[^=]+=\s*[^=\s]+)|(UNION\s+(?:ALL\s+)?SELECT)|(SELECT\s+.*?\s+FROM)|(ORDER\s+BY\s+\d+)|(--)"
)

XSS_RE = re.compile(
    r"(?i)(<script.*?>)|(onerror\s*=)|(onload\s*=)|(javascript\s*:)|(<img\s+src\s*=)"
)

TRAVERSAL_RE = re.compile(
    r"(?i)(\.\./)|(\.\.\\)|(%2e%2e%2f)|(%2e%2e%5c)"
)

CMD_INJ_RE = re.compile(
    r"(?i)(;\s*(?:whoami|id|cat|ping|nslookup|ls|curl|wget|ipconfig))|(&&\s*(?:whoami|id|cat|ping|nslookup|ls|curl|wget|ipconfig))|(\|\s*(?:whoami|id|cat|ping|nslookup|ls|curl|wget))"
)

SCAN_PATH_RE = re.compile(
    r"(?i)(/\.env)|(/\.git)|(/wp-admin)|(/wp-login\.php)|(/config\.json)|(/phpinfo\.php)|(/setup\.sh)|(/backup\.sql)|(/admin)"
)

SCAN_UA_RE = re.compile(
    r"(?i)(sqlmap)|(nikto)|(nmap)|(gobuster)|(dirb)|(go-http-client)"
)

def detect_attack(event: dict) -> dict:
    uri = event.get("uri", "")
    ua = event.get("user_agent", "")
    method = event.get("method", "")
    
    # 1. Command Injection (Critical Execution Tactic)
    if CMD_INJ_RE.search(uri):
        return {
            "attack_type": "Command Injection",
            "severity": "Critical",
            "confidence": 95.0
        }
        
    # 2. SQL Injection (Critical Exploitation Tactic)
    if SQLI_RE.search(uri):
        return {
            "attack_type": "SQL Injection",
            "severity": "Critical",
            "confidence": 90.0
        }
        
    # 3. Cross-Site Scripting (XSS - High Severity)
    if XSS_RE.search(uri):
        return {
            "attack_type": "XSS",
            "severity": "High",
            "confidence": 85.0
        }
        
    # 4. Directory Traversal (High Severity Discovery)
    if TRAVERSAL_RE.search(uri):
        return {
            "attack_type": "Directory Traversal",
            "severity": "High",
            "confidence": 90.0
        }
        
    # 5. Scanning / Reconnaissance (Medium/High)
    is_scanner_ua = SCAN_UA_RE.search(ua)
    is_sensitive_path = SCAN_PATH_RE.search(uri)
    
    if is_scanner_ua and is_sensitive_path:
        return {
            "attack_type": "Web Scanning",
            "severity": "High",
            "confidence": 98.0
        }
    elif is_scanner_ua:
        return {
            "attack_type": "Web Scanning",
            "severity": "Medium",
            "confidence": 90.0
        }
    elif is_sensitive_path:
        return {
            "attack_type": "Web Scanning",
            "severity": "Medium",
            "confidence": 70.0
        }
        
    # 6. Brute Force (POST request to Login URLs)
    if method == "POST" and (uri == "/login" or uri == "/wp-login.php" or uri == "/api/login"):
        return {
            "attack_type": "Brute Force",
            "severity": "Medium",
            "confidence": 65.0
        }
        
    return None
