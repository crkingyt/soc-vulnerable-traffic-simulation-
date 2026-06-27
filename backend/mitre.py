# Pre-populated MITRE ATT&CK Mapping
MITRE_MAP = {
    "SQL Injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "kill_chain_stage": "Exploitation",
        "description": "Attacker exploits a vulnerability in a public-facing application (SQL injection) to execute database queries or gain access.",
        "mitigation": "Use parameterized queries / prepared statements, apply input validation, and deploy a Web Application Firewall (WAF)."
    },
    "XSS": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "kill_chain_stage": "Exploitation",
        "description": "Attacker injects malicious scripts (JavaScript) into a trusted website, which are then executed in the victim's browser context.",
        "mitigation": "Implement context-aware output encoding, strict input validation, and enforce a strong Content Security Policy (CSP)."
    },
    "Directory Traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "kill_chain_stage": "Discovery",
        "description": "Attacker tries to browse directories outside the web server root to access sensitive files (like /etc/passwd or win.ini).",
        "mitigation": "Apply strict input sanitization, run the web service in a container/chroot jail, and restrict file access permissions."
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "kill_chain_stage": "Credential Access",
        "description": "Attacker systematically attempts combinations of usernames and passwords to gain unauthorized access to accounts.",
        "mitigation": "Enforce strong password complexity, implement rate limiting/CAPTCHA, enable account lockouts, and require Multi-Factor Authentication (MFA)."
    },
    "Command Injection": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "kill_chain_stage": "Execution",
        "description": "Attacker injects operating system commands through web application inputs to execute arbitrary system code.",
        "mitigation": "Avoid direct shell command execution, sanitize inputs with strict allowlists, and run services under low-privilege system accounts."
    },
    "Web Scanning": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "kill_chain_stage": "Reconnaissance",
        "description": "Attacker sends requests to map server resources, search for sensitive endpoints, and check for open vulnerabilities.",
        "mitigation": "Deploy rate limiting, inspect User-Agent strings, use threat intelligence feeds to block scanner IPs, and install a WAF."
    }
}

def get_mitre_mapping(attack_type: str) -> dict:
    """
    Get MITRE ATT&CK technique details, stage, description and recommended mitigation.
    """
    # Try to load mapping from local definition
    mapping = MITRE_MAP.get(attack_type)
    if mapping:
        return mapping
        
    return {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "kill_chain_stage": "Execution",
        "description": "Unclassified malicious activity matching generic interpreter execution.",
        "mitigation": "Monitor process execution and audit logs."
    }
