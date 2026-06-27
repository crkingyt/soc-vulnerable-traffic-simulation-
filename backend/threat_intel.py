# Mock Threat Intelligence database for simulation purposes
KNOWN_THREATS = {
    "192.168.1.10": {
        "reputation_score": 85,
        "threat_classification": "Active Scanner / Botnet",
        "provider": "EmergingThreats IP Feed",
        "action": "Block Recommended"
    },
    "10.10.10.5": {
        "reputation_score": 95,
        "threat_classification": "Malware C2 Server",
        "provider": "AbuseIPDB Top 100",
        "action": "Block Immediately"
    },
    "172.16.1.20": {
        "reputation_score": 90,
        "threat_classification": "Known Vulnerability Exploiter",
        "provider": "AlienVault OTX",
        "action": "Block Recommended"
    },
    "203.0.113.15": {
        "reputation_score": 75,
        "threat_classification": "Brute Force Host",
        "provider": "Spamhaus DROP List",
        "action": "Monitor/Block"
    },
    "198.51.100.8": {
        "reputation_score": 60,
        "threat_classification": "Tor Exit Node",
        "provider": "TorProject List",
        "action": "Monitor"
    }
}

def check_ip(ip: str) -> dict:
    """
    Check an IP against the Threat Intelligence feed.
    Returns details containing reputation score (0-100), classification, and provider.
    """
    if ip in KNOWN_THREATS:
        return {
            "matched": True,
            "reputation_score": KNOWN_THREATS[ip]["reputation_score"],
            "threat_classification": KNOWN_THREATS[ip]["threat_classification"],
            "provider": KNOWN_THREATS[ip]["provider"],
            "action": KNOWN_THREATS[ip]["action"]
        }
    
    return {
        "matched": False,
        "reputation_score": 0,
        "threat_classification": "Clean / Unknown",
        "provider": "Public Resolver Check",
        "action": "Allow"
    }
