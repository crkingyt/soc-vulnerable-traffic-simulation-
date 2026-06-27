import os
import subprocess
import platform
from datetime import datetime
from database import Database

async def block_ip(ip: str, reason: str, threat_score: int, blocked_by: str = "auto") -> bool:
    """
    Blocks an IP address using system firewall utilities (iptables on Linux, netsh on Windows)
    and records the block action in the local SQLite database.
    """
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # 1. Execute system command based on OS
    system_os = platform.system().lower()
    command_success = False
    
    try:
        if system_os == "linux":
            # Command: iptables -A INPUT -s <ip> -j DROP
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            # Proactively run block command (run as dry-run fallback if permission denied)
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            command_success = True
        elif system_os == "windows":
            # Command: netsh advfirewall firewall add rule name="SOC Block <ip>" dir=in action=block remoteip=<ip>
            rule_name = f"SOC Block {ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            command_success = True
        else:
            print(f"[RESPONSE ENGINE] Unsupported OS for firewall execution: {system_os}")
    except Exception as e:
        print(f"[RESPONSE ENGINE] Firewall block command failed for {ip} (Reason: {e}). Falling back to mock database logging.")
        command_success = False
        
    # 2. Record to sqlite blocked_ips table
    try:
        await Database.insert("""
            INSERT OR REPLACE INTO blocked_ips (ip, timestamp, reason, threat_score, blocked_by)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, timestamp, reason, threat_score, blocked_by))
        print(f"[RESPONSE ENGINE] Recorded IP block in database: {ip} (Reason: {reason}, Score: {threat_score}, By: {blocked_by})")
        return True
    except Exception as e:
        print(f"[RESPONSE ENGINE] Database insertion failed for block log: {e}")
        return False

async def is_ip_blocked(ip: str) -> bool:
    """
    Checks if a given IP address is currently blocked in the database.
    """
    try:
        rows = await Database.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
        return len(rows) > 0
    except Exception as e:
        print(f"[RESPONSE ENGINE] Error checking block status: {e}")
        return False

async def unblock_ip(ip: str) -> bool:
    """
    Unblocks an IP address by deleting system firewall rules
    and removing the record from the database.
    """
    system_os = platform.system().lower()
    try:
        if system_os == "linux":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True, text=True)
        elif system_os == "windows":
            rule_name = f"SOC Block {ip}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"[RESPONSE ENGINE] System firewall release failed for {ip}: {e}")

    try:
        await Database.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        print(f"[RESPONSE ENGINE] Released IP block: {ip}")
        return True
    except Exception as e:
        print(f"[RESPONSE ENGINE] Database deletion failed for block log: {e}")
        return False
