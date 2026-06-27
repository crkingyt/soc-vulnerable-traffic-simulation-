import os
import asyncio
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database import Database
from normalizer import normalize_line
from detection import detect_attack
from mitre import get_mitre_mapping
from threat_intel import check_ip
from scoring import calculate_score
from mitre_predictor import predict_next_stage
from response import block_ip, is_ip_blocked

# Global callbacks for websocket streaming
EVENT_CALLBACKS = []

def register_callback(cb):
    """
    Registers a callback function to handle broadcast events.
    """
    EVENT_CALLBACKS.append(cb)

async def broadcast_event(event_type: str, data: dict):
    """
    Broadcasts event data to all registered callbacks (e.g. WebSockets).
    """
    for cb in EVENT_CALLBACKS:
        try:
            await cb(event_type, data)
        except Exception as e:
            print(f"[COLLECTOR] Broadcast callback error: {e}")

async def process_log_line(line: str, server_type: str):
    """
    Core parsing, detection, scoring, mitre mapping, and block response pipeline.
    Runs on every newly written log entry.
    """
    # 1. Normalize the log entry
    event = normalize_line(line, server_type)
    if not event:
        return
        
    # 2. Insert normalized log into DB
    try:
        event_id = await Database.insert("""
            INSERT INTO normalized_events (timestamp, source_ip, method, uri, status_code, user_agent, server, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["timestamp"], event["source_ip"], event["method"], 
            event["uri"], event["status_code"], event["user_agent"], 
            event["server"], event["raw_log"]
        ))
        event["id"] = event_id
    except Exception as e:
        print(f"[COLLECTOR] DB Error saving normalized event: {e}")
        return
        
    # Stream raw log event to dashboard
    await broadcast_event("log", event)
    
    # 3. Run Detection signatures
    attack_details = detect_attack(event)
    if attack_details:
        attack_type = attack_details["attack_type"]
        severity = attack_details["severity"]
        confidence = attack_details["confidence"]
        
        # 4. Map to MITRE ATT&CK
        mitre_mapping = get_mitre_mapping(attack_type)
        mitre_id = mitre_mapping["technique_id"]
        kill_chain_stage = mitre_mapping["kill_chain_stage"]
        
        # 5. Check Threat Intel Feed
        ti_details = check_ip(event["source_ip"])
        ti_matched = ti_details["matched"]
        
        # 6. Calculate Frequency over rolling 5 minutes
        five_mins_ago = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z"
        freq_rows = await Database.execute("""
            SELECT COUNT(1) as cnt FROM alerts
            WHERE source_ip = ? AND timestamp >= ?
        """, (event["source_ip"], five_mins_ago))
        freq_count = freq_rows[0]["cnt"] if freq_rows else 0
        
        # 7. Threat Score Calculation
        threat_score = calculate_score(severity, mitre_id, ti_matched, freq_count)
        
        # 8. Automated Block verification
        already_blocked = await is_ip_blocked(event["source_ip"])
        auto_blocked = False
        
        if threat_score >= 80 and not already_blocked:
            reason = f"Auto-blocked: {attack_type} threat score {threat_score} >= 80"
            await block_ip(event["source_ip"], reason, threat_score, blocked_by="auto")
            auto_blocked = True
            
        # 9. Insert Alert in DB
        alert_data = {
            "timestamp": event["timestamp"],
            "source_ip": event["source_ip"],
            "server": event["server"],
            "attack_type": attack_type,
            "mitre_id": mitre_id,
            "kill_chain_stage": kill_chain_stage,
            "severity": severity,
            "confidence": confidence,
            "threat_score": threat_score,
            "raw_log": event["raw_log"],
            "status": "Active"
        }
        
        alert_id = await Database.insert("""
            INSERT INTO alerts (timestamp, source_ip, server, attack_type, mitre_id, kill_chain_stage, severity, confidence, threat_score, raw_log, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data["timestamp"], alert_data["source_ip"], alert_data["server"],
            alert_data["attack_type"], alert_data["mitre_id"], alert_data["kill_chain_stage"],
            alert_data["severity"], alert_data["confidence"], alert_data["threat_score"],
            alert_data["raw_log"], alert_data["status"]
        ))
        
        alert_data["id"] = alert_id
        alert_data["auto_blocked"] = auto_blocked or already_blocked
        
        # 10. Predict Next ATT&CK Stage (rolling 15 mins CKC stages)
        fifteen_mins_ago = (datetime.utcnow() - timedelta(minutes=15)).isoformat() + "Z"
        stage_rows = await Database.execute("""
            SELECT DISTINCT kill_chain_stage FROM alerts
            WHERE source_ip = ? AND timestamp >= ?
        """, (event["source_ip"], fifteen_mins_ago))
        observed_stages = [row["kill_chain_stage"] for row in stage_rows]
        
        alert_data["predictions"] = predict_next_stage(observed_stages)
        
        # Stream alert to dashboard
        await broadcast_event("alert", alert_data)

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, file_path: str, server_type: str, loop: asyncio.AbstractEventLoop):
        self.file_path = os.path.abspath(file_path)
        self.server_type = server_type
        self.loop = loop
        self.last_position = 0
        
        # Open file at the end to avoid parsing historical logs on startup
        if os.path.exists(self.file_path):
            self.last_position = os.path.getsize(self.file_path)

    def on_modified(self, event):
        if event.is_directory or os.path.abspath(event.src_path) != self.file_path:
            return
        self.read_new_lines()

    def read_new_lines(self):
        if not os.path.exists(self.file_path):
            return
            
        current_size = os.path.getsize(self.file_path)
        if current_size < self.last_position:
            # File rotated/cleared
            self.last_position = 0
            
        if current_size > self.last_position:
            with open(self.file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.last_position)
                lines = f.readlines()
                self.last_position = f.tell()
                for line in lines:
                    if line.strip():
                        # Thread-safe execution scheduling on main event loop
                        asyncio.run_coroutine_threadsafe(
                            process_log_line(line, self.server_type),
                            self.loop
                        )

class LogCollector:
    def __init__(self, apache_path: str, iis_path: str):
        self.apache_path = apache_path
        self.iis_path = iis_path
        self.observer = None

    def start(self, loop: asyncio.AbstractEventLoop):
        """
        Ensures log folders exist and schedules watchdog observer mappings.
        """
        # Create directories to prevent watchdog from raising schedule errors
        for path in [self.apache_path, self.iis_path]:
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
            # Create file if not exists
            if not os.path.exists(path):
                with open(path, "w"):
                    pass
                    
        self.observer = Observer()
        
        # Watch parent directory of logs
        apache_handler = LogFileHandler(self.apache_path, "apache", loop)
        iis_handler = LogFileHandler(self.iis_path, "iis", loop)
        
        self.observer.schedule(apache_handler, os.path.dirname(self.apache_path), recursive=False)
        self.observer.schedule(iis_handler, os.path.dirname(self.iis_path), recursive=False)
        
        self.observer.start()
        print(f"[COLLECTOR] Started watching Apache logs at {self.apache_path}")
        print(f"[COLLECTOR] Started watching IIS logs at {self.iis_path}")

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            print("[COLLECTOR] Stopped log watchers.")
