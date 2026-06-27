import os
import asyncio
import json
import uuid
from io import BytesIO
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from database import Database
from log_collector import LogCollector, register_callback
from response import block_ip, unblock_ip
from threat_intel import check_ip
from hunting import hunt_events
from incident import create_incident, get_all_incidents, update_incident
from report import get_report_data, generate_csv_report, generate_json_report, generate_pdf_report, get_offline_report_data

from log_upload import (
    UPLOAD_DIR,
    detect_log_format,
    detect_file_encoding,
    create_upload_job,
    process_offline_log_task
)

app = FastAPI(title="SOC/SOAR Platform Backend API")

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"[WS] Active websocket connection accepted. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[WS] Websocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        msg_str = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(msg_str)
            except Exception:
                disconnected.append(connection)
                
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

# Register log collector callback to pipe parsed logs & alerts directly to websockets
async def ws_broadcast_handler(event_type: str, data: dict):
    await manager.broadcast({
        "event_type": event_type, # 'log' or 'alert'
        "data": data
    })

register_callback(ws_broadcast_handler)

# Startup & Shutdown lifecycle hooks
log_collector = None

@app.on_event("startup")
async def startup_event():
    global log_collector
    # Initialize DB tables
    await Database.init_db()
    
    # Instantiate and start log watcher
    apache_log = os.getenv("LOG_APACHE_PATH", "../docker/logs/apache/access.log")
    iis_log = os.getenv("LOG_IIS_PATH", "../docker/logs/iis/access.log")
    
    loop = asyncio.get_event_loop()
    log_collector = LogCollector(apache_log, iis_log)
    log_collector.start(loop)

@app.on_event("shutdown")
def shutdown_event():
    if log_collector:
        log_collector.stop()

# --- API ENDPOINTS ---

@app.post("/api/config")
async def update_simulator_config(config: dict):
    """
    Updates simulator's live_config.json state from dashboard.
    """
    eps = config.get("eps")
    vp = config.get("vulnerable_percent")
    is_run = config.get("is_running", True)
    
    # Resolve config path relative to backend
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../simulation/live_config.json"))
    
    try:
        # Create directories if missing
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as f:
            json.dump({
                "eps": eps,
                "vulnerable_percent": vp,
                "is_running": is_run
            }, f, indent=4)
        return {"status": "success", "config": config}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")

@app.post("/api/start")
async def start_simulator():
    """
    Fires instruction to resume simulator requests.
    """
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../simulation/live_config.json"))
    config = {"eps": 10, "vulnerable_percent": 5.0, "is_running": True}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except Exception:
            pass
    config["is_running"] = True
    
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        return {"status": "success", "message": "Simulation started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stop")
async def stop_simulator():
    """
    Fires instruction to halt/pause simulator loop.
    """
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../simulation/live_config.json"))
    config = {"eps": 10, "vulnerable_percent": 5.0, "is_running": False}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except Exception:
            pass
    config["is_running"] = False
    
    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=4)
        return {"status": "success", "message": "Simulation stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/metrics")
async def get_dashboard_metrics():
    """
    Return cumulative metrics for dashboard indicators.
    """
    # Total events
    total_events_rows = await Database.execute("SELECT COUNT(1) as cnt FROM normalized_events")
    total_events = total_events_rows[0]["cnt"] if total_events_rows else 0
    
    # Blocked count
    blocked_rows = await Database.execute("SELECT COUNT(1) as cnt FROM blocked_ips")
    blocked_ips = blocked_rows[0]["cnt"] if blocked_rows else 0
    
    # Severity distribution
    sev_rows = await Database.execute("SELECT severity, COUNT(1) as cnt FROM alerts GROUP BY severity")
    sev_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in sev_rows:
        if r["severity"] in sev_dist:
            sev_dist[r["severity"]] = r["cnt"]
            
    # True vs False positives
    tp_rows = await Database.execute("SELECT COUNT(1) as cnt FROM alerts WHERE status IN ('Active', 'Escalated')")
    true_positives = tp_rows[0]["cnt"] if tp_rows else 0
    
    fp_rows = await Database.execute("SELECT COUNT(1) as cnt FROM alerts WHERE status = 'Dismissed'")
    false_positives = fp_rows[0]["cnt"] if fp_rows else 0
    
    # Attack type distribution
    attack_rows = await Database.execute("SELECT attack_type, COUNT(1) as cnt FROM alerts GROUP BY attack_type")
    attack_dist = {r["attack_type"]: r["cnt"] for r in attack_rows}
    
    # Top IPs
    top_ip_rows = await Database.execute("""
        SELECT source_ip, COUNT(1) as cnt 
        FROM alerts GROUP BY source_ip ORDER BY cnt DESC LIMIT 5
    """)
    top_ips = [{"ip": r["source_ip"], "count": r["cnt"]} for r in top_ip_rows]
    
    # Simulator states
    eps = 10
    vulnerable_percent = 5.0
    is_sim_running = False
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../simulation/live_config.json"))
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                cfg = json.load(f)
                eps = cfg.get("eps", 10)
                vulnerable_percent = cfg.get("vulnerable_percent", 5.0)
                is_sim_running = cfg.get("is_running", False)
        except Exception:
            pass
            
    return {
        "total_events": total_events,
        "current_eps": eps if is_sim_running else 0,
        "alerts_count": sum(sev_dist.values()),
        "severity_distribution": sev_dist,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "blocked_ips": blocked_ips,
        "attack_distribution": attack_dist,
        "top_attacking_ips": top_ips,
        "is_simulation_running": is_sim_running,
        "simulator_eps": eps,
        "vulnerable_percent": vulnerable_percent,
        "blocked_ips_list": [dict(r) for r in await Database.execute("SELECT ip, timestamp, reason, threat_score, blocked_by FROM blocked_ips ORDER BY timestamp DESC")],
        "top_mitre_techniques": [{"technique_id": r["mitre_id"], "attack_type": r["attack_type"], "count": r["cnt"]} for r in await Database.execute("SELECT mitre_id, attack_type, COUNT(1) as cnt FROM alerts GROUP BY mitre_id, attack_type ORDER BY cnt DESC LIMIT 5")]
    }

@app.get("/api/health")
async def get_system_health():
    import socket
    
    # 1. Check Apache Server (port 80)
    apache_healthy = False
    try:
        with socket.create_connection(("127.0.0.1", 80), timeout=0.1):
            apache_healthy = True
    except Exception:
        # Fallback check for log file existence
        apache_healthy = os.path.exists(os.getenv("LOG_APACHE_PATH", "../docker/logs/apache/access.log"))
        
    # 2. Check IIS Server (port 8080)
    iis_healthy = False
    try:
        with socket.create_connection(("127.0.0.1", 8080), timeout=0.1):
            iis_healthy = True
    except Exception:
        # Fallback check for log file existence
        iis_healthy = os.path.exists(os.getenv("LOG_IIS_PATH", "../docker/logs/iis/access.log"))
        
    # 3. Check Log Collector status
    collector_healthy = False
    if log_collector and log_collector.observer and log_collector.observer.is_alive():
        collector_healthy = True
        
    # 4. Check Detection Engine
    detection_healthy = True  # Loaded in memory and running
    
    # 5. Check Response Engine
    response_healthy = True  # Active
    
    # 6. Check Database
    database_healthy = False
    try:
        await Database.execute("SELECT 1")
        database_healthy = True
    except Exception:
        pass
        
    return {
        "apache": apache_healthy,
        "iis": iis_healthy,
        "collector": collector_healthy,
        "detection": detection_healthy,
        "response": response_healthy,
        "database": database_healthy
    }

@app.get("/api/alerts")
async def get_alerts_history(
    severity: str = None,
    attack_type: str = None,
    source_ip: str = None,
    status: str = None,
    limit: int = 50,
    offset: int = 0
):
    """
    Paginated filter history of threat logs.
    """
    query = "SELECT id, timestamp, source_ip, server, attack_type, mitre_id, kill_chain_stage, severity, confidence, threat_score, raw_log, status FROM alerts WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if attack_type:
        query += " AND attack_type = ?"
        params.append(attack_type)
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if status:
        query += " AND status = ?"
        params.append(status)
        
    count_rows = await Database.execute(f"SELECT COUNT(1) as cnt FROM ({query})", tuple(params))
    total = count_rows[0]["cnt"] if count_rows else 0
    
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = await Database.execute(query, tuple(params))
    return {
        "total": total,
        "results": [dict(r) for r in rows]
    }

@app.post("/api/alerts/{id}/block")
async def manual_block_ip(id: int):
    """
    Trigger manual defensive block for an IP tied to a specified alert (live or offline).
    """
    is_offline = False
    rows = await Database.execute("SELECT source_ip, attack_type, threat_score FROM alerts WHERE id = ?", (id,))
    if not rows:
        rows = await Database.execute("SELECT source_ip, attack_type, threat_score FROM offline_alerts WHERE id = ?", (id,))
        is_offline = True
        
    if not rows:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    source_ip = rows[0]["source_ip"]
    attack_type = rows[0]["attack_type"]
    threat_score = rows[0]["threat_score"]
    
    reason = f"Manual analyst block: Alert ID {id} ({attack_type})"
    success = await block_ip(source_ip, reason, threat_score, blocked_by="analyst")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to execute block instruction")
        
    # Set status to Escalated
    if is_offline:
        await Database.execute("UPDATE offline_alerts SET status = 'Escalated' WHERE id = ?", (id,))
    else:
        await Database.execute("UPDATE alerts SET status = 'Escalated' WHERE id = ?", (id,))
    
    # Push change update to frontend
    await manager.broadcast({
        "event_type": "alert_update",
        "data": {"id": id, "status": "Escalated", "source_ip": source_ip, "blocked": True, "is_offline": is_offline}
    })
    
    return {"status": "success", "ip": source_ip}

@app.post("/api/alerts/{id}/dismiss")
async def dismiss_alert(id: int):
    """
    Dismiss alert as reviewed / false positive (live or offline).
    """
    is_offline = False
    rows = await Database.execute("SELECT id FROM alerts WHERE id = ?", (id,))
    if not rows:
        rows = await Database.execute("SELECT id FROM offline_alerts WHERE id = ?", (id,))
        is_offline = True
        
    if not rows:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    if is_offline:
        await Database.execute("UPDATE offline_alerts SET status = 'Dismissed' WHERE id = ?", (id,))
    else:
        await Database.execute("UPDATE alerts SET status = 'Dismissed' WHERE id = ?", (id,))
    
    await manager.broadcast({
        "event_type": "alert_update",
        "data": {"id": id, "status": "Dismissed", "is_offline": is_offline}
    })
    
    return {"status": "success"}

@app.post("/api/blocked-ips/{ip}/unblock")
async def manual_unblock_ip(ip: str):
    """
    Release system firewall rule and database entry for blocked IP.
    """
    success = await unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to release firewall rule")
    return {"status": "success", "ip": ip}

@app.post("/api/settings/purge")
async def purge_database_records():
    """
    Purges all logs, alerts, blocked IPs, and incidents from the database to reset it.
    """
    try:
        await Database.execute("DELETE FROM normalized_events")
        await Database.execute("DELETE FROM alerts")
        await Database.execute("DELETE FROM blocked_ips")
        await Database.execute("DELETE FROM incidents")
        await Database.execute("DELETE FROM incident_alerts")
        await Database.execute("DELETE FROM upload_jobs")
        await Database.execute("DELETE FROM offline_alerts")
        await Database.execute("DELETE FROM offline_analytics")
        return {"status": "success", "message": "Database reset completed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset database: {e}")

# --- INCIDENT ENDPOINTS ---

@app.get("/api/incidents")
async def list_incidents():
    return await get_all_incidents()

@app.post("/api/incidents")
async def add_incident(incident_data: dict):
    attack_type = incident_data.get("attack_type")
    severity = incident_data.get("severity")
    notes = incident_data.get("analyst_notes")
    analyst = incident_data.get("assigned_analyst")
    alert_ids = incident_data.get("alert_ids", [])
    
    inc_id = await create_incident(attack_type, severity, "Open", notes, analyst, alert_ids)
    return {"status": "success", "id": inc_id}

@app.post("/api/incidents/{id}/update")
async def edit_incident(id: int, updates: dict):
    status = updates.get("status")
    notes = updates.get("analyst_notes")
    analyst = updates.get("assigned_analyst")
    
    success = await update_incident(id, status, notes, analyst)
    return {"status": "success" if success else "no_changes"}

# --- FORENSICS & THREAT HUNTING ---

@app.get("/api/hunt")
async def hunt_forensic_logs(
    source_ip: str = None,
    uri: str = None,
    user_agent: str = None,
    attack_type: str = None,
    severity: str = None,
    start_time: str = None,
    end_time: str = None,
    limit: int = 50,
    offset: int = 0
):
    """
    Provides forensic search over historical log and alert records.
    """
    return await hunt_events(source_ip, uri, user_agent, attack_type, severity, start_time, end_time, limit, offset)

@app.get("/api/intel/{ip}")
async def get_threat_intel(ip: str):
    """
    Query reputation classification for specified IP.
    """
    return check_ip(ip)

# --- REPORTS EXPORTS ---

@app.get("/api/export")
async def export_logs(format: str, start_time: str = None, end_time: str = None, job_id: str = None):
    if job_id:
        alerts, blocked, incidents = await get_offline_report_data(job_id)
    else:
        alerts, blocked, incidents = await get_report_data(start_time, end_time)
    
    if format == "csv":
        csv_data = generate_csv_report(alerts)
        filename = f"soc_offline_alerts_{job_id}.csv" if job_id else "soc_alerts.csv"
        return StreamingResponse(
            iter([csv_data]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    elif format == "json":
        json_data = generate_json_report(alerts, blocked, incidents)
        filename = f"soc_offline_report_{job_id}.json" if job_id else "soc_report.json"
        return StreamingResponse(
            iter([json_data]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    elif format == "pdf":
        pdf_bytes = generate_pdf_report(alerts, blocked, incidents)
        filename = f"soc_offline_report_{job_id}.pdf" if job_id else "soc_report.pdf"
        return StreamingResponse(
            BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    else:
        raise HTTPException(status_code=400, detail="Format must be: pdf, csv, or json")

# --- OFFLINE LOG UPLOAD & ANALYTICS ENDPOINTS ---

@app.post("/api/upload/logs")
async def upload_log_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    format: str = Form("auto"),
    column_mapping: str = Form(None)
):
    # Create unique job ID
    job_id = str(uuid.uuid4())
    
    # Save path
    original_filename = file.filename
    job_dir = os.path.join(UPLOAD_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)
    file_path = os.path.join(job_dir, original_filename)
    
    # Save the file
    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
            size_bytes = len(content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {e}")
        
    # Detect encoding
    encoding = detect_file_encoding(file_path)
    
    # If format is auto, detect it
    format_name = format
    if not format_name or format_name == "auto":
        format_name, confidence = detect_log_format(file_path, encoding)
        
    # Parse custom column mapping JSON
    parsed_mapping = None
    if column_mapping:
        try:
            parsed_mapping = json.loads(column_mapping)
        except Exception:
            pass

    # Register upload job
    await create_upload_job(job_id, original_filename, format_name, size_bytes, file_path)
    
    # Run the background parsing task
    background_tasks.add_task(
        process_offline_log_task, 
        job_id, 
        file_path, 
        format_name, 
        parsed_mapping
    )
    
    return {
        "status": "success",
        "job_id": job_id,
        "filename": original_filename,
        "format": format_name,
        "size_bytes": size_bytes
    }

@app.get("/api/upload/{job_id}/status")
async def get_upload_status(job_id: str):
    rows = await Database.execute("""
        SELECT job_id, filename, format, size_bytes, uploaded_at, status, total_lines, total_alerts, completed_at 
        FROM upload_jobs WHERE job_id = ?
    """, (job_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Job not found")
        
    return dict(rows[0])

@app.get("/api/upload/{job_id}/results")
async def get_upload_results(job_id: str):
    # Fetch job details
    job_rows = await Database.execute("SELECT * FROM upload_jobs WHERE job_id = ?", (job_id,))
    if not job_rows:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = dict(job_rows[0])
    if job["status"] != "complete":
        return {"status": job["status"], "message": "Job is not completed yet"}
        
    # Fetch summary analytics
    analytics_rows = await Database.execute("SELECT summary_json FROM offline_analytics WHERE job_id = ?", (job_id,))
    summary = {}
    if analytics_rows:
        try:
            summary = json.loads(analytics_rows[0]["summary_json"])
        except Exception:
            pass
            
    # Fetch list of offline alerts
    alert_rows = await Database.execute("""
        SELECT id, timestamp, source_ip, method, uri, status_code, user_agent, server, 
               attack_type, severity, confidence, threat_score, mitre_technique, kill_chain_stage, status 
        FROM offline_alerts WHERE job_id = ? ORDER BY id DESC
    """, (job_id,))
    
    # Convert alerts to dictionary list
    alerts = [dict(r) for r in alert_rows]
    
    # For each alert, check if source IP is blocked in live blocked_ips
    blocked_ips_rows = await Database.execute("SELECT ip FROM blocked_ips")
    blocked_ips_set = {r["ip"] for r in blocked_ips_rows}
    for alert in alerts:
        alert["auto_blocked"] = alert["source_ip"] in blocked_ips_set
        
    return {
        "job": job,
        "summary": summary,
        "alerts": alerts
    }

@app.get("/api/upload/history")
async def get_upload_history():
    rows = await Database.execute("""
        SELECT job_id, filename, format, size_bytes, uploaded_at, status, total_lines, total_alerts, completed_at 
        FROM upload_jobs ORDER BY uploaded_at DESC
    """)
    return [dict(r) for r in rows]

@app.delete("/api/upload/{job_id}")
async def delete_upload_job(job_id: str):
    # Fetch job file path to clean up files
    rows = await Database.execute("SELECT file_path FROM upload_jobs WHERE job_id = ?", (job_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Job not found")
        
    file_path = rows[0]["file_path"]
    
    # Remove database entries manually
    await Database.execute("DELETE FROM offline_analytics WHERE job_id = ?", (job_id,))
    await Database.execute("DELETE FROM offline_alerts WHERE job_id = ?", (job_id,))
    await Database.execute("DELETE FROM upload_jobs WHERE job_id = ?", (job_id,))
    
    # Remove physical file and its directory
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        job_dir = os.path.dirname(file_path)
        if os.path.exists(job_dir):
            os.rmdir(job_dir)
    except Exception as e:
        print(f"[CLEANUP ERROR] Failed to clean up file path {file_path}: {e}")
        
    return {"status": "success", "message": f"Job {job_id} deleted successfully"}

# --- WEBSOCKET stream ---

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, listen for ping or control commands if any
            await websocket.receive_text()
            # Echo or process commands if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS] WebSocket error: {e}")
        manager.disconnect(websocket)
