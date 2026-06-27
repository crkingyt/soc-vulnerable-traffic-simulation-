from datetime import datetime, timezone
from database import Database

async def create_incident(attack_type: str, severity: str, status: str = "Open", notes: str = None, analyst: str = None, alert_ids: list = None) -> int:
    """
    Creates a new incident record in the database, associates it with alerts, and flags alerts as Escalated.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    incident_id = await Database.insert("""
        INSERT INTO incidents (attack_type, severity, status, analyst_notes, assigned_analyst, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (attack_type, severity, status, notes, analyst, now, now))
    
    if alert_ids:
        for alert_id in alert_ids:
            await Database.insert("""
                INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id)
                VALUES (?, ?)
            """, (incident_id, alert_id))
            
            # Escalate alert status
            await Database.execute("""
                UPDATE alerts SET status = 'Escalated' WHERE id = ?
            """, (alert_id,))
            
    return incident_id

async def get_all_incidents() -> list:
    """
    Retrieve all incidents, attaching their mapped alert metadata.
    """
    rows = await Database.execute("""
        SELECT id, attack_type, severity, status, analyst_notes, assigned_analyst, created_at, updated_at
        FROM incidents ORDER BY id DESC
    """)
    incidents = []
    for r in rows:
        inc = dict(r)
        alert_rows = await Database.execute("""
            SELECT a.id, a.timestamp, a.source_ip, a.threat_score, a.severity, a.attack_type 
            FROM alerts a
            JOIN incident_alerts ia ON a.id = ia.alert_id
            WHERE ia.incident_id = ?
        """, (inc["id"],))
        inc["alerts"] = [dict(ar) for ar in alert_rows]
        incidents.append(inc)
    return incidents

async def update_incident(incident_id: int, status: str = None, notes: str = None, analyst: str = None) -> bool:
    """
    Updates status, notes, and analyst assignments on an existing incident.
    """
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    updates = []
    params = []
    
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if notes is not None:
        updates.append("analyst_notes = ?")
        params.append(notes)
    if analyst is not None:
        updates.append("assigned_analyst = ?")
        params.append(analyst)
        
    if not updates:
        return False
        
    updates.append("updated_at = ?")
    params.append(now)
    params.append(incident_id)
    
    query = f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?"
    await Database.execute(query, tuple(params))
    return True
