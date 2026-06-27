from database import Database

async def hunt_events(
    source_ip: str = None,
    uri: str = None,
    user_agent: str = None,
    attack_type: str = None,
    severity: str = None,
    start_time: str = None,
    end_time: str = None,
    limit: int = 50,
    offset: int = 0
) -> dict:
    """
    Performs forensic search over normalized logs, left-joining alert data if matches exist.
    Supports filtering by IP, URI, User-Agent, Attack Type, Severity, and Date Range.
    """
    query = """
        SELECT e.id, e.timestamp, e.source_ip, e.method, e.uri, e.status_code, e.user_agent, e.server, e.raw_log,
               a.attack_type, a.severity, a.threat_score, a.status as alert_status, a.id as alert_id
        FROM normalized_events e
        LEFT JOIN alerts a ON e.timestamp = a.timestamp AND e.source_ip = a.source_ip
        WHERE 1=1
    """
    params = []
    
    if source_ip:
        query += " AND e.source_ip = ?"
        params.append(source_ip)
    if uri:
        query += " AND e.uri LIKE ?"
        params.append(f"%{uri}%")
    if user_agent:
        query += " AND e.user_agent LIKE ?"
        params.append(f"%{user_agent}%")
    if attack_type:
        query += " AND a.attack_type = ?"
        params.append(attack_type)
    if severity:
        query += " AND a.severity = ?"
        params.append(severity)
    if start_time:
        query += " AND e.timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND e.timestamp <= ?"
        params.append(end_time)
        
    # Get total count before limits
    count_query = f"SELECT COUNT(1) as total FROM ({query})"
    count_rows = await Database.execute(count_query, tuple(params))
    total_count = count_rows[0]["total"] if count_rows else 0
    
    # Apply pagination and sorting
    query += " ORDER BY e.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    rows = await Database.execute(query, tuple(params))
    
    return {
        "total": total_count,
        "results": [dict(r) for r in rows]
    }
