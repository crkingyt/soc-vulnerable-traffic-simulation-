def calculate_score(severity: str, technique_id: str, ti_matched: bool, frequency_count: int) -> int:
    """
    Calculates a threat score from 0-100 based on severity, frequency, MITRE technique impact, and threat intel status.
    """
    # 1. Severity points (up to 40 pts)
    severity_map = {
        "Critical": 40,
        "High": 30,
        "Medium": 20,
        "Low": 10
    }
    severity_points = severity_map.get(severity, 10)
    
    # 2. Frequency points (up to 15 pts)
    # frequency_count represents events from the same IP in the last 5 minutes
    frequency_points = min(3, frequency_count) * 5
    
    # 3. MITRE impact points (up to 15 pts)
    # Higher-impact techniques like Execution (T1059) and C2 (T1071) add more weight
    high_impact_techniques = ["T1059", "T1083", "T1071"]
    mitre_points = 15 if technique_id in high_impact_techniques else 10
    
    # 4. Threat Intel match (20 pts)
    ti_points = 20 if ti_matched else 0
    
    # Total calculation
    total_score = severity_points + frequency_points + mitre_points + ti_points
    
    return min(100, max(0, total_score))
