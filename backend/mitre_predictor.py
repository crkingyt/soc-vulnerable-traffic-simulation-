def predict_next_stage(observed_stages: list) -> list:
    """
    Predicts the next cyber kill chain stage based on observed stages for a given IP.
    Returns a ranked list of predictions with confidence scores.
    """
    stages = set(observed_stages)
    predictions = []
    
    # 1. Reconnaissance -> Delivery / Initial Access (T1190) - 78%
    if "Reconnaissance" in stages and len(stages) == 1:
        predictions.append({
            "predicted_stage": "Delivery",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "confidence": 78
        })
        predictions.append({
            "predicted_stage": "Weaponization",
            "technique_id": "T1587",
            "technique_name": "Develop Capabilities",
            "confidence": 45
        })
        
    # 2. Reconnaissance + Exploitation -> Credential Access (T1110) - 85%
    elif "Reconnaissance" in stages and "Exploitation" in stages and len(stages) == 2:
        predictions.append({
            "predicted_stage": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "confidence": 85
        })
        
    # 3. Brute Force + SQLi (Credential Access + Exploitation) -> Lateral Movement / Persistence (72%)
    # In terms of CKC stages: Credential Access (Weaponization/Delivery/Exploitation depending on mapping)
    elif ("Credential Access" in stages or "Brute Force" in stages) and "Exploitation" in stages:
        predictions.append({
            "predicted_stage": "Installation",
            "technique_id": "T1543",
            "technique_name": "Create or Modify System Process",
            "confidence": 72
        })
        
    # 4. Scanning + Traversal + Exploitation (Reconnaissance + Actions on Objectives + Exploitation) -> Data Exfiltration / C2 (88%)
    elif "Reconnaissance" in stages and "Actions on Objectives" in stages and "Exploitation" in stages:
        predictions.append({
            "predicted_stage": "Command & Control",
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "confidence": 88
        })
        
    # Default Predictor fallback rules
    else:
        if not stages:
            predictions.append({
                "predicted_stage": "Reconnaissance",
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "confidence": 30
            })
        elif "Reconnaissance" in stages:
            predictions.append({
                "predicted_stage": "Exploitation",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "confidence": 60
            })
        elif "Exploitation" in stages:
            predictions.append({
                "predicted_stage": "Actions on Objectives",
                "technique_id": "T1083",
                "technique_name": "File and Directory Discovery",
                "confidence": 55
            })
        else:
            predictions.append({
                "predicted_stage": "Actions on Objectives",
                "technique_id": "T1020",
                "technique_name": "Automated Exfiltration",
                "confidence": 40
            })
            
    # Format list and sort by confidence
    predictions.sort(key=lambda x: x["confidence"], reverse=True)
    return predictions
