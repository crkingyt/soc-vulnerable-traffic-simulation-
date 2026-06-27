import asyncio
from database import Database
from normalizer import normalize_line
from detection import detect_attack
from scoring import calculate_score
from mitre import get_mitre_mapping
from threat_intel import check_ip
from mitre_predictor import predict_next_stage

async def run_tests():
    print("=== STARTING BACKEND LOG PROCESSING TESTS ===")
    
    # 1. DB Init Check
    print("\n[TEST 1] Initializing Database Schema...")
    await Database.init_db()
    print("Database Schema initialized successfully.")
    
    # Clean up previous tests
    await Database.execute("DELETE FROM normalized_events")
    await Database.execute("DELETE FROM alerts")
    await Database.execute("DELETE FROM blocked_ips")
    
    # 2. Apache Custom Log Parsing Test
    print("\n[TEST 2] Testing Apache log normalization...")
    apache_log = '192.168.1.10 127.0.0.1 - - [25/Jun/2026:17:20:22 +0530] "GET /search?q=%27%20OR%201%3D1%20-- HTTP/1.1" 200 45 "Mozilla/5.0"'
    event = normalize_line(apache_log, "apache")
    assert event is not None
    assert event["source_ip"] == "192.168.1.10"
    assert event["method"] == "GET"
    assert event["uri"] == "/search?q=%27%20OR%201%3D1%20--"
    assert event["status_code"] == 200
    assert event["server"] == "apache"
    print("Apache log parsed successfully:", event)
    
    # 3. Nginx W3C Log Parsing Test
    print("\n[TEST 3] Testing Nginx (IIS-mimic) log normalization...")
    nginx_log = "2026-06-25 11:51:22 10.10.10.5 POST /login 405 Mozilla/5.0 (Windows NT 10.0)"
    event_nginx = normalize_line(nginx_log, "iis")
    assert event_nginx is not None
    assert event_nginx["source_ip"] == "10.10.10.5"
    assert event_nginx["method"] == "POST"
    assert event_nginx["uri"] == "/login"
    assert event_nginx["status_code"] == 405
    assert event_nginx["server"] == "iis"
    print("Nginx log parsed successfully:", event_nginx)
    
    # 4. Detection engine test (SQLi)
    print("\n[TEST 4] Testing SQL Injection detection...")
    attack = detect_attack(event)
    assert attack is not None
    assert attack["attack_type"] == "SQL Injection"
    assert attack["severity"] == "Critical"
    print("SQLi Attack detected successfully:", attack)
    
    # 5. MITRE Mapping Test
    print("\n[TEST 5] Testing MITRE ATT&CK Mapping...")
    mapping = get_mitre_mapping(attack["attack_type"])
    assert mapping["technique_id"] == "T1190"
    assert mapping["kill_chain_stage"] == "Exploitation"
    print("MITRE Tactic mapped successfully:", mapping)
    
    # 6. Threat Intel Test
    print("\n[TEST 6] Testing Threat Intelligence lookup...")
    ti = check_ip(event["source_ip"])
    assert ti["matched"] is True
    assert ti["reputation_score"] == 85
    print("Threat Intel check matched successfully:", ti)
    
    # 7. Threat Score Test
    print("\n[TEST 7] Testing Threat Score Calculation...")
    score = calculate_score(attack["severity"], mapping["technique_id"], ti["matched"], frequency_count=2)
    # severity=Critical (40) + mitre (10) + TI (20) + frequency=2*5 (10) = 80
    assert score == 80
    print(f"Calculated Score: {score} (Expect: 80)")
    
    # 8. Prediction test
    print("\n[TEST 8] Testing Next Stage Predictor...")
    observed = ["Reconnaissance", "Exploitation"]
    predictions = predict_next_stage(observed)
    assert len(predictions) > 0
    assert predictions[0]["predicted_stage"] == "Credential Access"
    print("Next Stage predicted successfully:", predictions)
    
    print("\n=== ALL TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
