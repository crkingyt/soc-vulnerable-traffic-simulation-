import asyncio
import json
import os
import random
import time
import httpx

from config import LIVE_CONFIG_PATH, DEFAULT_EPS, DEFAULT_VULNERABLE_PERCENT, TARGETS, validate_config
from traffic import generate_benign_request
from attackers import generate_attack_request

# State variables
current_eps = DEFAULT_EPS
vulnerable_percent = DEFAULT_VULNERABLE_PERCENT
is_running = False

def load_live_config():
    global current_eps, vulnerable_percent, is_running
    if os.path.exists(LIVE_CONFIG_PATH):
        try:
            with open(LIVE_CONFIG_PATH, "r") as f:
                data = json.load(f)
                eps = data.get("eps", DEFAULT_EPS)
                vp = data.get("vulnerable_percent", DEFAULT_VULNERABLE_PERCENT)
                running = data.get("is_running", True) # Default to true if config file is written
                
                # Validate before applying
                validate_config(eps, vp)
                current_eps = eps
                vulnerable_percent = vp
                is_running = running
        except Exception as e:
            # Fall back to defaults on parse/validation errors
            print(f"Error loading live config: {e}. Using defaults.")
    else:
        # If no config exists, initialize it as stopped/default
        is_running = False
        save_live_config()

def save_live_config():
    try:
        with open(LIVE_CONFIG_PATH, "w") as f:
            json.dump({
                "eps": current_eps,
                "vulnerable_percent": vulnerable_percent,
                "is_running": is_running
            }, f, indent=4)
    except Exception as e:
        print(f"Error saving live config: {e}")

from datetime import datetime

async def write_mock_log(target_name: str, request_data: dict, status_code: int = 200):
    now = datetime.utcnow()
    method = request_data["method"]
    path = request_data["path"]
    
    # Reconstruct query params for log uri
    params = request_data.get("params", {})
    if params:
        query_str = "&".join(f"{k}={v}" for k, v in params.items())
        path = f"{path}?{query_str}"
        
    ua = request_data.get("headers", {}).get("User-Agent", "Mozilla/5.0")
    xff = request_data.get("headers", {}).get("X-Forwarded-For", "-")
    
    # Resolve log path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if target_name == "apache":
        log_path = os.path.abspath(os.path.join(base_dir, "../docker/logs/apache/access.log"))
        time_str = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        log_line = f'{xff} 127.0.0.1 - - [{time_str}] "{method} {path} HTTP/1.1" {status_code} 1024 "{ua}"\n'
    else:
        log_path = os.path.abspath(os.path.join(base_dir, "../docker/logs/iis/access.log"))
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")
        client_ip = xff if xff != "-" else "127.0.0.1"
        log_line = f'{date_str} {time_str} {client_ip} {method} {path} {status_code} {ua}\n'
        
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Error writing fallback mock log: {e}")

async def send_request(client: httpx.AsyncClient, target_name: str, target_url: str, request_data: dict):
    method = request_data["method"]
    path = request_data["path"]
    params = request_data.get("params", {})
    data = request_data.get("data", {})
    headers = request_data.get("headers", {})
    
    url = f"{target_url}{path}"
    
    try:
        if method == "GET":
            response = await client.get(url, params=params, headers=headers, timeout=2.0)
        elif method == "POST":
            response = await client.post(url, data=data, headers=headers, timeout=2.0)
        else:
            return None
        
        # Log simulated output
        is_attack = "attack_type" in request_data
        log_type = f"[ATTACK: {request_data.get('attack_type')}]" if is_attack else "[BENIGN]"
        print(f"{log_type} -> {target_name.upper()} {method} {path} - Status: {response.status_code}")
        return response
    except Exception as e:
        # Fall back to writing mock log lines directly on localhost log path
        is_attack = "attack_type" in request_data
        log_type = f"[MOCK ATTACK: {request_data.get('attack_type')}]" if is_attack else "[MOCK BENIGN]"
        status_code = 200 if not is_attack else (404 if request_data.get("attack_type") == "Scan" else 401)
        
        await write_mock_log(target_name, request_data, status_code)
        return None

async def main_loop():
    global current_eps, vulnerable_percent, is_running
    
    # Enable HTTP client
    async with httpx.AsyncClient() as client:
        print("Simulator starting. Press Ctrl+C to exit.")
        while True:
            # Reload configuration dynamically on each iteration
            load_live_config()
            
            if not is_running:
                # Idle sleep when simulator is paused/stopped via dashboard
                await asyncio.sleep(1.0)
                continue
                
            start_time = time.perf_counter()
            
            # Send requests to both targets in parallel
            tasks = []
            for target_name, target_url in TARGETS.items():
                # Roll for benign vs attack
                is_attack = random.uniform(0, 100) < vulnerable_percent
                if is_attack:
                    request_data = generate_attack_request()
                else:
                    request_data = generate_benign_request()
                
                tasks.append(send_request(client, target_name, target_url, request_data))
            
            # Run concurrently
            await asyncio.gather(*tasks)
            
            # Calculate sleep duration to match desired EPS
            elapsed = time.perf_counter() - start_time
            desired_interval = 1.0 / current_eps
            sleep_time = max(0.0, desired_interval - elapsed)
            
            await asyncio.sleep(sleep_time)

if __name__ == "__main__":
    try:
        # Write default running config state on start so it can run immediately if executed manually
        is_running = True
        save_live_config()
        
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("Simulator stopped.")
