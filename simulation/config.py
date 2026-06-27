import os

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_CONFIG_PATH = os.path.join(BASE_DIR, "live_config.json")

# Default values
DEFAULT_EPS = 10
DEFAULT_VULNERABLE_PERCENT = 5.0

# Targets
TARGETS = {
    "apache": "http://localhost:8080",
    "iis": "http://localhost:8081"
}

# Validation helper
def validate_config(eps: int, vulnerable_percent: float):
    assert 2 <= eps <= 30, "EPS must be between 2 and 30"
    assert 2.0 <= vulnerable_percent <= 30.0, "Vulnerable percent must be between 2.0 and 30.0"
    assert vulnerable_percent % 0.5 == 0, "Vulnerable percent must be in steps of 0.5"
