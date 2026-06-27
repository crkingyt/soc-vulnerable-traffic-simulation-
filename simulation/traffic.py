import random
from faker import Faker

fake = Faker()

# List of typical user agents to make requests look realistic
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
]

BENIGN_PATHS = [
    ("/", "GET"),
    ("/products", "GET"),
    ("/products/details", "GET"),
    ("/categories", "GET"),
    ("/about", "GET"),
    ("/contact", "GET"),
    ("/blog", "GET"),
    ("/blog/post", "GET"),
    ("/search", "GET"),
    ("/api/v1/status", "GET"),
    ("/login", "GET"),
    ("/login", "POST")
]

def generate_benign_request():
    path, method = random.choice(BENIGN_PATHS)
    
    # Generate headers
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": fake.url()
    }
    
    params = {}
    data = {}
    
    # Customize query params or body based on path
    if path == "/products/details":
        params["id"] = str(random.randint(1, 1000))
    elif path == "/categories":
        params["type"] = random.choice(["electronics", "books", "clothing", "home"])
    elif path == "/search":
        params["q"] = fake.word()
    elif path == "/blog/post":
        params["id"] = str(random.randint(1, 50))
    elif path == "/login" and method == "POST":
        # Realistic login attempt (not brute force frequency, just benign login request structure)
        data = {
            "username": fake.user_name(),
            "password": fake.password(length=10)
        }
        
    return {
        "method": method,
        "path": path,
        "params": params,
        "data": data,
        "headers": headers
    }
