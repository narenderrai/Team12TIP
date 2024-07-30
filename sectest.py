import requests

# Configuration
base_url = 'http://127.0.0.1/login.php'  # Change this to the URL of your target application
test_pages = [
    "/admin",                      # Admin page without authentication
    "/.env",                       # Direct access to sensitive files
    "/"                            # Home page to check headers
]

def test_admin_access():
    url = f"{base_url}{test_pages[0]}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Security Misconfiguration: Admin page is accessible without authentication at {url}")
    else:
        print(f"Admin access test passed (URL: {url}).")

def test_sensitive_files_access():
    url = f"{base_url}{test_pages[1]}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Security Misconfiguration: Sensitive file .env is accessible at {url}")
    else:
        print(f"Sensitive files access test passed (URL: {url}).")

def test_security_headers():
    url = f"{base_url}{test_pages[2]}"
    response = requests.get(url)
    headers_to_check = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
    missing_headers = [header for header in headers_to_check if header not in response.headers]
    
    if missing_headers:
        print(f"Security Misconfiguration: Missing security headers {missing_headers} on {url}")
    else:
        print(f"Security headers are properly configured on {url}.")

def run_tests():
    print("Running security misconfiguration tests...")
    test_admin_access()
    test_sensitive_files_access()
    test_security_headers()

run_tests()
