import requests
from bs4 import BeautifulSoup

# DVWA URLs and Vulnerability Name
login_url = 'http://127.0.0.1/login.php'
logout_url = 'http://127.0.0.1/logout.php'
vulnerability_name = "Session Management Failure"

# Default admin credentials
credentials = {
    'username': 'admin',
    'password': 'password'
}

# Start a session and login
session = requests.Session()
initial_page = session.get(login_url)
initial_soup = BeautifulSoup(initial_page.text, 'html.parser')
user_token = initial_soup.find('input', {'name':'user_token'}).get('value')
credentials['Login'] = 'Login'
credentials['user_token'] = user_token

login_response = session.post(login_url, data=credentials)

# Check login success by searching for a logout link
if 'logout.php' in login_response.text:
    print("Logged in successfully with username: admin and password: password.")

# Capture session cookie for reuse
session_cookies = session.cookies.get_dict()

# Define additional cookies
additional_cookies = {
    'example_cookie': 'value',
    'test_mode': '1'
}

# Update session cookies with additional ones
session.cookies.update(additional_cookies)

# Perform actions with updated cookies
# Example: Accessing a protected page
protected_response = session.get('http://127.0.0.1/vulnerabilities/')
print("Accessed protected page with updated cookies.")

# Perform logout
session.get(logout_url)

# Attempt to access a protected page using old session cookie
reuse_session = requests.Session()
reuse_session.cookies.update(session_cookies)
test_response = reuse_session.get('http://127.0.0.1/vulnerabilities/')

if 'logout.php' in test_response.text:
    print(f"{vulnerability_name} detected - Session still valid after logout with cookies: {session_cookies}")
else:
    print(f"{vulnerability_name} - Session properly invalidated after logout.")
