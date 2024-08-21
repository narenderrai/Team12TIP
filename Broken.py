import os
import subprocess
import re
import requests
from bs4 import BeautifulSoup

class DVWAAuthTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None

    def find_dvwa_container(self):
        """Finds the Docker container ID running DVWA."""
        try:
            # Use Docker CLI to find the DVWA container
            result = subprocess.run(
                ["docker", "ps", "--filter", "ancestor=vulnerables/web-dvwa", "--format", "{{.ID}}"],
                capture_output=True,
                text=True
            )
            container_id = result.stdout.strip()
            if container_id:
                print(f"Found DVWA container with ID: {container_id}")
                return container_id
            else:
                print("DVWA container not found.")
                return None
        except Exception as e:
            print(f"Error finding DVWA container: {e}")
            return None

    def copy_php_file_from_container(self, container_id, container_path, local_path):
        """Copies a PHP file from the Docker container to the local machine."""
        try:
            subprocess.run(
                ["docker", "cp", f"{container_id}:{container_path}", local_path],
                check=True
            )
            print(f"Copied {container_path} from container to {local_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error copying file from container: {e}")

    def analyze_php_code(self, php_code):
        """Analyzes PHP code for specific vulnerabilities related to authentication and prints them."""
        vulnerabilities = []

        # 1. Weak Passwords: Detect the use of md5 for hashing
        weak_password_pattern = re.compile(r"\$pass\s*=\s*md5\s*\(\s*\$[a-zA-Z_]+\s*\)\s*;")
        weak_password_vulns = weak_password_pattern.findall(php_code)
        if weak_password_vulns:
            for match in weak_password_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Weak password storage using md5 detected"))

        # 2. Session Fixation: Check if session IDs are regenerated after login
        session_fixation_pattern = re.compile(r"dvwaLogin\(\s*\$user\s*\);")
        session_fixation_vulns = session_fixation_pattern.findall(php_code)
        if session_fixation_vulns:
            for match in session_fixation_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Session fixation vulnerability: Session ID not regenerated after login"))

        # 3. Brute Force Vulnerability: Lack of account lockout or rate limiting
        brute_force_pattern = re.compile(r"if\s*\(.*mysqli_num_rows\(\s*\$result\s*\)\s*!=\s*1\s*\)")
        brute_force_vulns = brute_force_pattern.findall(php_code)
        if brute_force_vulns:
            # Assuming the code line to check the login failure
            for match in brute_force_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Potential brute force vulnerability: No lockout mechanism after failed login attempts"))

        # Print found vulnerabilities
        if vulnerabilities:
            print("[VULNERABILITIES FOUND]")
            for vuln, line_number, description in vulnerabilities:
                print(f"\n{description} at line {line_number}:\n{vuln.strip()}")
        else:
            print("[SECURE] No obvious authentication-related vulnerabilities found in PHP code.")

    def login(self, username, password):
        self.get_csrf_token()
        if not self.csrf_token:
            return False
        data = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': self.csrf_token
        }
        try:
            print(f"Attempting to login with username: {username}")
            response = self.session.post(f"{self.base_url}/login.php", data=data)
            response.raise_for_status()
            success = 'Welcome to Damn Vulnerable Web Application!' in response.text
            print(f"Login {'successful' if success else 'failed'}")
            return success
        except requests.RequestException as e:
            print(f"Error during login attempt: {e}")
            return False

    def get_csrf_token(self):
        try:
            print(f"Attempting to get CSRF token from {self.base_url}/login.php")
            response = self.session.get(f"{self.base_url}/login.php")
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                self.csrf_token = token_input['value']
                print(f"CSRF token obtained: {self.csrf_token}")
            else:
                print("CSRF token not found. HTML content:")
                print(response.text[:500])
                sys.exit(1)
        except requests.RequestException as e:
            print(f"Error accessing the login page: {e}")
            sys.exit(1)

    def test_weak_password(self):
        print("Testing weak passwords...")
        weak_passwords = ['password', '123456', 'admin']
        for password in weak_passwords:
            if self.login('admin', password):
                print(f"[VULNERABILITY] Weak password detected: 'admin' : '{password}'")
                return
        print("[SECURE] No common weak passwords detected")

    def test_brute_force_protection(self):
        print("Testing brute force protection...")
        username = 'admin'
        # Common weak passwords for brute force attempt
        passwords = ['wrongpass1', 'wrongpass2', 'wrongpass3', 'password']

        for password in passwords:
            success = self.login(username, password)
            if success:
                print(f"[VULNERABILITY] Brute force successful with password: {password}")
                return
        
        print("[SECURE] Brute force protection seems to be in place.")

    def test_session_fixation(self):
        print("Testing session fixation...")

        # Step 1: Start a session and get a session ID
        self.session.get(f"{self.base_url}/login.php")
        initial_session_id = self.session.cookies.get('PHPSESSID')
        print(f"Initial session ID: {initial_session_id}")

        # Step 2: Login with admin credentials
        if self.login('admin', 'password'):
            # Step 3: Check if session ID has changed
            new_session_id = self.session.cookies.get('PHPSESSID')
            print(f"New session ID after login: {new_session_id}")

            if initial_session_id == new_session_id:
                print("[VULNERABILITY] Session fixation possible: Session ID did not change after login.")
            else:
                print("[SECURE] Session fixation is not possible: Session ID changed after login.")
        else:
            print("Login failed during session fixation test.")

    def read_local_php_file(self, file_path):
        """Reads a local PHP file and returns its content."""
        try:
            with open(file_path, 'r') as file:
                return file.read()
        except FileNotFoundError:
            print(f"Error: File not found - {file_path}")
            return None
        except Exception as e:
            print(f"Error reading PHP file: {e}")
            return None

def main():
    base_url = "http://127.0.0.1"  # Adjust this to your DVWA URL
    print(f"Attempting to connect to DVWA at: {base_url}")
    
    tester = DVWAAuthTester(base_url)

    print("Testing for broken authentication vulnerabilities in DVWA...")

    # Find DVWA container and copy login.php to local
    container_id = tester.find_dvwa_container()
    if container_id:
        tester.copy_php_file_from_container(
            container_id, "/var/www/html/login.php", "login.php"
        )
        
    print("\nTest Case 1: Weak Password")
    tester.test_weak_password()

    print("\nTest Case 2: Brute Force Protection")
    tester.test_brute_force_protection()

    print("\nTest Case 3: Session Fixation")
    tester.test_session_fixation()

    print("\nTest Case 4: Analyze PHP Source for Vulnerabilities")
    php_source = tester.read_local_php_file('login.php')
    if php_source:
        tester.analyze_php_code(php_source)

if __name__ == "__main__":
    main()
