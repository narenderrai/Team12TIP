# DVWA Vulnerability Testing Scripts

These scripts are designed to detect vulnerabilities in the **Damn Vulnerable Web Application (DVWA)**. The scripts automate testing for broken authentication vulnerabilities and security misconfigurations related to file uploads.

## Scripts Overview

1. **DVWAAuthTester.py**:
   - Focuses on testing for authentication-related vulnerabilities.
   - Tests for issues such as weak passwords, lack of brute force protection, and session fixation vulnerabilities.
   - Analyzes PHP source code to detect common vulnerabilities.

2. **SecurityMisconfigurationTester.py**:
   - Focuses on testing for security misconfigurations related to file uploads.
   - Tests for issues such as improper file type validation, path traversal vulnerabilities, and the ability to upload web shells.
   - Analyzes PHP source code to detect file upload-related vulnerabilities.

## Prerequisites

1. **Docker**:
   - The DVWA application must be running inside a Docker container.
   - Ensure that Docker is installed and properly configured.

2. **Python 3.x**:
   - The scripts are written in Python and require Python 3.x to run.
   - Required Python packages:
     - `requests`
     - `beautifulsoup4`

3. **DVWA Setup**:
   - DVWA should be running locally, typically accessible at `http://127.0.0.1/dvwa`.
   - Ensure that DVWA is properly configured and running inside a Docker container.

## Installation

1. **Clone the Repository**:
   Clone this repository to your local machine.
   ```bash
   git clone https://github.com/your-repo/dvwa-tester.git
   cd dvwa-tester

Install Dependencies:
Install the required Python packages using pip:

(pip install requests beautifulsoup4)

Usage
1. Running DVWAAuthTester
This script checks for broken authentication vulnerabilities in DVWA.

Run the Script:


python3 DVWAAuthTester.py
Test Cases:

Weak Password: Attempts to log in with common weak passwords (e.g., password, 123456, admin).
Brute Force Protection: Simulates a brute force attack by trying multiple incorrect passwords.
Session Fixation: Checks if the session ID is regenerated after login to prevent session fixation attacks.
PHP Code Analysis: Analyzes the login.php file for authentication vulnerabilities such as weak password hashing, session fixation, and lack of brute force protection.
2. Running SecurityMisconfigurationTester
This script checks for security misconfigurations related to file uploads in DVWA.

Run the Script:

(python3 SecurityMisconfigurationTester.py)

Test Cases:

1) File Type Validation: Attempts to upload a PHP file to check if the application properly restricts file types.
Path Traversal: Attempts to upload a file with a path traversal payload (e.g., ../../etc/passwd).
Web Shell Upload: Attempts to upload a web shell (PHP script) that can execute system commands.
2) PHP Code Analysis: Analyzes the PHP file upload code for vulnerabilities such as missing file type validation, improper file handling, and path traversal issues.

How It Works:-

DVWAAuthTester
Login: The script logs into DVWA using the default credentials.

Vulnerability Tests: The script runs three test cases to check for weak passwords, brute force protection, and session fixation vulnerabilities.
PHP Code Analysis: The script fetches the login.php file from the DVWA container and analyzes it for security issues.

SecurityMisconfigurationTester
Login: The script logs into DVWA using the default credentials.
File Upload Tests: The script runs three test cases to check for file type validation, path traversal, and web shell upload vulnerabilities.
PHP Code Analysis: The script analyzes the file upload code for potential vulnerabilities.
