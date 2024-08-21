import requests
import re

# Define the base URL for the Flask application
BASE_URL = "http://127.0.0.1:5000"

# Static analysis function
def find_vulnerability_lines(file_path, patterns):
    vulnerability_lines = []

    with open(file_path, 'r') as file:
        lines = file.readlines()

        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    vulnerability_lines.append((i + 1, line.strip()))
    
    return vulnerability_lines

# Vulnerability checks for Broken Access Control
def check_idor_vulnerability():
    try:
        # Login as user1
        login_data = {"username": "user1"}
        response = requests.post(f"{BASE_URL}/login", json=login_data)
        if response.status_code != 200:
            print("Login failed.")
            return False

        # Attempt to access another user's order
        response = requests.get(f"{BASE_URL}/orders/2")
        if response.status_code == 200 and "user_id" in response.json() and response.json()["user_id"] != 2:
            print("IDOR vulnerability detected: Accessed another user's order.")
            return True
    except Exception as e:
        print(f"Error during IDOR vulnerability test: {e}")
    return False

def check_session_management():
    try:
        # Login as user1
        login_data = {"username": "user1"}
        response = requests.post(f"{BASE_URL}/login", json=login_data)
        if response.status_code != 200:
            print("Login failed.")
            return False

        # Attempt to access another user's document
        response = requests.get(f"{BASE_URL}/documents/2")
        if response.status_code == 200 and "user_id" in response.json() and response.json()["user_id"] != 2:
            print("Improper session management detected: Accessed another user's document.")
            return True
    except Exception as e:
        print(f"Error during session management vulnerability test: {e}")
    return False

def check_insecure_function_level_authorization():
    try:
        # Login as user1
        login_data = {"username": "user1"}
        response = requests.post(f"{BASE_URL}/login", json=login_data)
        if response.status_code != 200:
            print("Login failed.")
            return False

        # Attempt to delete another user's account
        response = requests.post(f"{BASE_URL}/delete_user/1")
        if response.status_code == 200:
            print("Insecure Function-Level Authorization detected: Non-admin user deleted another user's account.")
            return True
    except Exception as e:
        print(f"Error during Function-Level Authorization test: {e}")
    return False

# New function to analyze code for session management issues
def check_session_management_in_code(file_path):
    # Patterns to identify session management issues
    patterns = [
        r'session\["user_id"\]',   # Look for usage of session["user_id"]
        r'/documents/<int:doc_id>', # Look for document access routes
        r'/orders/<int:order_id>'   # Look for order access routes
    ]
    
    return find_vulnerability_lines(file_path, patterns)

# Analyze code for vulnerabilities based on detected vulnerabilities
def analyze_code_for_vulnerabilities(vulnerabilities):
    file_path = "app.py"  # Path to your Flask app file
    analysis_results = {}

    if "IDOR" in vulnerabilities:
        idor_patterns = [r'/orders/<int:order_id>', r'/documents/<int:doc_id>']
        idor_vulnerabilities = find_vulnerability_lines(file_path, idor_patterns)
        if idor_vulnerabilities:
            analysis_results["IDOR"] = idor_vulnerabilities

    if "Insecure Function-Level Authorization" in vulnerabilities:
        function_level_patterns = [r'/delete_user/<int:user_id>']
        function_level_vulnerabilities = find_vulnerability_lines(file_path, function_level_patterns)
        if function_level_vulnerabilities:
            analysis_results["Insecure Function-Level Authorization"] = function_level_vulnerabilities

    if "Session Management" in vulnerabilities:
        session_management_vulnerabilities = check_session_management_in_code(file_path)
        if session_management_vulnerabilities:
            analysis_results["Session Management"] = session_management_vulnerabilities

    return analysis_results

if __name__ == "__main__":
    vulnerabilities_detected = []

    print("\nTesting for Broken Access Control Vulnerabilities...\n")

    if check_idor_vulnerability():
        vulnerabilities_detected.append("IDOR")

    if check_session_management():
        vulnerabilities_detected.append("Session Management")

    if check_insecure_function_level_authorization():
        vulnerabilities_detected.append("Insecure Function-Level Authorization")

    if vulnerabilities_detected:
        print("\nApplication is vulnerable to the following Broken Access Control vulnerabilities:\n - " + "\n - ".join(vulnerabilities_detected) + "\n")

        # Perform code analysis only for the detected vulnerabilities
        analysis_results = analyze_code_for_vulnerabilities(vulnerabilities_detected)

        for vulnerability_type, lines in analysis_results.items():
            print(f"\n{vulnerability_type} Vulnerabilities found at lines:")
            for line_number, line in lines:
                print(f"Line {line_number}: {line}")

    else:
        print("\nNo Broken Access Control vulnerabilities detected.\n")
