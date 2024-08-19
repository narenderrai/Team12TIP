import requests
import re

# Define the base URL for the Flask application
BASE_URL = "http://127.0.0.1:5000"

# Static analysis function to identify routes handling Uncontrolled Resource Consumption
def find_routes_and_check_urc_vulnerabilities(file_path, pattern):
    vulnerability_lines = []
    
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                vulnerability_lines.append((i + 1, line.strip()))
        
    return vulnerability_lines

# Vulnerability checks for Uncontrolled Resource Consumption
def check_uncontrolled_file_generation():
    try:
        # Attempt to generate a large number of files
        data = {"number_of_files": 1000, "file_size": 1024}  # Large number of files with a 1KB size each
        response = requests.post(f"{BASE_URL}/generate_files", json=data)
        if response.status_code == 200:
            print("Uncontrolled File Generation vulnerability detected: Generated a large number of files.")
            return True
    except Exception as e:
        print(f"Error during Uncontrolled File Generation test: {e}")
    return False

def check_uncontrolled_memory_consumption():
    try:
        # Attempt to allocate a large amount of memory
        data = {"size": 1024}  # 1024 MB (1 GB)
        response = requests.post(f"{BASE_URL}/allocate_memory", json=data)
        if response.status_code == 200:
            print("Uncontrolled Memory Consumption vulnerability detected: Allocated a large amount of memory.")
            return True
    except Exception as e:
        print(f"Error during Uncontrolled Memory Consumption test: {e}")
    return False

def check_uncontrolled_file_upload():
    try:
        # Attempt to upload a large file
        with open("large_file.txt", "wb") as f:
            f.write(b"A" * 1024 * 1024 * 10)  # 10MB file
        
        with open("large_file.txt", "rb") as f:
            files = {"file": f}
            response = requests.post(f"{BASE_URL}/upload_file", files=files)
            if response.status_code == 200:
                print("Uncontrolled File Upload vulnerability detected: Uploaded a large file.")
                return True
    except Exception as e:
        print(f"Error during Uncontrolled File Upload test: {e}")
    return False

# Analyze code for vulnerabilities based on detected vulnerabilities
def analyze_code_for_vulnerabilities(vulnerabilities):
    file_path = "app.py"  # Path to your Flask app file
    analysis_results = {}

    if "Uncontrolled File Generation" in vulnerabilities:
        file_generation_vulnerabilities = find_routes_and_check_urc_vulnerabilities(file_path, r'/generate_files')
        if file_generation_vulnerabilities:
            analysis_results["Uncontrolled File Generation"] = file_generation_vulnerabilities

    if "Uncontrolled Memory Consumption" in vulnerabilities:
        memory_consumption_vulnerabilities = find_routes_and_check_urc_vulnerabilities(file_path, r'/allocate_memory')
        if memory_consumption_vulnerabilities:
            analysis_results["Uncontrolled Memory Consumption"] = memory_consumption_vulnerabilities

    if "Uncontrolled File Upload" in vulnerabilities:
        file_upload_vulnerabilities = find_routes_and_check_urc_vulnerabilities(file_path, r'/upload_file')
        if file_upload_vulnerabilities:
            analysis_results["Uncontrolled File Upload"] = file_upload_vulnerabilities

    return analysis_results

if __name__ == "__main__":
    vulnerabilities_detected = []

    print("\nTesting for Uncontrolled Resource Consumption Vulnerabilities...\n")

    if check_uncontrolled_file_generation():
        vulnerabilities_detected.append("Uncontrolled File Generation")

    if check_uncontrolled_memory_consumption():
        vulnerabilities_detected.append("Uncontrolled Memory Consumption")

    if check_uncontrolled_file_upload():
        vulnerabilities_detected.append("Uncontrolled File Upload")

    if vulnerabilities_detected:
        print("\nApplication is vulnerable to the following Uncontrolled Resource Consumption vulnerabilities:\n - " + "\n - ".join(vulnerabilities_detected) + "\n")

        # Perform code analysis only for the detected vulnerabilities
        analysis_results = analyze_code_for_vulnerabilities(vulnerabilities_detected)

        for vulnerability_type, lines in analysis_results.items():
            print(f"\n{vulnerability_type} Vulnerabilities found at lines:")
            for line_number, line in lines:
                print(f"Line {line_number}: {line}")

    else:
        print("\nNo Uncontrolled Resource Consumption vulnerabilities detected.\n")
