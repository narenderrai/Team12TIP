import requests
import time
import threading

# Configuration
DVWA_URL = "http://localhost/dvwa/vulnerable_endpoint"  # Replace with the actual endpoint
USERNAME = "admin"
PASSWORD = "password"
MAX_REQUESTS = 100
DELAY = 0.2  # Delay between requests in seconds
THRESHOLD_RESPONSE_TIME = 1.0  # Threshold for response time concern in seconds
THRESHOLD_REQUESTS_PER_SECOND = 5  # Max requests per second before considering abnormal

# Function to login to DVWA and return session
def login_to_dvwa():
    """Login to DVWA to obtain session cookie."""
    login_url = "http://localhost/dvwa/login.php"
    session = requests.Session()
    login_data = {
        'username': USERNAME,
        'password': PASSWORD,
        'Login': 'Login'
    }
    response = session.post(login_url, data=login_data)
    if "Login failed" in response.text:
        print("Failed to login to DVWA.")
        return None
    return session

# Function to test resource consumption
def test_resource_consumption(session):
    """Test the specified resource for uncontrolled consumption."""
    response_times = []
    request_count = 0
    start_time = time.time()
    
    for i in range(MAX_REQUESTS):
        current_time = time.time()
        
        # Check request rate
        elapsed_time = current_time - start_time
        if elapsed_time > 0:
            requests_per_second = request_count / elapsed_time
            if requests_per_second > THRESHOLD_REQUESTS_PER_SECOND:
                print(f"Warning: Requests per second ({requests_per_second}) exceed threshold!")
                break
        
        # Send request and measure response time
        start_request_time = time.time()
        response = session.get(DVWA_URL)
        elapsed_request_time = time.time() - start_request_time
        response_times.append(elapsed_request_time)
        request_count += 1

        print(f"Request {i+1}: Response Time = {elapsed_request_time:.2f}s, Status Code = {response.status_code}")
        
        if response.status_code != 200:
            print("Non-200 status code detected, stopping test.")
            break
        
        # Analyze response times for any unusual spikes
        if len(response_times) > 5:
            avg_response_time = sum(response_times[-5:]) / 5
            if avg_response_time > THRESHOLD_RESPONSE_TIME:
                print("Warning: Average response time increased significantly!")
                break
        
        # Delay between requests
        time.sleep(DELAY)

# Function to monitor system resources (mock)
def monitor_resources():
    """Mock function to monitor system resources."""
    # This can be expanded to check actual system resource utilization
    # using libraries like psutil or other monitoring tools.
    while True:
        # Simulate monitoring
        cpu_usage = 10  # Placeholder for CPU usage
        memory_usage = 100  # Placeholder for memory usage in MB
        
        print(f"CPU Usage: {cpu_usage}%, Memory Usage: {memory_usage}MB")
        
        # Implement logic to detect abnormal resource usage
        if cpu_usage > 80 or memory_usage > 500:
            print("Warning: High resource usage detected!")
        
        time.sleep(1)  # Monitoring interval

def main():
    session = login_to_dvwa()
    if session:
        print("Logged in successfully. Starting resource consumption test.")
        
        # Start monitoring resources in a separate thread
        monitoring_thread = threading.Thread(target=monitor_resources)
        monitoring_thread.start()
        
        test_resource_consumption(session)
        
        # Stop monitoring after test completion
        monitoring_thread.join(timeout=1)
    else:
        print("Unable to perform test without valid session.")

if __name__ == "__main__":
    main()
