import requests
import logging

class AccessControlTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def unauthorized_access(self, endpoint):
        """Test unauthorized access to endpoints."""
        try:
            response = requests.get(self.base_url + endpoint)
            message = f"Testing unauthorized access to {endpoint}: Status Code {response.status_code}"
            print(message)
            logging.info(message)
            if response.status_code == 200:
                vulnerability = f"Vulnerability detected in unauthorized access for {endpoint}."
                print(vulnerability)
                logging.warning(vulnerability)
            else:
                print(f"Access control in place for {endpoint}.")
                logging.info(f"Access control in place for {endpoint}.")
        except requests.RequestException as e:
            logging.error(f"Error testing unauthorized access: {e}")
            print(f"Error testing unauthorized access: {e}")

    def horizontal_privilege_escalation(self, endpoint, user_cookies, target_id):
        """Test horizontal privilege escalation by accessing another user's data."""
        try:
            response = requests.get(self.base_url + endpoint.format(target_id), cookies=user_cookies)
            message = f"Testing horizontal privilege escalation on {endpoint.format(target_id)}: Status Code {response.status_code}"
            print(message)
            logging.info(message)
            if response.status_code == 200 and target_id in response.text:
                vulnerability = f"Vulnerability detected in horizontal privilege escalation for {endpoint.format(target_id)}."
                print(vulnerability)
                logging.warning(vulnerability)
            else:
                print(f"Access control in place for {endpoint.format(target_id)}.")
                logging.info(f"Access control in place for {endpoint.format(target_id)}.")
        except requests.RequestException as e:
            logging.error(f"Error testing horizontal privilege escalation: {e}")
            print(f"Error testing horizontal privilege escalation: {e}")

    def vertical_privilege_escalation(self, endpoint, low_privilege_cookies, high_privilege_action):
        """Test vertical privilege escalation by attempting high-privilege actions with a low-privilege account."""
        try:
            response = requests.post(self.base_url + endpoint, cookies=low_privilege_cookies, data=high_privilege_action)
            message = f"Testing vertical privilege escalation on {endpoint}: Status Code {response.status_code}"
            print(message)
            logging.info(message)
            if response.status_code == 200:
                vulnerability = f"Vulnerability detected in vertical privilege escalation for {endpoint}."
                print(vulnerability)
                logging.warning(vulnerability)
            else:
                print(f"Access control in place for {endpoint}.")
                logging.info(f"Access control in place for {endpoint}.")
        except requests.RequestException as e:
            logging.error(f"Error testing vertical privilege escalation: {e}")
            print(f"Error testing vertical privilege escalation: {e}")

def main():
    base_url = "http://localhost:8888"

    # Set up logging to a file
    logging.basicConfig(filename='access_control_test.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Define test cases
    test_cases = [
        # Unauthorized Access Test Case
        {
            'type': 'unauthorized_access',
            'endpoint': "/orders?order_id=7"
        },

        # Horizontal Privilege Escalation Test Case
        {
            'type': 'horizontal_privilege_escalation',
            'endpoint': "/orders?order_id={}",
            'cookies': {'session': 'other-user-session-cookie'},  # Replace with another user's session cookie
            'target_id': '7'  # Assuming this order ID belongs to another user
        },

        # Vertical Privilege Escalation Test Case
        {
            'type': 'vertical_privilege_escalation',
            'endpoint': "/admin/update_order",
            'cookies': {'session': 'low-privilege-session-cookie'},  # Replace with a low-privilege user's session cookie
            'action': {'order_id': '7', 'status': 'completed'}  # Example of an unauthorized action
        }
    ]

    tester = AccessControlTester(base_url)
    for case in test_cases:
        if case['type'] == 'unauthorized_access':
            tester.unauthorized_access(case['endpoint'])
        elif case['type'] == 'horizontal_privilege_escalation':
            tester.horizontal_privilege_escalation(case['endpoint'], case['cookies'], case['target_id'])
        elif case['type'] == 'vertical_privilege_escalation':
            tester.vertical_privilege_escalation(case['endpoint'], case['cookies'], case['action'])
        else:
            logging.error(f"Unknown test case type: {case['type']}")

if __name__ == "__main__":
    main()
