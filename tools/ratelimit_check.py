import argparse
import json
import time
from collections import Counter
import requests

parser = argparse.ArgumentParser(description='Test (API) rate limiting by sending POST requests.')
parser.add_argument('url', type=str, help='The URL to send the POST requests to.')
parser.add_argument('data', type=str, help='Data to send as the body of the POST request. Can be a JSON array or form data.')
parser.add_argument('--content-type', type=str, choices=['json', 'form'], default='json', help='The content type of the data being sent (json or form). Default is json.')
parser.add_argument('--num-requests', type=int, default=1000, help='Number of requests to send. Default is 1000.')

args = parser.parse_args()

if args.content_type == 'json':
    try:
        data = json.loads(args.data)
        send_as_json = True
    except json.JSONDecodeError:
        print("Invalid JSON provided for content-type 'json'.")
        exit(1)
else:
    data = dict(x.split('=') for x in args.data.split('&'))
    send_as_json = False

start_time = time.time()

status_codes = []
for _ in range(args.num_requests):
    if send_as_json:
        response = requests.post(args.url, json=data)
    else:
        response = requests.post(args.url, data=data)
    status_codes.append(response.status_code)

end_time = time.time()

elapsed_time = end_time - start_time
status_code_counts = Counter(status_codes)

print(f"{args.num_requests} requests sent in {elapsed_time:.2f} seconds.")
print("Status Codes Received:")
for status_code, count in status_code_counts.items():
    print(f"{status_code}: {count} times")
