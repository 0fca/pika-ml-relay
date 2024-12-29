import json
#import pprint
import sseclient
from threading import Thread

def run_events(args):
    client = args[0]
    for event in client.events():
        print(event.data);

def with_requests(url, headers):
    """Get a streaming response for the given event feed using requests."""
    import requests
    return requests.get(url, stream=True, headers=headers)


url = 'http://127.0.0.1:3000/'
headers = {'Accept': 'text/event-stream'}
response = with_requests(url, headers)  # or with_requests(url, headers)
client = sseclient.SSEClient(response)

t = Thread(name="", target=run_events, daemon=True, args=client)
t.start()


