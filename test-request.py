import requests
import sys

TARGET = 'https://www.virustotal.com/api/v3/files/d14651e4b014d2d098c24ef76c7309da'
HEADERS = {'x-apikey': ''}
try:
    response = requests.get(TARGET, headers=HEADERS)
    print(response)
except requests.exceptions.HTTPError as e:
    print(e)