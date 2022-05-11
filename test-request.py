from nis import match
from unicodedata import category
import requests
import sys
import json

SAFE_HASH = 'd14651e4b014d2d098c24ef76c7309da'
BAD_HASH = '44d88612fea8a8f36de82e1278abb02f'
TARGET = 'https://www.virustotal.com/api/v3/files/'
HEADERS = {'x-apikey': ''}


def run(hash, api_key):
    headers = {'x-apikey': api_key}
    url = f"{TARGET}/{hash}"
    # response_safe = requests.get(TARGET + SAFE_HASH, headers=HEADERS) # safe response
    # response_bad = requests.get(TARGET + BAD_HASH, headers=HEADERS) # bad response
    response = requests.get(TARGET + BAD_HASH, headers=HEADERS)
    print(f"Status Code: {response.status_code}")
    

    if response.status_code == 401:
         print("Status Code: 401\nUser account is not active or API key is not valid")
         exit(1)
    if response.status_code == 200:
        print('Scan Success')
        response_json = json.loads(response.text)
        results = response_json['data']['attributes']['last_analysis_results']
        count = 0
        for i in results:
            if results[i]['category'] == 'malicious':
                count += 1


    # match statements require python version > 3.10
    # def http_response_code(status):
    #     match status:
    #         case 200:



if __name__ == '__main__':
    # parser = argparse.ArgumentParser(
    #     description="Virus Total API Tool",
    #     formatter_class=argparse.RawDescriptionHelpFormatter,
    #     epilog=textwrap.dedent('''Example:
    #     viruscheck.py -h <hash_value> -k <api_key>
    #     ''')
    # )
    # parser.add_argument('-h', '--hash', type=str, help='file hash value')
    # parser.add_argument('-k', '--key', type=str, help='API key')

    # args = parser.parse_args()
    if len(sys.argv) != 3:
        print("Did not recieve correct number of arguments")
        print("Example: python file.py <hash_value> <api_key>")
    hash = sys.argv[1]
    api_key = sys.argv[2]

    run(hash, api_key)