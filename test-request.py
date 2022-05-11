import requests
import sys
import json
import re

SAFE_HASH_MD5 = 'd14651e4b014d2d098c24ef76c7309da'
SAFE_HASH_SHA265 = '7539b2a70540ecd043b5a491aacd69060e5f1495fa28a6b3a09edc7888db6664'
BAD_HASH_MD5 = '44d88612fea8a8f36de82e1278abb02f'
BAD_HASH_SHA265 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
TARGET = 'https://www.virustotal.com/api/v3/files'
HEADERS = {'x-apikey': ''}


def check_hash(hash:str):
    md5_check = re.findall(r"([a-fA-F\d]{32})", hash)
    sha256_check = re.findall(r"([a-fA-F\d]{64})", hash)

    if len(md5_check) == 1:
        print("Hash is a valid MD5 hash.")
    elif len(sha256_check) == 1:
        print("Hash is a valid SHA256 hash.")
    else:
        print("Hash is not valid.")
        exit(2)

def run(hash, api_key):
    headers = {'x-apikey': api_key}
    url = f"{TARGET}/{hash}"
    # response_safe = requests.get(TARGET + SAFE_HASH_MD5, headers=HEADERS) # safe response
    # response_bad = requests.get(TARGET + BAD_HASH_MD5, headers=HEADERS) # bad response
    response = requests.get(url, headers=headers)

    if http_response_code(response.status_code):

        response_json = json.loads(response.text)['data']
        harmless_votes = response_json['attributes']['total_votes']['harmless']
        malicious_votes = response_json['attributes']['total_votes']['malicious']
        results = response_json['attributes']['last_analysis_results']
        count = 0

        for i in results:
            if results[i]['category'] == 'malicious':
                count += 1
        if count == 0:
            print("File is clean!")
        elif count < 5:
            print(f"File may be malicious, {count} AV engines flagged the file")
        elif count > 5:
            print(f'File is malicious, flagged by {count} AV engines')
        # print(f'{harmless_votes} people voted this file as harmless')
        # print(f'{malicious_votes} people voted this file as malicious')
    else:
        print("There was an error processing the request.")


def http_response_code(status):
    print(f'Status code: {status}')
    if status == 200:
        print('Scan successful!')
        return True
    elif status == 400:
        print('Error: Bad request.')
        return False
    elif status == 401:
        print('Error: Verify API key.')
        return False
    elif status == 403:
        print('Error: You are not allowed to perform this operation.')
        return False
    elif status == 404:
        print('Error: Requested resource was not available.')
        return False
    elif status == 429:
        print("Error: Too many requests.")
        return False
    elif status == 503:
        print('Error: Transient error, retry.')
        return False
    elif status == 504:
        print('Error: Operation took too long.')
        return False




if __name__ == '__main__':
    # Argparse not working correctly, fallback to sys.argv
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
    check_hash(hash)
    api_key = sys.argv[2]

    run(hash, api_key)