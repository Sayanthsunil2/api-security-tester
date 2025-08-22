import requests
import re

def test_idor(url,method="GET",headers=None,original_data=None,id_range=range(1,10)):
    headers=headers or {}

    id_values = re.findall(r'\d+', url)

    if not id_values:
        print("[-] no numeric ID found in url for idor testing. ")
        return
    
    print(f"Starting IDOR Testing on {url}")
    
    original_response = requests.request(method,url, headers=headers , data=original_data)
    baseline_status = original_response.status_code
    baseline_body = original_response.text[:200]

    for new_id in id_range:
        test_url = re.sub(r'\d+', str(new_id), url, count=1)
        response = requests.request(method, test_url, headers=headers, data=original_data)

        if response.status_code != baseline_status or response.text[:200] != baseline_body:
            print(f"[!] Possible IDOR at {test_url} [Status: {response.status_code}]")
        else:
            print(f"[-] No difference at {test_url}")
