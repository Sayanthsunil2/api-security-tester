import argparse
import requests
import json
from scanner import idor, xss, ssrf, sqli, rate_limit, cors, method_fuzzer

def send_request(url, method, headers=None, data=None):
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=data)
        elif method == "PUT":
            response = requests.put(url, headers=headers, data=data)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers)
        else:
            print(f"[-] Unsupported method: {method}")
            return
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Response Body:\n{response.text}")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Security Testing Tool phase 1")
    parser.add_argument("--url", required=True, help="Target API endpoint (e.g. https://api.site.com/user/1)")
    parser.add_argument("--method", default="GET", help="HTTP Method: GET, POST, PUT, DELETE")
    parser.add_argument("--headers", help="Request headers as JSON string")
    parser.add_argument("--data", help="Request body (for POST/PUT) as JSON string")
    parser.add_argument("--idor", action="store_true", help="Run IDOR vulnerability test")
    parser.add_argument("--xss", action="store_true", help="Run XSS vulnerability test")
    parser.add_argument("--ssrf", action="store_true", help="Run SSRF vulnerability test")
    parser.add_argument("--sqli", action="store_true", help="Run SQL Injection vulnerability test")
    parser.add_argument("--ratelimit", action="store_true", help="Run Rate Limit vulnerability test")
    parser.add_argument("--cors", action="store_true", help="Run CORS misconfiguration test")
    parser.add_argument("--methodfuzzer", action="store_true", help="Run HTTP Method Fuzzer test")



    args = parser.parse_args()

    headers = json.loads(args.headers) if args.headers else {}
    data = json.loads(args.data) if args.data else None

    if args.idor:
        idor.test_idor(args.url, headers)

    elif args.xss:
        xss.test_xss(args.url, args.method.upper(), headers=headers, data=data)

    elif args.ssrf:
        ssrf.test_url(args.url, args.method.upper(), headers=headers, data=data)
        
    elif args.sqli:
        sqli.test_sqli(args.url, args.method.upper(), headers=headers, data=data)
    
    elif args.ratelimit:
        rate_limit.test_rate_limit(args.url, headers)

    elif args.cors:
        cors.test_cors(args.url, headers=headers)

    elif args.method_fuzzer:
        method_fuzzer.test_method_fuzzer(args.url, headers)



    else:
        send_request(args.url, args.method.upper(), headers=headers, data=json.dumps(data) if data else None)
