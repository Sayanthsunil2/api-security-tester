import requests
import time 
import json

def test_rate_limit(url,headers=None):
    headers= headers or {}
    results = {
        "vulnerability":"Rate Limiting",
        "url": url,
        "rate_limit_detected": False,
        "responses":[]
    }

    print(f"Testing rate limiting on  {url}....")
    for i in range(15):
        response = results.get(url, headers=headers)
        results["responses"].append({
                "status_code":response.status_code,
                "body":response.text[:100]
        })
        print(f"Request {i+1}: Status {response.status_code}")

        if response.status_code == 429:
            results["rate_limit_detected"] = True
            print("[!] Rate limit detected (HTTP 429)")
            break
        
        time.sleep(0.2)  

    try:
        with open("output.json", "a") as f:
            f.write(json.dumps(results, indent=4) + "\n")
    except Exception as e:
        print(f"[!] Could not write to output.json: {e}")