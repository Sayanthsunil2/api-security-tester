import requests

def test_method_fuzzer(url,headers=None):

    methods = ["GET","POST","PUT","DELETE","TRACE","CONNECT","PATCH","OPTIONS"]

    findings=[]
    for method in methods:
        
        try:
            response = requests.request(method,url,headers=headers,timeout=5)
            findings.append({
                "method":method,
                "status_code":response.status_code,
                "body_snippet":response.text[:100]
            })

            print(f"[+]{method} -> {response.status_code}")

        except Exception as e:
            findings.append({
                "method":method,
                "error":str(e)
            })

            print(f"[!] {method} -> Error: {e}")

    return findings
