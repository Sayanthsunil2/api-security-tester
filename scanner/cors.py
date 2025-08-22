import requests
import json

ORIGINS_TO_TRY = [
    "https://evil.com",             
    "https://example.com.evil.com", 
    "null",                         
    "http://localhost:3000",         
]

def _classify(acao,acac,tested_orgin):
    acac_true = (acac or "").lower() =="true"

    if acao == tested_orgin and acac_true:
        return("vulnerable","Reflects attacker orgin and allow credentials (high risk)")
    
    if acao== tested_orgin and not acac_true:
        return("warning", "Reflects arbitary orgin (response readable if not credentialed)")
    
    if acao == "*" and acac_true:
        return("warning", "wildcard with credential is misconfigured")
    
    if acao == "*":
        return("warning","wildcard orgin allowed public read from any site ")
    
    return("ok"," No reflection or wildcard for this orgin ")

def test_cors(url, headers=None, write_report=True):
    print("\n[+]Testing for cors misconfiguration...")
    findings=[]

    base_headers = headers.copy() if headers else {}
    
    for origin in ORIGINS_TO_TRY:
        test_headers= base_headers.copy()
        test_headers["origin"] = origin

        try:
            resp= requests.get(url,headers=test_headers,timeout=5)

            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")

            status, notes = _classify(acao, acac, origin)

            print(f"  Origin={origin}  ->  ACAO={acao}  ACAC={acac}  =>  {status.upper()}: {notes}")

            findings.append({
                "tested_origin": origin,
                "http_status": resp.status_code,
                "acao": acao,
                "acac": acac,
                "status": status,
                "notes": notes,
            })

        except Exception as e:
            print(f"[!] Error for origin {origin}: {e}")
            findings.append({
                "tested_origin": origin,
                "http_status": None,
                "acao": None,
                "acac": None,
                "status": "error",
                "notes": str(e),
            })


    if any(f["status"] == "vulnerable" for f in findings):
        severity = "high"
    elif any(f["status"] == "warning" for f in findings):
        severity = "medium"
    else:
        severity = "info"

    report = {
        "vulnerability": "CORS",
        "url": url,
        "overall_severity": severity,
        "findings": findings,
    }

    if write_report:
        try:
            with open("output.json", "a") as f:
                f.write(json.dumps(report, indent=4) + "\n")
        except Exception as e:
            print(f"[!] Could not write to output.json: {e}")

    return report