import requests
from urllib.parse import urlparse, parse_qs
from base64 import b64encode
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def sign_request(url, method, body, headers, key):
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    path = parsed_url.path
    has_body = len(body) != 0

    if has_body:
        body_string = "&".join([key + "=" + body[key] for key in body.keys()])
    else:
        body_string = ""
    body_sha = SHA256.new(body_string.encode("utf-8"))
    body_digest = "sha-256=" + b64encode(body_sha.digest()).decode("utf-8")

    date = headers["X-Nordea-Originating-Date"]
    signature_string = f"\
(request-target): {method.lower()} {path}\n\
x-nordea-originating-host: {host}\n\
x-nordea-originating-date: {date}"
    
    if "Content-Type" in headers:
        content_type = headers['Content-Type']
        signature_string += f"\ncontent-type: {content_type}"
    if has_body:
        signature_string += f"\ndigest: {body_digest}"
    print(signature_string)

    encrypted_signature = encrypt_signature(signature_string, key)
    headers_in_request = " ".join([z.split(":")[0] for z in signature_string.split("\n")])
    print("headers:    ", headers)
    signature = f'\
keyId="{(headers["X-IBM-Client-ID"])}",\
algorithm="rsa-sha256",\
headers="{headers_in_request}",\
signature="{encrypted_signature}"'

    headers["signature"] = signature
    if has_body:
        headers["digest"] = body_digest

def encrypt_signature(signature, key):
    rsa_key = RSA.import_key(key)
    return b64encode(pkcs1_15.new(rsa_key).sign(SHA256.new(signature.encode("utf-8")))).decode("utf-8")

def get_time_string():
    time = datetime.utcnow()
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT")

def do_request(client_id, client_secret, key):
    start_url = f"https://api.nordeaopenbanking.com/business/v4/authorize?state=oauth2&client_id={client_id}&scope=ACCOUNTS_BASIC,ACCOUNTS_BALANCES,ACCOUNTS_DETAILS,ACCOUNTS_TRANSACTIONS&duration=129600&redirect_uri=https://example.com&country=FI&company_id=12345678"
    start_headers = {
        "Content-Type": "application/json",
        "X-IBM-Client-Id": client_id
    }

    r = requests.get(start_url, headers=start_headers, allow_redirects=False)
    print("Start request got code ", r.status_code)

    redirect_location = r.headers["Location"]
    print("Got redirect location: ", redirect_location)
    redirect_url = urlparse(redirect_location)
    qs = parse_qs(redirect_url.query)
    oauth_code = qs["code"][0]

    auth_url = "https://api.nordeaopenbanking.com/business/v4/authorize/token"
    auth_body = {
        "code": oauth_code,
        "grant_type": "authorization_code",
        "redirect_uri": "https://example.com"
    }
    
    auth_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-IBM-Client-ID": client_id,
        "X-IBM-Client-Secret": client_secret,
        "X-Nordea-Originating-Date": get_time_string(),
        "X-Nordea-Originating-Host": "api.nordeaopenbanking.com",
    }

    sign_request(auth_url, "post", auth_body, auth_headers, key)

    auth_r = requests.post(
        auth_url, auth_body, headers=auth_headers, allow_redirects=False
    )
    print("Auth request got code: ", auth_r.status_code)
    auth_result = auth_r.json()
    print("Received data: ", auth_result)
    access_token = auth_result["access_token"]

    transactions_url = "https://api.nordeaopenbanking.com/business/v4/accounts/FI3815903000105518-EUR/transactions"
    transactions_headers = {
        "Authorization": f"Bearer {access_token}",
        "X-IBM-Client-ID": client_id,
        "X-IBM-Client-Secret": client_secret,
        "X-Nordea-Originating-Date": get_time_string(),
        "X-Nordea-Originating-Host": "api.nordeaopenbanking.com"
    }

    sign_request(transactions_url, "get", {}, transactions_headers, key)

    print("transactions headers: ", transactions_headers)

    transactions_r = requests.get(
        transactions_url, headers=transactions_headers
    )
    print("Transcations request got code: ", transactions_r.status_code)

    return transactions_r.json()
