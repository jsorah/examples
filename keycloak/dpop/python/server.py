import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import requests
from jose import jwt
import uuid
import time
import json
import hashlib
import base64

KEYCLOAK_PROTO = 'http' # Yep, http for local testing, like I said, not production code.
KEYCLOAK_HOST_AND_REALM = 'localhost:8080/realms/master'
KEYCLOAK_BASE_URL = f'{KEYCLOAK_PROTO}://{KEYCLOAK_HOST_AND_REALM}'
MY_PORT = 8000
MY_CLIENT_ID = 'dpop-client'

def hash_at(access_token):
    # we need to hash the access token - per RFC9449 - Base64(sha256(access token)) - only if used with an access token
    # But, it seems like Keycloak doesn't require this ... yet. DPoP _is_ a preview feature.
    sha256_of_access_token = hashlib.sha256(access_token.encode()).digest()
    return base64.b64encode(sha256_of_access_token).decode()

def mint_dpop_data(htm, htu):
    return {
        'jti': str(uuid.uuid4()), # Good random value, UUID4 is acceptable
        'iat': int(time.time()), # Basically, right now in seconds since epoch
        'htm': htm,
        'htu': htu
    }

class DpopRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    This is not meant to be production ready code, but to demonstrate the flows used for DPoP in OAuth

    Assumes
    - running on localhost
    - you have created a client 'dpop-client' on your keycloak instance
    - you have configured the client to be DPoP bound
    """
    def write_preformatted_string(self, value):
        self.wfile.write(b'<pre>')
        self.wfile.write(bytes(value, 'utf-8'))
        self.wfile.write(b'</pre>')

    def write_para(self, value):
        self.wfile.write(b'<p>')
        self.wfile.write(bytes(value, 'utf-8'))
        self.wfile.write(b'</p>')

    def write_newline(self):
        self.wfile.write(b'\r\n')

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if parsed_url.path == '/authorize': # do code to token exchange + other fun stuff.
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.write_para('Attempt to exchange code for an access token')

            print(query_params)

            query_params['code']
            form_data = {
                    'code': query_params['code'],
                    'client_id': MY_CLIENT_ID,
                    'redirect_uri': f'http://localhost:{MY_PORT}/authorize',
                    'grant_type': 'authorization_code'
            }

            # DPoP stuff comes next!
            supersecret = None
            with open("privateKey.pem", 'r') as f:
                supersecret = f.read()

            dpop_payload = mint_dpop_data('POST', f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/token')

            # TODO - load from file
            jwk = {"kty":"RSA","n":"tub_x-Nb4Ik9-swz74D3k5_0tYsdRQRcS83_VvYzDQZMCAAWHGv7-0tReSo15b4zjPh2WCaOqqfosN8Jw7-Y0BPtL5W4T0TNToLmSaC6UJ-lcfknIG59WbJIte2rVBPAwL-EXTXArxzjxfb7xtJb0J7ISw3QojdSZ1JV37x5ekIt2zfjIbqi_brrkGbbD_hw-jQXVj61KU-1uaFREfWRGr7YtAYqtLXXwjnhaDyIbBqsny8R44PpraOlip8QcH2jG309_0g3jB9SqlbAnQ7d2-Th-aVGWx1ZP3rfm8iZ1Vep2cpZWDr2rYmLE9oLJxGztJhRweinFpeE_-zgmAkOKw","e":"AQAB"}

            token = jwt.encode(dpop_payload, supersecret, algorithm='RS256', headers={'typ':'dpop+jwt', 'jwk': jwk})

            self.write_para("Here is our DPoP proof we will send")
            self.write_preformatted_string(token)

            response = requests.post(f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/token', 
                                     data=form_data,
                                     headers={'dpop': token})
            
            if response.status_code == 200:
                self.write_newline()
                self.write_para('It was successful')
                print(json.dumps(response.json(), indent=2))
                self.write_newline()
                self.write_preformatted_string(json.dumps(response.json(), indent=2))                
                self.write_newline()
                self.write_para('Now we will try for a refresh token using DPoP...')
                self.write_newline()

                # Now, lets immediately exchange that refresh token for a new access token. Live life on the edge.                

                dpop_payload_for_refresh = mint_dpop_data('POST',f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/token')

                dpop_for_refresh = jwt.encode(dpop_payload_for_refresh, supersecret, algorithm='RS256', headers={'typ': 'dpop+jwt', 'jwk': jwk})

                self.write_para("Here is our DPoP proof we will send")
                self.write_preformatted_string(dpop_for_refresh)

                form_data_for_refresh = {
                    'client_id': MY_CLIENT_ID,
                    'grant_type': 'refresh_token',
                    'refresh_token': response.json()['refresh_token']
                }                

                refresh_response = requests.post(f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/token',
                                                 data = form_data_for_refresh,
                                                 headers={'dpop': dpop_for_refresh}                                                 
                                                 )
                
                if refresh_response.status_code == 200:
                    self.write_newline()
                    self.write_para('It was successful')
                    self.write_preformatted_string(json.dumps(refresh_response.json(), indent=2))
                    
                    # How about lets try to get stuff from the user info endpoint?
                    self.write_newline()
                    self.write_para('Now we will try for the userinfo endpoint using DPoP')
                    self.write_newline()

                    current_access_token = refresh_response.json()['access_token']

                    # Interestingly Keycloak doesn't seem concerned about our lack of 'ath' field here...
                    dpop_payload_for_userinfo = mint_dpop_data('POST', f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/userinfo')

                    dpop_for_userinfo = jwt.encode(dpop_payload_for_userinfo, supersecret, algorithm='RS256', headers={'typ': 'dpop+jwt', 'jwk': jwk})

                    self.write_para("Here is our DPoP proof we will send")
                    self.write_preformatted_string(dpop_for_userinfo)

                    userinfo_response = requests.post(f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/userinfo',
                                                      headers={
                                                          'Authorization': f'Bearer {current_access_token}', 
                                                          'dpop': dpop_for_userinfo})
                    
                    if userinfo_response.status_code == 200:
                        self.write_newline()
                        self.write_para('It was successful')
                        self.write_preformatted_string(json.dumps(userinfo_response.json(), indent=2))
                    else:
                        self.write_newline()
                        self.write_para('It had some problems.')
                        self.write_newline()
                        self.write_para(f'The status code was {userinfo_response.status_code}')                        
                        self.write_preformatted_string(userinfo_response.text)
                        print(response.headers)
                    
                else:
                    self.write_newline()
                    self.write_para('It had some problems.')
                    self.write_newline()
                    self.write_para(f'The status code was {refresh_response.status_code}')
                    self.write_preformatted_string(refresh_response.text)
                    
            else:
                self.write_newline()
                self.write_para('It had some problems.')
                self.write_newline()
                self.write_preformatted_string(response.text)                

        elif parsed_url.path == '/login': # initiate auth code flow from this URL, in an ideal world, use PKCE.
            self.send_response(302)
            self.send_header('location',f'{KEYCLOAK_BASE_URL}/protocol/openid-connect/auth?client_id={MY_CLIENT_ID}&redirect_uri=http://localhost:{MY_PORT}/authorize&response_type=code&scope=openid')
            self.end_headers()
        else:
            super().do_GET()

def main():
    
    with socketserver.TCPServer(("", MY_PORT), DpopRequestHandler) as httpd:
        print(f"Server started on port {MY_PORT}")
        httpd.serve_forever()
        
if __name__ == '__main__':
    main()
