import base64
import hashlib
import http.server
import json
import logging
import os
import socketserver
import time
import uuid
from urllib.parse import urlparse, parse_qs

import requests
from jose import jwt

log = logging.getLogger(__name__)

KEYCLOAK_PROTO = 'http'  # Yep, http for local testing, like I said, not production code.
KEYCLOAK_HOST_AND_REALM = 'localhost:8080/realms/master'
KEYCLOAK_BASE_URL = f'{KEYCLOAK_PROTO}://{KEYCLOAK_HOST_AND_REALM}'
KEYCLOAK_WELL_KNOWN = f'{KEYCLOAK_BASE_URL}/.well-known/openid-configuration'

MY_PORT = 8000
MY_CLIENT_ID = 'dpop-client'


class Dpop:

    @staticmethod
    def dpop_data(htm, htu, ath=None):
        dpop_dict = {
            'jti': str(uuid.uuid4()),  # Good random value, UUID4 is acceptable
            'iat': int(time.time()),  # Basically, right now in seconds since epoch
            'htm': htm,
            'htu': htu
        }

        # not always required
        if ath:
            dpop_dict['ath'] = ath

        return dpop_dict

    @staticmethod
    def dpop_header(jwk):
        return {
            'typ': 'dpop+jwt',
            'jwk': jwk
        }

    @staticmethod
    def hash_at(access_token):
        # we need to hash the access token - per RFC9449 - Base64(sha256(access token)) - only if used with an access
        # token But, it seems like Keycloak doesn't require this ... yet. DPoP _is_ a preview feature.
        sha256_of_access_token = hashlib.sha256(access_token.encode()).digest()
        return base64.b64encode(sha256_of_access_token).decode()


class DpopRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    This is not meant to be production ready code, but to demonstrate the flows used for DPoP in OAuth

    Assumes
    - running on localhost
    - you have created a client 'dpop-client' on your keycloak instance
    - you have configured the client to be DPoP bound
    """

    def write_h1(self, value):
        self.wfile.write(b'<h1>')
        self.wfile.write(bytes(value, 'utf-8'))
        self.wfile.write(b'</h1>')

    def write_preformatted_string(self, value):
        self.wfile.write(b'<pre>')
        self.wfile.write(bytes(value, 'utf-8'))
        self.wfile.write(b'</pre>')

    def write_para(self, value):
        self.wfile.write(b'<p>')
        self.wfile.write(bytes(value, 'utf-8'))
        self.wfile.write(b'</p>')

    def write_hr(self):
        self.wfile.write(b'<hr />')

    def write_response_failure(self, response):
        self.write_para('It had some problems.')
        self.write_para(f'The status code was {response.status_code}')
        self.write_preformatted_string(response.text)
        log.debug(response.headers)

    def write_response_success(self, response):
        self.write_para('It was successful')
        response_json = response.json()
        self.write_preformatted_string(json.dumps(response_json, indent=2))
        return response_json

    def write_dpop_info(self, dpop_proof):
        self.write_para("Here is our DPoP proof we will send")
        self.write_preformatted_string(dpop_proof)

    def invoke_userinfo(self, current_access_token):
        # Interestingly Keycloak doesn't seem concerned about our lack of 'ath' field here...
        userinfo_endpoint = OIDC_CONFIGURATION['userinfo_endpoint']
        dpop_proof = create_dpop('POST', userinfo_endpoint)

        self.write_dpop_info(dpop_proof)

        userinfo_response = requests.post(userinfo_endpoint,
                                          headers={
                                              'Authorization': f'Bearer {current_access_token}',
                                              'dpop': dpop_proof})

        if userinfo_response.status_code != 200:
            self.write_response_failure(userinfo_response)
            return None

        return self.write_response_success(userinfo_response)

    def invoke_refresh_token(self, current_refresh_token):
        token_endpoint = OIDC_CONFIGURATION['token_endpoint']
        dpop_proof = create_dpop('POST', token_endpoint)

        self.write_dpop_info(dpop_proof)

        form_data_for_refresh = {
            'client_id': MY_CLIENT_ID,
            'grant_type': 'refresh_token',
            'refresh_token': current_refresh_token
        }

        refresh_response = requests.post(token_endpoint,
                                         data=form_data_for_refresh,
                                         headers={'dpop': dpop_proof}
                                         )

        if refresh_response.status_code != 200:
            self.write_response_failure(refresh_response)
            return None

        return self.write_response_success(refresh_response)

    def invoke_code_exchange(self, code):

        form_data = {
            'code': code,
            'client_id': MY_CLIENT_ID,
            'redirect_uri': f'http://localhost:{MY_PORT}/authorize',
            'grant_type': 'authorization_code'
        }

        # DPoP stuff comes next!
        token_endpoint = OIDC_CONFIGURATION['token_endpoint']
        dpop_proof = create_dpop('POST', token_endpoint)

        self.write_dpop_info(dpop_proof)

        response = requests.post(token_endpoint,
                                 data=form_data,
                                 headers={'dpop': dpop_proof})

        if response.status_code != 200:
            self.write_response_failure(response)
            return None

        return self.write_response_success(response)

    def handle_authorize_endpoint(self, query_params):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.write_h1('Attempt to exchange code for an access token')

        response = self.invoke_code_exchange(query_params['code'])
        if not response:
            return

        self.write_hr()
        self.write_h1('Now we will try for a refresh token using DPoP...')

        # Now, lets immediately exchange that refresh token for a new access token. Live life on the edge.
        refresh_response = self.invoke_refresh_token(response['refresh_token'])
        if not refresh_response:
            return

        # How about lets try to get stuff from the user info endpoint?
        self.write_hr()
        self.write_h1('Now we will try for the userinfo endpoint using DPoP')

        userinfo_response = self.invoke_userinfo(refresh_response['access_token'])
        if not userinfo_response:
            return

    def handle_login_endpoint(self):
        self.send_response(302)
        self.send_header('location',
                         f'{OIDC_CONFIGURATION["authorization_endpoint"]}?client_id={MY_CLIENT_ID}&redirect_uri=http://localhost:{MY_PORT}/authorize&response_type=code&scope=openid')
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)

        if parsed_url.path == '/authorize':  # do code to token exchange + other fun stuff.
            self.handle_authorize_endpoint(query_params)
        elif parsed_url.path == '/login':  # initiate auth code flow from this URL, in an ideal world, use PKCE.
            self.handle_login_endpoint()
        else:  # just send them to the login page otherwise
            self.send_response(302)
            self.send_header('location', f'http://localhost:{MY_PORT}/login')
            self.end_headers()


def create_dpop(htm, htu):
    dpop_payload_for_refresh = Dpop.dpop_data(htm, htu)
    dpop_for_refresh = jwt.encode(dpop_payload_for_refresh, PRIVATE_KEY, algorithm='RS256',
                                  headers=Dpop.dpop_header(PUBLIC_JWK))
    return dpop_for_refresh


def does_server_support_dpop(oidc_configuration):
    dpop_attr = 'dpop_signing_alg_values_supported'

    return dpop_attr in oidc_configuration and len(
        oidc_configuration[dpop_attr]) > 0


def main():
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

    well_known_response = requests.get(KEYCLOAK_WELL_KNOWN)
    well_known_response_json = well_known_response.json()

    if well_known_response.status_code != 200:
        log.error(f'Could not retrieve well-known OIDC configuration from {KEYCLOAK_WELL_KNOWN}')
        log.error("Have you started your authorization server?")
        return
    elif not does_server_support_dpop(well_known_response_json):
        log.error("Authorization Server does not support DPoP. :-(")
        log.error("Did you start with a version of Keycloak that supports it, and enable the DPoP feature?")
        return

    log.info("Authorization Server advertises DPoP support!")

    global OIDC_CONFIGURATION
    OIDC_CONFIGURATION = well_known_response_json

    global PRIVATE_KEY
    with open(os.environ.get("DPOP_PRIVATE_KEY_FILE", "privateKey.pem"), 'r') as f:
        PRIVATE_KEY = f.read()

    global PUBLIC_JWK
    with open(os.environ.get("DPOP_PUBLIC_KEY_FILE", "publicKey.jwk"), 'r') as f:
        PUBLIC_JWK = json.loads(f.read())

    with socketserver.TCPServer(("", MY_PORT), DpopRequestHandler) as httpd:
        log.info(f"Server started on port {MY_PORT} - browse to http://localhost:{MY_PORT}/login to start!")
        httpd.serve_forever()


if __name__ == '__main__':
    main()
