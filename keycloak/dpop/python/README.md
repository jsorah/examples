
# DPoP on Keycloak (nightly)

https://datatracker.ietf.org/doc/html/rfc9449

## Start the server

Need to enable preview feature `dpop`

```
podman run -it --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:nightly start-dev --features=dpop
```

## add a client

dpop-client
- redirect-uri: http://localhost:8000
- Advanced Tab -> OAuth 2.0 DPoP Bound Access Tokens Enabled

## Generate the keys
Requirements - openssl and https://github.com/jphastings/jwker
1. `openssl genrsa -out privateKey.pem 2048`
2. `openssl rsa -in privateKey.pem -pubout -out publicKey.pem`
3. `jwker publicKey.pem > publicKey.jwk`

## Set up the python project

1. `python -m venv env`
2. `source bin/env/activate`
3. `pip install -r requirements.txt`
4. `python server.py`