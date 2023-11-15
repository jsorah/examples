
# DPoP on Keycloak (nightly)

https://datatracker.ietf.org/doc/html/rfc9449

## Start the server

Need to enable preview feature `dpop`

```
podman run --pull=always -it --rm --name keycloak-test -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:nightly \
    start-dev --features=dpop
```

## Add a public client with DPoP bound tokens enabled

### Using `kcadm.sh` and the [client.json](client.json)
```
podman exec -i keycloak-test \
    /opt/keycloak/bin/kcadm.sh \
    create clients \
    --server http://localhost:8080 \
    --realm master \
    --user admin \
    --password admin \
    -f - < client.json
```

### Manually
dpop-client
- make sure its public
- redirect-uri: http://localhost:8000
- Advanced Tab -> OAuth 2.0 DPoP Bound Access Tokens Enabled

## Generate the keys
Requirements - openssl and https://github.com/jphastings/jwker
1. `openssl genrsa -out privateKey.pem 2048`
2. `openssl rsa -in privateKey.pem -pubout -out publicKey.pem`
3. `jwker publicKey.pem > publicKey.jwk`

## Set up the python project

1. `python -m venv env`
2. `source env/bin/activate`
3. `pip install -r requirements.txt`
4. `python server.py`
