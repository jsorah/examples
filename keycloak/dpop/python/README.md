
DPoP on Keycloak (23)

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

## Generate a JWKS

https://web3auth.io/docs/auth-provider-setup/byo-jwt-providers#how-to-convert-pem-to-jwks

https://github.com/jphastings/jwker


doesn't like HS256
