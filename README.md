# Python eoepca-security

NOTE: Name is a placeholder 

Shared implementation of authentication/authorization related code for
clients written in Python.

Current focus is on:

+ Using OAuth/OIDC tokens as forwarded by APISIX

for use with

+ FastAPI

The main contribution at the moment is `eoepca_security.OIDCProxyScheme` which can be used
with FastAPI similarly to [built-in security schemes](https://fastapi.tiangolo.com/tutorial/security/):
```python
security_scheme = OIDCProxyScheme(
    openIdConnectUrl = "https://.../.well-known/openid-configuration",
    audience = "account",
    id_token_header = "x-id-token",
    refresh_token_header = "x-refresh-token",
    auth_token_header = "Authorization",
    auth_token_in_authorization = True,
    auto_error = False,
    scheme_name = "OIDC behind auth proxy"
)

@app.get("/")
async def root(
    security: typing.Annotated[typing.Any, Depends(security_scheme)],
):
    if security is None:
        username = "unauthorised person"
    elif "preferred_username" in security["claims"]:
        username = security["claims"]["preferred_username"]
    else:
        username = "mysterious stranger"
    # ...
```

## Example

To run the [example service](./example/app.py) using [uv](https://docs.astral.sh/uv/) first set
environment variables (see [env.example](./env.example)) and run
```
uv run fastapi dev example/app.py --host=0.0.0.0
```
Use `--port=8080` to select a port and `--root-path=/...` if you use a proxy prefix.

When accessed, the example service tries to access `REMOTE_PROTECTED_ENDPOINT` once by forwarding
access tokens (if provided and valid), then runs a background task that accesses `REMOTE_PROTECTED_ENDPOINT` 
every 20 seconds for a few minutes by refreshing the access token (if provided). 

The service expects to be forwarded access, refresh, and ID tokens, as done by the openid-connect plugin
for APISIX. See
[this guide](https://github.com/EOEPCA/resource-health/wiki/Exposing-a-local-service-on-the-apx.develop.eoepca.org-ingress)
for how to expose a locally running service behind a remote APISIX ingress.
