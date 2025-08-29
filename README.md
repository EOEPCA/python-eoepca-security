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

First create an `.env` file with environment variables based on [.env.example](./.env.example). The scripts will automatically load environment variables from it in addition to the actual environment variables.

Run the [example service](./example/app.py) using [uv](https://docs.astral.sh/uv/)
```
uv run fastapi dev example/app.py --host=0.0.0.0
```
Use `--port=8080` to select a port and `--root-path=/...` if you use a proxy prefix.

When accessed, the example service tries to access `REMOTE_PROTECTED_ENDPOINT` once by forwarding
access tokens (if provided and valid), then runs a background task that accesses `REMOTE_PROTECTED_ENDPOINT` 
every 20 seconds for a few minutes by refreshing the access token (if provided). 

The service expects to be forwarded access, refresh, and ID tokens, as done by the openid-connect plugin for APISIX. See [this guide](https://github.com/EOEPCA/resource-health/wiki/Exposing-a-local-service-on-the-apx.develop.eoepca.org-ingress) for how to expose a locally running service behind a remote APISIX ingress.

## mitmproxy add-on

The repository also contains an example [mitmproxy](https://mitmproxy.org/) add-on, which can be used to proxy (unauthenticated) requests to a service which requires authentication. It does so by using provided access and/or refresh tokens.

Usage example
```
mitmdump -s mitmproxy-oidc-addon.py --set refresh_token="..." --set oidc_url=".../.well-known/openid-configuration" --mode reverse:https://remote_service:remote_port
```
Once running, [http://localhost:8080](http://localhost:8080) will forward to
[https://remote_service:remote_port](https://remote_service:remote_port) (with refreshed auth tokens).

You can also use the utility script [example/run-mitmproxy.py](./example/run-mitmproxy.py) which configures the add-on through environment variables (see [.env.example](./.env.example)). This is especially useful when used in a container,

```
docker build -t mitmproxy-oidc -f Dockerfile.mitmproxy
```


```
docker run --rm -it  -p 8080:8080 -e OPEN_ID_CONNECT_URL="$OPEN_ID_CONNECT_URL" -e OPEN_ID_CONNECT_CLIENT_ID="$OPEN_ID_CONNECT_CLIENT_ID" -e OPEN_ID_CONNECT_CLIENT_SECRET="$OPEN_ID_CONNECT_CLIENT_SECRET" -e REMOTE_PROTECTED_DOMAIN="$REMOTE_PROTECTED_DOMAIN" -e TLS_NO_VERIFY="true" -e OPEN_ID_CONNECT_AUDIENCE="$OPEN_ID_CONNECT_AUDIENCE" -e OPEN_ID_REFRESH_TOKEN="$OPEN_ID_REFRESH_TOKEN" mitmproxy-oidc
```