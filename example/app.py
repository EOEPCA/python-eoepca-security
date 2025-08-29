from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request, BackgroundTasks
import os
import logging
import time
import typing
import requests

from eoepca_security import OIDCProxyScheme, ClientCredentials, Tokens
from eoepca_security.util import OIDCUtil

# Load environment variables from .env file
load_dotenv()

LOG = logging.getLogger("ExampleApp")

app = FastAPI()

OPEN_ID_CONNECT_URL = os.environ["OPEN_ID_CONNECT_URL"]
OPEN_ID_CONNECT_AUDIENCE = os.environ.get("OPEN_ID_CONNECT_AUDIENCE") or "account"

## Only needed for refresh/background task
OPEN_ID_CONNECT_CLIENT_ID = os.environ["OPEN_ID_CONNECT_CLIENT_ID"]
OPEN_ID_CONNECT_CLIENT_SECRET = os.environ["OPEN_ID_CONNECT_CLIENT_SECRET"]

CLIENT_CREDENTIALS = ClientCredentials(
    OPEN_ID_CONNECT_CLIENT_ID, OPEN_ID_CONNECT_CLIENT_SECRET
)

## Upstream "backend" endpoint to ping
REMOTE_PROTECTED_ENDPOINT = os.environ["REMOTE_PROTECTED_ENDPOINT"]

TLS_NO_VERIFY = (os.environ.get("TLS_NO_VERIFY") or "false").lower() == "true"

session = requests.Session()


def background(tokens: Tokens) -> None:
    wait = 20
    oidc_util = OIDCUtil(session)
    for i in range(20):
        if i % 3 == 2 and tokens is not None:
            oidc_config = oidc_util.get_oidc_config(OPEN_ID_CONNECT_URL)

            new_refresh_token, new_auth_token = oidc_util.refresh_auth_token(
                oidc_config,
                CLIENT_CREDENTIALS,
                tokens["refresh"],
            )

            new_auth_token = oidc_util.validate_auth_token(
                oidc_config, new_auth_token, OPEN_ID_CONNECT_AUDIENCE
            )

            tokens["refresh"] = new_refresh_token
            tokens["auth"] = new_auth_token

        if tokens is not None:
            headers = {"Authorization": f"Bearer {tokens['auth'].raw}"}
        else:
            headers = {}

        backend_request = session.get(
            REMOTE_PROTECTED_ENDPOINT,
            headers=headers,
            verify=not TLS_NO_VERIFY,
        )

        print(f"Background task ({i}), status: {backend_request.status_code}")

        time.sleep(wait)


security_scheme = OIDCProxyScheme(
    openIdConnectUrl=OPEN_ID_CONNECT_URL,
    audience=OPEN_ID_CONNECT_AUDIENCE,
    id_token_header="x-id-token",
    refresh_token_header="x-refresh-token",
    auth_token_header="Authorization",
    auth_token_in_authorization=True,
    auto_error=False,
    scheme_name="OIDC behind auth proxy",
)


@app.get("/")
async def root(
    tokens: typing.Annotated[Tokens, Depends(security_scheme)],
    req: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, typing.Any]:
    if tokens is None:
        username = "unauthorised person"
    elif "preferred_username" in tokens["id"].decoded:
        username = tokens["id"].decoded["preferred_username"]
    else:
        username = "mysterious stranger"

    if tokens is None:
        backend_request_headers = {}
    else:
        backend_request_headers = {"Authorization": f"Bearer {tokens['auth'].raw}"}

    backend_request = session.get(
        REMOTE_PROTECTED_ENDPOINT,
        headers=backend_request_headers,
        verify=not TLS_NO_VERIFY,
    )

    if backend_request.status_code != 200:
        backend_data = {
            "status_code": backend_request.status_code,
            "message": backend_request.text,
        }
    else:
        backend_data = backend_request.json()

    background_tasks.add_task(background, tokens)

    return {
        "message": f"Hello World, Hello {username}!",
        "backend": backend_data,
        "headers": dict(req.headers),
        "security": {
            "auth": tokens["auth"].raw,
            "id": tokens["id"].raw,
            "refresh": tokens["refresh"].raw,
            "id_claims": tokens["id"].decoded,
        }
        if tokens is not None
        else {},
    }
