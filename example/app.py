from fastapi import Depends, FastAPI, Request, BackgroundTasks

from eoepca_security import OIDCProxyScheme

import os
import logging
import time

import typing
# import typing_extensions

import requests

LOG = logging.getLogger("ExampleApp")

app = FastAPI()

OPEN_ID_CONNECT_URL = os.environ["OPEN_ID_CONNECT_URL"]
OPEN_ID_CONNECT_AUDIENCE = os.environ.get("OPEN_ID_CONNECT_AUDIENCE") or "account"

## Only needed for refresh/background task
OPEN_ID_CONNECT_CLIENT_ID = os.environ["OPEN_ID_CONNECT_CLIENT_ID"]
OPEN_ID_CONNECT_CLIENT_SECRET = os.environ["OPEN_ID_CONNECT_CLIENT_SECRET"]

## Upstream "backend" endpoint to ping
REMOTE_PROTECTED_ENDPOINT = os.environ["REMOTE_PROTECTED_ENDPOINT"]

TLS_NO_VERIFY = (os.environ.get("TLS_NO_VERIFY") or "false").lower() == "true"


def background(security: typing.Any) -> None:
    wait = 20
    for i in range(20):
        if i % 3 == 2 and security is not None:
            oidc_config = requests.get(OPEN_ID_CONNECT_URL).json()
            token_endpoint = oidc_config["token_endpoint"]

            refresh_data = requests.post(
                token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": security["tokens"]["refresh"],
                    "client_id": OPEN_ID_CONNECT_CLIENT_ID,
                    "client_secret": OPEN_ID_CONNECT_CLIENT_SECRET,
                },
            ).json()

            security["tokens"]["auth"] = refresh_data["access_token"]
            security["tokens"]["refresh"] = refresh_data["refresh_token"]

        if security:
            headers = {"Authorization": f"Bearer {security['tokens']['auth']}"}
        else:
            headers = {}

        backend_request = requests.get(
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
    security: typing.Annotated[typing.Any, Depends(security_scheme)],
    req: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, typing.Any]:
    if security is None:
        username = "unauthorised person"
    elif "preferred_username" in security["claims"]:
        username = security["claims"]["preferred_username"]
    else:
        username = "mysterious stranger"

    if security is None:
        backend_request_headers = {}
    else:
        backend_request_headers = {
            "Authorization": f"Bearer {security['tokens']['auth']}"
        }

    backend_request = requests.get(
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

    background_tasks.add_task(background, security)

    return {
        "message": f"Hello World, Hello {username}!",
        "backend": backend_data,
        "headers": dict(req.headers),
        "security": security,
    }
