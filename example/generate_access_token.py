import os
import requests

from eoepca_security import (
    request_oidcutil,
    ClientCredentials,
    RefreshToken,
)

OPEN_ID_CONNECT_URL = os.environ.get("OPEN_ID_CONNECT_URL")
if OPEN_ID_CONNECT_URL is None:
    exit("Please set OPEN_ID_CONNECT_URL")

OPEN_ID_CONNECT_CLIENT_ID = os.environ.get("OPEN_ID_CONNECT_CLIENT_ID")
if OPEN_ID_CONNECT_CLIENT_ID is None:
    exit("Please set OPEN_ID_CONNECT_CLIENT_ID")

OPEN_ID_CONNECT_CLIENT_SECRET = os.environ.get("OPEN_ID_CONNECT_CLIENT_SECRET")
if OPEN_ID_CONNECT_CLIENT_SECRET is None:
    exit("Please set OPEN_ID_CONNECT_CLIENT_SECRET")

OPEN_ID_CONNECT_AUDIENCE = os.environ.get("OPEN_ID_CONNECT_AUDIENCE")
if OPEN_ID_CONNECT_AUDIENCE is None:
    exit("Please set OPEN_ID_CONNECT_AUDIENCE")

OPEN_ID_REFRESH_TOKEN = os.environ.get("OPEN_ID_REFRESH_TOKEN")
if OPEN_ID_REFRESH_TOKEN is None:
    exit("Please set OPEN_ID_REFRESH_TOKEN")

client_credentials = ClientCredentials(
    OPEN_ID_CONNECT_CLIENT_ID, OPEN_ID_CONNECT_CLIENT_SECRET
)

new_refresh_token, new_auth_token = request_oidcutil(
    OPEN_ID_CONNECT_URL,
    session=requests.Session(),
    prev_oidc_util=None
).refresh_auth_token(
    client_credentials,
    RefreshToken(OPEN_ID_REFRESH_TOKEN),
)

# print(f"New refresh token:\n\n{new_refresh_token.raw}\n\nAuth token\n\n{new_auth_token.raw}\n")
print(new_auth_token.raw)
