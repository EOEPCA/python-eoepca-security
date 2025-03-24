from mitmproxy.tools.main import mitmdump
import os

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

OPEN_ID_AUTH_TOKEN = os.environ.get("OPEN_ID_AUTH_TOKEN")
OPEN_ID_REFRESH_TOKEN = os.environ.get("OPEN_ID_REFRESH_TOKEN")
if OPEN_ID_AUTH_TOKEN is None and OPEN_ID_REFRESH_TOKEN is None:
    exit("Please set at least one of OPEN_ID_AUTH_TOKEN or OPEN_ID_REFRESH_TOKEN")

if "TLS_NO_VERIFY" not in os.environ:
    EXTRA_ARGS = []
else:
    EXTRA_ARGS = ["--set", "ssl_insecure=true"]

PROXY_HOST = os.environ.get("PROXY_HOST")
PROXY_PORT = os.environ.get("PROXY_PORT")

mitmdump(args=["-s", "mitmproxy-oidc-addon.py"] + EXTRA_ARGS)
