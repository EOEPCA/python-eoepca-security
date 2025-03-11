"""
mitmproxy addon that adds an OIDC-authentication token to
proxied requests. The authentication-token is refreshed using
a refresh token, if provided.

Example:
mitmdump -s mitmproxy-oidc-addon.py --set refresh_token="..." --set oidc_url=".../.well-known/openid-configuration" --mode reverse:https://remote_service:remote_port

after which http://localhost:8080 forwards to https://remote_service:remote_port
(with refreshed auth tokens).
"""

import datetime
from typing import Optional, Self, Iterable
import os

from mitmproxy import ctx as ctx, http as http
from mitmproxy.exceptions import OptionsError as OptionsError
from mitmproxy.addonmanager import Loader as Loader

from eoepca_security import (
    request_oidcutil,
    OIDCUtil,
    ClientCredentials,
    # AuthToken,
    ValidatedAuthToken,
    RefreshToken,
)


class OIDCAuthProxy:
    def __init__(self : Self):
        self._current_auth_token: ValidatedAuthToken | None = None
        self._current_refresh_token: RefreshToken | None = None
        self._oidcutil: OIDCUtil | None = None
        self._client_credentials: ClientCredentials | None = None

    def load(self, loader : Loader) -> None:
        loader.add_option(
            name="auth_token",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_AUTH_TOKEN"),
            help="(Initial) auth token (defaults to $OPEN_ID_AUTH_TOKEN)",
        )
        loader.add_option(
            name="refresh_token",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_REFRESH_TOKEN"),
            help="(Initial) refresh token (defaults to $OPEN_ID_REFRESH_TOKEN)",
        )
        loader.add_option(
            name="oidc_url",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_URL"),
            help="OIDC Well-known configuration URL (defaults to $OPEN_ID_CONNECT_URL)",
        )
        loader.add_option(
            name="oidc_client_id",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_ID"),
            help="OIDC client ID (defaults to $OPEN_ID_CONNECT_CLIENT_ID)",
        )
        loader.add_option(
            name="oidc_client_secret",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_SECRET"),
            help="OIDC client secret (defaults to $OPEN_ID_CONNECT_CLIENT_SECRET)",
        )
        loader.add_option(
            name="oidc_audience",
            typespec=Optional[str], # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_AUDIENCE"),
            help="OIDC audience (for access token, defaults to $OPEN_ID_CONNECT_AUDIENCE)",
        )

    def configure(self, updates : Iterable[str]) -> None:
        if ctx.options.oidc_url is None:
            raise OptionsError("Must specify oidc_url") # type: ignore
        if "oidc_url" in updates:
            self._oidcutil = request_oidcutil(ctx.options.oidc_url)
        assert self._oidcutil is not None

        # if "auth_token" in updates or "refresh_token" in updates:
        if ctx.options.auth_token is None and ctx.options.refresh_token is None:
            raise OptionsError(
                "Needs at least one of auth_token and refresh_token"
            ) # type: ignore

        if "auth_token" in updates:
            if ctx.options.auth_token is not None:
                self._current_auth_token = self._oidcutil.validate_auth_token(
                    ctx.options.auth_token, ctx.options.oidc_audience
                )

        # if "oidc_client_id" in updates or "oidc_client_secret" in updates:
        if ctx.options.oidc_client_id is None:
            raise OptionsError("Must specify oidc_client_id") # type: ignore

        if ctx.options.oidc_client_secret is None:
            raise OptionsError("Must specify oidc_client_secret") # type: ignore

        self._client_credentials = ClientCredentials(
            ctx.options.oidc_client_id, ctx.options.oidc_client_secret
        )

    def request(self, flow : http.HTTPFlow) -> None:
        if self._current_auth_token is not None and self._current_auth_token.is_expired(
            margin=datetime.timedelta(minutes=1)
        ):
            ctx.log.info("auth_token expired") # type: ignore
            self._current_auth_token = None

        if self._current_auth_token is None:
            if self._current_refresh_token is None:
                if ctx.options.refresh_token is None:
                    raise RuntimeError(
                        "Unable to refresh auth token due to missing refresh_token"
                    )
                self._current_refresh_token = RefreshToken(ctx.options.refresh_token)

            if self._oidcutil is None:
                raise RuntimeError("Internal error: _oidcutil not set")

            if self._client_credentials is None:
                raise RuntimeError("Internal error: _client_credentials not set")

            ctx.log.info("Refreshing auth_token") # type: ignore
            new_refresh_token, new_auth_token = self._oidcutil.refresh_auth_token(
                self._client_credentials,
                self._current_refresh_token,
            )

            new_auth_token = self._oidcutil.validate_auth_token(
                new_auth_token, ctx.options.oidc_audience
            )

            self._current_auth_token = new_auth_token
            self._current_refresh_token = new_refresh_token

        flow.request.headers["authorization"] = f"Bearer {self._current_auth_token.raw}"


addons = [OIDCAuthProxy()]
