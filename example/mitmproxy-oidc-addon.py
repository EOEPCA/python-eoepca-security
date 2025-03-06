"""
mitmproxy addon that adds an OIDC-authentication token to
proxied requests. The authentication-token is refreshed using
a refresh token, if provided.

Example:
mitmdump -s mitmproxy-oidc-addon.py --set refresh_token="..." --set oidc_url=".../.well-known/openid-configuration" --mode reverse:https://remote_service:remote_port

after which http://localhost:8080 forwards to https://remote_service:remote_port
(with refreshed auth tokens).
"""
import logging
import datetime
from typing import Optional
import os

from mitmproxy import ctx
from mitmproxy import exceptions

from eoepca_security import (
    request_oidcutil,
    OIDCUtil,
    ClientCredentials,
    AuthToken,
    ValidatedAuthToken,
    RefreshToken,
)


class OIDCAuthProxy:
    def __init__(self):
        self._current_auth_token: ValidatedAuthToken | None = None
        self._current_refresh_token: RefreshToken | None = None
        self._oidcutil: OIDCUtil | None = None
        self._client_credentials: ClientCredentials | None = None

    def load(self, loader):
        loader.add_option(
            name="auth_token",
            typespec=Optional[str],
            default=None,
            help="(Initial) auth token",
        )
        loader.add_option(
            name="refresh_token",
            typespec=Optional[str],
            default=None,
            help="(Initial) refresh token",
        )
        loader.add_option(
            name="oidc_url",
            typespec=Optional[str],
            default=os.environ.get("OPEN_ID_CONNECT_URL"),
            help="OIDC Well-known configuration URL (defaults to $OPEN_ID_CONNECT_URL)",
        )
        loader.add_option(
            name="oidc_client_id",
            typespec=Optional[str],
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_ID"),
            help="OIDC client ID (defaults to $OPEN_ID_CONNECT_CLIENT_ID)",
        )
        loader.add_option(
            name="oidc_client_secret",
            typespec=Optional[str],
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_SECRET"),
            help="OIDC client secret (defaults to $OPEN_ID_CONNECT_CLIENT_SECRET)",
        )
        loader.add_option(
            name="oidc_audience",
            typespec=Optional[str],
            default=os.environ.get("OPEN_ID_CONNECT_AUDIENCE"),
            help="OIDC audience (for access token)",
        )

    def configure(self, updates):
        if ctx.options.oidc_url is None:
            raise exceptions.OptionsError("Must specify oidc_url")
        if "oidc_url" in updates:
            self._oidcutil = request_oidcutil(ctx.options.oidc_url)
        assert self._oidcutil is not None

        # if "auth_token" in updates or "refresh_token" in updates:
        if ctx.options.auth_token is None and ctx.options.refresh_token is None:
            raise exceptions.OptionsError(
                "Needs at least one of auth_token and refresh_token"
            )

        if "auth_token" in updates:
            if ctx.options.auth_token is not None:
                self._current_auth_token = self._oidcutil.validate_auth_token(
                    ctx.options.auth_token, ctx.options.oidc_audience
                )

        # if "oidc_client_id" in updates or "oidc_client_secret" in updates:
        if ctx.options.oidc_client_id is None:
            raise exceptions.OptionsError("Must specify oidc_client_id")

        if ctx.options.oidc_client_secret is None:
            raise exceptions.OptionsError("Must specify oidc_client_secret")

        self._client_credentials = ClientCredentials(
            ctx.options.oidc_client_id, ctx.options.oidc_client_secret
        )

    def request(self, flow):
        if self._current_auth_token is not None and self._current_auth_token.is_expired(
            margin=datetime.timedelta(minutes=1)
        ):
            logging.info("auth_token expired")
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

            logging.info("Refreshing auth_token")
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
