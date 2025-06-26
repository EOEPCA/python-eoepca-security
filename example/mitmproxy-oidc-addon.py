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
from typing import Any, Optional, Self, Iterable
import os
from urllib.parse import urlparse
import requests

from mitmproxy import ctx as ctx, http as http
from mitmproxy.exceptions import OptionsError as OptionsError
from mitmproxy.addonmanager import Loader as Loader

from eoepca_security import (
    OIDCUtil,
    ClientCredentials,
    # AuthToken,
    ValidatedAuthToken,
    RefreshToken,
)


class OIDCAuthProxy:
    def __init__(self: Self):
        self._current_auth_token: ValidatedAuthToken | None = None
        self._current_refresh_token: RefreshToken | None = None
        self._oidc_util: OIDCUtil | None = None
        self._oidc_config: dict[str, Any] | None = None
        self._client_credentials: ClientCredentials | None = None

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="auth_token",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_AUTH_TOKEN"),
            help="(Initial) auth token (defaults to $OPEN_ID_AUTH_TOKEN)",
        )
        loader.add_option(
            name="refresh_token",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_REFRESH_TOKEN"),
            help="(Initial) refresh token (defaults to $OPEN_ID_REFRESH_TOKEN)",
        )
        loader.add_option(
            name="oidc_url",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_URL"),
            help="OIDC Well-known configuration URL (defaults to $OPEN_ID_CONNECT_URL)",
        )
        loader.add_option(
            name="oidc_client_id",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_ID"),
            help="OIDC client ID (defaults to $OPEN_ID_CONNECT_CLIENT_ID)",
        )
        loader.add_option(
            name="oidc_client_secret",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_CLIENT_SECRET"),
            help="OIDC client secret (defaults to $OPEN_ID_CONNECT_CLIENT_SECRET)",
        )
        loader.add_option(
            name="oidc_audience",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("OPEN_ID_CONNECT_AUDIENCE"),
            help="OIDC audience (for access token, defaults to $OPEN_ID_CONNECT_AUDIENCE)",
        )
        loader.add_option(
            name="termination_endpoint",
            typespec=Optional[str],  # type: ignore
            default=os.environ.get("PROXY_TERMINATION_ENDPOINT"),
            help=(
                "Endpoint to trigger termination of the proxy, useful when running in a sidecar, "
                "format is a url like http://host:port/path where host may be 0.0.0.0 and port/path "
                "may be skipped to indicate wildcards "
                "(defaults to $PROXY_TERMINATION_ENDPOINT or http://0.0.0.0/quitquitquit)"
            ),
        )

    def configure(self, updates: Iterable[str]) -> None:
        if ctx.options.oidc_url is None:
            raise OptionsError("Must specify oidc_url")  # type: ignore
        if "oidc_url" in updates:
            self._oidc_util = OIDCUtil(requests.Session())
            self._oidc_config = self._oidc_util.get_oidc_config(ctx.options.oidc_url)
        assert self._oidc_util is not None
        assert self._oidc_config is not None

        # if "auth_token" in updates or "refresh_token" in updates:
        if ctx.options.auth_token is None and ctx.options.refresh_token is None:
            raise OptionsError("Needs at least one of auth_token and refresh_token")  # type: ignore

        # if "oidc_client_id" in updates or "oidc_client_secret" in updates:
        if ctx.options.oidc_client_id is None:
            raise OptionsError("Must specify oidc_client_id")  # type: ignore

        if ctx.options.oidc_client_secret is None:
            raise OptionsError("Must specify oidc_client_secret")  # type: ignore

        self._client_credentials = ClientCredentials(
            ctx.options.oidc_client_id, ctx.options.oidc_client_secret
        )

        if ctx.options.termination_endpoint is None:
            self._termination_host: Optional[str] = None
            self._termination_port: Optional[int] = None
            self._termination_path: Optional[str] = "quitquitquit"
        else:
            termination_url = urlparse(ctx.options.termination_endpoint)

            if termination_url.hostname == "0.0.0.0":
                self._termination_host = None
            else:
                self._termination_host = termination_url.hostname

            self._termination_port = termination_url.port

            reduced_path = termination_url.path.strip().strip("/")
            self._termination_path = reduced_path if reduced_path else None

        if "auth_token" in updates:
            if ctx.options.auth_token is not None:
                self._current_auth_token = self._oidc_util.validate_auth_token(
                    self._oidc_config, ctx.options.auth_token, ctx.options.oidc_audience
                )

        if "refresh_token" in updates:
            self._current_refresh_token = RefreshToken(ctx.options.refresh_token)
            # self._ensure_access_token()

    def _ensure_access_token(self) -> ValidatedAuthToken:
        if self._current_auth_token is not None and self._current_auth_token.is_expired(
            margin=datetime.timedelta(minutes=1)
        ):
            ctx.log.info("auth_token expired")  # type: ignore
            self._current_auth_token = None

        if self._current_auth_token is None:
            if self._current_refresh_token is None:
                raise RuntimeError(
                    "Unable to refresh auth token due to missing refresh_token"
                )

            if self._oidc_util is None:
                raise RuntimeError("Internal error: _oidc_util not set")

            if self._oidc_config is None:
                raise RuntimeError("Internal error: _oidc_config not set")

            if self._client_credentials is None:
                raise RuntimeError("Internal error: _client_credentials not set")

            ctx.log.info("Refreshing auth_token")  # type: ignore
            new_refresh_token, new_auth_token = self._oidc_util.refresh_auth_token(
                self._oidc_config,
                self._client_credentials,
                self._current_refresh_token,
            )

            new_auth_token = self._oidc_util.validate_auth_token(
                self._oidc_config, new_auth_token, ctx.options.oidc_audience
            )

            self._current_auth_token = new_auth_token
            self._current_refresh_token = new_refresh_token

        return self._current_auth_token

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        flow.intercept()  # type: ignore

        if any(
            [
                self._termination_host is not None,
                self._termination_port is not None,
                self._termination_path is not None,
            ]
        ) and all(
            [
                self._termination_host is None
                or self._termination_host == flow.request.host,
                self._termination_port is None
                or self._termination_port == flow.request.port,
                self._termination_path is None
                or self._termination_path == flow.request.path.strip().strip("/"),
            ]
        ):
            flow.kill()  # type: ignore
            ctx.master.shutdown()  # type: ignore

        try:
            current_auth_token = self._ensure_access_token()
        except RuntimeError as e:
            ctx.log.error(str(e))  # type: ignore
            flow.kill()  # type: ignore

        # ctx.log.info(f"Bearer {self._current_auth_token.raw}")

        # age = datetime.datetime.now() - current_auth_token.issued_at()
        # slack_age = datetime.timedelta(seconds=1)
        # if age < slack_age:
        #     delay = (slack_age - age).total_seconds()
        #     ctx.log.info(f"Delaying {delay}s due to fresh token")  # type: ignore
        #     time.sleep(delay)

        flow.request.headers["authorization"] = f"Bearer {current_auth_token.raw}"
        flow.resume()  # type: ignore


addons = [OIDCAuthProxy()]
