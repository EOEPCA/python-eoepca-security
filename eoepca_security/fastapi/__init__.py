from fastapi import Request
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OpenIdConnect as OpenIdConnectModel
from starlette.exceptions import HTTPException
import logging
from starlette.status import HTTP_403_FORBIDDEN

import typing
import typing_extensions

from .. import util

LOG = logging.getLogger("OIDCProxyScheme")

__all__ = ["OIDCProxyScheme"]

Tokens = typing.TypedDict(
    "Tokens",
    {
        "auth": util.ValidatedAuthToken,
        "id": util.ValidatedIDToken,
        "refresh": util.RefreshToken,
    },
)


class OIDCProxyScheme(SecurityBase):
    """
    Currently specifically designed for running auth behind an APISIX proxy
    that uses the openid-connect plugin.
    """

    def __init__(
        self,
        *,
        openIdConnectUrl: typing.Annotated[
            str,
            typing_extensions.Doc("The OpenID Connect URL."),
        ],
        audience: typing.Annotated[
            str, typing_extensions.Doc("The client id for validating the auth.")
        ],
        id_token_header: typing.Annotated[
            str, typing_extensions.Doc("Header name for id token.")
        ],
        auth_token_header: typing.Annotated[
            str, typing_extensions.Doc("Header name for auth token.")
        ],
        refresh_token_header: typing.Annotated[
            str, typing_extensions.Doc("Header name for refresh token.")
        ],
        auth_token_in_authorization: typing.Annotated[
            bool,
            typing_extensions.Doc(
                "id_token_header is treated as an authorization header with scheme"
            ),
        ] = True,
        scheme_name: typing.Annotated[
            typing.Optional[str],
            typing_extensions.Doc(
                """
                Security scheme name.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        description: typing.Annotated[
            typing.Optional[str],
            typing_extensions.Doc(
                """
                Security scheme description.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        auto_error: typing.Annotated[
            bool,
            typing_extensions.Doc(
                """
                By default, if the header is not provided, `APIKeyHeader` will
                automatically cancel the request and send the client an error.

                If `auto_error` is set to `False`, when the header is not available,
                instead of erroring out, the dependency result will be `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, in a header or
                in an HTTP Bearer token).
                """
            ),
        ] = True,
    ):
        self.model = OpenIdConnectModel(
            openIdConnectUrl=openIdConnectUrl, description=description
        )
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

        self._id_token_header = id_token_header
        self._auth_token_header = auth_token_header
        self._refresh_token_header = refresh_token_header
        self._auth_token_in_authorization = auth_token_in_authorization
        self._audience = audience

    async def __call__(self, request: Request) -> Tokens | None:
        id_token_raw = request.headers.get(self._id_token_header)

        if not self._auth_token_in_authorization:
            auth_token_raw = request.headers.get(self._auth_token_header)
        else:
            auth_token_header_raw = request.headers.get(self._auth_token_header)
            scheme, auth_token_raw = get_authorization_scheme_param(
                auth_token_header_raw
            )

        if scheme.lower() != "bearer":
            LOG.error(f"Invalid credential scheme {scheme}, expecting 'bearer'")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )

            return None

        refresh_token_raw = request.headers.get(self._refresh_token_header)

        if id_token_raw is None or auth_token_raw is None or refresh_token_raw is None:
            missing_tokens = [
                token_name
                for token_name, token_value in [
                    ("id", id_token_raw),
                    ("auth", auth_token_raw),
                    ("refresh", refresh_token_raw),
                ]
                if token_value is None
            ]
            LOG.error(f"Missing tokens: {','.join(missing_tokens)}")

            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            return None

        ## NOTE: Get rid of this downcasting...
        try:
            assert isinstance(self.model, OpenIdConnectModel)
            oidc_util = util.request_oidcutil(self.model.openIdConnectUrl)
        except Exception as e:
            LOG.error(f"Failed to get OIDC JWKS client: {str(e)}")

            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )

        try:
            auth_token = oidc_util.validate_auth_token(
                auth_token_raw,
                audience=self._audience,
            )
        except Exception as e:
            LOG.error(f"Failed to read token data: {str(e)}")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )
            return None

        try:
            id_token = oidc_util.validate_id_token(auth_token, id_token_raw)
        except Exception as e:
            LOG.error(f"Failed to validate id token: {str(e)}")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )
            return None

        return {
            "auth": auth_token,
            "id": id_token,
            "refresh": util.RefreshToken(raw=refresh_token_raw),
        }
