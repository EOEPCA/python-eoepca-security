from fastapi import Depends, FastAPI, Request, BackgroundTasks
from fastapi.security.base import SecurityBase
from fastapi.security import OpenIdConnect, HTTPBearer, APIKeyHeader
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OpenIdConnect as OpenIdConnectModel
from starlette.exceptions import HTTPException
import base64
import json
import time
import logging
from starlette.status import HTTP_403_FORBIDDEN

import typing
import typing_extensions

import jwt
import requests

LOG = logging.getLogger("OIDCProxyScheme")

__all__=[
    "OIDCProxyScheme"
]

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
            str,
            typing_extensions.Doc("The client id for validating the auth.")
        ],
        id_token_header: typing.Annotated[str, typing_extensions.Doc("Header name for id token.")],
        auth_token_header: typing.Annotated[str, typing_extensions.Doc("Header name for auth token.")],
        refresh_token_header: typing.Annotated[str, typing_extensions.Doc("Header name for refresh token.")],
        auth_token_in_authorization: typing.Annotated[bool, typing_extensions.Doc("id_token_header is treated as an authorization header with scheme")] = True,
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

    async def __call__(self, request: Request) -> typing.Optional[typing.Dict[str,typing.Any]]:
        id_token_value = request.headers.get(self._id_token_header)
        
        if not self._auth_token_in_authorization:
            auth_token_value = request.headers.get(self._auth_token_header)
        else:
            auth_token_header_raw = request.headers.get(self._auth_token_header)
            scheme, auth_token_value = get_authorization_scheme_param(auth_token_header_raw)
            
        if scheme.lower() != "bearer":
            LOG.error(f"Invalid credential scheme {scheme}, expecting 'bearer'")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )

            return None

        refresh_token_value = request.headers.get(self._refresh_token_header)

        if id_token_value is None or auth_token_value is None or refresh_token_value is None:
            missing_tokens = [
                token_name
                for token_name, token_value in [
                    ("id", id_token_value),
                    ("auth", auth_token_value),
                    ("refresh", refresh_token_value)
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
            assert(isinstance(self.model, OpenIdConnectModel))
            oidc_config = requests.get(
                self.model.openIdConnectUrl
            ).json()
            signing_algos = oidc_config["id_token_signing_alg_values_supported"]
            jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

            signing_key = jwks_client.get_signing_key_from_jwt(auth_token_value)
        except Exception as e:
            LOG.error(f"Failed to get OIDC JWKS client: {str(e)}")

            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Invalid authentication credentials",
                )

        try:
            auth_token_data = jwt.decode_complete(
                auth_token_value,
                key=signing_key,
                audience=self._audience,
                algorithms=signing_algos,
            )
        except Exception as e:
            LOG.error(f"Failed to read token data: {str(e)}")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Invalid authentication credentials"
                )
            return None

        try:
            alg_obj = jwt.get_algorithm_by_name(auth_token_data["header"]["alg"])
        
            auth_token_digest = alg_obj.compute_hash_digest(auth_token_value.encode())
            auth_token_digest_computed_at_hash = base64.urlsafe_b64encode(auth_token_digest[: (len(auth_token_digest) // 2)]).rstrip(b"=")

            id_token_data = json.loads(base64.urlsafe_b64decode(id_token_value))
        except Exception as e:
            LOG.error(f"Failed to compute id token at_hash: {str(e)}")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Invalid authentication credentials"
                )
            return None

        if auth_token_digest_computed_at_hash != id_token_data["at_hash"].encode():
            LOG.error("Failed to validate id token at_hash")
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Invalid authentication credentials"
                )
            return None

        return {
            "tokens" : {
                "auth": auth_token_value,
                "id": id_token_value,
                "refresh": refresh_token_value
            },
            "claims" : id_token_data # + auth_token_data?
        }
