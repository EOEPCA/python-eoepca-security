import base64
import json
import datetime

import typing

import jwt
import requests


class AuthToken:
    def __init__(self, raw: str):
        self.raw = raw


class DecodedAuthToken(AuthToken):
    def __init__(self, raw: str, decoded: dict[str, typing.Any]):
        super().__init__(raw=raw)
        self.decoded = decoded

    def digest(self) -> bytes:
        alg_obj = jwt.get_algorithm_by_name(self.decoded["header"]["alg"])
        auth_token_digest = alg_obj.compute_hash_digest(self.raw.encode())

        return base64.urlsafe_b64encode(
            auth_token_digest[: (len(auth_token_digest) // 2)]
        ).rstrip(b"=")

    def is_expired(
        self,
        at_time: datetime.datetime | None = None,
        margin: datetime.timedelta | None = None,
    ) -> bool:
        expiry_time = datetime.datetime.fromtimestamp(self.decoded["payload"]["exp"]) 

        at_time = at_time or datetime.datetime.now()

        if margin is not None:
            at_time = at_time + margin
        
        return expiry_time <= at_time


class ValidatedAuthToken(DecodedAuthToken):
    def __init__(self, raw: str, decoded: dict[str, typing.Any]):
        super().__init__(raw=raw, decoded=decoded)


class IDToken:
    def __init__(self, raw: str):
        self.raw = raw


class DecodedIDToken(IDToken):
    def __init__(self, raw: str, decoded: dict[str, typing.Any]):
        super().__init__(raw=raw)
        self.decoded = decoded


class ValidatedIDToken(DecodedIDToken):
    def __init__(self, raw: str, decoded: dict[str, typing.Any]):
        super().__init__(raw=raw, decoded=decoded)


class RefreshToken:
    def __init__(self, raw: str):
        self.raw = raw


class ClientCredentials:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret


class OIDCUtil:
    """
    utility class that wraps an OpenID-connect Well-Known Configuration
    """

    def __init__(self, oidc_config: dict[str, typing.Any]):
        self._oidc_config = oidc_config
        self._jwks_client = jwt.PyJWKClient(oidc_config["jwks_uri"])

    def validate_auth_token(
        self, auth_token: AuthToken | str, audience: str | None = None
    ) -> ValidatedAuthToken:
        """
        Validates an auth token and returns decoded and validated auth token.
        """
        if isinstance(auth_token, str):
            auth_token = AuthToken(raw=auth_token)

        signing_key = self._jwks_client.get_signing_key_from_jwt(auth_token.raw)

        return ValidatedAuthToken(
            raw=auth_token.raw,
            decoded=jwt.decode_complete(
                auth_token.raw,
                key=signing_key,
                audience=audience,
                algorithms=self._oidc_config["id_token_signing_alg_values_supported"],
            ),
        )

    def validate_id_token(
        self, auth_token: ValidatedAuthToken, id_token: IDToken | str
    ) -> ValidatedIDToken:
        """
        Validates an ID token and returns validated and decoded token.
        """
        if isinstance(id_token, str):
            id_token = IDToken(raw=id_token)

        id_token_data = json.loads(base64.urlsafe_b64decode(id_token.raw))

        if auth_token.digest() != id_token_data["at_hash"].encode():
            raise RuntimeError("id token has incorrect at_hash")

        return ValidatedIDToken(raw=id_token.raw, decoded=id_token_data)

    def refresh_auth_token(
        self, client_credentials: ClientCredentials, refresh_token: RefreshToken
    ) -> tuple[RefreshToken, AuthToken]:
        token_endpoint = self._oidc_config["token_endpoint"]

        refresh_data = requests.post(
            token_endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.raw,
                "client_id": client_credentials.client_id,
                "client_secret": client_credentials.client_secret,
            },
        ).json()

        return (
            RefreshToken(refresh_data["refresh_token"]),
            AuthToken(refresh_data["access_token"]),
        )


def request_oidcutil(url: str, **kvargs: dict[str, typing.Any]) -> OIDCUtil:
    """
    GETs an OpenID-connect Well-Known configuration and returns the corresponding OIDCUtil.
    """
    return OIDCUtil(oidc_config=requests.get(url, **kvargs).json())  # type: ignore
