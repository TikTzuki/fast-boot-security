from typing import Dict, Type, Any

import uvicorn

from fast_boot.middleware import HttpSecurityMiddleWare
from fast_boot.schemas import AbstractUser, UnAuthenticatedUser
from fast_boot.security.authentication import Authenticator
from fast_boot.security.http_security import HttpSecurity
from .main import app

import typing

from fastapi.security.utils import get_authorization_scheme_param
from starlette.authentication import AuthCredentials
from starlette.requests import HTTPConnection


class AuthenticationManager(Authenticator):
    async def authenticate(self, conn: HTTPConnection) -> typing.Tuple[AuthCredentials, typing.Optional[AbstractUser]]:
        unauthenticated = AuthCredentials(), UnAuthenticatedUser()
        authorization: str = conn.headers.get("Authorization")
        if not authorization:
            return unauthenticated
        scheme, credentials = get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            return unauthenticated
        if scheme == "Bearer":
            ...
        # authenticated_user = AbstractUser(
        #     access_token=credentials,
        #     user_info=data_decode["user_info"],
        # )
        # return AuthCredentials(scopes=[]), authenticated_user


class FastHttpSecurityMiddleWare(HttpSecurityMiddleWare):
    def configure(self, http: HttpSecurity):
        super().configure(http)
        http.authorize_requests() \
            .regex_matchers(None, "/role-login/*").anonymous() \
            .regex_matchers("get", "/role$").has_role("role-1") \
            .regex_matchers("get", "/any-role").has_any_role("role-2", "role-3", "ACCESS") \
            .regex_matchers("get", "/permission").has_authority("permission-1") \
            .regex_matchers("get", "/any-permission").has_any_authority("permission-2", "permission-3") \
            .any_request().authenticated()

    def create_shared_object(self) -> Dict[Type, Any]:
        shared_objects = super().create_shared_object()
        shared_objects.update({Authenticator: AuthenticationManager()})
        return shared_objects


app.add_middleware(HttpSecurityMiddleWare)

if __name__ == "__main__":
    uvicorn.run('tests.test_middleware:app', host="127.0.0.1", port=8000, reload=True)
