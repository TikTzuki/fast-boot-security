import abc
import typing

from fastapi.security import HTTPBasicCredentials
from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.requests import HTTPConnection

from fast_boot.schemas import AbstractUser, Filter


class AuthenticationTrustResolver:
    def is_anonymous(self, authentication: HTTPBasicCredentials) -> bool:
        ...

    def is_remember_me(self, authentication: HTTPBasicCredentials) -> bool:
        ...


class UsernamePasswordAuthenticationFilter(Filter):
    async def do_filter(self, request, response, filter_chain) -> None:
        pass


class Authenticator(AuthenticationBackend):
    @abc.abstractmethod
    async def authenticate(self, conn: HTTPConnection) -> typing.Tuple[AuthCredentials, AbstractUser]:
        ...
