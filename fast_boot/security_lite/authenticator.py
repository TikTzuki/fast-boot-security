import abc
from typing import Tuple

from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection, Request

from fast_boot.schemas import AbstractUser


class Authenticator(AuthenticationBackend):
    @abc.abstractmethod
    async def authenticate(self, request: Request) -> Tuple[AuthCredentials, AbstractUser]:
        ...
