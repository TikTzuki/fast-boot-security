import abc
from typing import Tuple

from fast_boot.schemas import AbstractUser
from starlette.authentication import AuthenticationBackend, AuthCredentials
from starlette.requests import HTTPConnection


class Authenticator(AuthenticationBackend):
    @abc.abstractmethod
    async def authenticate(self, conn: HTTPConnection) -> Tuple[AuthCredentials, AbstractUser]:
        ...
