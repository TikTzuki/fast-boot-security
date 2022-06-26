import itertools
from typing import Dict, List, Iterable

from starlette import status

from fast_boot import error_code
from fast_boot.exception import LOSException
from fast_boot.schemas import AbstractUser


class AccessDecisionManager:
    permit_all: str = "permitAll"
    deny_all: str = "denyAll"
    anonymous: str = "anonymous"
    authenticated: str = "authenticated"
    fully_authenticated = "fullyAuthenticated"
    remember_me = "rememberMe"
    has_any_role = "hasAnyRole"
    has_role = "hasRole"
    has_authority = "hasAuthority"
    has_any_authority = "hasAnyAuthority"

    def decide(self, user: AbstractUser, attributes: List[Dict]):
        for attr in attributes:
            key = list(attr.keys())[0]
            if key in {self.has_any_authority, self.has_authority}:
                self.compare_authority(user, attr.values())
            elif key in {self.has_role, self.has_any_role}:
                self.compare_role(user, attr.values())

    def compare_role(self, user: AbstractUser, attribute: Iterable[str]):
        granted_roles = {role.code for role in user.get_role_hierarchy().roles}
        for granted_role in granted_roles:
            if granted_role in attribute:
                return
        raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)

    def compare_authority(self, user: AbstractUser, authorities: Iterable[str]):
        granted_permissions = set(itertools.chain(*[{per.code for per in role.permissions} for role in user.get_role_hierarchy().roles]))
        for granted_permission in granted_permissions:
            if granted_permission in authorities:
                return
        raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)
