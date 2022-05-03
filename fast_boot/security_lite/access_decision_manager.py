import itertools
from typing import List

import orjson
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

    def decide(self, user: AbstractUser, attributes: List[str]):
        for attr in attributes:
            if attr.startswith(self.has_any_authority):
                self.compare_authority(user, attr.replace(self.has_any_authority + "(", "[")[:-1] + "]")
            if attr.startswith(self.has_authority):
                self.compare_authority(user, attr.replace(self.has_authority + "(", "[")[:-1] + "]")
            if attr.startswith(self.has_role):
                self.compare_role(user, attr.replace(self.has_role + "(", "[")[:-1] + "]")
            if attr.startswith(self.has_any_role):
                self.compare_role(user, attr.replace(self.has_any_role + "(", "[")[:-1] + "]")

    def compare_role(self, user: AbstractUser, attribute: str):
        attribute = attribute.replace("'", '"')
        roles = set(orjson.loads(attribute))
        granted_roles = {role.role_code for role in user.role_hierarchy.roles}
        for granted_role in granted_roles:
            if granted_role in roles:
                return
        raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)

    def compare_authority(self, user: AbstractUser, attribute: str):
        attribute = attribute.replace("'", '"')
        authorities = set(orjson.loads(attribute))
        granted_permissions = set(itertools.chain(*[{per.permission_code for per in role.permissions} for role in user.role_hierarchy.roles]))
        for granted_permission in granted_permissions:
            if granted_permission in authorities:
                return
        raise LOSException.with_error(code=error_code.ACCESS_DENIED, status_code=status.HTTP_403_FORBIDDEN)
