from typing import List

from fast_boot.security.core import GrantedAuthority


class Role:
    role: str
    permissions: List[str] = []

    def __init__(self, role: str, permissions: List[str]):
        self.role = role
        self.permissions = permissions


class RoleHierarchy:
    roles: List[Role] = []

    def get_reachable_granted_authorities(self, authorities: List[GrantedAuthority]) -> List[GrantedAuthority]:
        ...
